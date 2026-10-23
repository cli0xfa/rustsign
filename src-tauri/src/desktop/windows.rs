//! A non-painting child HWND exposes the HTML maximize button to Windows Snap.
//! It is a sibling above WebView2, which would otherwise consume hit testing.
use super::ChromeRect;
use std::{
    collections::HashMap,
    sync::{LazyLock, Mutex},
};
use tauri::{Emitter, WebviewWindow};
use windows::{
    Win32::{
        Foundation::{HGLOBAL, HWND, LPARAM, LRESULT, POINT, RECT, WPARAM},
        Graphics::Dwm::{
            DWMWA_CLOAK, DWMWA_WINDOW_CORNER_PREFERENCE, DWMWCP_ROUND, DwmFlush,
            DwmSetWindowAttribute,
        },
        Graphics::Gdi::{ClientToScreen, ValidateRect},
        System::Com::StructuredStorage::CreateStreamOnHGlobal,
        System::LibraryLoader::GetModuleHandleW,
        UI::Controls::WM_MOUSELEAVE,
        UI::HiDpi::GetDpiForWindow,
        UI::{
            Input::KeyboardAndMouse::{
                ReleaseCapture, SetCapture, TME_LEAVE, TME_NONCLIENT, TRACKMOUSEEVENT,
                TrackMouseEvent,
            },
            Shell::{DefSubclassProc, RemoveWindowSubclass, SetWindowSubclass},
            WindowsAndMessaging::*,
        },
    },
    core::w,
};

#[derive(Clone)]
struct Chrome {
    window: WebviewWindow,
    overlay: isize,
    rect: ChromeRect,
    blocked: bool,
    pressed: bool,
}
static WINDOWS: LazyLock<Mutex<HashMap<isize, Chrome>>> = LazyLock::new(Default::default);

fn cloak(window: &WebviewWindow, hidden: bool) -> tauri::Result<()> {
    let value = i32::from(hidden);
    unsafe {
        DwmSetWindowAttribute(
            window.hwnd()?,
            DWMWA_CLOAK,
            &value as *const _ as *const _,
            std::mem::size_of_val(&value) as u32,
        )
        .map_err(std::io::Error::other)?;
    }
    Ok(())
}

/// Let WebView2 render while DWM keeps the window off the desktop. A completed
/// in-memory preview is the render barrier; there is no splash or fixed delay.
pub async fn show_painted(window: &WebviewWindow) -> tauri::Result<()> {
    cloak(window, true)?;
    if let Err(error) = window.show() {
        let _ = cloak(window, false);
        return Err(error);
    }
    let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
    let setup = window.with_webview(move |webview| unsafe {
        let completed_sender = sender.clone();
        let capture = (|| -> windows::core::Result<()> {
            let stream = CreateStreamOnHGlobal(HGLOBAL::default(), true)?;
            let retained_stream = stream.clone();
            let handler = webview2_com::CapturePreviewCompletedHandler::create(Box::new(move |status| {
                drop(retained_stream);
                let _ = completed_sender.send(status.map_err(|e| e.to_string()));
                Ok(())
            }));
            webview.controller().CoreWebView2()?.CapturePreview(
                webview2_com::Microsoft::Web::WebView2::Win32::COREWEBVIEW2_CAPTURE_PREVIEW_IMAGE_FORMAT_PNG,
                &stream, &handler)?;
            Ok(())
        })();
        if let Err(error) = capture { let _ = sender.send(Err(error.to_string())); }
    });
    let painted = match setup {
        Err(error) => Err(error),
        Ok(()) => {
            match tokio::time::timeout(std::time::Duration::from_secs(8), receiver.recv()).await {
                Ok(Some(Ok(()))) => Ok(()),
                Ok(Some(Err(error))) => Err(std::io::Error::other(error).into()),
                _ => Err(std::io::Error::other("WebView2 did not produce the first frame.").into()),
            }
        }
    };
    if painted.is_err() {
        let _ = window.hide();
    }
    // The compositor has the rendered surface before the cloak is removed.
    unsafe {
        let _ = DwmFlush();
    }
    let uncloaked = cloak(window, false);
    painted.and(uncloaked)
}

fn position(parent: HWND) {
    let chrome = WINDOWS
        .lock()
        .ok()
        .and_then(|items| items.get(&(parent.0 as isize)).cloned());
    let Some(chrome) = chrome else {
        return;
    };
    // Query Win32 directly inside window procedures; never wait on the Tauri
    // event loop while handling a synchronous native resize/DPI message.
    let scale = unsafe { GetDpiForWindow(parent) }.max(96) as f64 / 96.0;
    let [x, y, width, height] = chrome.rect.physical(scale);
    unsafe {
        let overlay = HWND(chrome.overlay as *mut _);
        if chrome.blocked {
            let _ = ShowWindow(overlay, SW_HIDE);
        } else {
            let _ = SetWindowPos(
                overlay,
                Some(HWND_TOP),
                x,
                y,
                width,
                height,
                SWP_NOACTIVATE | SWP_SHOWWINDOW,
            );
        }
    }
}

fn emit_caption(parent: HWND, action: &str) {
    let window = WINDOWS.lock().ok().and_then(|items| {
        items
            .get(&(parent.0 as isize))
            .map(|chrome| chrome.window.clone())
    });
    if let Some(window) = window {
        let _ = window.emit("desktop://caption", action);
    }
}

unsafe extern "system" fn overlay_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    unsafe {
        let parent = GetParent(hwnd).unwrap_or_default();
        match msg {
            WM_NCHITTEST => return LRESULT(HTMAXBUTTON as isize),
            WM_ERASEBKGND => return LRESULT(1),
            WM_PAINT => {
                let _ = ValidateRect(Some(hwnd), None);
                return LRESULT(0);
            }
            WM_NCMOUSEMOVE | WM_MOUSEMOVE => {
                emit_caption(parent, "enter");
                let mut tracking = TRACKMOUSEEVENT {
                    cbSize: std::mem::size_of::<TRACKMOUSEEVENT>() as u32,
                    dwFlags: if msg == WM_NCMOUSEMOVE {
                        TME_LEAVE | TME_NONCLIENT
                    } else {
                        TME_LEAVE
                    },
                    hwndTrack: hwnd,
                    dwHoverTime: 0,
                };
                let _ = TrackMouseEvent(&mut tracking);
            }
            WM_NCMOUSELEAVE | WM_MOUSELEAVE => emit_caption(parent, "leave"),
            WM_NCLBUTTONDOWN | WM_LBUTTONDOWN => {
                if let Ok(mut items) = WINDOWS.lock()
                    && let Some(chrome) = items.get_mut(&(parent.0 as isize))
                {
                    chrome.pressed = true;
                }
                SetCapture(hwnd);
                emit_caption(parent, "down");
                return LRESULT(0);
            }
            WM_NCLBUTTONUP | WM_LBUTTONUP => {
                let was_pressed = WINDOWS
                    .lock()
                    .ok()
                    .and_then(|mut items| {
                        items.get_mut(&(parent.0 as isize)).map(|chrome| {
                            let pressed = chrome.pressed;
                            chrome.pressed = false;
                            pressed
                        })
                    })
                    .unwrap_or(false);
                let _ = ReleaseCapture();
                emit_caption(parent, "up");
                let mut cursor = POINT {
                    x: (lparam.0 as i16) as i32,
                    y: ((lparam.0 >> 16) as i16) as i32,
                };
                if msg == WM_LBUTTONUP {
                    let _ = ClientToScreen(hwnd, &mut cursor);
                }
                let mut bounds = RECT::default();
                if was_pressed
                    && GetWindowRect(hwnd, &mut bounds).is_ok()
                    && cursor.x >= bounds.left
                    && cursor.x < bounds.right
                    && cursor.y >= bounds.top
                    && cursor.y < bounds.bottom
                {
                    emit_caption(parent, "click");
                }
                return LRESULT(0);
            }
            WM_CAPTURECHANGED => {
                if let Ok(mut items) = WINDOWS.lock()
                    && let Some(chrome) = items.get_mut(&(parent.0 as isize))
                {
                    chrome.pressed = false;
                }
                emit_caption(parent, "up");
            }
            _ => {}
        }
        DefWindowProcW(hwnd, msg, wparam, lparam)
    }
}

unsafe extern "system" fn parent_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
    _id: usize,
    _data: usize,
) -> LRESULT {
    unsafe {
        match msg {
            WM_SYSCOMMAND if (wparam.0 as u32 & 0xfff0) == SC_KEYMENU && lparam.0 == 32 => {
                let window = WINDOWS.lock().ok().and_then(|items| {
                    items
                        .get(&(hwnd.0 as isize))
                        .map(|chrome| chrome.window.clone())
                });
                if let Some(window) = window {
                    let _ = window.emit("desktop://window-menu", ());
                }
                return LRESULT(0);
            }
            WM_SYSCHAR if wparam.0 == 32 => {
                let window = WINDOWS.lock().ok().and_then(|items| {
                    items
                        .get(&(hwnd.0 as isize))
                        .map(|chrome| chrome.window.clone())
                });
                if let Some(window) = window {
                    let _ = window.emit("desktop://window-menu", ());
                }
                return LRESULT(0);
            }
            WM_SIZE | WM_DPICHANGED => {
                let result = DefSubclassProc(hwnd, msg, wparam, lparam);
                position(hwnd);
                return result;
            }
            WM_NCDESTROY => {
                if let Ok(mut items) = WINDOWS.lock() {
                    items.remove(&(hwnd.0 as isize));
                }
                let _ = RemoveWindowSubclass(hwnd, Some(parent_proc), 0x5253);
            }
            _ => {}
        }
        DefSubclassProc(hwnd, msg, wparam, lparam)
    }
}

pub fn install(window: &WebviewWindow) -> tauri::Result<()> {
    let parent = window.hwnd()?;
    unsafe {
        let module = GetModuleHandleW(None).map_err(std::io::Error::other)?;
        let class = WNDCLASSW {
            lpfnWndProc: Some(overlay_proc),
            hInstance: module.into(),
            lpszClassName: w!("RustSignSnapRegion"),
            ..Default::default()
        };
        // Register once for the lifetime of the process. An existing class is fine.
        RegisterClassW(&class);
        let overlay = CreateWindowExW(
            WINDOW_EX_STYLE(0),
            w!("RustSignSnapRegion"),
            w!(""),
            WS_CHILD | WS_CLIPSIBLINGS,
            0,
            0,
            0,
            0,
            Some(parent),
            None,
            Some(module.into()),
            None,
        )
        .map_err(std::io::Error::other)?;
        WINDOWS.lock().unwrap_or_else(|e| e.into_inner()).insert(
            parent.0 as isize,
            Chrome {
                window: window.clone(),
                overlay: overlay.0 as isize,
                rect: ChromeRect {
                    x: 0.0,
                    y: 0.0,
                    width: 0.0,
                    height: 0.0,
                },
                blocked: true,
                pressed: false,
            },
        );
        if !SetWindowSubclass(parent, Some(parent_proc), 0x5253, 0).as_bool() {
            return Err(tauri::Error::Anyhow(
                windows::core::Error::from_win32().into(),
            ));
        }
        let _ = DwmSetWindowAttribute(
            parent,
            DWMWA_WINDOW_CORNER_PREFERENCE,
            &DWMWCP_ROUND as *const _ as *const _,
            std::mem::size_of_val(&DWMWCP_ROUND) as u32,
        );
    }
    Ok(())
}

pub fn sync(window: &WebviewWindow, rect: ChromeRect, blocked: bool) -> tauri::Result<()> {
    let parent = window.hwnd()?;
    if let Some(chrome) = WINDOWS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get_mut(&(parent.0 as isize))
    {
        chrome.rect = rect;
        chrome.blocked = blocked;
    }
    position(parent);
    Ok(())
}

pub fn system_action(window: &WebviewWindow, action: &str) -> tauri::Result<()> {
    let command = match action {
        "move" => SC_MOVE,
        "resize" => SC_SIZE,
        _ => return Ok(()),
    };
    let parent = window.hwnd()?;
    unsafe {
        PostMessageW(
            Some(parent),
            WM_SYSCOMMAND,
            WPARAM(command as usize),
            LPARAM(0),
        )
        .map_err(std::io::Error::other)?;
    }
    Ok(())
}

#[cfg(feature = "desktop-smoke")]
pub fn probe(window: &WebviewWindow) -> tauri::Result<serde_json::Value> {
    let parent = window.hwnd()?;
    let chrome = WINDOWS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&(parent.0 as isize))
        .cloned();
    let Some(chrome) = chrome else {
        return Ok(serde_json::Value::Null);
    };
    unsafe {
        let overlay = HWND(chrome.overlay as *mut _);
        let mut bounds = RECT::default();
        GetWindowRect(overlay, &mut bounds).map_err(std::io::Error::other)?;
        let x = (bounds.left + bounds.right) / 2;
        let y = (bounds.top + bounds.bottom) / 2;
        let point = LPARAM(((y as u32 & 0xffff) << 16 | (x as u32 & 0xffff)) as isize);
        let hit = SendMessageW(overlay, WM_NCHITTEST, Some(WPARAM(0)), Some(point)).0;
        Ok(serde_json::json!({
            "hit": hit, "visible": IsWindowVisible(overlay).as_bool(),
            "width": bounds.right - bounds.left, "height": bounds.bottom - bounds.top,
            "blocked": chrome.blocked,
            "nativeTitlebar": window.is_decorated()?,
        }))
    }
}

#[cfg(feature = "desktop-smoke")]
pub fn click_for_test(window: &WebviewWindow) -> tauri::Result<()> {
    let parent = window.hwnd()?;
    let chrome = WINDOWS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&(parent.0 as isize))
        .cloned();
    if let Some(chrome) = chrome {
        unsafe {
            let overlay = HWND(chrome.overlay as *mut _);
            let mut bounds = RECT::default();
            GetWindowRect(overlay, &mut bounds).map_err(std::io::Error::other)?;
            let x = (bounds.left + bounds.right) / 2;
            let y = (bounds.top + bounds.bottom) / 2;
            let point = LPARAM(((y as u32 & 0xffff) << 16 | (x as u32 & 0xffff)) as isize);
            SendMessageW(
                overlay,
                WM_NCLBUTTONDOWN,
                Some(WPARAM(HTMAXBUTTON as usize)),
                Some(point),
            );
            SendMessageW(
                overlay,
                WM_NCLBUTTONUP,
                Some(WPARAM(HTMAXBUTTON as usize)),
                Some(point),
            );
        }
    }
    Ok(())
}

#[cfg(feature = "desktop-smoke")]
pub fn menu_for_test(window: &WebviewWindow) -> tauri::Result<()> {
    unsafe {
        SendMessageW(
            window.hwnd()?,
            WM_SYSCOMMAND,
            Some(WPARAM(SC_KEYMENU as usize)),
            Some(LPARAM(32)),
        );
    }
    Ok(())
}
