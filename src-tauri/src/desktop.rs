//! Window lifecycle is independent of the React tree and remains authoritative on exit.
use crate::CommandError;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, OnceLock};
use tauri::{Emitter, Manager, WebviewWindow};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};

#[cfg(windows)]
mod windows;

#[cfg(all(windows, feature = "desktop-smoke"))]
pub use windows::click_for_test as click_native_chrome_for_test;
#[cfg(all(windows, feature = "desktop-smoke"))]
pub use windows::menu_for_test as native_menu_for_test;
#[cfg(all(windows, feature = "desktop-smoke"))]
pub use windows::probe as probe_native_chrome;

#[derive(Default)]
struct Lifecycle {
    active: usize,
    closing: bool,
}
static LIFECYCLE: LazyLock<Arc<Mutex<Lifecycle>>> = LazyLock::new(Default::default);
static APP: OnceLock<tauri::AppHandle> = OnceLock::new();
static STARTED: AtomicBool = AtomicBool::new(false);
static STARTUP_GENERATION: AtomicU64 = AtomicU64::new(0);
static STARTUP_LOCK: LazyLock<tokio::sync::Mutex<()>> = LazyLock::new(Default::default);

fn desktop_error(message: impl ToString) -> CommandError {
    CommandError {
        category: "desktop",
        message: message.to_string(),
    }
}

pub struct TaskGuard(Arc<Mutex<Lifecycle>>);
impl Drop for TaskGuard {
    fn drop(&mut self) {
        let active = {
            let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
            state.active -= 1;
            state.active
        };
        if let Some(app) = APP.get() {
            let _ = app.emit("desktop://activity", active);
        }
    }
}

fn acquire_task(lifecycle: Arc<Mutex<Lifecycle>>) -> Result<TaskGuard, CommandError> {
    {
        let mut state = lifecycle.lock().map_err(desktop_error)?;
        if state.closing {
            return Err(desktop_error("Application is closing."));
        }
        state.active += 1;
        if let Some(app) = APP.get() {
            let _ = app.emit("desktop://activity", state.active);
        }
    }
    Ok(TaskGuard(lifecycle))
}

pub fn begin_task() -> Result<TaskGuard, CommandError> {
    acquire_task(LIFECYCLE.clone())
}

#[derive(Clone, Copy, Serialize, PartialEq, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum CloseState {
    Busy,
    ConfirmTsa,
    Closing,
}

fn prepare_close(state: &mut Lifecycle, tsa_running: bool, confirmed: bool) -> CloseState {
    if state.closing {
        return CloseState::Closing;
    }
    if state.active != 0 {
        return CloseState::Busy;
    }
    if tsa_running && !confirmed {
        return CloseState::ConfirmTsa;
    }
    state.closing = true;
    CloseState::Closing
}

#[tauri::command]
pub async fn request_app_close(
    window: WebviewWindow,
    confirm_tsa_stop: bool,
) -> Result<CloseState, CommandError> {
    let result = {
        let mut state = LIFECYCLE.lock().map_err(desktop_error)?;
        if state.closing {
            return Ok(CloseState::Closing);
        }
        prepare_close(
            &mut state,
            rustsign_lib::get_local_tsa_status().running,
            confirm_tsa_stop,
        )
    };
    if result != CloseState::Closing {
        return Ok(result);
    }
    // Admission is closed under the same lock as the active-task check.
    // A concurrent IPC cannot start a write between that check and destruction.
    let stopped = tokio::task::spawn_blocking(rustsign_lib::stop_local_tsa).await;
    let stopped = match stopped {
        Ok(value) => value.map_err(CommandError::from),
        Err(error) => Err(CommandError::from(error)),
    };
    if let Err(error) = stopped {
        LIFECYCLE.lock().map_err(desktop_error)?.closing = false;
        return Err(error);
    }
    if let Err(error) = window.destroy() {
        LIFECYCLE.lock().map_err(desktop_error)?.closing = false;
        return Err(desktop_error(error));
    }
    Ok(result)
}

pub fn native_close(window: WebviewWindow) {
    tauri::async_runtime::spawn(async move {
        match request_app_close(window.clone(), false).await {
            Ok(result) => {
                let _ = window.emit("desktop://close-state", result);
            }
            Err(error) => {
                let _ = window.emit("desktop://close-error", error.message);
            }
        }
    });
}

pub fn initialize(window: &WebviewWindow) -> tauri::Result<()> {
    let _ = APP.set(window.app_handle().clone());
    #[cfg(windows)]
    windows::install(window)?;
    Ok(())
}

pub fn arm_startup(window: WebviewWindow) {
    STARTED.store(false, Ordering::SeqCst);
    let generation = STARTUP_GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(10));
        if STARTED.load(Ordering::SeqCst) || STARTUP_GENERATION.load(Ordering::SeqCst) != generation
        {
            return;
        }
        let retry_window = window.clone();
        window.dialog().message("工作台未能完成加载。请重新加载，或退出后重试。\nThe workspace could not load. Reload it or exit and try again.")
            .title("RustSign — 启动失败 / Startup failed")
            .kind(MessageDialogKind::Error)
            .buttons(MessageDialogButtons::OkCancelCustom("重新加载 / Reload".into(), "退出 / Exit".into()))
            .show(move |retry| {
                if retry {
                    arm_startup(retry_window.clone());
                    let _ = retry_window.eval("location.reload()");
                } else { retry_window.app_handle().exit(1); }
            });
    });
}

#[tauri::command]
pub async fn complete_startup(window: WebviewWindow, theme: String) -> Result<(), CommandError> {
    let _startup = STARTUP_LOCK.lock().await;
    #[cfg(feature = "desktop-smoke")]
    if std::env::var("RUSTSIGN_SMOKE_STALL_STARTUP").as_deref() == Ok("1") {
        return Err(desktop_error(
            "Startup failure injected by the native test harness.",
        ));
    }
    let (color, native_theme) = match theme.as_str() {
        "light" => (
            tauri::window::Color(246, 247, 249, 255),
            tauri::Theme::Light,
        ),
        "dark" => (tauri::window::Color(21, 23, 30, 255), tauri::Theme::Dark),
        _ => return Err(desktop_error("Unknown window theme.")),
    };
    window
        .set_background_color(Some(color))
        .map_err(desktop_error)?;
    window
        .set_theme(Some(native_theme))
        .map_err(desktop_error)?;
    if !STARTED.load(Ordering::SeqCst) {
        #[cfg(windows)]
        windows::show_painted(&window)
            .await
            .map_err(desktop_error)?;
        #[cfg(not(windows))]
        window.show().map_err(desktop_error)?;
        STARTED.store(true, Ordering::SeqCst);
        let _ = window.set_focus();
    }
    Ok(())
}

#[derive(Clone, Copy, Deserialize, Debug)]
pub struct ChromeRect {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

impl ChromeRect {
    #[cfg(any(windows, test))]
    fn physical(self, scale: f64) -> [i32; 4] {
        [self.x, self.y, self.width, self.height].map(|value| (value * scale).round() as i32)
    }
}

#[tauri::command]
pub fn sync_window_chrome(
    window: WebviewWindow,
    maximize_rect: ChromeRect,
    blocked: bool,
) -> Result<(), CommandError> {
    if [
        maximize_rect.x,
        maximize_rect.y,
        maximize_rect.width,
        maximize_rect.height,
    ]
    .iter()
    .any(|v| !v.is_finite() || *v < 0.0)
    {
        return Err(desktop_error("Invalid window control rectangle."));
    }
    #[cfg(windows)]
    windows::sync(&window, maximize_rect, blocked).map_err(desktop_error)?;
    #[cfg(not(windows))]
    let _ = (window, maximize_rect, blocked);
    Ok(())
}

#[tauri::command]
pub fn window_system_action(window: WebviewWindow, action: String) -> Result<(), CommandError> {
    #[cfg(windows)]
    if matches!(action.as_str(), "move" | "resize") {
        return windows::system_action(&window, &action).map_err(desktop_error);
    }
    // Keep the portable implementation type-checked on Windows as well.
    match action.as_str() {
        "move" => window.start_dragging().map_err(desktop_error)?,
        "resize" => window
            .as_ref()
            .window()
            .start_resize_dragging(tauri_runtime::ResizeDirection::SouthEast)
            .map_err(desktop_error)?,
        _ => return Err(desktop_error("Unsupported window action.")),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn active_task_blocks_close_and_guard_releases_on_error() {
        let state = Arc::new(Mutex::new(Lifecycle::default()));
        let guard = acquire_task(state.clone()).unwrap();
        assert_eq!(
            prepare_close(&mut state.lock().unwrap(), false, true),
            CloseState::Busy
        );
        drop(guard);
        assert_eq!(
            prepare_close(&mut state.lock().unwrap(), false, false),
            CloseState::Closing
        );
        assert!(acquire_task(state).is_err());
    }
    #[test]
    fn tsa_confirmation_does_not_lock_out_tasks() {
        let mut state = Lifecycle::default();
        assert_eq!(
            prepare_close(&mut state, true, false),
            CloseState::ConfirmTsa
        );
        assert!(!state.closing);
        assert_eq!(prepare_close(&mut state, true, true), CloseState::Closing);
        assert_eq!(prepare_close(&mut state, true, false), CloseState::Closing);
    }

    #[test]
    fn caption_geometry_tracks_common_windows_display_scales() {
        let rect = ChromeRect {
            x: 822.0,
            y: 0.0,
            width: 46.0,
            height: 39.0,
        };
        assert_eq!(rect.physical(1.0), [822, 0, 46, 39]);
        assert_eq!(rect.physical(1.5), [1233, 0, 69, 59]);
        assert_eq!(rect.physical(2.0), [1644, 0, 92, 78]);
    }
}
