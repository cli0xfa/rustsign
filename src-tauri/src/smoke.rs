//! Opt-in native WebView2/IPC smoke harness; absent from normal builds.
use std::sync::atomic::{AtomicBool, Ordering};
use tauri::{Emitter, Manager, plugin::TauriPlugin, webview::PageLoadEvent};

#[tauri::command]
pub async fn desktop_smoke_probe(
    window: tauri::WebviewWindow,
    action: String,
) -> Result<serde_json::Value, String> {
    if action == "busy-close" {
        let _task = crate::desktop::begin_task().map_err(|e| e.message)?;
        return crate::desktop::request_app_close(window, false)
            .await
            .map(|value| serde_json::json!(value))
            .map_err(|e| e.message);
    }
    if action == "emit-caption" {
        window
            .emit("desktop://caption", "click")
            .map_err(|e| e.to_string())?;
    }
    #[cfg(windows)]
    if action == "caption-click" {
        crate::desktop::click_native_chrome_for_test(&window).map_err(|e| e.to_string())?;
    }
    #[cfg(windows)]
    if action == "window-menu" {
        crate::desktop::native_menu_for_test(&window).map_err(|e| e.to_string())?;
    }
    match action.as_str() {
        "maximize" => window.maximize(),
        "restore" => window.unmaximize(),
        "minimize" => window.minimize(),
        "unminimize" => window.unminimize(),
        _ => Ok(()),
    }
    .map_err(|e| e.to_string())?;
    #[cfg(windows)]
    let chrome = crate::desktop::probe_native_chrome(&window).map_err(|e| e.to_string())?;
    #[cfg(not(windows))]
    let chrome = serde_json::Value::Null;
    Ok(
        serde_json::json!({ "visible": window.is_visible().map_err(|e| e.to_string())?,
        "maximized": window.is_maximized().map_err(|e| e.to_string())?,
        "minimized": window.is_minimized().map_err(|e| e.to_string())?,
        "scale": window.scale_factor().map_err(|e| e.to_string())?, "chrome": chrome }),
    )
}

#[tauri::command]
pub fn finish_desktop_smoke(
    app: tauri::AppHandle,
    success: bool,
    checks: Vec<String>,
    error: Option<String>,
) {
    if let Some(path) = std::env::var_os("RUSTSIGN_SMOKE_RESULT") {
        let report = serde_json::json!({ "success": success, "checks": checks, "error": error });
        std::fs::write(path, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    }
    app.exit(if success { 0 } else { 1 });
}

pub fn plugin() -> TauriPlugin<tauri::Wry> {
    let started = AtomicBool::new(false);
    let theme = std::env::var("RUSTSIGN_SMOKE_THEME")
        .ok()
        .filter(|value| matches!(value.as_str(), "dark" | "light"));
    let initialization = theme
        .map(|theme| {
            format!(
                "try {{ localStorage.setItem('rustsign-theme', {}); }} catch {{}}",
                serde_json::to_string(&theme).unwrap()
            )
        })
        .unwrap_or_default();
    tauri::plugin::Builder::new("smoke")
        .js_init_script(initialization)
        .on_page_load(move |webview, payload| {
            if let Some(path) = std::env::var_os("RUSTSIGN_SMOKE_RESULT") {
                use std::io::Write;
                if let Ok(mut file) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(std::path::PathBuf::from(path).with_extension("log"))
                {
                    let _ = writeln!(file, "page {:?}: {}", payload.event(), payload.url());
                }
            }
            if payload.url().scheme() == "about" {
                return;
            }
            if payload.event() != PageLoadEvent::Finished || started.swap(true, Ordering::Relaxed) {
                return;
            }
            let Some(file) = std::env::var_os("RUSTSIGN_SMOKE_FILE") else {
                return;
            };
            let Some(cert) = std::env::var_os("RUSTSIGN_SMOKE_CERT") else {
                return;
            };
            let config = serde_json::json!({ "file": std::path::PathBuf::from(file).to_string_lossy(), "cert": std::path::PathBuf::from(cert).to_string_lossy() });
            let script = format!(
                "({})({});",
                include_str!("../tests/native_smoke.js"),
                config
            );
            if let Err(error) = webview.eval(script) {
                finish_desktop_smoke(
                    webview.app_handle().clone(),
                    false,
                    Vec::new(),
                    Some(error.to_string()),
                );
            }
        })
        .build()
}
