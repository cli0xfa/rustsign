#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use rustsign_lib::{
    CodeSignError, CrossCertResult, LocalTsaConfig, LocalTsaStatus, SignRequest, SignResult,
    SignRules, SignatureInfo, VerifyResult, cert_gen, cert_manager, cross_cert,
    get_local_tsa_status, load_local_tsa_config, rules,
};
use serde::{Deserialize, Serialize};
use tauri::{Builder, Manager, command, generate_context, generate_handler};

mod desktop;

#[cfg(feature = "desktop-smoke")]
mod smoke;

#[derive(Debug, Serialize)]
pub struct CommandError {
    category: &'static str,
    message: String,
}
impl From<CodeSignError> for CommandError {
    fn from(error: CodeSignError) -> Self {
        let category = match &error {
            CodeSignError::Io(_) => "io",
            CodeSignError::Pe(_) => "pe",
            CodeSignError::Certificate(_) => "certificate",
            CodeSignError::Signing(_) => "signing",
            CodeSignError::Timestamp(_) | CodeSignError::Http(_) => "timestamp",
            CodeSignError::Tsa(_) => "tsa",
        };
        Self {
            category,
            message: error.to_string(),
        }
    }
}
impl From<tokio::task::JoinError> for CommandError {
    fn from(error: tokio::task::JoinError) -> Self {
        Self {
            category: "unknown",
            message: error.to_string(),
        }
    }
}
async fn blocking<T, F>(operation: F) -> Result<T, CommandError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, CodeSignError> + Send + 'static,
{
    let task = desktop::begin_task()?;
    tokio::task::spawn_blocking(move || {
        let _task = task;
        operation()
    })
    .await?
    .map_err(CommandError::from)
}

#[derive(Debug, Serialize)]
pub struct ActionResult {
    success: bool,
    message: String,
}
#[derive(Debug, Serialize)]
pub struct ExportBatchResult {
    success: bool,
    message: String,
    paths: Vec<String>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct FileDialogRequest {
    title: Option<String>,
    multiple: bool,
    filters: Vec<FileFilter>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct FileFilter {
    name: String,
    extensions: Vec<String>,
}

#[command]
async fn sign_pe_file(request: SignRequest) -> Result<SignResult, CommandError> {
    blocking(move || rustsign_lib::sign_file(&request)).await
}
#[command]
async fn remove_pe_signature(file_path: String) -> Result<SignResult, CommandError> {
    blocking(move || rustsign_lib::remove_signature(&file_path)).await
}
#[command]
async fn list_certificates() -> Result<Vec<cert_manager::CertificateView>, CommandError> {
    blocking(cert_manager::list_certificate_views).await
}
#[command]
async fn import_certificate(
    file_path: String,
    password: Option<String>,
) -> Result<ActionResult, CommandError> {
    blocking(move || {
        let entry = cert_manager::import_certificate(&file_path, password.as_deref())?;
        Ok(ActionResult {
            success: true,
            message: format!("Imported certificate: {}", entry.subject),
        })
    })
    .await
}
#[command]
async fn delete_certificate(id: String) -> Result<(), CommandError> {
    blocking(move || cert_manager::delete_certificate(&id)).await
}
#[command]
async fn export_certificate_command(
    id: String,
    format: String,
    output_path: String,
    password: Option<String>,
) -> Result<ActionResult, CommandError> {
    blocking(move || {
        rustsign_lib::export_certificate(&id, &format, &output_path, password.as_deref())?;
        Ok(ActionResult {
            success: true,
            message: "Certificate exported successfully".into(),
        })
    })
    .await
}
#[command]
async fn export_certificates_command(
    ids: Vec<String>,
    format: String,
    output_dir: String,
    password: Option<String>,
) -> Result<ExportBatchResult, CommandError> {
    blocking(move || {
        let paths =
            rustsign_lib::export_certificates(&ids, &format, &output_dir, password.as_deref())?;
        Ok(ExportBatchResult {
            success: true,
            message: format!("Exported {} certificate(s)", paths.len()),
            paths,
        })
    })
    .await
}
#[command]
async fn download_cross_cert() -> Result<CrossCertResult, CommandError> {
    let _task = desktop::begin_task()?;
    let rules = rules::SignRules::load().map_err(CommandError::from)?;
    let store = if rules.cross_cert_store_path.is_empty() {
        None
    } else {
        Some(rules.cross_cert_store_path.as_str())
    };
    cross_cert::download_cross_certs(store)
        .await
        .map_err(CommandError::from)
}
#[command]
fn save_rules(rules_data: SignRules) -> Result<(), CommandError> {
    let _task = desktop::begin_task()?;
    rules_data.save().map_err(CommandError::from)
}
#[command]
fn load_rules() -> Result<SignRules, CommandError> {
    rules::SignRules::load().map_err(CommandError::from)
}
#[command]
async fn verify_pe_signature(file_path: String) -> Result<VerifyResult, CommandError> {
    blocking(move || rustsign_lib::verify_signature(&file_path)).await
}
#[command]
async fn list_pe_signatures(file_path: String) -> Result<Vec<SignatureInfo>, CommandError> {
    blocking(move || rustsign_lib::list_signatures(&file_path)).await
}
#[command]
async fn remove_pe_signature_at(file_path: String, index: u32) -> Result<SignResult, CommandError> {
    blocking(move || rustsign_lib::remove_signature_at(&file_path, index as usize)).await
}
#[command]
async fn reorder_pe_signatures(
    file_path: String,
    order: Vec<u32>,
) -> Result<SignResult, CommandError> {
    blocking(move || {
        rustsign_lib::reorder_signatures(
            &file_path,
            &order
                .into_iter()
                .map(|index| index as usize)
                .collect::<Vec<_>>(),
        )
    })
    .await
}
#[command]
async fn add_timestamp(
    file_path: String,
    tsa_url: String,
    digest_algorithm: Option<String>,
) -> Result<SignResult, CommandError> {
    blocking(move || {
        rustsign_lib::timestamp::timestamp_file(
            std::path::Path::new(&file_path),
            &tsa_url,
            &digest_algorithm.unwrap_or_else(|| "sha256".into()),
        )?;
        Ok(SignResult {
            success: true,
            message: format!("Timestamp added to {file_path}"),
        })
    })
    .await
}
#[command]
async fn remove_timestamp(file_path: String) -> Result<SignResult, CommandError> {
    blocking(move || {
        rustsign_lib::remove_timestamp_from_file(std::path::Path::new(&file_path))?;
        Ok(SignResult {
            success: true,
            message: format!("Timestamp removed from {file_path}"),
        })
    })
    .await
}
#[command]
async fn start_tsa_server(config: LocalTsaConfig) -> Result<LocalTsaStatus, CommandError> {
    blocking(move || rustsign_lib::start_local_tsa(&config)).await
}
#[command]
async fn stop_tsa_server() -> Result<LocalTsaStatus, CommandError> {
    blocking(rustsign_lib::stop_local_tsa).await
}
#[command]
fn get_tsa_server_status() -> LocalTsaStatus {
    get_local_tsa_status()
}
#[command]
fn load_local_tsa_config_command() -> Result<LocalTsaConfig, CommandError> {
    load_local_tsa_config().map_err(CommandError::from)
}
#[command]
async fn generate_test_cert(
    options: cert_gen::CertGenOptions,
    output_dir: Option<String>,
) -> Result<cert_gen::TestCertResult, CommandError> {
    blocking(move || cert_gen::generate_test_cert_files(options, output_dir)).await
}

fn build_file_dialog(
    app: &tauri::AppHandle,
    title: Option<&str>,
    filters: &[FileFilter],
) -> tauri_plugin_dialog::FileDialogBuilder<tauri::Wry> {
    use tauri_plugin_dialog::DialogExt;
    let mut builder = app.dialog().file();
    if let Some(title) = title {
        builder = builder.set_title(title);
    }
    for filter in filters {
        let extensions: Vec<&str> = filter.extensions.iter().map(String::as_str).collect();
        builder = builder.add_filter(&filter.name, &extensions);
    }
    builder
}
#[command]
async fn open_file_dialog(
    app: tauri::AppHandle,
    request: FileDialogRequest,
) -> Result<Option<String>, CommandError> {
    let builder = build_file_dialog(&app, request.title.as_deref(), &request.filters);
    let task = desktop::begin_task()?;
    Ok(tokio::task::spawn_blocking(move || {
        let _task = task;
        if request.multiple {
            builder
                .blocking_pick_files()
                .and_then(|paths| paths.into_iter().next())
                .map(|path| path.to_string())
        } else {
            builder.blocking_pick_file().map(|path| path.to_string())
        }
    })
    .await?)
}
#[command]
async fn save_file_dialog(
    app: tauri::AppHandle,
    request: FileDialogRequest,
) -> Result<Option<String>, CommandError> {
    let builder = build_file_dialog(&app, request.title.as_deref(), &request.filters);
    let task = desktop::begin_task()?;
    Ok(tokio::task::spawn_blocking(move || {
        let _task = task;
        builder.blocking_save_file().map(|path| path.to_string())
    })
    .await?)
}
#[command]
async fn open_directory_dialog(
    app: tauri::AppHandle,
    title: Option<String>,
) -> Result<Option<String>, CommandError> {
    let builder = build_file_dialog(&app, title.as_deref(), &[]);
    let task = desktop::begin_task()?;
    Ok(tokio::task::spawn_blocking(move || {
        let _task = task;
        builder.blocking_pick_folder().map(|path| path.to_string())
    })
    .await?)
}
fn main() {
    let builder = Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            if let Some(window) = app.get_webview_window("main") {
                desktop::initialize(&window)?;
                desktop::arm_startup(window);
            }
            Ok(())
        })
        .on_page_load(|webview, payload| {
            if payload.event() == tauri::webview::PageLoadEvent::Started
                && payload.url().scheme() != "about"
                && let Some(window) = webview.app_handle().get_webview_window("main")
            {
                let _ = window.hide();
                desktop::arm_startup(window);
            }
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                if let Some(window) = window.app_handle().get_webview_window("main") {
                    desktop::native_close(window);
                }
            }
        });
    #[cfg(feature = "desktop-smoke")]
    let builder = builder.plugin(smoke::plugin());
    builder
        .invoke_handler(|invoke| {
            #[cfg(feature = "desktop-smoke")]
            if matches!(
                invoke.message.command(),
                "finish_desktop_smoke" | "desktop_smoke_probe"
            ) {
                let handler: fn(tauri::ipc::Invoke<tauri::Wry>) -> bool =
                    generate_handler![smoke::finish_desktop_smoke, smoke::desktop_smoke_probe];
                return handler(invoke);
            }
            let handler: fn(tauri::ipc::Invoke<tauri::Wry>) -> bool = generate_handler![
                sign_pe_file,
                remove_pe_signature,
                verify_pe_signature,
                list_pe_signatures,
                remove_pe_signature_at,
                reorder_pe_signatures,
                add_timestamp,
                remove_timestamp,
                start_tsa_server,
                stop_tsa_server,
                get_tsa_server_status,
                load_local_tsa_config_command,
                generate_test_cert,
                list_certificates,
                import_certificate,
                delete_certificate,
                export_certificate_command,
                export_certificates_command,
                download_cross_cert,
                save_rules,
                load_rules,
                open_file_dialog,
                save_file_dialog,
                open_directory_dialog,
                desktop::complete_startup,
                desktop::sync_window_chrome,
                desktop::request_app_close,
                desktop::window_system_action
            ];
            handler(invoke)
        })
        .run(generate_context!())
        .expect("error while running tauri application");
}
