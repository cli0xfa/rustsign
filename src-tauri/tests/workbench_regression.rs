use rustsign_lib::{SignRequest, cert_gen, cert_manager};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;

struct TemporaryDirectory(PathBuf);
impl TemporaryDirectory {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("rustsign-workbench-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}
impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test_data")
        .join(name)
}
fn request(path: &std::path::Path) -> SignRequest {
    SignRequest {
        file_path: path.to_string_lossy().into_owned(),
        cert_id: None,
        cert_path: Some(fixture("test_combined.pem").to_string_lossy().into_owned()),
        cert_password: None,
        sign_mode: "app".into(),
        digest_algorithm: "sha256".into(),
        timestamp_url: None,
        description: None,
        url: None,
        cross_cert_path: None,
        replace_signature: true,
    }
}

#[test]
fn runtime_metadata_does_not_change_stored_schema_or_expose_passwords() {
    let mut entry =
        cert_manager::parse_cert_info(fixture("test_combined.pem").to_str().unwrap(), None)
            .unwrap();
    entry.password = Some("not-for-the-interface".into());
    let stored = serde_json::to_value(&entry).unwrap();
    assert!(stored.get("has_private_key").is_none());
    let view = cert_manager::certificate_view(entry);
    assert!(view.file_readable);
    assert_eq!(view.has_private_key, Some(true));
    assert!(view.not_after_secs.unwrap() > view.not_before_secs.unwrap());
    let serialized = serde_json::to_string(&view).unwrap();
    assert!(!serialized.contains("not-for-the-interface"));
    let public = cert_manager::certificate_view(
        cert_manager::parse_cert_info(fixture("test_cert.pem").to_str().unwrap(), None).unwrap(),
    );
    assert_eq!(public.has_private_key, Some(false));
}

#[test]
fn missing_certificate_retains_identity_and_reports_unknown_capabilities() {
    let temp = TemporaryDirectory::new();
    let mut entry =
        cert_manager::parse_cert_info(fixture("test_combined.pem").to_str().unwrap(), None)
            .unwrap();
    let subject = entry.subject.clone();
    entry.file_path = temp.0.join("missing.pfx").to_string_lossy().into_owned();
    let view = cert_manager::certificate_view(entry);
    assert_eq!(view.entry.subject, subject);
    assert!(!view.file_readable);
    assert_eq!(view.has_private_key, None);
    assert_eq!(view.not_after_secs, None);
    assert!(view.read_error.is_some());
}

#[test]
fn timestamp_failure_reports_no_write_and_preserves_original_bytes() {
    let temp = TemporaryDirectory::new();
    let path = temp.0.join("client.exe");
    std::fs::copy(fixture("test_hello.exe"), &path).unwrap();
    let before = std::fs::read(&path).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut bytes = [0; 4096];
        let _ = stream.read(&mut bytes);
        stream.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
    });
    let mut sign = request(&path);
    sign.timestamp_url = Some(format!("http://{address}"));
    let result = rustsign_lib::sign_file(&sign).unwrap();
    server.join().unwrap();
    assert!(!result.success);
    assert!(result.message.contains("original file was not modified"));
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn replace_append_reorder_and_remove_preserve_the_existing_signing_flow() {
    let temp = TemporaryDirectory::new();
    let path = temp.0.join("client.exe");
    std::fs::copy(fixture("test_hello.exe"), &path).unwrap();
    let mut sign = request(&path);
    assert!(rustsign_lib::sign_file(&sign).unwrap().success);
    sign.replace_signature = false;
    assert!(rustsign_lib::sign_file(&sign).unwrap().success);
    assert_eq!(
        rustsign_lib::list_signatures(&sign.file_path)
            .unwrap()
            .len(),
        2
    );
    rustsign_lib::reorder_signatures(&sign.file_path, &[1, 0]).unwrap();
    assert!(
        rustsign_lib::verify_signature(&sign.file_path)
            .unwrap()
            .valid
    );
    rustsign_lib::remove_signature_at(&sign.file_path, 1).unwrap();
    assert_eq!(
        rustsign_lib::list_signatures(&sign.file_path)
            .unwrap()
            .len(),
        1
    );
    sign.replace_signature = true;
    assert!(rustsign_lib::sign_file(&sign).unwrap().success);
    assert_eq!(
        rustsign_lib::list_signatures(&sign.file_path)
            .unwrap()
            .len(),
        1
    );
    rustsign_lib::remove_signature(&sign.file_path).unwrap();
    assert!(
        rustsign_lib::list_signatures(&sign.file_path)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn generation_returns_real_artifact_paths_and_supports_subordinate_certificates() {
    assert!(
        std::env::var_os("RUSTSIGN_DATA_DIR").is_some(),
        "Run regression tests with an isolated RUSTSIGN_DATA_DIR"
    );
    let temp = TemporaryDirectory::new();
    let files = cert_gen::generate_test_cert_files(
        cert_gen::CertGenOptions::default(),
        Some(temp.0.to_string_lossy().into_owned()),
    )
    .unwrap();
    assert_eq!(files.output_files.len(), 6);
    for path in &files.output_files {
        assert!(std::path::Path::new(path).is_file());
    }
    assert_eq!(
        std::fs::read_to_string(temp.0.join("test_codesign.pem")).unwrap(),
        files.sign_pem
    );
    let issuer = cert_manager::import_certificate(
        temp.0.join("test_root_ca.pfx").to_str().unwrap(),
        Some("test123"),
    )
    .unwrap();
    let view = cert_manager::certificate_view(issuer.clone());
    assert_eq!(view.can_issue, Some(true));
    let child = cert_gen::generate_test_cert_files(
        cert_gen::CertGenOptions {
            is_root_ca: false,
            issuer_cert_id: Some(issuer.id.clone()),
            ..Default::default()
        },
        Some(temp.0.join("child").to_string_lossy().into_owned()),
    )
    .unwrap();
    assert_eq!(child.output_files.len(), 3);
    assert!(child.root_pem.is_empty());
    assert!(std::path::Path::new(child.sign_pfx_path.as_ref().unwrap()).exists());
    cert_manager::delete_certificate(&issuer.id).unwrap();
}

#[test]
fn tsa_bind_failure_does_not_report_running_and_stop_allows_immediate_restart() {
    assert!(
        std::env::var_os("RUSTSIGN_DATA_DIR").is_some(),
        "Run regression tests with an isolated RUSTSIGN_DATA_DIR"
    );
    let certificate =
        cert_manager::import_certificate(fixture("test_combined.pem").to_str().unwrap(), None)
            .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let config = rustsign_lib::LocalTsaConfig {
        port,
        cert_id: Some(certificate.id.clone()),
        ..Default::default()
    };
    assert!(rustsign_lib::start_local_tsa(&config).is_err());
    assert!(!rustsign_lib::get_local_tsa_status().running);
    drop(listener);
    assert!(rustsign_lib::start_local_tsa(&config).unwrap().running);
    assert!(!rustsign_lib::stop_local_tsa().unwrap().running);
    assert!(rustsign_lib::start_local_tsa(&config).unwrap().running);
    rustsign_lib::stop_local_tsa().unwrap();
    cert_manager::delete_certificate(&certificate.id).unwrap();
}
