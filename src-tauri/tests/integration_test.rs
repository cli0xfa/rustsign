use der::Sequence;
use der::asn1::{Any, OctetString};
use der::{Decode, Encode};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

fn cert_db_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[test]
fn test_end_to_end_sign_and_verify() {
    // Paths to test files (relative to workspace root)
    let test_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test_data");

    let pe_file = test_dir.join("test_hello.exe");
    let cert_file = test_dir.join("test_combined.pem");

    if !pe_file.exists() {
        eprintln!("Skipping test: test EXE not found at {}", pe_file.display());
        return;
    }
    if !cert_file.exists() {
        eprintln!(
            "Skipping test: test cert not found at {}",
            cert_file.display()
        );
        return;
    }

    // Make a copy of the PE file to sign
    let signed_pe = test_dir.join("test_hello_signed.exe");
    std::fs::copy(&pe_file, &signed_pe).expect("Failed to copy PE file");

    // Build sign request
    let request = rustsign_lib::SignRequest {
        file_path: signed_pe.to_string_lossy().to_string(),
        cert_id: None,
        cert_path: Some(cert_file.to_string_lossy().to_string()),
        cert_password: None,
        sign_mode: "app".to_string(),
        digest_algorithm: "sha256".to_string(),
        timestamp_url: None,
        description: Some("Test Signature".to_string()),
        url: Some("https://example.com".to_string()),
        cross_cert_path: None,
        replace_signature: true,
    };

    // Sign the file
    let result = rustsign_lib::sign_file(&request).expect("sign_file failed");
    assert!(result.success, "Signing failed: {}", result.message);
    println!("Sign result: {}", result.message);

    // Verify the signature
    let verify_result = rustsign_lib::verify_signature(&signed_pe.to_string_lossy().to_string())
        .expect("verify_signature failed");

    println!("Verify result: {:?}", verify_result);
    assert!(
        verify_result.valid,
        "Signature verification failed: {}",
        verify_result.message
    );

    // Cleanup
    let _ = std::fs::remove_file(&signed_pe);
}

#[test]
fn test_authenticode_cms_structure_matches_windows_expectations() {
    if !cfg!(windows) {
        eprintln!("Skipping test: Get-AuthenticodeSignature is only available on Windows");
        return;
    }

    let test_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test_data");

    let pe_file = test_dir.join("test_hello.exe");
    let cert_file = test_dir.join("test_combined.pem");

    if !pe_file.exists() {
        eprintln!("Skipping test: test EXE not found at {}", pe_file.display());
        return;
    }
    if !cert_file.exists() {
        eprintln!(
            "Skipping test: test cert not found at {}",
            cert_file.display()
        );
        return;
    }

    let signed_pe = test_dir.join("test_hello_authenticode.exe");
    std::fs::copy(&pe_file, &signed_pe).expect("Failed to copy PE file");

    let request = rustsign_lib::SignRequest {
        file_path: signed_pe.to_string_lossy().to_string(),
        cert_id: None,
        cert_path: Some(cert_file.to_string_lossy().to_string()),
        cert_password: None,
        sign_mode: "app".to_string(),
        digest_algorithm: "sha256".to_string(),
        timestamp_url: None,
        description: None,
        url: None,
        cross_cert_path: None,
        replace_signature: true,
    };

    let result = rustsign_lib::sign_file(&request).expect("sign_file failed");
    assert!(result.success, "Signing failed: {}", result.message);

    let signed_data = parse_signed_data(&signed_pe);
    assert_eq!(signed_data.version, cms::content_info::CmsVersion::V1);
    assert_eq!(
        signed_data.encap_content_info.econtent_type.to_string(),
        "1.3.6.1.4.1.311.2.1.4"
    );

    let signer_info = signed_data
        .signer_infos
        .0
        .iter()
        .next()
        .expect("missing signer info");
    assert_eq!(
        signer_info.signature_algorithm.oid.to_string(),
        "1.2.840.113549.1.1.1"
    );
    assert!(
        signer_info
            .signature_algorithm
            .parameters
            .as_ref()
            .is_some_and(|param| param.is_null()),
        "signatureAlgorithm should carry NULL parameters"
    );
    assert!(
        signer_info
            .digest_alg
            .parameters
            .as_ref()
            .is_some_and(|param| param.is_null()),
        "digestAlgorithm should carry NULL parameters"
    );

    let signed_attrs = signer_info
        .signed_attrs
        .as_ref()
        .expect("missing signed attributes");
    let attr_oids = signed_attrs
        .iter()
        .map(|attr| attr.oid.to_string())
        .collect::<Vec<_>>();
    assert!(
        attr_oids.iter().any(|oid| oid == "1.3.6.1.4.1.311.2.1.12"),
        "missing SpcSpOpusInfo"
    );
    assert!(
        attr_oids.iter().any(|oid| oid == "1.3.6.1.4.1.311.2.1.11"),
        "missing SpcStatementType"
    );

    let opus_info = signed_attrs
        .iter()
        .find(|attr| attr.oid.to_string() == "1.3.6.1.4.1.311.2.1.12")
        .expect("SpcSpOpusInfo attr missing");
    let opus_der = opus_info
        .values
        .iter()
        .next()
        .expect("SpcSpOpusInfo value missing")
        .to_der()
        .expect("SpcSpOpusInfo DER");
    assert_eq!(opus_der, vec![0x30, 0x00]);

    let status = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "Import-Module \"$PSHOME/Modules/Microsoft.PowerShell.Security/Microsoft.PowerShell.Security.psd1\" -ErrorAction Stop; (Get-AuthenticodeSignature -FilePath '{}').Status",
                signed_pe.display()
            ),
        ])
        .output()
        .expect("run Get-AuthenticodeSignature");
    assert!(
        status.status.success(),
        "Get-AuthenticodeSignature failed: {}",
        String::from_utf8_lossy(&status.stderr)
    );
    let status_text = String::from_utf8_lossy(&status.stdout).trim().to_string();
    assert_ne!(
        status_text, "HashMismatch",
        "Windows still reports HashMismatch"
    );

    let _ = std::fs::remove_file(&signed_pe);
}

#[test]
fn test_end_to_end_sign_and_timestamp_with_mock_tsa() {
    let test_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test_data");

    let pe_file = test_dir.join("test_hello.exe");
    let cert_file = test_dir.join("test_combined.pem");

    if !pe_file.exists() || !cert_file.exists() {
        eprintln!("Skipping test: timestamp signing inputs are missing");
        return;
    }

    let signed_pe = test_dir.join("test_hello_timestamped.exe");
    std::fs::copy(&pe_file, &signed_pe).expect("copy PE");

    let tsa = MockTsaServer::start();
    let request = rustsign_lib::SignRequest {
        file_path: signed_pe.to_string_lossy().to_string(),
        cert_id: None,
        cert_path: Some(cert_file.to_string_lossy().to_string()),
        cert_password: None,
        sign_mode: "app".to_string(),
        digest_algorithm: "sha256".to_string(),
        timestamp_url: Some(tsa.url()),
        description: Some("RustSign Timestamp".to_string()),
        url: Some("https://example.com".to_string()),
        cross_cert_path: None,
        replace_signature: true,
    };

    let result = rustsign_lib::sign_file(&request).expect("sign_file with timestamp failed");
    assert!(result.success, "Signing failed: {}", result.message);

    let file_size = std::fs::metadata(&signed_pe).expect("metadata").len();
    let original_size = std::fs::metadata(&pe_file)
        .expect("original metadata")
        .len();
    eprintln!(
        "TIMESTAMP TEST: original={original_size} bytes, signed={file_size} bytes, delta={}",
        file_size - original_size
    );

    let verify_result =
        rustsign_lib::verify_signature(&signed_pe.to_string_lossy()).expect("verify result");
    assert!(
        verify_result.valid,
        "Verification failed: {}",
        verify_result.message
    );
    assert!(verify_result.has_timestamp, "expected RFC3161 timestamp");

    let timestamp_request = tsa.finish();
    let decoded_request =
        TimeStampReqFixture::from_der(&timestamp_request).expect("decode timestamp request");
    assert_eq!(
        decoded_request.message_imprint.hash_algorithm.oid,
        const_oid::db::rfc5912::ID_SHA_256
    );
    assert_eq!(decoded_request.cert_req, Some(true));

    let _ = std::fs::remove_file(&signed_pe);
}

#[test]
fn test_signing_ignores_duplicate_certificates_in_bundle() {
    let test_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test_data");

    let pe_file = test_dir.join("test_hello.exe");
    let cert_file = test_dir.join("test_cert.pem");
    let key_file = test_dir.join("test_key.pem");

    if !pe_file.exists() || !cert_file.exists() || !key_file.exists() {
        eprintln!("Skipping test: bundle inputs are missing");
        return;
    }

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let bundle_path = std::env::temp_dir().join(format!("codesign-bundle-{nanos}.pem"));
    let signed_pe = test_dir.join("test_hello_chain.exe");

    let cert_pem = std::fs::read_to_string(&cert_file).expect("read cert");
    let key_pem = std::fs::read_to_string(&key_file).expect("read key");
    let bundle = format!("{cert_pem}\n{cert_pem}\n{key_pem}\n");
    std::fs::write(&bundle_path, bundle).expect("write bundle");
    std::fs::copy(&pe_file, &signed_pe).expect("copy PE");

    let request = rustsign_lib::SignRequest {
        file_path: signed_pe.to_string_lossy().to_string(),
        cert_id: None,
        cert_path: Some(bundle_path.to_string_lossy().to_string()),
        cert_password: None,
        sign_mode: "driver".to_string(),
        digest_algorithm: "sha256".to_string(),
        timestamp_url: None,
        description: None,
        url: None,
        cross_cert_path: None,
        replace_signature: true,
    };

    let result = rustsign_lib::sign_file(&request).expect("sign_file failed");
    assert!(result.success, "Signing failed: {}", result.message);

    let signed_data = parse_signed_data(&signed_pe);
    let cert_count = signed_data
        .certificates
        .as_ref()
        .map(|certs| certs.0.len())
        .unwrap_or(0);
    assert_eq!(cert_count, 1, "duplicate certificates should be skipped");

    let _ = std::fs::remove_file(&bundle_path);
    let _ = std::fs::remove_file(&signed_pe);
}

#[test]
fn test_driver_signing_with_historical_pfx_excludes_self_signed_root() {
    let historical_pfx = std::path::PathBuf::from(r"D:\Desktop\avk\10sign\1.pfx");
    if !historical_pfx.exists() {
        eprintln!(
            "Skipping test: historical PFX not found at {}",
            historical_pfx.display()
        );
        return;
    }

    let test_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test_data");
    let pe_file = test_dir.join("test_hello.exe");
    if !pe_file.exists() {
        eprintln!("Skipping test: test EXE not found at {}", pe_file.display());
        return;
    }

    let signed_pe = test_dir.join("test_hello_driver_chain.exe");
    std::fs::copy(&pe_file, &signed_pe).expect("copy PE");

    let cross_cert = PathBuf::from(
        r"C:\Users\tian\AppData\Local\rustsign\cross-certs\VeriSign_G5_to_Microsoft_Code_Verification_Root.cer",
    );
    if !cross_cert.exists() {
        eprintln!(
            "Skipping test: cross-cert not found at {}",
            cross_cert.display()
        );
        let _ = std::fs::remove_file(&signed_pe);
        return;
    }

    let request = rustsign_lib::SignRequest {
        file_path: signed_pe.to_string_lossy().to_string(),
        cert_id: None,
        cert_path: Some(historical_pfx.to_string_lossy().to_string()),
        cert_password: None,
        sign_mode: "driver".to_string(),
        digest_algorithm: "sha1".to_string(),
        timestamp_url: None,
        description: None,
        url: None,
        cross_cert_path: Some(cross_cert.to_string_lossy().to_string()),
        replace_signature: true,
    };

    let result = rustsign_lib::sign_file(&request).expect("sign_file failed");
    assert!(result.success, "Signing failed: {}", result.message);

    let signed_data = parse_signed_data(&signed_pe);
    let certs = signed_data
        .certificates
        .as_ref()
        .expect("missing certificates");
    assert_eq!(certs.0.len(), 3, "self-signed root should be excluded");

    let self_signed_count = certs
        .0
        .iter()
        .filter_map(|choice| match choice {
            cms::cert::CertificateChoices::Certificate(cert) => Some(cert),
            _ => None,
        })
        .filter(|cert| cert.tbs_certificate.subject == cert.tbs_certificate.issuer)
        .count();
    assert_eq!(
        self_signed_count, 0,
        "embedded root certificate should be excluded"
    );

    let _ = std::fs::remove_file(&signed_pe);
}

#[test]
fn test_export_certificate_formats() {
    let _guard = cert_db_lock().lock().unwrap();

    let test_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test_data");

    let cert_file = test_dir.join("test_combined.pem");
    if !cert_file.exists() {
        eprintln!(
            "Skipping test: test cert not found at {}",
            cert_file.display()
        );
        return;
    }

    // Import certificate first
    let entry = rustsign_lib::cert_manager::import_certificate(cert_file.to_str().unwrap(), None)
        .expect("import_certificate failed");

    // Test PEM export
    let pem_out = test_dir.join("test_export.pem");
    rustsign_lib::cert_manager::export_certificate(
        &entry.id,
        "pem",
        pem_out.to_str().unwrap(),
        None,
    )
    .expect("PEM export failed");
    assert!(pem_out.exists(), "PEM export file not created");
    let pem_content = std::fs::read_to_string(&pem_out).unwrap();
    assert!(
        pem_content.contains("BEGIN CERTIFICATE"),
        "PEM missing certificate"
    );
    assert!(
        pem_content.contains("BEGIN PRIVATE KEY") || pem_content.contains("BEGIN RSA PRIVATE KEY"),
        "PEM missing private key"
    );
    println!("PEM export: OK");

    // Test PFX export
    let pfx_out = test_dir.join("test_export.pfx");
    rustsign_lib::cert_manager::export_certificate(
        &entry.id,
        "pfx",
        pfx_out.to_str().unwrap(),
        Some("testpass"),
    )
    .expect("PFX export failed");
    assert!(pfx_out.exists(), "PFX export file not created");
    // Verify exported PFX can be parsed
    let pfx_data = std::fs::read(&pfx_out).unwrap();
    let pfx = p12::PFX::parse(&pfx_data).expect("Exported PFX parse failed");
    assert!(
        pfx.verify_mac("testpass"),
        "Exported PFX password verification failed"
    );
    let certs = pfx.cert_x509_bags("testpass").unwrap();
    assert!(!certs.is_empty(), "Exported PFX has no certificates");
    let keys = pfx.key_bags("testpass").unwrap();
    assert!(!keys.is_empty(), "Exported PFX has no private keys");
    println!("PFX export: OK");

    // Test PVK+SPC export
    let pvk_spc_base = test_dir.join("test_export").to_string_lossy().to_string();
    rustsign_lib::cert_manager::export_certificate(&entry.id, "pvk_spc", &pvk_spc_base, None)
        .expect("PVK+SPC export failed");
    let pvk_path = test_dir.join("test_export.pvk");
    let spc_path = test_dir.join("test_export.spc");
    assert!(pvk_path.exists(), "PVK file not created");
    assert!(spc_path.exists(), "SPC file not created");
    // Verify PVK header
    let pvk_data = std::fs::read(&pvk_path).unwrap();
    assert!(pvk_data.len() >= 24, "PVK file too small");
    let magic = u32::from_le_bytes([pvk_data[0], pvk_data[1], pvk_data[2], pvk_data[3]]);
    assert_eq!(magic, 0xB0B5F11E, "PVK magic mismatch");
    println!("PVK+SPC export: OK");

    // Cleanup
    let _ = std::fs::remove_file(&pem_out);
    let _ = std::fs::remove_file(&pfx_out);
    let _ = std::fs::remove_file(&pvk_path);
    let _ = std::fs::remove_file(&spc_path);
    let _ = rustsign_lib::cert_manager::delete_certificate(&entry.id);
}

#[test]
fn test_remove_signature_round_trip() {
    let test_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test_data");

    let pe_file = test_dir.join("test_hello.exe");
    let cert_file = test_dir.join("test_combined.pem");

    if !pe_file.exists() || !cert_file.exists() {
        eprintln!("Skipping test: signing inputs are missing");
        return;
    }

    let signed_pe = test_dir.join("test_hello_removed.exe");
    std::fs::copy(&pe_file, &signed_pe).expect("copy PE");

    let request = rustsign_lib::SignRequest {
        file_path: signed_pe.to_string_lossy().to_string(),
        cert_id: None,
        cert_path: Some(cert_file.to_string_lossy().to_string()),
        cert_password: None,
        sign_mode: "app".to_string(),
        digest_algorithm: "sha256".to_string(),
        timestamp_url: None,
        description: None,
        url: None,
        cross_cert_path: None,
        replace_signature: true,
    };

    let sign_result = rustsign_lib::sign_file(&request).expect("sign_file failed");
    assert!(
        sign_result.success,
        "Signing failed: {}",
        sign_result.message
    );

    let verify_result =
        rustsign_lib::verify_signature(&signed_pe.to_string_lossy()).expect("verify signed file");
    assert!(verify_result.valid, "expected signature to verify");

    let remove_result =
        rustsign_lib::remove_signature(&signed_pe.to_string_lossy()).expect("remove signature");
    assert!(
        remove_result.success,
        "remove_signature failed: {}",
        remove_result.message
    );

    let verify_after_remove =
        rustsign_lib::verify_signature(&signed_pe.to_string_lossy()).expect("verify after remove");
    assert!(!verify_after_remove.valid, "signature should be removed");
    assert!(
        verify_after_remove.message.contains("No signature found"),
        "unexpected message after removal: {}",
        verify_after_remove.message
    );

    let _ = std::fs::remove_file(&signed_pe);
}

#[test]
fn test_export_multiple_certificates_to_directory() {
    let _guard = cert_db_lock().lock().unwrap();

    let test_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test_data");

    let cert_file = test_dir.join("test_combined.pem");
    if !cert_file.exists() {
        eprintln!(
            "Skipping test: test cert not found at {}",
            cert_file.display()
        );
        return;
    }

    let entry_one =
        rustsign_lib::cert_manager::import_certificate(cert_file.to_str().unwrap(), None)
            .expect("first import failed");
    let entry_two =
        rustsign_lib::cert_manager::import_certificate(cert_file.to_str().unwrap(), None)
            .expect("second import failed");

    let export_dir = std::env::temp_dir().join(format!(
        "rustsign-batch-export-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));

    let output_paths = rustsign_lib::cert_manager::export_certificates(
        &[entry_one.id.clone(), entry_two.id.clone()],
        "pem",
        export_dir.to_str().unwrap(),
        None,
    )
    .expect("batch export failed");

    assert_eq!(output_paths.len(), 2, "expected one output per certificate");
    for output_path in &output_paths {
        assert!(
            std::path::Path::new(output_path).exists(),
            "missing batch export output: {output_path}"
        );
    }

    for output_path in output_paths {
        let _ = std::fs::remove_file(output_path);
    }
    let _ = std::fs::remove_dir_all(&export_dir);
    let _ = rustsign_lib::cert_manager::delete_certificate(&entry_one.id);
    let _ = rustsign_lib::cert_manager::delete_certificate(&entry_two.id);
}

#[test]
fn test_sign_with_imported_password_protected_pfx_uses_saved_password() {
    let _guard = cert_db_lock().lock().unwrap();

    let test_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test_data");

    let pe_file = test_dir.join("test_hello.exe");
    let cert_pem_path = test_dir.join("test_cert.pem");
    let key_pem_path = test_dir.join("test_key.pem");
    if !pe_file.exists() || !cert_pem_path.exists() || !key_pem_path.exists() {
        eprintln!("Skipping test: required signing fixtures are missing");
        return;
    }

    let cert_pem = std::fs::read_to_string(&cert_pem_path).expect("read cert PEM");
    let key_pem = std::fs::read_to_string(&key_pem_path).expect("read key PEM");
    let (_, cert_der) = pem_rfc7468::decode_vec(cert_pem.as_bytes()).expect("decode cert PEM");
    let (_, key_der) = pem_rfc7468::decode_vec(key_pem.as_bytes()).expect("decode key PEM");

    let pfx_password = "testpass";
    let pfx = p12::PFX::new(&cert_der, &key_der, None, pfx_password, "rustsign-test")
        .expect("build test PFX");

    let unique_suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let pfx_path = std::env::temp_dir().join(format!("rustsign-import-{unique_suffix}.pfx"));
    let signed_pe = std::env::temp_dir().join(format!("rustsign-signed-{unique_suffix}.exe"));

    std::fs::write(&pfx_path, pfx.to_der()).expect("write test PFX");
    std::fs::copy(&pe_file, &signed_pe).expect("copy PE file");

    let entry = rustsign_lib::cert_manager::import_certificate(
        pfx_path.to_str().unwrap(),
        Some(pfx_password),
    )
    .expect("import password-protected PFX");

    let request = rustsign_lib::SignRequest {
        file_path: signed_pe.to_string_lossy().to_string(),
        cert_id: Some(entry.id.clone()),
        cert_path: None,
        cert_password: None,
        sign_mode: "app".to_string(),
        digest_algorithm: "sha256".to_string(),
        timestamp_url: None,
        description: None,
        url: None,
        cross_cert_path: None,
        replace_signature: true,
    };

    let result = rustsign_lib::sign_file(&request).expect("sign with imported certificate");
    assert!(result.success, "Signing failed: {}", result.message);

    let verify_result =
        rustsign_lib::verify_signature(&signed_pe.to_string_lossy()).expect("verify result");
    assert!(
        verify_result.valid,
        "Verification failed: {}",
        verify_result.message
    );

    let _ = std::fs::remove_file(&pfx_path);
    let _ = std::fs::remove_file(&signed_pe);
    let _ = rustsign_lib::cert_manager::delete_certificate(&entry.id);
}

fn parse_signed_data(path: &std::path::Path) -> cms::signed_data::SignedData {
    use der::Decode;

    let data = std::fs::read(path).expect("read signed file");
    let entries = rustsign_lib::pe::read_all_signatures(&data).expect("read signatures");
    let signature = &entries.first().expect("no signatures").data;

    let content_info =
        cms::content_info::ContentInfo::from_der(signature).expect("parse ContentInfo");
    let signed_data_any = der::Any::new(der::Tag::Sequence, content_info.content.value().to_vec())
        .expect("wrap SignedData");
    cms::signed_data::SignedData::from_der(&signed_data_any.to_der().expect("SignedData DER"))
        .expect("parse SignedData")
}

#[derive(Clone, Debug, Sequence)]
struct MessageImprintFixture {
    hash_algorithm: x509_cert::spki::AlgorithmIdentifierOwned,
    hashed_message: OctetString,
}

#[derive(Clone, Debug, Sequence)]
struct TimeStampReqFixture {
    version: u8,
    message_imprint: MessageImprintFixture,
    #[asn1(optional = "true")]
    req_policy: Option<const_oid::ObjectIdentifier>,
    #[asn1(optional = "true")]
    nonce: Option<u64>,
    #[asn1(optional = "true")]
    cert_req: Option<bool>,
}

#[derive(Clone, Debug, Sequence)]
struct PkiStatusInfoFixture {
    status: u8,
    #[asn1(optional = "true")]
    status_string: Option<Any>,
    #[asn1(optional = "true")]
    fail_info: Option<Any>,
}

#[derive(Clone, Debug, Sequence)]
struct TimeStampRespFixture {
    status: PkiStatusInfoFixture,
    #[asn1(optional = "true")]
    time_stamp_token: Option<cms::content_info::ContentInfo>,
}

struct MockTsaServer {
    url: String,
    request_receiver: std::sync::mpsc::Receiver<Vec<u8>>,
    handle: std::thread::JoinHandle<()>,
}

impl MockTsaServer {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock TSA");
        let addr = listener.local_addr().expect("mock TSA address");
        let (request_sender, request_receiver) = std::sync::mpsc::channel();

        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept mock TSA connection");
            let request_body = read_http_body(&mut stream);
            request_sender
                .send(request_body)
                .expect("send request body");

            let response_body = build_timestamp_response_fixture();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/timestamp-reply\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response_body.len()
            );
            stream
                .write_all(response.as_bytes())
                .and_then(|_| stream.write_all(&response_body))
                .expect("write mock TSA response");
        });

        Self {
            url: format!("http://{addr}"),
            request_receiver,
            handle,
        }
    }

    fn url(&self) -> String {
        self.url.clone()
    }

    fn finish(self) -> Vec<u8> {
        let request = self
            .request_receiver
            .recv()
            .expect("receive timestamp request");
        self.handle.join().expect("join mock TSA");
        request
    }
}

fn read_http_body(stream: &mut TcpStream) -> Vec<u8> {
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .expect("set read timeout");

    let mut buffer = Vec::new();
    let mut temp = [0u8; 1024];
    let mut headers_len = None;
    let mut content_length = None;

    loop {
        let bytes_read = stream.read(&mut temp).expect("read mock TSA request");
        if bytes_read == 0 {
            break;
        }
        buffer.extend_from_slice(&temp[..bytes_read]);

        if headers_len.is_none() {
            if let Some(index) = find_header_terminator(&buffer) {
                headers_len = Some(index);
                content_length = Some(parse_content_length(&buffer[..index]));
            }
        }

        if let (Some(header_end), Some(expected_body_len)) = (headers_len, content_length) {
            let body_len = buffer.len().saturating_sub(header_end);
            if body_len >= expected_body_len {
                return buffer[header_end..header_end + expected_body_len].to_vec();
            }
        }
    }

    Vec::new()
}

fn find_header_terminator(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

fn parse_content_length(headers: &[u8]) -> usize {
    let header_text = String::from_utf8_lossy(headers);
    header_text
        .lines()
        .find_map(|line| {
            let lower = line.to_ascii_lowercase();
            lower
                .strip_prefix("content-length:")
                .and_then(|value| value.trim().parse::<usize>().ok())
        })
        .unwrap_or(0)
}

#[test]
fn test_sign_append_then_list_signatures() {
    let test_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test_data");

    let pe_file = test_dir.join("test_hello.exe");
    let cert_file = test_dir.join("test_combined.pem");

    if !pe_file.exists() || !cert_file.exists() {
        eprintln!("Skipping: test files not found");
        return;
    }

    let signed_pe = test_dir.join("test_hello_multi.exe");
    std::fs::copy(&pe_file, &signed_pe).expect("copy PE");

    // First signature
    let req1 = rustsign_lib::SignRequest {
        file_path: signed_pe.to_string_lossy().to_string(),
        cert_id: None,
        cert_path: Some(cert_file.to_string_lossy().to_string()),
        cert_password: None,
        sign_mode: "app".to_string(),
        digest_algorithm: "sha256".to_string(),
        timestamp_url: None,
        description: Some("Sig 1".to_string()),
        url: None,
        cross_cert_path: None,
        replace_signature: true,
    };
    let r1 = rustsign_lib::sign_file(&req1).expect("sign 1");
    assert!(r1.success, "Sign 1 failed: {}", r1.message);

    // List signatures after first sign
    let infos =
        rustsign_lib::list_signatures(&signed_pe.to_string_lossy().to_string()).expect("list 1");
    assert_eq!(infos.len(), 1, "Expected 1 signature after first sign");

    // Second signature (append mode)
    let req2 = rustsign_lib::SignRequest {
        file_path: signed_pe.to_string_lossy().to_string(),
        cert_id: None,
        cert_path: Some(cert_file.to_string_lossy().to_string()),
        cert_password: None,
        sign_mode: "app".to_string(),
        digest_algorithm: "sha1".to_string(),
        timestamp_url: None,
        description: Some("Sig 2".to_string()),
        url: None,
        cross_cert_path: None,
        replace_signature: false, // APPEND
    };
    let r2 = rustsign_lib::sign_file(&req2).expect("sign 2");
    assert!(r2.success, "Sign 2 failed: {}", r2.message);

    // List signatures after second sign
    let infos =
        rustsign_lib::list_signatures(&signed_pe.to_string_lossy().to_string()).expect("list 2");
    assert_eq!(infos.len(), 2, "Expected 2 signatures, got {}", infos.len());

    // Verify they have different digests
    assert_ne!(
        infos[0].digest_algorithm, infos[1].digest_algorithm,
        "Two signatures should have different digest algorithms"
    );

    println!(
        "Sig 0: subject={:?} digest={:?}",
        infos[0].subject, infos[0].digest_algorithm
    );
    println!(
        "Sig 1: subject={:?} digest={:?}",
        infos[1].subject, infos[1].digest_algorithm
    );

    // Verify the nested structure: one WIN_CERTIFICATE entry containing
    // the nested signature chain (newest signature wraps the older one).
    let data = std::fs::read(&signed_pe).unwrap();
    let entries = rustsign_lib::pe::read_all_signatures(&data).unwrap();
    assert_eq!(
        entries.len(),
        1,
        "Nested signatures produce a single WIN_CERTIFICATE entry"
    );

    let _ = std::fs::remove_file(&signed_pe);
}

fn build_timestamp_response_fixture() -> Vec<u8> {
    let token = cms::content_info::ContentInfo {
        content_type: const_oid::db::rfc5911::ID_DATA,
        content: Any::new(der::Tag::OctetString, b"mock-tsa-token".to_vec())
            .expect("build mock timestamp token"),
    };

    TimeStampRespFixture {
        status: PkiStatusInfoFixture {
            status: 0,
            status_string: None,
            fail_info: None,
        },
        time_stamp_token: Some(token),
    }
    .to_der()
    .expect("encode mock timestamp response")
}

#[test]
fn test_driver_sign_with_real_pfx_excludes_self_signed_root() {
    let pfx_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test_data")
        .join("1.pfx");
    if !pfx_path.exists() {
        eprintln!("Skipping: 1.pfx not found");
        return;
    }

    let test_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test_data");
    let pe_file = test_dir.join("test_hello.exe");
    if !pe_file.exists() {
        eprintln!("Skipping: test_hello.exe not found");
        return;
    }

    let signed_pe = test_dir.join("test_hello_driver_diagnostic.exe");
    std::fs::copy(&pe_file, &signed_pe).expect("copy PE");

    // Also copy to a temp dir that doesn't have cross-certs, to test bundled fallback
    let cross_cert_dir = test_dir.join("empty_cross_cert_dir");
    std::fs::create_dir_all(&cross_cert_dir).expect("create empty dir");

    let request = rustsign_lib::SignRequest {
        file_path: signed_pe.to_string_lossy().to_string(),
        cert_id: None,
        cert_path: Some(pfx_path.to_string_lossy().to_string()),
        cert_password: None,
        sign_mode: "driver".to_string(),
        digest_algorithm: "sha256".to_string(),
        timestamp_url: None,
        description: Some("Diagnostic driver sign".to_string()),
        url: None,
        cross_cert_path: Some(cross_cert_dir.to_string_lossy().to_string()),
        replace_signature: true,
    };

    let result = rustsign_lib::sign_file(&request).expect("sign_file failed");
    assert!(result.success, "Signing failed: {}", result.message);

    // Verify the signed file can be parsed and has the old driver-signing chain shape:
    // leaf + issuing intermediate + Microsoft cross-cert, with no self-signed root.
    let data = std::fs::read(&signed_pe).expect("read signed PE");
    let entries = rustsign_lib::pe::read_all_signatures(&data).expect("read signatures");
    assert!(!entries.is_empty(), "Expected at least one signature entry");

    let signed_data = parse_signed_data(&signed_pe);
    let certs = signed_data
        .certificates
        .as_ref()
        .expect("missing certificates");
    assert_eq!(
        certs.0.len(),
        3,
        "driver signature should embed leaf + intermediate + cross-cert"
    );

    let self_signed_count = certs
        .0
        .iter()
        .filter_map(|choice| match choice {
            cms::cert::CertificateChoices::Certificate(cert) => Some(cert),
            _ => None,
        })
        .filter(|cert| cert.tbs_certificate.subject == cert.tbs_certificate.issuer)
        .count();
    assert_eq!(
        self_signed_count, 0,
        "driver signature must not embed self-signed roots"
    );

    let _ = std::fs::remove_file(&signed_pe);
    let _ = std::fs::remove_dir_all(cross_cert_dir);
}

/// Regression test for the test-certificate generation fix.
///
/// Before the fix, `generate_test_cert_pair` produced a two-tier hierarchy
/// (self-signed root CA + leaf code-signing cert) and only the leaf was
/// embedded in the driver signature. Because the leaf was not self-signed,
/// Windows could not build a certificate chain from the embedded signature and
/// rejected the driver with "A certificate chain could not be built to a
/// trusted root authority" (the `test_data/false.sys` failure).
///
/// After the fix the test certificate is self-signed (WDK test-cert pattern,
/// like `test_data/true.sys`), so Windows can build the chain from the embedded
/// certificate alone. With the root not installed we therefore expect the same
/// status Windows reports for `true.sys` — "UnknownError" with the message
/// "terminated in a root certificate which is not trusted" — and crucially NOT
/// "could not be built to a trusted root authority".
#[test]
fn test_generated_self_signed_cert_builds_chain_on_windows() {
    if !cfg!(windows) {
        eprintln!("Skipping test: Get-AuthenticodeSignature is only available on Windows");
        return;
    }

    let test_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test_data");
    let false_sys = test_dir.join("false.sys");
    if !false_sys.exists() {
        eprintln!(
            "Skipping test: false.sys not found at {}",
            false_sys.display()
        );
        return;
    }

    // Generate a fresh self-signed test certificate.
    let options = rustsign_lib::CertGenOptions {
        password: "test123".to_string(),
        ..Default::default()
    };
    let (_root, sign) =
        rustsign_lib::generate_test_cert_pair(&options).expect("generate test cert pair");

    // Sanity: the certificate is self-signed.
    let (_, sign_der) = pem_rfc7468::decode_vec(sign.cert_pem.as_bytes()).expect("decode PEM");
    let sign_cert = x509_cert::Certificate::from_der(&sign_der).expect("parse cert");
    assert_eq!(
        sign_cert.tbs_certificate.issuer.to_string(),
        sign_cert.tbs_certificate.subject.to_string(),
        "generated test certificate must be self-signed"
    );

    // Save the PFX and write an unsigned copy of the driver to sign.
    let tmp = std::env::temp_dir().join(format!(
        "rustsign-selfsigned-{}.d",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&tmp).unwrap();
    let pfx_path = tmp.join("test_codesign.pfx");
    std::fs::write(&pfx_path, &sign.pfx_der).unwrap();

    let unsigned_driver = tmp.join("unsigned.sys");
    std::fs::copy(&false_sys, &unsigned_driver).unwrap();
    // Strip the existing (broken) signature so we sign a clean image.
    rustsign_lib::pe::remove_signature(&unsigned_driver).expect("strip existing signature");

    let signed_driver = tmp.join("selfsigned.sys");
    std::fs::copy(&unsigned_driver, &signed_driver).unwrap();

    let request = rustsign_lib::SignRequest {
        file_path: signed_driver.to_string_lossy().to_string(),
        cert_id: None,
        cert_path: Some(pfx_path.to_string_lossy().to_string()),
        cert_password: Some("test123".to_string()),
        sign_mode: "driver".to_string(),
        digest_algorithm: "sha256".to_string(),
        timestamp_url: None,
        description: None,
        url: None,
        cross_cert_path: None,
        replace_signature: true,
    };
    let result = rustsign_lib::sign_file(&request).expect("sign_file failed");
    assert!(result.success, "Signing failed: {}", result.message);

    // Ask Windows to verify the signature. Without the test root installed we
    // do not expect "Valid" — we only assert that Windows can BUILD the chain,
    // i.e. the failure is "untrusted root" (like true.sys) rather than
    // "could not be built" (the false.sys regression).
    let out = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "[Console]::OutputEncoding=[Text.Encoding]::UTF8; \
                 $s = Get-AuthenticodeSignature -FilePath '{}'; \
                 Write-Output ('STATUS=' + $s.Status); \
                 Write-Output ('MSG=' + $s.StatusMessage)",
                signed_driver.display()
            ),
        ])
        .output()
        .expect("run Get-AuthenticodeSignature");
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    println!("Get-AuthenticodeSignature:\n{}", text);

    assert!(
        !text.contains("could not be built"),
        "Windows could not build the certificate chain — the test certificate \
         is not self-contained. Got:\n{}",
        text
    );

    let _ = std::fs::remove_dir_all(&tmp);
}
