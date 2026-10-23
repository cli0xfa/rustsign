pub mod cert_gen;
pub mod cert_manager;
pub mod cross_cert;
pub mod crypto;
pub mod local_tsa;
pub mod pe;
pub mod rules;
pub mod signer;
pub mod timestamp;
pub mod verify;

use base64::Engine;
use der::Decode;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::path::{Path, PathBuf};
use x509_cert::Certificate;

pub use cert_gen::{
    CertGenOptions, GeneratedCert, generate_subordinate_cert, generate_test_cert_pair,
};
pub use cert_manager::{
    CertEntry, delete_certificate, export_certificate, export_certificates, get_certificate,
    import_certificate, list_certificates,
};
pub use cross_cert::{CrossCertResult, download_cross_certs, find_matching_cross_cert};
pub use local_tsa::{
    LocalTsaConfig, LocalTsaStatus, get_local_tsa_status, load_local_tsa_config, start_local_tsa,
    stop_local_tsa,
};
pub use rules::SignRules;
pub use timestamp::{remove_timestamp_from_cms, remove_timestamp_from_file};
pub use verify::{SignatureInfo, VerifyResult, oid_to_display_name, verify_signature};

/// Isolated data roots for debug builds and automated desktop smoke tests.
pub fn data_dir() -> PathBuf {
    #[cfg(debug_assertions)]
    if let Some(path) = std::env::var_os("RUSTSIGN_DATA_DIR") {
        return PathBuf::from(path);
    }
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("rustsign")
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignRequest {
    pub file_path: String,
    pub cert_id: Option<String>,
    pub cert_path: Option<String>,
    pub cert_password: Option<String>,
    pub sign_mode: String,
    pub digest_algorithm: String,
    pub timestamp_url: Option<String>,
    pub description: Option<String>,
    pub url: Option<String>,
    pub cross_cert_path: Option<String>,
    pub replace_signature: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignResult {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, thiserror::Error)]
pub enum CodeSignError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("PE file error: {0}")]
    Pe(String),
    #[error("Certificate error: {0}")]
    Certificate(String),
    #[error("Signing error: {0}")]
    Signing(String),
    #[error("Timestamp error: {0}")]
    Timestamp(String),
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("TSA server error: {0}")]
    Tsa(String),
}

impl From<reqwest::Error> for CodeSignError {
    fn from(error: reqwest::Error) -> Self {
        CodeSignError::Http(error.to_string())
    }
}

pub fn sign_file(request: &SignRequest) -> Result<SignResult, CodeSignError> {
    let resolved_certificate = resolve_certificate_context(request)?;
    let sign_mode = normalize_sign_mode(request);
    let digest_algorithm = normalize_digest_algorithm(request);

    let cert_password = resolved_certificate.password.as_deref();
    let crypto::LoadedCertificate {
        cert,
        private_key,
        mut extra_certs,
    } = crypto::load_certificate(&resolved_certificate.path, cert_password)?;

    let pe_data = std::fs::read(&request.file_path)?;
    let digest = compute_digest(&pe_data, &digest_algorithm)?;

    if sign_mode == "driver" {
        // Kernel-mode cross-signing must not embed the self-signed root CA.
        // Keep the leaf + issuing intermediates + Microsoft cross-cert only,
        // otherwise Windows may build the chain to the self-signed VeriSign root
        // instead of Microsoft Code Verification Root and reject the driver
        // with event ID 577.
        extra_certs.retain(|extra_cert| {
            extra_cert.tbs_certificate.subject != extra_cert.tbs_certificate.issuer
        });

        let rules = rules::SignRules::load().unwrap_or_default();
        let configured_path = request
            .cross_cert_path
            .as_deref()
            .filter(|path| !path.trim().is_empty())
            .map(PathBuf::from)
            .or_else(|| {
                if !rules.auto_download_cross_cert {
                    return None;
                }

                if !rules.cross_cert_store_path.trim().is_empty() {
                    Some(PathBuf::from(rules.cross_cert_store_path))
                } else {
                    Some(cross_cert::default_cross_cert_store_path())
                }
            });

        if let Some(cross_cert_path) = configured_path
            && let Some(cross_cert) = load_driver_cross_cert(&cert, &extra_certs, &cross_cert_path)?
        {
            extra_certs.push(cross_cert);
        }
    }

    // When appending, flatten the existing CMS chain and strip each entry's
    // old nested attribute so they become standalone. Each prior signature
    // then gets its own SPC_NESTED_SIGNATURE attribute at the outermost level,
    // without any duplication or size explosion.
    let previous_entries: Vec<Vec<u8>> = if !request.replace_signature {
        pe::read_all_signatures(&pe_data)
            .ok()
            .and_then(|entries| entries.into_iter().next())
            .map(|e| {
                let chain =
                    verify::collect_nested_cms_chain(&e.data).unwrap_or_else(|_| vec![e.data]);
                chain
                    .into_iter()
                    .map(|der| verify::remove_nested_from_cms(&der).unwrap_or(der))
                    .collect()
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let prev_refs: Vec<&[u8]> = previous_entries.iter().map(|v| v.as_slice()).collect();

    let cms_signature = signer::create_signature(
        &digest,
        &cert,
        &private_key,
        &digest_algorithm,
        request.description.as_deref(),
        request.url.as_deref(),
        &extra_certs,
        &prev_refs,
    )?;

    // Timestamp the CMS signature in-memory before writing to PE,
    // so we never need to read back and re-write (which would destroy
    // appended signatures on multi-signed files).
    let cms_signature = if let Some(tsa_url) = &request.timestamp_url {
        if !tsa_url.trim().is_empty() {
            match timestamp::timestamp_cms_signature(&cms_signature, tsa_url, &digest_algorithm) {
                Ok(ts_sig) => ts_sig,
                Err(error) => {
                    return Ok(SignResult {
                        success: false,
                        message: format!(
                            "Timestamp failed before writing; the original file was not modified: {error}"
                        ),
                    });
                }
            }
        } else {
            cms_signature
        }
    } else {
        cms_signature
    };

    let output_path = PathBuf::from(&request.file_path);
    // When nesting (appending with existing sig), always replace the certificate
    // table because the old signature is already embedded inside the new CMS.
    let do_replace = request.replace_signature || !previous_entries.is_empty();
    pe::write_signature(&pe_data, &cms_signature, &output_path, do_replace)?;

    Ok(SignResult {
        success: true,
        message: format!("Signed: {}", output_path.display()),
    })
}

pub fn remove_signature(file_path: &str) -> Result<SignResult, CodeSignError> {
    let removed = pe::remove_signature(Path::new(file_path))?;
    Ok(SignResult {
        success: removed,
        message: if removed {
            format!("Signature removed: {file_path}")
        } else {
            "No signature found in the file".to_string()
        },
    })
}

struct ResolvedCertificateContext {
    path: PathBuf,
    password: Option<String>,
}

fn resolve_certificate_context(
    request: &SignRequest,
) -> Result<ResolvedCertificateContext, CodeSignError> {
    if let Some(id) = &request.cert_id {
        let entry = get_certificate(id)?;
        return match entry {
            Some(entry) => Ok(ResolvedCertificateContext {
                path: PathBuf::from(entry.file_path),
                password: request.cert_password.clone().or(entry.password),
            }),
            None => Err(CodeSignError::Certificate(
                "Certificate not found".to_string(),
            )),
        };
    }

    if let Some(path) = &request.cert_path {
        return Ok(ResolvedCertificateContext {
            path: PathBuf::from(path),
            password: request.cert_password.clone(),
        });
    }

    Err(CodeSignError::Certificate(
        "No certificate selected".to_string(),
    ))
}

pub(crate) fn compute_digest(pe_data: &[u8], algorithm: &str) -> Result<Vec<u8>, CodeSignError> {
    let file = object::read::File::parse(pe_data)
        .map_err(|e| CodeSignError::Pe(format!("Failed to parse file: {e:?}")))?;

    match algorithm {
        "sha1" => {
            let mut hasher = sha1::Sha1::new();
            compute_digest_inner(file, &mut hasher)?;
            Ok(hasher.finalize().to_vec())
        }
        "sha384" => {
            let mut hasher = sha2::Sha384::new();
            compute_digest_inner(file, &mut hasher)?;
            Ok(hasher.finalize().to_vec())
        }
        "sha512" => {
            let mut hasher = sha2::Sha512::new();
            compute_digest_inner(file, &mut hasher)?;
            Ok(hasher.finalize().to_vec())
        }
        _ => {
            let mut hasher = sha2::Sha256::new();
            compute_digest_inner(file, &mut hasher)?;
            Ok(hasher.finalize().to_vec())
        }
    }
}

fn load_cross_cert_from_data(data: &[u8]) -> Result<Certificate, CodeSignError> {
    if let Ok(data_str) = std::str::from_utf8(data) {
        let begin = "-----BEGIN CERTIFICATE-----";
        let end = "-----END CERTIFICATE-----";
        if let (Some(start_idx), Some(end_idx)) = (data_str.find(begin), data_str.find(end)) {
            let block = &data_str[start_idx..end_idx + end.len()];
            let body = block
                .lines()
                .filter(|line| !line.starts_with("-----"))
                .flat_map(|line| line.chars())
                .filter(|ch| !ch.is_whitespace())
                .collect::<String>();
            let der = base64::engine::general_purpose::STANDARD
                .decode(body)
                .map_err(|e| CodeSignError::Certificate(format!("PEM decode error: {e:?}")))?;
            return Certificate::from_der(&der)
                .map_err(|e| CodeSignError::Certificate(format!("DER parse error: {e:?}")));
        }
    }

    Certificate::from_der(data)
        .map_err(|e| CodeSignError::Certificate(format!("DER parse error: {e:?}")))
}

fn load_driver_cross_cert(
    cert: &Certificate,
    extra_certs: &[Certificate],
    cross_cert_path: &Path,
) -> Result<Option<Certificate>, CodeSignError> {
    let resolved_path = if cross_cert_path.is_dir() {
        cross_cert::find_matching_cross_cert(cert, extra_certs, cross_cert_path)?
    } else if cross_cert_path.exists() {
        Some(cross_cert_path.to_path_buf())
    } else {
        None
    };

    if let Some(path) = resolved_path {
        let cross_cert_data = std::fs::read(&path)?;
        let cross_cert = load_cross_cert_from_data(&cross_cert_data)?;
        return Ok(Some(cross_cert));
    }

    if let Some(bundled) = cross_cert::find_matching_bundled_cross_cert(cert, extra_certs)? {
        return Ok(Some(bundled));
    }

    Ok(None)
}

pub(crate) fn compute_digest_for_verify(
    pe_data: &[u8],
    algorithm: &str,
) -> Result<Vec<u8>, CodeSignError> {
    compute_digest(pe_data, algorithm)
}

fn normalize_sign_mode(request: &SignRequest) -> String {
    if !request.sign_mode.trim().is_empty() {
        return request.sign_mode.trim().to_ascii_lowercase();
    }

    infer_sign_mode(&request.file_path).to_string()
}

fn infer_sign_mode(file_path: &str) -> &'static str {
    if file_path.to_ascii_lowercase().ends_with(".sys") {
        "driver"
    } else {
        "app"
    }
}

fn normalize_digest_algorithm(request: &SignRequest) -> String {
    if !request.digest_algorithm.trim().is_empty() {
        return request.digest_algorithm.trim().to_ascii_lowercase();
    }

    rules::SignRules::load()
        .ok()
        .map(|rules| rules.default_digest_algo)
        .filter(|algo| !algo.trim().is_empty())
        .unwrap_or_else(|| "sha256".to_string())
}

pub fn list_signatures(file_path: &str) -> Result<Vec<SignatureInfo>, CodeSignError> {
    let data = std::fs::read(file_path)?;
    verify::list_signatures(&data)
}

/// Remove a specific signature by index (0-based).
pub fn remove_signature_at(file_path: &str, index: usize) -> Result<SignResult, CodeSignError> {
    let data = std::fs::read(file_path)?;
    let new_data = pe::remove_signature_at(&data, index)?;
    std::fs::write(file_path, new_data)?;
    Ok(SignResult {
        success: true,
        message: format!("Removed signature #{}", index),
    })
}

/// Reorder signatures. `order` is a permutation of 0..N-1.
pub fn reorder_signatures(file_path: &str, order: &[usize]) -> Result<SignResult, CodeSignError> {
    let data = std::fs::read(file_path)?;
    let new_data = pe::reorder_signatures(&data, order)?;
    std::fs::write(file_path, new_data)?;
    Ok(SignResult {
        success: true,
        message: format!("Reordered {} signatures", order.len()),
    })
}

fn compute_digest_inner<'a>(
    file: object::read::File<'a, &'a [u8]>,
    hasher: &mut dyn digest::Update,
) -> Result<(), CodeSignError> {
    match file {
        object::read::File::Pe32(pe) => {
            authenticode::authenticode_digest(&pe, hasher)
                .map_err(|e| CodeSignError::Pe(format!("Failed to compute digest: {e:?}")))?;
        }
        object::read::File::Pe64(pe) => {
            authenticode::authenticode_digest(&pe, hasher)
                .map_err(|e| CodeSignError::Pe(format!("Failed to compute digest: {e:?}")))?;
        }
        _ => return Err(CodeSignError::Pe("Not a PE file".to_string())),
    }
    Ok(())
}
