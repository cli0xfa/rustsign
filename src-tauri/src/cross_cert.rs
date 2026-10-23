use crate::CodeSignError;
use base64::Engine;
use der::Decode;
use reqwest::header::{ACCEPT, USER_AGENT};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use x509_cert::Certificate;

#[derive(Debug, Clone, Copy)]
struct CrossCertSource {
    name: &'static str,
    file_name: &'static str,
    candidate_urls: &'static [&'static str],
}

#[derive(Debug, Clone, Copy)]
struct BundledCrossCert {
    file_name: &'static str,
    pem_data: &'static str,
}

/// Microsoft cross certificates are a legacy driver-signing mechanism.
/// We still try the historical endpoints, preferring HTTPS first when it works.
const CROSS_CERT_SOURCES: &[CrossCertSource] = &[
    CrossCertSource {
        name: "DigiCert",
        file_name: "DigiCertSha2AssuredIDCodeSigningCA.crt",
        candidate_urls: &[
            "https://www.microsoft.com/pki/certs/DigiCertSha2AssuredIDCodeSigningCA.crt",
            "http://www.microsoft.com/pki/certs/DigiCertSha2AssuredIDCodeSigningCA.crt",
        ],
    },
    CrossCertSource {
        name: "Sectigo (Comodo)",
        file_name: "ComodoRSCACodeSigningCA.crt",
        candidate_urls: &[
            "https://www.microsoft.com/pki/certs/ComodoRSCACodeSigningCA.crt",
            "http://www.microsoft.com/pki/certs/ComodoRSCACodeSigningCA.crt",
        ],
    },
    CrossCertSource {
        name: "GlobalSign",
        file_name: "GlobalSignCodeSigningCA.crt",
        candidate_urls: &[
            "https://www.microsoft.com/pki/certs/GlobalSignCodeSigningCA.crt",
            "http://www.microsoft.com/pki/certs/GlobalSignCodeSigningCA.crt",
        ],
    },
];

const BUNDLED_CROSS_CERTS: &[BundledCrossCert] = &[BundledCrossCert {
    file_name: "VeriSign_G5_to_Microsoft_Code_Verification_Root.pem",
    pem_data: include_str!(
        "../assets/cross-certs/VeriSign_G5_to_Microsoft_Code_Verification_Root.pem"
    ),
}];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossCertResult {
    pub success: bool,
    pub message: String,
    pub path: Option<String>,
}

pub fn default_cross_cert_store_path() -> PathBuf {
    let mut path = dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("."));
    path.push("rustsign");
    path.push("cross-certs");
    path
}

/// Download Microsoft cross certificates.
///
/// These endpoints are legacy and may no longer be available because Microsoft
/// retired cross-certificate based driver signing.
pub async fn download_cross_certs(
    store_dir: Option<&str>,
) -> Result<CrossCertResult, CodeSignError> {
    let store_path = if let Some(dir) = store_dir {
        PathBuf::from(dir)
    } else {
        default_cross_cert_store_path()
    };

    fs::create_dir_all(&store_path)?;
    let bundled_count = write_bundled_cross_certs(&store_path)?;

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()?;

    let mut downloaded = 0;
    let mut failed = 0;
    let mut failures = Vec::new();

    for source in CROSS_CERT_SOURCES {
        match download_single_cert(&client, source, &store_path).await {
            Ok(filename) => {
                println!("Downloaded {}: {filename}", source.name);
                downloaded += 1;
            }
            Err(e) => {
                eprintln!("Failed to download {}: {e:?}", source.name);
                failures.push(format!("{}: {}", source.name, e));
                failed += 1;
            }
        }
    }

    let success = bundled_count > 0 || downloaded > 0;
    let message = if success {
        format!(
            "Cross-cert store is ready. Bundled: {bundled_count}, online downloaded: {downloaded}, online failed: {failed}.",
        )
    } else {
        let failure_suffix = failures
            .first()
            .map(|detail| format!(" First error: {detail}"))
            .unwrap_or_default();
        format!(
            "No cross certificates are available. Historical Microsoft download URLs may have been retired.{failure_suffix}"
        )
    };

    Ok(CrossCertResult {
        success,
        message,
        path: Some(store_path.to_string_lossy().to_string()),
    })
}

pub fn write_bundled_cross_certs(store_path: &Path) -> Result<usize, CodeSignError> {
    let mut written = 0;
    for bundled in BUNDLED_CROSS_CERTS {
        let cert = parse_certificate_payload(bundled.pem_data.as_bytes())?;
        let out_path = store_path.join(bundled.file_name);
        fs::write(out_path, bundled.pem_data.as_bytes())?;
        let _ = cert;
        written += 1;
    }
    Ok(written)
}

async fn download_single_cert(
    client: &reqwest::Client,
    source: &CrossCertSource,
    store_path: &Path,
) -> Result<String, CodeSignError> {
    let mut last_error = None;
    let file_path = store_path.join(source.file_name);

    for url in source.candidate_urls {
        match try_download_single_url(client, url, &file_path).await {
            Ok(()) => return Ok(source.file_name.to_string()),
            Err(error) => last_error = Some(format!("{url}: {error}")),
        }
    }

    Err(CodeSignError::Certificate(
        last_error.unwrap_or_else(|| "no download URL available".to_string()),
    ))
}

async fn try_download_single_url(
    client: &reqwest::Client,
    url: &str,
    output_path: &Path,
) -> Result<(), CodeSignError> {
    let response = client
        .get(url)
        .header(
            ACCEPT,
            "application/pkix-cert,application/x-x509-ca-cert,application/octet-stream,*/*",
        )
        .header(USER_AGENT, "rustsign/0.1")
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| CodeSignError::Certificate(format!("HTTP error: {e:?}")))?;

    let response = response
        .error_for_status()
        .map_err(|e| CodeSignError::Certificate(format!("HTTP status error: {e:?}")))?;

    let bytes = response
        .bytes()
        .await
        .map_err(|e| CodeSignError::Certificate(format!("Download error: {e:?}")))?;

    validate_certificate_payload(&bytes)?;
    fs::write(output_path, &bytes)?;

    Ok(())
}

fn validate_certificate_payload(data: &[u8]) -> Result<(), CodeSignError> {
    parse_certificate_payload(data).map(|_| ())
}

fn parse_certificate_payload(data: &[u8]) -> Result<Certificate, CodeSignError> {
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

/// Load cross certificate from path.
pub fn load_cross_cert(path: &str) -> Result<Vec<u8>, CodeSignError> {
    fs::read(path).map_err(|e| e.into())
}

/// Find matching cross certificate for a given certificate.
pub fn find_matching_cross_cert(
    cert: &Certificate,
    extra_certs: &[Certificate],
    cross_cert_dir: &Path,
) -> Result<Option<PathBuf>, CodeSignError> {
    if !cross_cert_dir.exists() {
        return Ok(None);
    }

    let chain_issuers = collect_chain_issuers(cert, extra_certs);
    let mut fallback = None;

    for entry in fs::read_dir(cross_cert_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !is_certificate_file(&path) {
            continue;
        }

        let cert_data = fs::read(&path)?;
        let candidate = match parse_certificate_payload(&cert_data) {
            Ok(cert) => cert,
            Err(_) => continue,
        };

        if matches_cross_cert_candidate(&candidate, &chain_issuers) {
            let candidate_issuer = normalize_name(&candidate.tbs_certificate.issuer.to_string());
            if candidate_issuer.contains("microsoft code verification root")
                || candidate_issuer.contains("microsoft")
            {
                return Ok(Some(path));
            }
            if fallback.is_none() {
                fallback = Some(path);
            }
        }
    }

    Ok(fallback)
}

pub fn find_matching_bundled_cross_cert(
    cert: &Certificate,
    extra_certs: &[Certificate],
) -> Result<Option<Certificate>, CodeSignError> {
    let chain_issuers = collect_chain_issuers(cert, extra_certs);
    let mut fallback = None;

    for bundled in BUNDLED_CROSS_CERTS {
        let candidate = parse_certificate_payload(bundled.pem_data.as_bytes())?;
        if matches_cross_cert_candidate(&candidate, &chain_issuers) {
            let candidate_issuer = normalize_name(&candidate.tbs_certificate.issuer.to_string());
            if candidate_issuer.contains("microsoft code verification root")
                || candidate_issuer.contains("microsoft")
            {
                return Ok(Some(candidate));
            }
            if fallback.is_none() {
                fallback = Some(candidate);
            }
        }
    }

    Ok(fallback)
}

fn collect_chain_issuers(
    cert: &Certificate,
    extra_certs: &[Certificate],
) -> std::collections::HashSet<String> {
    let mut issuers = std::collections::HashSet::new();
    issuers.insert(normalize_name(&cert.tbs_certificate.issuer.to_string()));
    for extra_cert in extra_certs {
        issuers.insert(normalize_name(
            &extra_cert.tbs_certificate.issuer.to_string(),
        ));
    }
    issuers
}

fn matches_cross_cert_candidate(
    candidate: &Certificate,
    chain_issuers: &std::collections::HashSet<String>,
) -> bool {
    let candidate_subject = normalize_name(&candidate.tbs_certificate.subject.to_string());
    chain_issuers.contains(&candidate_subject)
}

fn is_certificate_file(path: &Path) -> bool {
    path.extension()
        .map(|ext| {
            let ext = ext.to_string_lossy().to_lowercase();
            ext == "crt" || ext == "cer" || ext == "pem"
        })
        .unwrap_or(false)
}

fn normalize_name(name: &str) -> String {
    name.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::{
        CROSS_CERT_SOURCES, default_cross_cert_store_path, find_matching_bundled_cross_cert,
        find_matching_cross_cert, parse_certificate_payload, validate_certificate_payload,
        write_bundled_cross_certs,
    };
    use der::Decode;
    use std::path::PathBuf;
    use x509_cert::Certificate;

    #[test]
    fn cross_cert_sources_prefer_https() {
        assert!(CROSS_CERT_SOURCES.iter().all(|source| {
            source
                .candidate_urls
                .first()
                .unwrap()
                .starts_with("https://")
        }));
    }

    #[test]
    fn certificate_payload_validation_accepts_real_pem() {
        let pem_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("test_data")
            .join("test_combined.pem");
        let pem_data = std::fs::read(pem_path).expect("expected test certificate");
        validate_certificate_payload(&pem_data).expect("certificate payload should parse");
    }

    #[test]
    fn certificate_payload_validation_rejects_html() {
        let err = validate_certificate_payload(b"<html><body>404</body></html>");
        assert!(err.is_err());
    }

    #[test]
    fn default_cross_cert_store_path_ends_with_cross_certs() {
        let path = default_cross_cert_store_path();
        let text = path.to_string_lossy().replace('\\', "/");
        assert!(text.ends_with("/rustsign/cross-certs"));
    }

    #[test]
    fn find_matching_cross_cert_accepts_directory_paths() {
        let test_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("test_data");
        let pem_data = std::fs::read(test_dir.join("test_cert.pem")).unwrap();
        let data_str = String::from_utf8(pem_data.clone()).unwrap();
        let begin = "-----BEGIN CERTIFICATE-----";
        let end = "-----END CERTIFICATE-----";
        let start_idx = data_str.find(begin).unwrap();
        let end_idx = data_str.find(end).unwrap() + end.len();
        let block = &data_str[start_idx..end_idx];
        let (_, der) = pem_rfc7468::decode_vec(block.as_bytes()).unwrap();
        let cert = Certificate::from_der(&der).unwrap();

        let temp_dir = std::env::temp_dir().join(format!(
            "codesign-crosscert-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let cert_path = temp_dir.join("test-cross-cert.pem");
        std::fs::write(&cert_path, pem_data).unwrap();

        let matched = find_matching_cross_cert(&cert, &[], &temp_dir).unwrap();
        assert_eq!(matched, Some(cert_path));

        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn bundled_cross_cert_matches_historical_chain() {
        let chain_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("test_data")
            .join("extracted-chain");
        let leaf =
            parse_certificate_payload(&std::fs::read(chain_dir.join("leaf.cer")).unwrap()).unwrap();
        let intermediate =
            parse_certificate_payload(&std::fs::read(chain_dir.join("intermediate.cer")).unwrap())
                .unwrap();

        let matched = find_matching_bundled_cross_cert(&leaf, &[intermediate]).unwrap();
        assert!(matched.is_some());
    }

    #[test]
    fn write_bundled_cross_certs_populates_store() {
        let temp_dir = std::env::temp_dir().join(format!(
            "codesign-bundled-crosscert-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&temp_dir).unwrap();

        let written = write_bundled_cross_certs(&temp_dir).unwrap();
        assert!(written > 0);

        let entries = std::fs::read_dir(&temp_dir).unwrap().count();
        assert!(entries >= written);

        let _ = std::fs::remove_dir_all(temp_dir);
    }
}
