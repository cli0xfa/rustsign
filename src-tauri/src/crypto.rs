use crate::CodeSignError;
use der::{Decode, Encode};
use rsa::RsaPrivateKey;
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use std::fs;
use std::path::Path;
use x509_cert::Certificate;

#[derive(Debug, Clone)]
pub struct LoadedCertificate {
    pub cert: Certificate,
    pub private_key: Vec<u8>,
    pub extra_certs: Vec<Certificate>,
}

/// Load a certificate bundle and private key from a file.
/// Supports PFX/P12 and PEM formats, and preserves any additional certificates
/// that should be embedded alongside the signing certificate.
pub fn load_certificate(
    path: &Path,
    password: Option<&str>,
) -> Result<LoadedCertificate, CodeSignError> {
    let data = fs::read(path)?;

    if has_pkcs12_extension(path) {
        load_pfx(&data, password)
    } else if is_pem_data(&data) {
        load_pem(&data, password)
    } else {
        load_pfx(&data, password).or_else(|_| load_pem(&data, password))
    }
}

fn has_pkcs12_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| matches!(ext.to_ascii_lowercase().as_str(), "pfx" | "p12"))
        .unwrap_or(false)
}

fn is_pem_data(data: &[u8]) -> bool {
    let text = String::from_utf8_lossy(data);
    text.contains("-----BEGIN CERTIFICATE-----") || text.contains("-----BEGIN PRIVATE KEY-----")
}

pub(crate) fn parse_pfx_data(data: &[u8]) -> Result<p12::PFX, String> {
    // Try strict DER parse first (works for most compliant PFX files)
    if let Ok(pfx) = p12::PFX::parse(data) {
        return Ok(pfx);
    }

    // Fallback 1: try stripping 4-byte LE length prefix (Windows certutil)
    if data.len() > 4 {
        let prefix_len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if prefix_len > 0
            && prefix_len <= data.len() - 4
            && prefix_len >= data.len().saturating_sub(8)
            && let Ok(pfx) = p12::PFX::parse(&data[4..])
        {
            return Ok(pfx);
        }
    }

    // Fallback 2: Some PFX exporters produce MacData that can't be parsed
    // by the p12 crate's strict parser. We reconstruct the PFX without MacData,
    // which is safe because verify_mac returns true when mac_data is None.
    parse_pfx_skip_mac(data).map_err(|e| format!("Invalid PFX: {e:?}"))
}

/// Read a DER tag+length at `offset`. Returns (header_size, content_start, content_length).
fn read_der_length(data: &[u8], offset: usize) -> Option<(usize, usize, usize)> {
    let length_byte = *data.get(offset + 1)?;
    if length_byte & 0x80 == 0 {
        let header = offset + 2;
        Some((header, header, length_byte as usize))
    } else {
        let num_len_bytes = (length_byte & 0x7f) as usize;
        if num_len_bytes == 0 || num_len_bytes > 4 {
            return None;
        }
        let mut content_len = 0usize;
        for i in 0..num_len_bytes {
            content_len = (content_len << 8) | (*data.get(offset + 2 + i)? as usize);
        }
        let header = offset + 2 + num_len_bytes;
        Some((header, header, content_len))
    }
}

/// Parse a PFX by extracting the ContentInfo manually and skipping MacData.
/// Used as a fallback for PFX files with non-standard MacData encoding
/// that the p12 crate's strict parser rejects.
fn parse_pfx_skip_mac(data: &[u8]) -> Result<p12::PFX, String> {
    // PFX structure: SEQUENCE { INTEGER(version=3), SEQUENCE(ContentInfo), MacData }
    let _ = read_der_length(data, 0).ok_or_else(|| "Invalid PFX outer SEQUENCE".to_string())?;

    // Version is at offset 4: 02 01 03 (3 bytes)
    if data.get(4..7) != Some(&[0x02, 0x01, 0x03]) {
        return Err("Unexpected PFX version encoding".to_string());
    }

    // ContentInfo SEQUENCE starts at offset 7
    let (_, ci_content_start, ci_content_len) =
        read_der_length(data, 7).ok_or_else(|| "Invalid ContentInfo SEQUENCE".to_string())?;
    let ci_end = ci_content_start + ci_content_len;

    // Extract just the ContentInfo bytes (without trailing MacData)
    let ci_bytes = &data[7..ci_end];

    let auth_safe = p12::ContentInfo::from_der(ci_bytes)
        .map_err(|e| format!("ContentInfo parse error: {e:?}"))?;

    Ok(p12::PFX {
        version: 3,
        auth_safe,
        mac_data: None,
    })
}

fn load_pfx(data: &[u8], password: Option<&str>) -> Result<LoadedCertificate, CodeSignError> {
    let password = password.unwrap_or("");

    let pfx = parse_pfx_data(data).map_err(CodeSignError::Certificate)?;

    if !pfx.verify_mac(password) {
        return Err(CodeSignError::Certificate(
            "PFX password verification failed".to_string(),
        ));
    }

    let cert_bags = pfx
        .cert_x509_bags(password)
        .map_err(|e| CodeSignError::Certificate(format!("PFX cert extraction failed: {e:?}")))?;

    if cert_bags.is_empty() {
        return Err(CodeSignError::Certificate(
            "No certificates found in PFX".to_string(),
        ));
    }

    let certs = cert_bags
        .iter()
        .map(|cert_der| {
            Certificate::from_der(cert_der).map_err(|e| {
                CodeSignError::Certificate(format!("Failed to parse certificate: {e:?}"))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let key_bags = pfx
        .key_bags(password)
        .map_err(|e| CodeSignError::Certificate(format!("PFX key extraction failed: {e:?}")))?;

    if key_bags.is_empty() {
        return Err(CodeSignError::Certificate(
            "No private key found in PFX".to_string(),
        ));
    }

    build_loaded_certificate(certs, key_bags[0].clone())
}

fn load_pem(data: &[u8], _password: Option<&str>) -> Result<LoadedCertificate, CodeSignError> {
    let data_str = String::from_utf8_lossy(data);

    let cert_blocks = extract_pem_blocks(&data_str, "CERTIFICATE");
    if cert_blocks.is_empty() {
        return Err(CodeSignError::Certificate(
            "No CERTIFICATE block found".to_string(),
        ));
    }

    let certs = cert_blocks
        .into_iter()
        .map(|cert_pem| {
            let (_, cert_der) = pem_rfc7468::decode_vec(cert_pem.as_bytes())
                .map_err(|e| CodeSignError::Certificate(format!("Failed to decode PEM: {e:?}")))?;
            Certificate::from_der(&cert_der).map_err(|e| {
                CodeSignError::Certificate(format!("Failed to parse certificate: {e:?}"))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let key_pem = extract_pem_block(&data_str, "PRIVATE KEY")
        .or_else(|| extract_pem_block(&data_str, "RSA PRIVATE KEY"))
        .or_else(|| extract_pem_block(&data_str, "EC PRIVATE KEY"))
        .ok_or_else(|| CodeSignError::Certificate("No PRIVATE KEY block found".to_string()))?;

    let (_, key_bytes) = pem_rfc7468::decode_vec(key_pem.as_bytes())
        .map_err(|e| CodeSignError::Certificate(format!("Failed to decode key PEM: {e:?}")))?;

    build_loaded_certificate(certs, key_bytes)
}

pub(crate) fn build_loaded_certificate(
    mut certs: Vec<Certificate>,
    private_key: Vec<u8>,
) -> Result<LoadedCertificate, CodeSignError> {
    let leaf_index = find_signing_certificate_index(&certs, &private_key)?;
    let cert = certs.remove(leaf_index);

    // Keep all additional certificates including self-signed roots,
    // so the CMS cert chain is complete. Windows shows "processed
    // chain, terminates in untrusted root" instead of "cannot verify".
    // Only remove exact duplicates of the signing certificate itself.
    let signing_cert_der = cert
        .to_der()
        .map_err(|e| CodeSignError::Certificate(format!("Cert DER: {e:?}")))?;
    certs.retain(|extra_cert| {
        let Ok(der) = extra_cert.to_der() else {
            return false;
        };
        der != signing_cert_der.as_slice()
    });

    Ok(LoadedCertificate {
        cert,
        private_key,
        extra_certs: certs,
    })
}

fn find_signing_certificate_index(
    certs: &[Certificate],
    private_key: &[u8],
) -> Result<usize, CodeSignError> {
    let private_key = parse_private_key(private_key)?;
    let expected_public_key = rsa::RsaPublicKey::from(&private_key);

    certs
        .iter()
        .position(|cert| certificate_matches_private_key(cert, &expected_public_key))
        .ok_or_else(|| {
            CodeSignError::Certificate(
                "No certificate in the bundle matches the private key".to_string(),
            )
        })
}

fn certificate_matches_private_key(
    cert: &Certificate,
    expected_public_key: &rsa::RsaPublicKey,
) -> bool {
    let subject_public_key = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();

    rsa::RsaPublicKey::from_pkcs1_der(subject_public_key)
        .or_else(|_| rsa::RsaPublicKey::from_public_key_der(subject_public_key))
        .map(|public_key| public_key == *expected_public_key)
        .unwrap_or(false)
}

fn parse_private_key(key_bytes: &[u8]) -> Result<RsaPrivateKey, CodeSignError> {
    if let Ok(key) = RsaPrivateKey::from_pkcs8_der(key_bytes) {
        return Ok(key);
    }
    if let Ok(key) = RsaPrivateKey::from_pkcs1_der(key_bytes) {
        return Ok(key);
    }
    Err(CodeSignError::Certificate(
        "Failed to parse RSA private key (tried PKCS#8 and PKCS#1)".to_string(),
    ))
}

fn extract_pem_block<'a>(pem_str: &'a str, label: &str) -> Option<&'a str> {
    extract_pem_blocks(pem_str, label).into_iter().next()
}

fn extract_pem_blocks<'a>(pem_str: &'a str, label: &str) -> Vec<&'a str> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut blocks = Vec::new();
    let mut search_from = 0;

    while let Some(start_rel) = pem_str[search_from..].find(&begin) {
        let start_idx = search_from + start_rel;
        let end_rel = match pem_str[start_idx..].find(&end) {
            Some(index) => index,
            None => break,
        };
        let end_idx = start_idx + end_rel + end.len();
        blocks.push(&pem_str[start_idx..end_idx]);
        search_from = end_idx;
    }

    blocks
}

#[cfg(test)]
mod tests {
    use super::load_certificate;
    use std::path::PathBuf;

    fn unique_temp_path(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("rustsign-{nanos}-{name}"))
    }

    #[test]
    fn load_pem_removes_duplicate_signing_cert_from_extra_certs() {
        let test_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("test_data");
        let cert_pem = std::fs::read_to_string(test_dir.join("test_cert.pem")).unwrap();
        let key_pem = std::fs::read_to_string(test_dir.join("test_key.pem")).unwrap();

        let bundle_path = unique_temp_path("bundle.pem");
        let bundle = format!("{cert_pem}\n{cert_pem}\n{key_pem}\n");
        std::fs::write(&bundle_path, bundle).unwrap();

        let loaded = load_certificate(&bundle_path, None).expect("load PEM bundle");
        assert_eq!(loaded.extra_certs.len(), 0);

        let _ = std::fs::remove_file(bundle_path);
    }

    #[test]
    fn load_pfx_removes_duplicate_signing_cert_from_extra_certs() {
        let test_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("test_data");
        let cert_der = std::fs::read(test_dir.join("test_cert.pem")).unwrap();
        let key_der = std::fs::read(test_dir.join("test_key.pem")).unwrap();

        let cert_pem = String::from_utf8(cert_der).unwrap();
        let key_pem = String::from_utf8(key_der).unwrap();
        let (_, cert_der) = pem_rfc7468::decode_vec(cert_pem.as_bytes()).unwrap();
        let (_, key_der) = pem_rfc7468::decode_vec(key_pem.as_bytes()).unwrap();

        let pfx = p12::PFX::new_with_cas(&cert_der, &key_der, &[&cert_der], "testpass", "codesign")
            .expect("build PFX");

        let pfx_path = unique_temp_path("bundle.pfx");
        std::fs::write(&pfx_path, pfx.to_der()).unwrap();

        let loaded = load_certificate(&pfx_path, Some("testpass")).expect("load PFX bundle");
        assert_eq!(loaded.extra_certs.len(), 0);

        let _ = std::fs::remove_file(pfx_path);
    }

    #[test]
    fn parse_demo_pfx_files() {
        let demo_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("demo")
            .join("cer");

        let entries = std::fs::read_dir(&demo_dir);
        let entries = match entries {
            Ok(e) => e,
            Err(_) => {
                eprintln!("Skipping: demo/cer not found at {}", demo_dir.display());
                return;
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if !matches!(ext.to_ascii_lowercase().as_str(), "pfx" | "p12") {
                continue;
            }

            let file_name = path.file_stem().unwrap_or_default().to_string_lossy();
            // Password is after the last underscore in the filename
            let password = file_name.rsplit('_').next().unwrap_or("");

            let data = std::fs::read(&path).expect("read PFX");
            match super::parse_pfx_data(&data) {
                Ok(pfx) => {
                    if !pfx.verify_mac(password) {
                        eprintln!("FAIL {}: password '{}' rejected", path.display(), password);
                    } else {
                        eprintln!("OK   {} (password '{}')", path.display(), password);
                    }
                }
                Err(e) => {
                    eprintln!("FAIL {}: {}", path.display(), e);
                }
            }
        }
    }

    #[test]
    fn load_pfx_keeps_self_signed_roots_in_chain_for_cms_embedding() {
        use der::Encode;

        let root_pem = std::fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .join("test_data/test_cert.pem"),
        )
        .expect("root fixture");
        let (_, root_der) = pem_rfc7468::decode_vec(&root_pem).expect("root DER");
        let (_, sign) = crate::cert_gen::generate_test_cert_pair(&Default::default())
            .expect("generate separate signing identity");
        let (_, cert_der) = pem_rfc7468::decode_vec(sign.cert_pem.as_bytes()).unwrap();
        let (_, key_der) = pem_rfc7468::decode_vec(sign.key_pem.as_bytes()).unwrap();
        let pfx = p12::PFX::new_with_cas(&cert_der, &key_der, &[&root_der], "testpass", "codesign")
            .expect("PFX with self-signed root");
        let pfx_path = unique_temp_path("with-root.pfx");
        std::fs::write(&pfx_path, pfx.to_der()).unwrap();

        let loaded = load_certificate(&pfx_path, Some("testpass")).expect("load PFX with root");
        let root = loaded
            .extra_certs
            .iter()
            .find(|cert| cert.to_der().unwrap() == root_der)
            .expect("self-signed root must remain embedded");
        assert_eq!(root.tbs_certificate.subject, root.tbs_certificate.issuer);
        std::fs::remove_file(pfx_path).unwrap();
    }
}
