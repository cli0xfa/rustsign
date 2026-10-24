use crate::{CodeSignError, crypto};
use der::{Decode, Encode};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;
use x509_cert::Certificate;
use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertEntry {
    pub id: String,
    pub file_path: String,
    pub password: Option<String>,
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub not_before: String,
    pub not_after: String,
    pub signature_algorithm: String,
    pub thumbprint: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CertDatabase {
    pub certs: Vec<CertEntry>,
}

/// Runtime information is deliberately separate from the on-disk database.
#[derive(Debug, Serialize)]
pub struct CertificateView {
    #[serde(flatten)]
    pub entry: CertEntry,
    pub not_before_secs: Option<u64>,
    pub not_after_secs: Option<u64>,
    pub has_private_key: Option<bool>,
    pub purposes: Option<Vec<String>>,
    pub is_ca: Option<bool>,
    pub can_issue: Option<bool>,
    pub file_readable: bool,
    pub read_error: Option<String>,
}

pub fn certificate_view(mut entry: CertEntry) -> CertificateView {
    let metadata = (|| -> Result<_, CodeSignError> {
        let bundle = load_cert_bundle(&entry.file_path, entry.password.as_deref())?;
        let cert = Certificate::from_der(&bundle.cert_der)
            .map_err(|error| CodeSignError::Certificate(error.to_string()))?;
        let mut purposes = Vec::new();
        let mut is_ca = false;
        let mut can_issue = false;
        for extension in cert
            .tbs_certificate
            .extensions
            .as_deref()
            .unwrap_or_default()
        {
            let value = extension.extn_value.as_bytes();
            match extension.extn_id.to_string().as_str() {
                "2.5.29.37" => {
                    purposes = ExtendedKeyUsage::from_der(value)
                        .map_err(|error| CodeSignError::Certificate(error.to_string()))?
                        .0
                        .iter()
                        .map(ToString::to_string)
                        .collect();
                }
                "2.5.29.19" => {
                    is_ca = BasicConstraints::from_der(value)
                        .map_err(|error| CodeSignError::Certificate(error.to_string()))?
                        .ca;
                }
                "2.5.29.15" => {
                    can_issue = KeyUsage::from_der(value)
                        .map_err(|error| CodeSignError::Certificate(error.to_string()))?
                        .key_cert_sign();
                }
                _ => {}
            }
        }
        Ok((
            cert.tbs_certificate
                .validity
                .not_before
                .to_unix_duration()
                .as_secs(),
            cert.tbs_certificate
                .validity
                .not_after
                .to_unix_duration()
                .as_secs(),
            bundle.key_der.is_some(),
            purposes,
            is_ca,
            is_ca && can_issue,
        ))
    })();
    // Passwords are resolved by ID in the Rust signing engine, not in the UI.
    entry.password = None;
    let mut view = CertificateView {
        entry,
        not_before_secs: None,
        not_after_secs: None,
        has_private_key: None,
        purposes: None,
        is_ca: None,
        can_issue: None,
        file_readable: metadata.is_ok(),
        read_error: None,
    };
    match metadata {
        Ok((before, after, key, purposes, ca, issue)) => {
            view.not_before_secs = Some(before);
            view.not_after_secs = Some(after);
            view.has_private_key = Some(key);
            view.purposes = Some(purposes);
            view.is_ca = Some(ca);
            view.can_issue = Some(issue);
        }
        Err(error) => {
            view.read_error = Some(error.to_string());
        }
    }
    view
}

pub fn list_certificate_views() -> Result<Vec<CertificateView>, CodeSignError> {
    Ok(list_certificates()?
        .into_iter()
        .map(certificate_view)
        .collect())
}

#[derive(Debug, Clone)]
struct CertBundle {
    cert_der: Vec<u8>,
    key_der: Option<Vec<u8>>,
    extra_cert_ders: Vec<Vec<u8>>,
}

impl CertDatabase {
    fn db_path() -> PathBuf {
        crate::data_dir().join("certs.json")
    }

    pub fn load() -> Result<Self, CodeSignError> {
        let path = Self::db_path();
        if path.exists() {
            let data = fs::read_to_string(&path)?;
            let db: CertDatabase = serde_json::from_str(&data)
                .map_err(|e| CodeSignError::Certificate(format!("Parse DB error: {e:?}")))?;
            Ok(db)
        } else {
            Ok(CertDatabase::default())
        }
    }

    pub fn save(&self) -> Result<(), CodeSignError> {
        let path = Self::db_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let data = serde_json::to_string_pretty(self)
            .map_err(|e| CodeSignError::Certificate(format!("Serialize DB error: {e:?}")))?;
        fs::write(&path, data)?;
        Ok(())
    }
}

pub fn parse_cert_info(
    file_path: &str,
    password: Option<&str>,
) -> Result<CertEntry, CodeSignError> {
    let bundle = load_cert_bundle(file_path, password)?;
    let cert = Certificate::from_der(&bundle.cert_der)
        .map_err(|e| CodeSignError::Certificate(format!("Failed to parse certificate: {e:?}")))?;

    let subject = format_name(&cert.tbs_certificate.subject);
    let issuer = format_name(&cert.tbs_certificate.issuer);
    let serial = cert.tbs_certificate.serial_number.to_string();
    let not_before = format_time(&cert.tbs_certificate.validity.not_before);
    let not_after = format_time(&cert.tbs_certificate.validity.not_after);
    let sig_algo = cert.signature_algorithm.oid.to_string();

    let cert_der = cert
        .to_der()
        .map_err(|e| CodeSignError::Certificate(format!("DER encode error: {e:?}")))?;
    let hash = sha2::Sha256::digest(&cert_der);
    let thumbprint = format!("{:x}", hash);

    Ok(CertEntry {
        id: Uuid::new_v4().to_string(),
        file_path: file_path.to_string(),
        password: password.map(|value| value.to_string()),
        subject,
        issuer,
        serial_number: serial,
        not_before,
        not_after,
        signature_algorithm: sig_algo,
        thumbprint,
    })
}

fn load_cert_bundle(file_path: &str, password: Option<&str>) -> Result<CertBundle, CodeSignError> {
    let path = Path::new(file_path);
    let data = fs::read(path)?;

    if has_pkcs12_extension(path) {
        load_pfx_bundle(&data, password)
    } else if looks_like_pem(&data) {
        let data_str = String::from_utf8_lossy(&data);
        load_pem_bundle(&data_str)
    } else {
        load_der_bundle(&data)
    }
}

fn has_pkcs12_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| matches!(ext.to_ascii_lowercase().as_str(), "pfx" | "p12"))
        .unwrap_or(false)
}

fn looks_like_pem(data: &[u8]) -> bool {
    let text = String::from_utf8_lossy(data);
    text.contains("-----BEGIN CERTIFICATE-----")
        || text.contains("-----BEGIN PRIVATE KEY-----")
        || text.contains("-----BEGIN RSA PRIVATE KEY-----")
        || text.contains("-----BEGIN EC PRIVATE KEY-----")
}

fn load_pfx_bundle(data: &[u8], password: Option<&str>) -> Result<CertBundle, CodeSignError> {
    let password = password.unwrap_or("");

    let pfx = crypto::parse_pfx_data(data).map_err(CodeSignError::Certificate)?;

    if !pfx.verify_mac(password) {
        return Err(CodeSignError::Certificate(
            "PFX password verification failed".to_string(),
        ));
    }

    let certs = pfx
        .cert_x509_bags(password)
        .map_err(|e| CodeSignError::Certificate(format!("PFX cert extraction failed: {e:?}")))?
        .iter()
        .map(|cert_der| {
            Certificate::from_der(cert_der).map_err(|e| {
                CodeSignError::Certificate(format!("Failed to parse certificate: {e:?}"))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let key_der = pfx
        .key_bags(password)
        .map_err(|e| CodeSignError::Certificate(format!("PFX key extraction failed: {e:?}")))?
        .into_iter()
        .next();

    build_bundle_from_components(certs, key_der)
}

fn load_pem_bundle(pem_str: &str) -> Result<CertBundle, CodeSignError> {
    let certs = extract_pem_blocks(pem_str, "CERTIFICATE")
        .into_iter()
        .map(|cert_pem| {
            let (_, cert_der) = pem_rfc7468::decode_vec(cert_pem.as_bytes())
                .map_err(|e| CodeSignError::Certificate(format!("PEM decode error: {e:?}")))?;
            Certificate::from_der(&cert_der).map_err(|e| {
                CodeSignError::Certificate(format!("Failed to parse certificate: {e:?}"))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let key_der = extract_pem_private_key(pem_str)?;
    build_bundle_from_components(certs, key_der)
}

fn load_der_bundle(data: &[u8]) -> Result<CertBundle, CodeSignError> {
    let cert = Certificate::from_der(data)
        .map_err(|e| CodeSignError::Certificate(format!("DER parse error: {e:?}")))?;

    Ok(CertBundle {
        cert_der: cert
            .to_der()
            .map_err(|e| CodeSignError::Certificate(format!("DER encode error: {e:?}")))?,
        key_der: None,
        extra_cert_ders: Vec::new(),
    })
}

fn build_bundle_from_components(
    certs: Vec<Certificate>,
    key_der: Option<Vec<u8>>,
) -> Result<CertBundle, CodeSignError> {
    if certs.is_empty() {
        return Err(CodeSignError::Certificate(
            "No certificates found in bundle".to_string(),
        ));
    }

    if let Some(key_der) = key_der {
        let loaded = crypto::build_loaded_certificate(certs, key_der)?;
        let cert_der = loaded
            .cert
            .to_der()
            .map_err(|e| CodeSignError::Certificate(format!("DER encode error: {e:?}")))?;
        let extra_cert_ders = loaded
            .extra_certs
            .into_iter()
            .map(|cert| {
                cert.to_der()
                    .map_err(|e| CodeSignError::Certificate(format!("DER encode error: {e:?}")))
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(CertBundle {
            cert_der,
            key_der: Some(loaded.private_key),
            extra_cert_ders,
        })
    } else {
        let mut iter = certs.into_iter();
        let cert = iter.next().expect("certs already checked as non-empty");
        let extra_cert_ders = iter
            .map(|extra_cert| {
                extra_cert
                    .to_der()
                    .map_err(|e| CodeSignError::Certificate(format!("DER encode error: {e:?}")))
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(CertBundle {
            cert_der: cert
                .to_der()
                .map_err(|e| CodeSignError::Certificate(format!("DER encode error: {e:?}")))?,
            key_der: None,
            extra_cert_ders,
        })
    }
}

fn extract_pem_private_key(pem_str: &str) -> Result<Option<Vec<u8>>, CodeSignError> {
    for label in ["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"] {
        if let Some(block) = extract_pem_block(pem_str, label) {
            let (_, der) = pem_rfc7468::decode_vec(block.as_bytes())
                .map_err(|e| CodeSignError::Certificate(format!("Key PEM decode error: {e:?}")))?;
            return Ok(Some(der));
        }
    }
    Ok(None)
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

fn format_name(name: &x509_cert::name::Name) -> String {
    name.to_string()
}

fn format_time(time: &x509_cert::time::Time) -> String {
    match time {
        x509_cert::time::Time::UtcTime(value) => format!("{}", value.to_date_time()),
        x509_cert::time::Time::GeneralTime(value) => format!("{}", value.to_date_time()),
    }
}

pub fn import_certificate(
    file_path: &str,
    password: Option<&str>,
) -> Result<CertEntry, CodeSignError> {
    let entry = parse_cert_info(file_path, password)?;
    let mut db = CertDatabase::load()?;
    db.certs.push(entry.clone());
    db.save()?;
    Ok(entry)
}

pub fn list_certificates() -> Result<Vec<CertEntry>, CodeSignError> {
    let db = CertDatabase::load()?;
    Ok(db.certs)
}

pub fn delete_certificate(id: &str) -> Result<(), CodeSignError> {
    let mut db = CertDatabase::load()?;
    db.certs.retain(|entry| entry.id != id);
    db.save()?;
    Ok(())
}

pub fn get_certificate(id: &str) -> Result<Option<CertEntry>, CodeSignError> {
    let db = CertDatabase::load()?;
    Ok(db.certs.into_iter().find(|entry| entry.id == id))
}

/// Build a Microsoft PVK file from private key DER.
/// PVK format:
///   DWORD magic = 0xB0B5F11E
///   DWORD reserved = 0
///   DWORD keytype = 2 (signature)
///   DWORD encrypted = 0 (plaintext)
///   DWORD saltlen = 0
///   DWORD keylen
///   [key data]
fn build_pvk_file(key_der: &[u8]) -> Vec<u8> {
    let mut pvk = Vec::new();
    pvk.extend_from_slice(&0xB0B5F11Eu32.to_le_bytes());
    pvk.extend_from_slice(&0u32.to_le_bytes());
    pvk.extend_from_slice(&2u32.to_le_bytes());
    pvk.extend_from_slice(&0u32.to_le_bytes());
    pvk.extend_from_slice(&0u32.to_le_bytes());
    pvk.extend_from_slice(&(key_der.len() as u32).to_le_bytes());
    pvk.extend_from_slice(key_der);
    pvk
}

pub fn export_certificate(
    id: &str,
    format: &str,
    output_path: &str,
    password: Option<&str>,
) -> Result<(), CodeSignError> {
    let entry = get_certificate(id)?;
    let entry = match entry {
        Some(entry) => entry,
        None => {
            return Err(CodeSignError::Certificate(
                "Certificate not found".to_string(),
            ));
        }
    };

    let bundle = load_cert_bundle(&entry.file_path, entry.password.as_deref())?;

    match format {
        "pem" => export_as_pem(&bundle, output_path),
        "pfx" => export_as_pfx(&bundle, output_path, password.unwrap_or("")),
        "pvk_spc" => export_as_pvk_spc(&bundle, output_path),
        _ => Err(CodeSignError::Certificate(format!(
            "Unsupported export format: {format}"
        ))),
    }
}

pub fn export_certificates(
    ids: &[String],
    format: &str,
    output_dir: &str,
    password: Option<&str>,
) -> Result<Vec<String>, CodeSignError> {
    let output_dir = Path::new(output_dir);
    fs::create_dir_all(output_dir)?;

    let mut outputs = Vec::new();
    for (index, id) in ids.iter().enumerate() {
        let entry = get_certificate(id)?;
        let entry = match entry {
            Some(entry) => entry,
            None => {
                return Err(CodeSignError::Certificate(format!(
                    "Certificate not found: {id}"
                )));
            }
        };

        let base_name = build_export_basename(&entry, index);
        let output_path = match format {
            "pem" => output_dir.join(format!("{base_name}.pem")),
            "pfx" => output_dir.join(format!("{base_name}.pfx")),
            "pvk_spc" => output_dir.join(base_name),
            _ => {
                return Err(CodeSignError::Certificate(format!(
                    "Unsupported export format: {format}"
                )));
            }
        };

        export_certificate(id, format, &output_path.to_string_lossy(), password)?;
        outputs.push(output_path.to_string_lossy().to_string());
    }

    Ok(outputs)
}

fn build_export_basename(entry: &CertEntry, index: usize) -> String {
    let preferred = if entry.subject.trim().is_empty() {
        entry.thumbprint.clone()
    } else {
        sanitize_file_name(&entry.subject)
    };

    if preferred.is_empty() {
        format!("certificate-{}", index + 1)
    } else {
        format!(
            "{preferred}-{}-{}",
            &entry.thumbprint[..8.min(entry.thumbprint.len())],
            index + 1
        )
    }
}

fn sanitize_file_name(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if matches!(ch, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*') {
                '_'
            } else {
                ch
            }
        })
        .collect::<String>()
        .trim()
        .trim_matches('.')
        .replace(' ', "_")
}

fn export_as_pem(bundle: &CertBundle, output_path: &str) -> Result<(), CodeSignError> {
    let mut output = String::new();

    let cert_pem = pem_rfc7468::encode_string(
        "CERTIFICATE",
        pem_rfc7468::LineEnding::default(),
        &bundle.cert_der,
    )
    .map_err(|e| CodeSignError::Certificate(format!("PEM encode error: {e:?}")))?;
    output.push_str(&cert_pem);
    output.push('\n');

    for extra_cert_der in &bundle.extra_cert_ders {
        let cert_pem = pem_rfc7468::encode_string(
            "CERTIFICATE",
            pem_rfc7468::LineEnding::default(),
            extra_cert_der,
        )
        .map_err(|e| CodeSignError::Certificate(format!("PEM encode error: {e:?}")))?;
        output.push_str(&cert_pem);
        output.push('\n');
    }

    if let Some(key_der) = &bundle.key_der {
        let label = if is_rsa_pkcs1_key(key_der) {
            "RSA PRIVATE KEY"
        } else {
            "PRIVATE KEY"
        };

        let key_pem =
            pem_rfc7468::encode_string(label, pem_rfc7468::LineEnding::default(), key_der)
                .map_err(|e| CodeSignError::Certificate(format!("Key PEM encode error: {e:?}")))?;
        output.push_str(&key_pem);
        output.push('\n');
    }

    fs::write(output_path, output)?;
    Ok(())
}

fn is_rsa_pkcs1_key(der: &[u8]) -> bool {
    if der.len() < 16 || der[0] != 0x30 {
        return false;
    }

    let mut idx = 2;
    if der[1] & 0x80 != 0 {
        let len_bytes = (der[1] & 0x7f) as usize;
        idx = 2 + len_bytes;
    }
    if idx >= der.len() || der[idx] != 0x02 {
        return false;
    }

    idx += 1;
    let value_len = if der[idx] & 0x80 != 0 {
        let len_bytes = (der[idx] & 0x7f) as usize;
        idx += 1 + len_bytes;
        0usize
    } else {
        let len = der[idx] as usize;
        idx += 1 + len;
        len
    };
    if value_len == 0 && idx >= der.len() {
        return false;
    }

    der.get(idx) == Some(&0x02)
}

fn export_as_pfx(
    bundle: &CertBundle,
    output_path: &str,
    password: &str,
) -> Result<(), CodeSignError> {
    let key_der = bundle.key_der.as_ref().ok_or_else(|| {
        CodeSignError::Certificate(
            "Cannot export to PFX: no private key found in source file".to_string(),
        )
    })?;

    let extra_refs = bundle
        .extra_cert_ders
        .iter()
        .map(|cert_der| cert_der.as_slice())
        .collect::<Vec<_>>();

    let pfx = if extra_refs.is_empty() {
        p12::PFX::new(&bundle.cert_der, key_der, None, password, "rustsign")
    } else {
        p12::PFX::new_with_cas(&bundle.cert_der, key_der, &extra_refs, password, "rustsign")
    }
    .ok_or_else(|| {
        CodeSignError::Certificate(
            "Failed to create PFX: key format may be incompatible".to_string(),
        )
    })?;

    fs::write(output_path, pfx.to_der())?;
    Ok(())
}

fn export_as_pvk_spc(bundle: &CertBundle, output_path: &str) -> Result<(), CodeSignError> {
    let key_der = bundle.key_der.as_ref().ok_or_else(|| {
        CodeSignError::Certificate(
            "Cannot export to PVK+SPC: no private key found in source file".to_string(),
        )
    })?;

    let pvk_path = format!("{output_path}.pvk");
    fs::write(&pvk_path, build_pvk_file(key_der))?;

    let spc_path = format!("{output_path}.spc");
    let cert = Certificate::from_der(&bundle.cert_der)
        .map_err(|e| CodeSignError::Certificate(format!("Cert parse error: {e:?}")))?;
    let content_info = cms::content_info::ContentInfo::try_from(cert)
        .map_err(|e| CodeSignError::Certificate(format!("SPC build error: {e:?}")))?;
    fs::write(
        &spc_path,
        content_info
            .to_der()
            .map_err(|e| CodeSignError::Certificate(format!("SPC DER error: {e:?}")))?,
    )?;

    Ok(())
}
