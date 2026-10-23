use crate::CodeSignError;
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerIdentifier, SignerInfo, SignerInfos};
use const_oid::ObjectIdentifier;
use der::asn1::SetOfVec;
use der::{Decode, Encode, Tag};
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::signature::Verifier;
use std::path::Path;
use x509_cert::Certificate;
use x509_cert::attr::{Attribute, AttributeValue, Attributes};

const RFC3161_TIMESTAMP_TOKEN_OID: &str = "1.2.840.113549.1.9.16.2.14";
const LEGACY_TIMESTAMP_TOKEN_OID: &str = "1.3.6.1.4.1.311.3.3.1";
const SPC_NESTED_SIGNATURE_OID: &str = "1.3.6.1.4.1.311.2.4.1";

const SPC_NESTED_SIG_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.4.1");

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VerifyResult {
    pub valid: bool,
    pub message: String,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub digest_algorithm: Option<String>,
    pub has_timestamp: bool,
}

/// Summary info for one signature in a PE file's certificate table.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignatureInfo {
    pub index: u32,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub digest_algorithm: Option<String>,
    pub has_timestamp: bool,
}

/// Map an X.509 signature algorithm OID to a human-readable name.
pub fn oid_to_display_name(oid: &str) -> String {
    match oid {
        "1.2.840.113549.1.1.11" => "SHA-256 with RSA".to_string(),
        "1.2.840.113549.1.1.5" => "SHA-1 with RSA".to_string(),
        "1.2.840.113549.1.1.12" => "SHA-384 with RSA".to_string(),
        "1.2.840.113549.1.1.13" => "SHA-512 with RSA".to_string(),
        "1.2.840.10045.4.3.2" => "SHA-256 with ECDSA".to_string(),
        "1.2.840.10045.4.3.3" => "SHA-384 with ECDSA".to_string(),
        "1.2.840.10045.4.3.4" => "SHA-512 with ECDSA".to_string(),
        "1.2.840.113549.1.1.10" => "RSASSA-PSS".to_string(),
        "1.2.840.113549.1.1.1" => "RSA".to_string(),
        _ => oid.to_string(),
    }
}

/// List all signatures in a PE file without full cryptographic verification.
/// Handles both separate WIN_CERTIFICATE entries and nested signatures
/// (szOID_NESTED_SIGNATURE in unsigned attributes).
pub fn list_signatures(data: &[u8]) -> Result<Vec<SignatureInfo>, CodeSignError> {
    let entries = crate::pe::read_all_signatures(data)?;
    if entries.is_empty() {
        return Ok(Vec::new());
    }

    let mut infos = Vec::new();
    let mut index: u32 = 0;

    // Process the first WIN_CERTIFICATE entry — it may contain nested signatures.
    let sig_bytes = trim_der_object(&entries[0].data).unwrap_or(&entries[0].data);
    if let Ok(ci) = parse_content_info(sig_bytes) {
        collect_signatures_from_cms(&ci, &mut infos, &mut index);
    }

    // Process any remaining separate entries (legacy multi-entry format).
    for entry in &entries[1..] {
        let sig_bytes = trim_der_object(&entry.data).unwrap_or(&entry.data);
        if let Ok(ci) = parse_content_info(sig_bytes) {
            collect_signatures_from_cms(&ci, &mut infos, &mut index);
        }
    }

    Ok(infos)
}

/// Recursively collect signatures from a CMS ContentInfo, following nested
/// signatures in unsigned attributes.
fn collect_signatures_from_cms(
    content_info: &ContentInfo,
    infos: &mut Vec<SignatureInfo>,
    index: &mut u32,
) {
    let signed_data_oid = const_oid::db::rfc5911::ID_SIGNED_DATA;
    if content_info.content_type != signed_data_oid {
        return;
    }

    let sd = match parse_signed_data(content_info) {
        Ok(sd) => sd,
        Err(_) => return,
    };

    let signer_info = match sd.signer_infos.0.iter().next() {
        Some(si) => si,
        None => return,
    };

    let cert = find_signer_cert(signer_info, &sd).ok();
    let has_ts = signer_info
        .unsigned_attrs
        .as_ref()
        .map(has_timestamp_attribute)
        .unwrap_or(false);

    let digest_name = digest_oid_to_name(&signer_info.digest_alg.oid);

    infos.push(SignatureInfo {
        index: *index,
        subject: cert.as_ref().map(|c| c.tbs_certificate.subject.to_string()),
        issuer: cert.as_ref().map(|c| c.tbs_certificate.issuer.to_string()),
        digest_algorithm: digest_name.map(|s| s.to_string()),
        has_timestamp: has_ts,
    });
    *index += 1;

    // Recursively process nested signatures from unsigned attributes.
    if let Some(attrs) = &signer_info.unsigned_attrs {
        for attr in attrs.iter() {
            if attr.oid.to_string() == SPC_NESTED_SIGNATURE_OID {
                for value in attr.values.iter() {
                    // The nested CMS is stored as the raw DER of a ContentInfo
                    // inside the attribute value.
                    if let Ok(value_bytes) = value.to_der() {
                        if value_bytes.is_empty() {
                            continue;
                        }
                        let sig_bytes = trim_der_object(&value_bytes).unwrap_or(&value_bytes);
                        if let Ok(nested_ci) = parse_content_info(sig_bytes) {
                            collect_signatures_from_cms(&nested_ci, infos, index);
                        } else if let Ok(nested_ci) = parse_content_info(&value_bytes) {
                            // Also try the raw bytes without trimming.
                            collect_signatures_from_cms(&nested_ci, infos, index);
                        }
                    }
                }
            }
        }
    }
}

/// Verify the Authenticode signature on a PE file.
pub fn verify_signature(file_path: &str) -> Result<VerifyResult, CodeSignError> {
    let data = std::fs::read(Path::new(file_path))?;

    // Parse PE and extract certificate table (first signature)
    let entries = crate::pe::read_all_signatures(&data)?;
    let first_entry = match entries.first() {
        Some(entry) => entry,
        None => {
            return Ok(VerifyResult {
                valid: false,
                message: "No signature found in PE file".to_string(),
                subject: None,
                issuer: None,
                digest_algorithm: None,
                has_timestamp: false,
            });
        }
    };
    let signature = &first_entry.data;

    // Parse CMS ContentInfo
    let signature = trim_der_object(signature).unwrap_or(signature);

    let content_info = match parse_content_info(signature) {
        Ok(ci) => ci,
        Err(e) => {
            return Ok(VerifyResult {
                valid: false,
                message: format!("Failed to parse CMS: {e:?}"),
                subject: None,
                issuer: None,
                digest_algorithm: None,
                has_timestamp: false,
            });
        }
    };

    // Check content type is SignedData
    let signed_data_oid = const_oid::db::rfc5911::ID_SIGNED_DATA;
    if content_info.content_type != signed_data_oid {
        return Ok(VerifyResult {
            valid: false,
            message: format!("Unexpected CMS content type: {}", content_info.content_type),
            subject: None,
            issuer: None,
            digest_algorithm: None,
            has_timestamp: false,
        });
    }

    // Parse SignedData
    // ContentInfo.content is [0] EXPLICIT, so content.value() is SignedData without SEQUENCE tag.
    // We need to re-wrap it with SEQUENCE tag for proper DER parsing.
    let signed_data = match parse_signed_data(&content_info) {
        Ok(sd) => sd,
        Err(e) => {
            return Ok(VerifyResult {
                valid: false,
                message: format!("Failed to parse SignedData: {e:?}"),
                subject: None,
                issuer: None,
                digest_algorithm: None,
                has_timestamp: false,
            });
        }
    };

    // Check signer info exists
    if signed_data.signer_infos.0.is_empty() {
        return Ok(VerifyResult {
            valid: false,
            message: "No signer info found".to_string(),
            subject: None,
            issuer: None,
            digest_algorithm: None,
            has_timestamp: false,
        });
    }

    // Get digest algorithm from first signer info
    let signer_info = signed_data.signer_infos.0.iter().next().unwrap();
    let signer_cert = find_signer_cert(signer_info, &signed_data).ok();
    let subject = signer_cert
        .as_ref()
        .map(|cert| cert.tbs_certificate.subject.to_string());
    let issuer = signer_cert
        .as_ref()
        .map(|cert| cert.tbs_certificate.issuer.to_string());
    let digest_algo_name = digest_oid_to_name(&signer_info.digest_alg.oid)
        .unwrap_or("sha256")
        .to_string();

    // Check for timestamp in unsigned attributes
    let has_timestamp = signer_info
        .unsigned_attrs
        .as_ref()
        .map(has_timestamp_attribute)
        .unwrap_or(false);

    // Try to extract and verify digest from SpcIndirectDataContent
    let digest_match = verify_digest(&data, &signed_data)?;

    // Cryptographically verify the CMS signature using signer's public key
    let sig_valid = match verify_cms_signature(&signed_data) {
        Ok(valid) => valid,
        Err(e) => {
            return Ok(VerifyResult {
                valid: false,
                message: format!("CMS signature verification error: {e}"),
                subject,
                issuer,
                digest_algorithm: Some(digest_algo_name.clone()),
                has_timestamp,
            });
        }
    };

    let message = if !sig_valid {
        "CMS signature verification failed (possible forged signature)".to_string()
    } else if digest_match {
        "Signature structure valid, Authenticode digest matches".to_string()
    } else {
        "Signature structure valid but Authenticode digest does NOT match (file may be tampered)"
            .to_string()
    };

    let valid = sig_valid && digest_match;

    Ok(VerifyResult {
        valid,
        message,
        subject,
        issuer,
        digest_algorithm: Some(digest_algo_name),
        has_timestamp,
    })
}

pub(crate) fn trim_der_object(data: &[u8]) -> Option<&[u8]> {
    let total_length = der_object_total_length(data)?;
    if total_length <= data.len() {
        Some(&data[..total_length])
    } else {
        None
    }
}

fn der_object_total_length(data: &[u8]) -> Option<usize> {
    if data.len() < 2 {
        return None;
    }

    let length_byte = data[1];
    if length_byte & 0x80 == 0 {
        return Some(2 + length_byte as usize);
    }

    let length_bytes = (length_byte & 0x7f) as usize;
    if length_bytes == 0
        || length_bytes > std::mem::size_of::<usize>()
        || data.len() < 2 + length_bytes
    {
        return None;
    }

    let mut value_length = 0usize;
    for byte in &data[2..2 + length_bytes] {
        value_length = value_length.checked_mul(256)?.checked_add(*byte as usize)?;
    }

    2usize.checked_add(length_bytes)?.checked_add(value_length)
}

pub(crate) fn parse_content_info(signature: &[u8]) -> Result<ContentInfo, CodeSignError> {
    ContentInfo::from_der(signature)
        .map_err(|e| CodeSignError::Signing(format!("Failed to parse CMS content info: {e:?}")))
}

pub(crate) fn parse_signed_data(content_info: &ContentInfo) -> Result<SignedData, CodeSignError> {
    let signed_data_any = der::Any::new(Tag::Sequence, content_info.content.value().to_vec())
        .map_err(|e| CodeSignError::Signing(format!("Failed to wrap SignedData: {e:?}")))?;
    SignedData::from_der(&signed_data_any.to_der().map_err(|e| {
        CodeSignError::Signing(format!("Failed to encode wrapped SignedData: {e:?}"))
    })?)
    .map_err(|e| CodeSignError::Signing(format!("Failed to parse SignedData: {e:?}")))
}

fn has_timestamp_attribute(attrs: &x509_cert::attr::Attributes) -> bool {
    attrs
        .iter()
        .any(|attr| match attr.oid.to_string().as_str() {
            RFC3161_TIMESTAMP_TOKEN_OID => attr.values.iter().any(|value| {
                value
                    .to_der()
                    .ok()
                    .and_then(|der| ContentInfo::from_der(&der).ok())
                    .is_some()
            }),
            LEGACY_TIMESTAMP_TOKEN_OID => true,
            _ => false,
        })
}

/// Extract the CMS signature from the PE certificate table.
pub(crate) fn extract_signature(data: &[u8]) -> Result<&[u8], CodeSignError> {
    let pe = goblin::pe::PE::parse(data)
        .map_err(|e| CodeSignError::Pe(format!("Failed to parse PE: {e:?}")))?;

    let optional_header = pe
        .header
        .optional_header
        .ok_or_else(|| CodeSignError::Pe("No optional header found".to_string()))?;

    let cert_dir = optional_header.data_directories.get_certificate_table();

    let Some(cert_dir) = cert_dir else {
        return Ok(&[]);
    };

    if cert_dir.size == 0 {
        return Ok(&[]);
    }

    let cert_offset = cert_dir.virtual_address as usize;
    let cert_size = cert_dir.size as usize;

    if cert_offset + cert_size > data.len() {
        return Err(CodeSignError::Pe(
            "Certificate table out of bounds".to_string(),
        ));
    }

    let cert_table = &data[cert_offset..cert_offset + cert_size];

    if cert_table.len() < 8 {
        return Ok(&[]);
    }

    // Parse WIN_CERTIFICATE header
    let dw_length =
        u32::from_le_bytes([cert_table[0], cert_table[1], cert_table[2], cert_table[3]]) as usize;
    let w_revision = u16::from_le_bytes([cert_table[4], cert_table[5]]);
    let w_cert_type = u16::from_le_bytes([cert_table[6], cert_table[7]]);

    if dw_length > cert_table.len() {
        return Err(CodeSignError::Pe(
            "Invalid WIN_CERTIFICATE length".to_string(),
        ));
    }

    if w_revision != 0x0200 && w_revision != 0x0100 {
        return Err(CodeSignError::Pe(format!(
            "Unknown WIN_CERTIFICATE revision: 0x{w_revision:04x}"
        )));
    }

    if w_cert_type != 0x0002 {
        return Err(CodeSignError::Pe(format!(
            "Unexpected certificate type: 0x{w_cert_type:04x}"
        )));
    }

    // bCertificate starts at offset 8
    Ok(&cert_table[8..dw_length])
}

fn digest_oid_to_name(oid: &const_oid::ObjectIdentifier) -> Option<&'static str> {
    if *oid == const_oid::db::rfc5912::ID_SHA_1 {
        Some("sha1")
    } else if *oid == const_oid::db::rfc5912::ID_SHA_256 {
        Some("sha256")
    } else if *oid == const_oid::db::rfc5912::ID_SHA_384 {
        Some("sha384")
    } else if *oid == const_oid::db::rfc5912::ID_SHA_512 {
        Some("sha512")
    } else {
        None
    }
}

/// Verify the Authenticode digest by extracting it from CMS and recomputing.
fn verify_digest(
    data: &[u8],
    signed_data: &cms::signed_data::SignedData,
) -> Result<bool, CodeSignError> {
    // Get digest algorithm from signer info
    let signer_info = signed_data
        .signer_infos
        .0
        .iter()
        .next()
        .ok_or_else(|| CodeSignError::Signing("No signer info".to_string()))?;

    let digest_oid = &signer_info.digest_alg.oid;

    let algo = match digest_oid_to_name(digest_oid) {
        Some(name) => name,
        None => return Ok(false),
    };

    // Compute actual digest from PE file
    let actual_digest = crate::compute_digest_for_verify(data, algo)?;

    // Extract expected digest from SpcIndirectDataContent in econtent
    if let Some(econtent) = &signed_data.encap_content_info.econtent {
        if let Ok(spc_indirect) = econtent.decode_as::<crate::signer::SpcIndirectDataContent>() {
            let expected = spc_indirect.message_digest.digest.as_bytes();
            return Ok(actual_digest == expected);
        }
    }

    Ok(false)
}

/// Cryptographically verify the CMS SignerInfo signature using the signer's RSA public key.
fn verify_cms_signature(signed_data: &cms::signed_data::SignedData) -> Result<bool, CodeSignError> {
    let signer_info = signed_data
        .signer_infos
        .0
        .iter()
        .next()
        .ok_or_else(|| CodeSignError::Signing("No signer info".to_string()))?;

    let signer_cert = find_signer_cert(signer_info, signed_data)?;

    // Extract RSA public key from the certificate's SubjectPublicKeyInfo
    let spki = &signer_cert.tbs_certificate.subject_public_key_info;
    let pk_bytes = spki.subject_public_key.raw_bytes();

    let public_key = {
        use rsa::pkcs1::DecodeRsaPublicKey;
        use rsa::pkcs8::DecodePublicKey;
        rsa::RsaPublicKey::from_pkcs1_der(pk_bytes)
            .or_else(|_| rsa::RsaPublicKey::from_public_key_der(pk_bytes))
            .map_err(|e| CodeSignError::Signing(format!("Failed to parse RSA public key: {e:?}")))?
    };

    // signed_attrs must be present for Authenticode
    let signed_attrs = signer_info
        .signed_attrs
        .as_ref()
        .ok_or_else(|| CodeSignError::Signing("No signed attributes in signature".to_string()))?;

    // Encode signed_attrs as DER, then replace the outer SET OF tag (0x31)
    // with IMPLICIT [0] CONTEXT-SPECIFIC CONSTRUCTED (0xA0) because the
    // CMS signature is computed over the IMPLICIT [0] tagged form.
    let signed_attrs_der = signed_attrs
        .to_der()
        .map_err(|e| CodeSignError::Signing(format!("Signed attrs encode error: {e:?}")))?;

    if signed_attrs_der.is_empty() {
        return Ok(false);
    }

    let signature_bytes = signer_info.signature.as_bytes();
    let digest_oid = &signer_info.digest_alg.oid;

    let sig = Signature::try_from(signature_bytes)
        .map_err(|e| CodeSignError::Signing(format!("Invalid signature bytes: {e:?}")))?;

    let result = if *digest_oid == const_oid::db::rfc5912::ID_SHA_1 {
        VerifyingKey::<sha1::Sha1>::new(public_key).verify(&signed_attrs_der, &sig)
    } else if *digest_oid == const_oid::db::rfc5912::ID_SHA_256 {
        VerifyingKey::<sha2::Sha256>::new(public_key).verify(&signed_attrs_der, &sig)
    } else if *digest_oid == const_oid::db::rfc5912::ID_SHA_384 {
        VerifyingKey::<sha2::Sha384>::new(public_key).verify(&signed_attrs_der, &sig)
    } else if *digest_oid == const_oid::db::rfc5912::ID_SHA_512 {
        VerifyingKey::<sha2::Sha512>::new(public_key).verify(&signed_attrs_der, &sig)
    } else {
        return Ok(false);
    };

    match result {
        Ok(()) => Ok(true),
        Err(e) => {
            eprintln!("Signature verification failed: {e:?}");
            Ok(false)
        }
    }
}

fn find_signer_cert(
    signer_info: &cms::signed_data::SignerInfo,
    signed_data: &cms::signed_data::SignedData,
) -> Result<Certificate, CodeSignError> {
    let (issuer, serial) = match &signer_info.sid {
        SignerIdentifier::IssuerAndSerialNumber(ias) => (&ias.issuer, &ias.serial_number),
        SignerIdentifier::SubjectKeyIdentifier(_) => {
            return Err(CodeSignError::Signing(
                "SubjectKeyIdentifier sid not supported".to_string(),
            ));
        }
    };

    let certs = signed_data
        .certificates
        .as_ref()
        .ok_or_else(|| CodeSignError::Signing("No certificates in signed data".to_string()))?;

    for cert_choice in certs.0.iter() {
        if let cms::cert::CertificateChoices::Certificate(cert) = cert_choice
            && cert.tbs_certificate.issuer == *issuer
            && cert.tbs_certificate.serial_number == *serial
        {
            return Ok(cert.clone());
        }
    }

    Err(CodeSignError::Signing(
        "Signer certificate not found in CMS".to_string(),
    ))
}

// ── Nested CMS helpers for reorder / remove ──

/// Collect all CMS ContentInfo DER bytes from a nested signature chain.
/// Returns the chain from outermost (index 0) to innermost (index N-1).
pub(crate) fn collect_nested_cms_chain(cms_der: &[u8]) -> Result<Vec<Vec<u8>>, CodeSignError> {
    let bytes = trim_der_object(cms_der).unwrap_or(cms_der);
    let ci = parse_content_info(bytes)?;
    let sd = parse_signed_data(&ci)?;

    let si = sd
        .signer_infos
        .0
        .iter()
        .next()
        .ok_or_else(|| CodeSignError::Signing("No signer info in nested CMS".to_string()))?;

    let mut chain = vec![bytes.to_vec()];

    if let Some(ref attrs) = si.unsigned_attrs {
        for attr in attrs.iter() {
            if attr.oid == SPC_NESTED_SIG_OID {
                for val in attr.values.iter() {
                    if let Ok(vb) = val.to_der()
                        && !vb.is_empty()
                    {
                        let inner = trim_der_object(&vb).unwrap_or(&vb);
                        let rest = collect_nested_cms_chain(inner)?;
                        chain.extend(rest);
                    }
                }
            }
        }
    }

    Ok(chain)
}

/// Rebuild a nested CMS chain from ordered ContentInfo DERs (outermost first).
/// The last entry becomes the innermost with no nested attribute.
pub(crate) fn rebuild_nested_cms_chain(cms_ders: &[Vec<u8>]) -> Result<Vec<u8>, CodeSignError> {
    if cms_ders.is_empty() {
        return Err(CodeSignError::Signing("Empty CMS chain".to_string()));
    }
    // Strip old nested from innermost to avoid stale references creating cycles.
    let mut current = remove_nested_from_cms(cms_ders.last().unwrap())?;
    for outer_der in cms_ders[..cms_ders.len() - 1].iter().rev() {
        current = set_nested_cms(outer_der, &current)?;
    }
    Ok(current)
}

/// Remove SPC_NESTED_SIGNATURE from a CMS ContentInfo without adding a
/// replacement. Used to clean chain entries before building a flat attribute set.
pub(crate) fn remove_nested_from_cms(cms_der: &[u8]) -> Result<Vec<u8>, CodeSignError> {
    let bytes = trim_der_object(cms_der).unwrap_or(cms_der);
    let ci = parse_content_info(bytes)?;
    modify_cms_unsigned(&ci, |unsigned| {
        let mut attrs: Vec<Attribute> = std::mem::take(unsigned).into_vec();
        attrs.retain(|a| a.oid != SPC_NESTED_SIG_OID);
        *unsigned = SetOfVec::try_from(attrs).expect("attribute set");
    })
}

/// Modify the unsigned_attrs of the first signer_info and re-encode the CMS.
fn modify_cms_unsigned<F>(ci: &ContentInfo, f: F) -> Result<Vec<u8>, CodeSignError>
where
    F: FnOnce(&mut Attributes),
{
    let sd = parse_signed_data(ci)?;
    let mut si_list: Vec<SignerInfo> = sd.signer_infos.0.iter().cloned().collect();
    if si_list.is_empty() {
        return Err(CodeSignError::Signing(
            "No signer info to modify".to_string(),
        ));
    }
    let mut unsigned = si_list[0].unsigned_attrs.clone().unwrap_or_default();
    f(&mut unsigned);
    si_list[0].unsigned_attrs = if unsigned.as_slice().is_empty() {
        None
    } else {
        Some(unsigned)
    };

    let new_sd = SignedData {
        version: sd.version,
        digest_algorithms: sd.digest_algorithms,
        encap_content_info: sd.encap_content_info,
        certificates: sd.certificates,
        crls: sd.crls,
        signer_infos: SignerInfos::try_from(si_list)
            .map_err(|e: der::Error| CodeSignError::Signing(format!("SignerInfos: {e:?}")))?,
    };
    let sd_der = new_sd
        .to_der()
        .map_err(|e| CodeSignError::Signing(format!("SignedData encode: {e:?}")))?;
    let new_ci = ContentInfo {
        content_type: ci.content_type,
        content: der::Any::from_der(&sd_der)
            .map_err(|e| CodeSignError::Signing(format!("ContentInfo any: {e:?}")))?,
    };
    new_ci
        .to_der()
        .map_err(|e| CodeSignError::Signing(format!("ContentInfo encode: {e:?}")))
}

/// Set (or replace) the nested CMS in a ContentInfo's unsigned attributes.
fn set_nested_cms(outer_der: &[u8], nested_der: &[u8]) -> Result<Vec<u8>, CodeSignError> {
    let bytes = trim_der_object(outer_der).unwrap_or(outer_der);
    let ci = parse_content_info(bytes)?;
    let nested = nested_der.to_vec();
    modify_cms_unsigned(&ci, move |unsigned| {
        let mut attrs: Vec<Attribute> = std::mem::take(unsigned).into_vec();
        attrs.retain(|a| a.oid != SPC_NESTED_SIG_OID);
        let attr_val = AttributeValue::from_der(&nested).expect("nested CMS DER is valid ASN.1");
        let mut values: SetOfVec<AttributeValue> = Default::default();
        values.insert(attr_val).expect("attribute value set");
        attrs.push(Attribute {
            oid: SPC_NESTED_SIG_OID,
            values,
        });
        *unsigned = SetOfVec::try_from(attrs).expect("attribute set");
    })
}

#[cfg(test)]
mod tests {
    use super::{der_object_total_length, trim_der_object};

    #[test]
    fn trim_der_object_removes_trailing_padding() {
        let der_with_padding = [0x30, 0x03, 0x02, 0x01, 0x05, 0x00, 0x00, 0x00];
        let trimmed = trim_der_object(&der_with_padding).expect("trimmed DER");
        assert_eq!(trimmed, &der_with_padding[..5]);
    }

    #[test]
    fn der_object_total_length_supports_long_form_length() {
        let der = [0x30, 0x81, 0x80];
        assert_eq!(der_object_total_length(&der), Some(131));
    }
}
