use crate::CodeSignError;
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerInfo, SignerInfos};
use const_oid::ObjectIdentifier;
use der::asn1::{Any, AnyRef, OctetString, SetOfVec};
use der::{Decode, Encode, Reader, Sequence};
use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use std::path::Path;
use std::time::Duration;
use x509_cert::attr::{Attribute, AttributeValue, Attributes};
use x509_cert::spki::AlgorithmIdentifierOwned;

const RFC3161_TIMESTAMP_TOKEN_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.14");
// Windows Authenticode expects the legacy Microsoft OID for timestamps,
// not the standard PKCS#9 id-aa-timeStampToken OID.
const TIMESTAMP_ATTRIBUTE_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.3.3.1");
const LEGACY_TIMESTAMP_TOKEN_OID: ObjectIdentifier = TIMESTAMP_ATTRIBUTE_OID;

#[derive(Clone, Debug, Sequence)]
pub(crate) struct MessageImprint {
    pub(crate) hash_algorithm: AlgorithmIdentifierOwned,
    pub(crate) hashed_message: OctetString,
}

#[derive(Clone, Debug, Sequence)]
pub(crate) struct TimeStampReq {
    pub(crate) version: u8,
    pub(crate) message_imprint: MessageImprint,
    #[asn1(optional = "true")]
    pub(crate) req_policy: Option<ObjectIdentifier>,
    #[asn1(optional = "true")]
    pub(crate) nonce: Option<u64>,
    #[asn1(optional = "true")]
    pub(crate) cert_req: Option<bool>,
}

#[derive(Clone, Debug, Sequence)]
pub(crate) struct PkiStatusInfo {
    pub(crate) status: u8,
    #[asn1(optional = "true")]
    pub(crate) status_string: Option<Any>,
    #[asn1(optional = "true")]
    pub(crate) fail_info: Option<Any>,
}

#[derive(Clone, Debug, Sequence)]
pub(crate) struct TimeStampResp {
    pub(crate) status: PkiStatusInfo,
    #[asn1(optional = "true")]
    pub(crate) time_stamp_token: Option<ContentInfo>,
}

/// Attach an RFC 3161 timestamp to a CMS signature (raw DER bytes).
/// Returns the updated CMS signature DER with the timestamp token attached.
pub fn timestamp_cms_signature(
    cms_der: &[u8],
    tsa_url: &str,
    digest_algorithm: &str,
) -> Result<Vec<u8>, CodeSignError> {
    let tsa_url = tsa_url.trim();
    if tsa_url.is_empty() {
        return Ok(cms_der.to_vec());
    }

    let signature = crate::verify::trim_der_object(cms_der).unwrap_or(cms_der);
    let content_info = crate::verify::parse_content_info(signature)
        .map_err(|error| CodeSignError::Timestamp(error.to_string()))?;
    let signed_data = crate::verify::parse_signed_data(&content_info)
        .map_err(|error| CodeSignError::Timestamp(error.to_string()))?;

    let signer_info =
        signed_data.signer_infos.0.iter().next().ok_or_else(|| {
            CodeSignError::Timestamp("No signer info found for timestamping".into())
        })?;

    let request = build_timestamp_request(signer_info.signature.as_bytes(), digest_algorithm)?;
    let response = send_timestamp_request(tsa_url, &request)?;
    // Preserve the raw timestamp token DER from the TSA — do NOT re-encode
    // through the cms crate, which may change the ASN.1 encoding and break
    // Windows timestamp verification.
    let token_der = parse_timestamp_response_raw(&response)?;
    attach_timestamp_token_raw(&signed_data, &token_der)
}

/// Attach an RFC 3161 timestamp to an already signed PE file.
/// If the file has multiple signatures, timestamps the last entry (newest).
pub fn timestamp_file(
    file_path: &Path,
    tsa_url: &str,
    digest_algorithm: &str,
) -> Result<(), CodeSignError> {
    let tsa_url = tsa_url.trim();
    if tsa_url.is_empty() {
        return Ok(());
    }

    let pe_data = std::fs::read(file_path)?;
    let entries = crate::pe::read_all_signatures(&pe_data)?;
    if entries.is_empty() {
        return Err(CodeSignError::Timestamp(
            "Cannot timestamp an unsigned PE file".to_string(),
        ));
    }

    // Timestamp the last signature (most recently appended)
    let last_entry = entries.last().unwrap();
    let updated_signature = timestamp_cms_signature(&last_entry.data, tsa_url, digest_algorithm)?;

    if entries.len() == 1 {
        crate::pe::write_signature(&pe_data, &updated_signature, file_path, true)?;
    } else {
        // Preserve other signatures, replace only the last one
        let mut updated_entries: Vec<Vec<u8>> = entries[..entries.len() - 1]
            .iter()
            .map(|e| e.data.clone())
            .collect();
        updated_entries.push(updated_signature);
        crate::pe::write_signatures_entries(&pe_data, &updated_entries, file_path)?;
    }
    Ok(())
}

/// Remove timestamp attributes from a signed PE file.
/// Strips all timestamp-related unsigned attributes (both legacy and RFC 3161 OIDs)
/// from the primary signature. If no unsigned attributes remain, the field is removed.
pub fn remove_timestamp_from_file(file_path: &Path) -> Result<(), CodeSignError> {
    let pe_data = std::fs::read(file_path)?;
    let entries = crate::pe::read_all_signatures(&pe_data)?;
    if entries.is_empty() {
        return Err(CodeSignError::Timestamp(
            "No signature found in the file".into(),
        ));
    }

    let cleaned = remove_timestamp_from_cms(&entries[0].data)?;
    crate::pe::write_signature(&pe_data, &cleaned, file_path, true)?;
    Ok(())
}

/// Remove timestamp attributes from a raw CMS DER buffer.
/// Returns the updated CMS DER with timestamp unsigned attributes stripped.
pub fn remove_timestamp_from_cms(cms_der: &[u8]) -> Result<Vec<u8>, CodeSignError> {
    let sig = crate::verify::trim_der_object(cms_der).unwrap_or(cms_der);
    let content_info = crate::verify::parse_content_info(sig)
        .map_err(|e| CodeSignError::Timestamp(e.to_string()))?;
    let signed_data = crate::verify::parse_signed_data(&content_info)
        .map_err(|e| CodeSignError::Timestamp(e.to_string()))?;

    let mut signer_infos: Vec<SignerInfo> = signed_data.signer_infos.0.iter().cloned().collect();
    let mut removed = false;

    for si in &mut signer_infos {
        if let Some(ref attrs) = si.unsigned_attrs {
            let mut kept: Attributes = Default::default();
            for attr in attrs.iter() {
                if attr.oid == TIMESTAMP_ATTRIBUTE_OID || attr.oid == RFC3161_TIMESTAMP_TOKEN_OID {
                    removed = true;
                } else {
                    kept.insert(attr.clone()).map_err(|e| {
                        CodeSignError::Timestamp(format!("Failed to rebuild attributes: {e:?}"))
                    })?;
                }
            }
            si.unsigned_attrs = if kept.is_empty() { None } else { Some(kept) };
        }
    }

    if !removed {
        return Err(CodeSignError::Timestamp(
            "No timestamp attribute found".into(),
        ));
    }

    let updated_sd = SignedData {
        version: signed_data.version,
        digest_algorithms: signed_data.digest_algorithms.clone(),
        encap_content_info: signed_data.encap_content_info.clone(),
        certificates: signed_data.certificates.clone(),
        crls: signed_data.crls.clone(),
        signer_infos: SignerInfos::try_from(signer_infos).map_err(|e| {
            CodeSignError::Timestamp(format!("Failed to rebuild signer infos: {e:?}"))
        })?,
    };

    encode_signed_data(&updated_sd)
}

fn build_timestamp_request(
    encrypted_digest: &[u8],
    digest_algorithm: &str,
) -> Result<Vec<u8>, CodeSignError> {
    let digest_oid = digest_algorithm_oid(digest_algorithm);
    let digest = compute_digest(encrypted_digest, digest_algorithm);
    let request = TimeStampReq {
        version: 1,
        message_imprint: MessageImprint {
            hash_algorithm: algorithm_identifier_with_null(digest_oid),
            hashed_message: OctetString::new(digest).map_err(|e| {
                CodeSignError::Timestamp(format!("Failed to encode message imprint: {e:?}"))
            })?,
        },
        req_policy: None,
        nonce: None,
        cert_req: Some(true),
    };

    request
        .to_der()
        .map_err(|e| CodeSignError::Timestamp(format!("Failed to encode RFC3161 request: {e:?}")))
}

fn send_timestamp_request(tsa_url: &str, request: &[u8]) -> Result<Vec<u8>, CodeSignError> {
    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| CodeSignError::Timestamp(format!("Failed to build HTTP client: {e}")))?;

    let response = client
        .post(tsa_url)
        .header(CONTENT_TYPE, "application/timestamp-query")
        .header(ACCEPT, "application/timestamp-reply")
        .body(request.to_vec())
        .send()
        .map_err(|e| CodeSignError::Timestamp(format!("Timestamp request failed: {e}")))?;

    if !response.status().is_success() {
        return Err(CodeSignError::Timestamp(format!(
            "Timestamp service returned HTTP {}",
            response.status()
        )));
    }

    response
        .bytes()
        .map(|bytes| bytes.to_vec())
        .map_err(|e| CodeSignError::Timestamp(format!("Failed to read timestamp response: {e}")))
}

fn parse_timestamp_response_raw(response: &[u8]) -> Result<Vec<u8>, CodeSignError> {
    // Parse TimeStampResp to validate, then extract the raw ContentInfo DER
    // of the timestamp token. We must NOT re-encode through the cms crate
    // because it may alter the ASN.1 encoding (e.g. EXPLICIT vs not),
    // breaking Windows timestamp verification.
    let ts_resp = TimeStampResp::from_der(response).map_err(|e| {
        CodeSignError::Timestamp(format!("Failed to parse RFC3161 response: {e:?}"))
    })?;

    match ts_resp.status.status {
        0 | 1 => {}
        status => {
            return Err(CodeSignError::Timestamp(format!(
                "Timestamp service returned failure status {status}"
            )));
        }
    }

    let _token = ts_resp.time_stamp_token.ok_or_else(|| {
        CodeSignError::Timestamp(
            "Timestamp service returned success without a timestamp token".to_string(),
        )
    })?;

    // Manually extract the ContentInfo DER from the response bytes.
    // TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken ContentInfo OPTIONAL }
    // We find the ContentInfo by skipping past the PKIStatusInfo SEQUENCE.
    extract_content_info_from_resp(response).ok_or_else(|| {
        CodeSignError::Timestamp("Failed to extract timestamp token DER from response".into())
    })
}

/// Extract the raw DER bytes of the second SEQUENCE (ContentInfo) from a TimeStampResp.
fn extract_content_info_from_resp(data: &[u8]) -> Option<Vec<u8>> {
    // Use checked DER lengths on every platform, but copy the original token
    // TLV instead of serializing ContentInfo again.
    AnyRef::from_der(data)
        .ok()?
        .sequence(|reader| {
            let _: PkiStatusInfo = reader.decode()?;
            let token = reader.tlv_bytes()?;
            ContentInfo::from_der(token)?;
            Ok(token.to_vec())
        })
        .ok()
}

/// Attach a timestamp token using the raw DER bytes from the TSA response,
/// preserving the TSA's original ASN.1 encoding.
fn attach_timestamp_token_raw(
    signed_data: &SignedData,
    token_der: &[u8],
) -> Result<Vec<u8>, CodeSignError> {
    let mut signer_infos = signed_data
        .signer_infos
        .0
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    let signer_info = signer_infos.first().cloned().ok_or_else(|| {
        CodeSignError::Timestamp("No signer info found while inserting timestamp".to_string())
    })?;

    signer_infos[0] = signer_info_with_timestamp_raw(&signer_info, token_der)?;

    let updated_signed_data = SignedData {
        version: signed_data.version,
        digest_algorithms: signed_data.digest_algorithms.clone(),
        encap_content_info: signed_data.encap_content_info.clone(),
        certificates: signed_data.certificates.clone(),
        crls: signed_data.crls.clone(),
        signer_infos: SignerInfos::try_from(signer_infos).map_err(|e| {
            CodeSignError::Timestamp(format!("Failed to rebuild signer infos: {e:?}"))
        })?,
    };

    encode_signed_data(&updated_signed_data)
}

/// Replace timestamp attributes without re-encoding the supplied token.
fn signer_info_with_timestamp_raw(
    signer_info: &SignerInfo,
    token_der: &[u8],
) -> Result<SignerInfo, CodeSignError> {
    let mut updated_attrs: Attributes = Default::default();

    if let Some(existing_attrs) = &signer_info.unsigned_attrs {
        for attr in existing_attrs.iter() {
            if attr.oid != RFC3161_TIMESTAMP_TOKEN_OID && attr.oid != LEGACY_TIMESTAMP_TOKEN_OID {
                updated_attrs.insert(attr.clone()).map_err(|e| {
                    CodeSignError::Timestamp(format!(
                        "Failed to preserve unsigned attribute during timestamping: {e:?}"
                    ))
                })?;
            }
        }
    }

    updated_attrs
        .insert(timestamp_attribute_raw(token_der)?)
        .map_err(|e| {
            CodeSignError::Timestamp(format!("Failed to add RFC3161 timestamp attribute: {e:?}"))
        })?;

    let mut updated_signer = signer_info.clone();
    updated_signer.unsigned_attrs = Some(updated_attrs);
    Ok(updated_signer)
}

/// Build a timestamp attribute from raw DER bytes of the TSA's ContentInfo.
/// Uses the bytes directly without re-encoding, preserving the TSA's ASN.1 structure.
fn timestamp_attribute_raw(token_der: &[u8]) -> Result<Attribute, CodeSignError> {
    let attribute_value = AttributeValue::from_der(token_der).map_err(|e| {
        CodeSignError::Timestamp(format!("Failed to encode timestamp attribute value: {e:?}"))
    })?;
    let mut values: SetOfVec<AttributeValue> = Default::default();
    values.insert(attribute_value).map_err(|e| {
        CodeSignError::Timestamp(format!(
            "Failed to build timestamp attribute value set: {e:?}"
        ))
    })?;

    Ok(Attribute {
        oid: TIMESTAMP_ATTRIBUTE_OID,
        values,
    })
}

fn encode_signed_data(signed_data: &SignedData) -> Result<Vec<u8>, CodeSignError> {
    let signed_data_der = signed_data.to_der().map_err(|e| {
        CodeSignError::Timestamp(format!("Failed to encode updated SignedData: {e:?}"))
    })?;
    let content_info = ContentInfo {
        content_type: const_oid::db::rfc5911::ID_SIGNED_DATA,
        content: Any::from_der(&signed_data_der).map_err(|e| {
            CodeSignError::Timestamp(format!("Failed to wrap updated SignedData: {e:?}"))
        })?,
    };

    content_info
        .to_der()
        .map_err(|e| CodeSignError::Timestamp(format!("Failed to encode updated CMS: {e:?}")))
}

fn compute_digest(data: &[u8], digest_algorithm: &str) -> Vec<u8> {
    use sha2::Digest;

    match digest_algorithm.to_ascii_lowercase().as_str() {
        "sha1" => sha1::Sha1::digest(data).to_vec(),
        "sha384" => sha2::Sha384::digest(data).to_vec(),
        "sha512" => sha2::Sha512::digest(data).to_vec(),
        _ => sha2::Sha256::digest(data).to_vec(),
    }
}

fn digest_algorithm_oid(digest_algorithm: &str) -> ObjectIdentifier {
    match digest_algorithm.to_ascii_lowercase().as_str() {
        "sha1" => const_oid::db::rfc5912::ID_SHA_1,
        "sha384" => const_oid::db::rfc5912::ID_SHA_384,
        "sha512" => const_oid::db::rfc5912::ID_SHA_512,
        _ => const_oid::db::rfc5912::ID_SHA_256,
    }
}

fn algorithm_identifier_with_null(oid: ObjectIdentifier) -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid,
        parameters: Some(Any::null()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::Tag;

    #[test]
    fn timestamp_request_uses_expected_digest_algorithm() {
        let request = build_timestamp_request(b"hello", "sha384").expect("timestamp request");
        let decoded = TimeStampReq::from_der(&request).expect("decode request");

        assert_eq!(decoded.version, 1);
        assert_eq!(
            decoded.message_imprint.hash_algorithm.oid,
            const_oid::db::rfc5912::ID_SHA_384
        );
        assert_eq!(decoded.cert_req, Some(true));
    }

    #[test]
    fn timestamp_response_returns_embedded_token() {
        let token = fake_timestamp_token();
        let response = TimeStampResp {
            status: PkiStatusInfo {
                status: 0,
                status_string: None,
                fail_info: None,
            },
            time_stamp_token: Some(token.clone()),
        }
        .to_der()
        .expect("encode response");

        let parsed = parse_timestamp_response_raw(&response).expect("parse response");
        assert_eq!(parsed, token.to_der().expect("encode token"));
    }

    #[test]
    fn timestamp_response_preserves_long_token_der() {
        let token = ContentInfo {
            content_type: const_oid::db::rfc5911::ID_DATA,
            content: Any::new(Tag::OctetString, vec![0x42; 512]).expect("long token"),
        };
        let response = TimeStampResp {
            status: PkiStatusInfo {
                status: 1,
                status_string: None,
                fail_info: None,
            },
            time_stamp_token: Some(token.clone()),
        }
        .to_der()
        .expect("encode response");

        assert_eq!(
            parse_timestamp_response_raw(&response).expect("granted with modifications"),
            token.to_der().expect("token DER")
        );
    }

    #[test]
    fn timestamp_response_rejects_failure_and_missing_token() {
        for status in [0, 1, 2, 3, 4, 5] {
            let response = TimeStampResp {
                status: PkiStatusInfo {
                    status,
                    status_string: None,
                    fail_info: None,
                },
                time_stamp_token: None,
            }
            .to_der()
            .expect("encode response");
            assert!(parse_timestamp_response_raw(&response).is_err());
        }
    }

    #[test]
    fn malformed_timestamp_lengths_return_errors_without_panicking() {
        let malformed: &[&[u8]] = &[
            &[],
            &[0x30],
            &[0x30, 0x7f],
            &[0x30, 0x80],
            &[0x30, 0x82, 0xff, 0xff],
            &[0x30, 0x02, 0x30, 0x7f],
            &[
                0x30, 0x89, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            ],
        ];
        for response in malformed {
            assert!(extract_content_info_from_resp(response).is_none());
            assert!(parse_timestamp_response_raw(response).is_err());
        }
    }

    #[test]
    fn attach_timestamp_replaces_previous_timestamp_attributes() {
        let mut signed_data = signed_data_fixture();
        let timestamp_token = fake_timestamp_token();
        let token_der = timestamp_token.to_der().expect("token DER");
        let mut signers = signed_data
            .signer_infos
            .0
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        let mut microsoft_attr = timestamp_attribute_raw(&token_der).expect("Microsoft attr");
        let mut standard_attr = microsoft_attr.clone();
        standard_attr.oid = RFC3161_TIMESTAMP_TOKEN_OID;
        // An unrelated unsigned attribute must survive timestamp replacement.
        microsoft_attr.oid = ObjectIdentifier::new_unwrap("1.2.3.4");
        let preserved_attr = microsoft_attr.clone();
        signers[0].unsigned_attrs = Some(
            Attributes::try_from(vec![
                timestamp_attribute_raw(&token_der).expect("old timestamp"),
                standard_attr,
                preserved_attr.clone(),
            ])
            .expect("old unsigned attributes"),
        );
        signed_data.signer_infos = SignerInfos::try_from(signers).expect("signers");

        let updated_cms =
            attach_timestamp_token_raw(&signed_data, &token_der).expect("attach token");
        let content_info =
            crate::verify::parse_content_info(&updated_cms).expect("parse updated content info");
        let updated_signed_data =
            crate::verify::parse_signed_data(&content_info).expect("parse updated signed data");
        let updated_signer = updated_signed_data
            .signer_infos
            .0
            .iter()
            .next()
            .expect("signer after timestamp");
        let attrs = updated_signer
            .unsigned_attrs
            .as_ref()
            .expect("unsigned attributes");

        let timestamp_attrs = attrs
            .iter()
            .filter(|attr| attr.oid == TIMESTAMP_ATTRIBUTE_OID)
            .count();
        assert_eq!(timestamp_attrs, 1);
        assert!(
            !attrs
                .iter()
                .any(|attr| attr.oid == RFC3161_TIMESTAMP_TOKEN_OID)
        );
        assert!(attrs.iter().any(|attr| attr == &preserved_attr));
        let token_value = attrs
            .iter()
            .find(|attr| attr.oid == TIMESTAMP_ATTRIBUTE_OID)
            .unwrap()
            .values
            .iter()
            .next()
            .unwrap();
        assert_eq!(token_value.to_der().expect("stored token DER"), token_der);
    }

    fn fake_timestamp_token() -> ContentInfo {
        ContentInfo {
            content_type: const_oid::db::rfc5911::ID_DATA,
            content: Any::new(Tag::OctetString, b"mock-tsa-token".to_vec())
                .expect("timestamp token any"),
        }
    }

    fn signed_data_fixture() -> SignedData {
        let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace root");
        let cert_path = workspace_root.join("test_data").join("test_combined.pem");
        let loaded = crate::crypto::load_certificate(&cert_path, None).expect("load test cert");
        let cms = crate::signer::create_signature(
            &[0x42; 32],
            &loaded.cert,
            &loaded.private_key,
            "sha256",
            Some("RustSign"),
            Some("https://example.com"),
            &loaded.extra_certs,
            &[],
        )
        .expect("create fixture signature");
        let content_info = crate::verify::parse_content_info(&cms).expect("fixture content info");
        crate::verify::parse_signed_data(&content_info).expect("fixture signed data")
    }
}
