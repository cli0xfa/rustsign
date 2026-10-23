use crate::CodeSignError;
use cms::builder::SignerInfoBuilder;
use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::content_info::{CmsVersion, ContentInfo};
use cms::signed_data::{
    CertificateSet, EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfos,
};
use const_oid::ObjectIdentifier;
use der::asn1::{Any, BitString, BmpString, ContextSpecific, Ia5String, OctetString, SetOfVec};
use der::{Decode, Encode, Sequence, TagMode, TagNumber};
use rsa::RsaPrivateKey;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::{Keypair, Signer};
use sha2::Digest;
use std::collections::HashSet;
use x509_cert::Certificate;
use x509_cert::attr::{Attribute, AttributeValue, Attributes};
use x509_cert::builder::Builder;
use x509_cert::spki::{AlgorithmIdentifierOwned, DynSignatureAlgorithmIdentifier};

// Authenticode OIDs
const SPC_INDIRECT_DATA_CONTENT: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.1.4");
const SPC_STATEMENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.1.11");
const SPC_SP_OPUS_INFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.1.12");
const SPC_PE_IMAGE_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.1.15");
const SPC_INDIVIDUAL_SP_KEY_PURPOSE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.1.21");
const SPC_NESTED_SIGNATURE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.4.1");
const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
pub(crate) const ID_CT_TST_INFO: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");

// ESS signingCertificate (old, RFC 2634) — SHA-1 hash
const ID_AA_SIGNING_CERTIFICATE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.12");

#[derive(Clone, Debug, Sequence)]
struct ESSCertID {
    cert_hash: OctetString,
}

#[derive(Clone, Debug, Sequence)]
struct SigningCertificate {
    certs: Vec<ESSCertID>,
}

// ESS signingCertificateV2 (RFC 5035) — SHA-256 hash
const ID_AA_SIGNING_CERTIFICATE_V2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");

#[derive(Clone, Debug, Sequence)]
struct ESSCertIDv2 {
    hash_algorithm: AlgorithmIdentifierOwned,
    cert_hash: OctetString,
}

#[derive(Clone, Debug, Sequence)]
struct SigningCertificateV2 {
    certs: Vec<ESSCertIDv2>,
}

/// SpcIndirectDataContent for Authenticode.
#[derive(Clone, Debug, Sequence)]
pub(crate) struct SpcIndirectDataContent {
    pub(crate) data: SpcAttributeTypeAndOptionalValue,
    pub(crate) message_digest: DigestInfo,
}

#[derive(Clone, Debug, Sequence)]
pub(crate) struct SpcAttributeTypeAndOptionalValue {
    pub(crate) type_: ObjectIdentifier,
    pub(crate) value: Any,
}

#[derive(Clone, Debug, Sequence)]
pub(crate) struct DigestInfo {
    pub(crate) digest_algorithm: AlgorithmIdentifierOwned,
    pub(crate) digest: OctetString,
}

#[derive(Clone, Debug, Sequence)]
struct SpcPeImageData {
    flags: BitString,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    file: Any,
}

#[derive(Clone, Debug, Sequence)]
struct SpcSpOpusInfo {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    program_name: Option<Any>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    more_info: Option<Any>,
}

#[derive(Clone, Debug, Sequence)]
struct SpcStatementType {
    purpose: ObjectIdentifier,
}

/// Map a digest algorithm name to its OID. Unknown values fall back to SHA-256.
fn digest_oid_for(algorithm: &str) -> ObjectIdentifier {
    match algorithm {
        "sha1" => const_oid::db::rfc5912::ID_SHA_1,
        "sha384" => const_oid::db::rfc5912::ID_SHA_384,
        "sha512" => const_oid::db::rfc5912::ID_SHA_512,
        _ => const_oid::db::rfc5912::ID_SHA_256,
    }
}

/// Instantiate the RSA signing key for the requested digest algorithm and run
/// `$body` with it bound to `$signer`. Each match arm produces a concrete
/// `SigningKey<D>`; the body stays generic over `S`, so the four algorithm
/// variants share one implementation instead of being copy-pasted.
macro_rules! with_signer {
    ($key:expr, $algo:expr, $signer:ident, $body:expr) => {
        match $algo {
            "sha1" => {
                let $signer = SigningKey::<sha1::Sha1>::new($key);
                $body
            }
            "sha384" => {
                let $signer = SigningKey::<sha2::Sha384>::new($key);
                $body
            }
            "sha512" => {
                let $signer = SigningKey::<sha2::Sha512>::new($key);
                $body
            }
            _ => {
                let $signer = SigningKey::<sha2::Sha256>::new($key);
                $body
            }
        }
    };
}

/// Create an Authenticode CMS/PKCS#7 signature with the specified digest algorithm.
/// Each entry in `previous_cms_entries` is embedded as a separate SPC_NESTED_SIGNATURE
/// attribute at the same level in unsigned attributes, so Windows Explorer can
/// enumerate all signatures.
pub fn create_signature(
    digest: &[u8],
    cert: &Certificate,
    private_key: &[u8],
    digest_algorithm: &str,
    description: Option<&str>,
    url: Option<&str>,
    extra_certs: &[Certificate],
    previous_cms_entries: &[&[u8]],
) -> Result<Vec<u8>, CodeSignError> {
    let rsa_private_key = parse_private_key(private_key)?;
    let digest_oid = digest_oid_for(digest_algorithm);

    with_signer!(rsa_private_key, digest_algorithm, signer, {
        build_signature(
            digest,
            cert,
            &signer,
            digest_oid,
            description,
            url,
            extra_certs,
            previous_cms_entries,
        )
    })
}

/// Create a CMS SignedData containing a TSTInfo as the encapsulated content.
/// This produces a timestamp token for inclusion in a TimeStampResp.
/// The eContentType is id-ct-TSTInfo (1.2.840.113549.1.9.16.1.4).
/// Per CMS (RFC 5652 §5.2), eContent is wrapped in an OCTET STRING.
pub fn create_timestamp_token(
    tst_info_der: &[u8],
    cert: &Certificate,
    private_key: &[u8],
    digest_algorithm: &str,
    extra_certs: &[Certificate],
) -> Result<Vec<u8>, CodeSignError> {
    let rsa_private_key = parse_private_key(private_key)?;
    let digest_oid = digest_oid_for(digest_algorithm);

    with_signer!(rsa_private_key, digest_algorithm, signer, {
        build_tsa_signed_data(tst_info_der, cert, &signer, digest_oid, extra_certs)
    })
}

fn build_tsa_signed_data<S>(
    tst_info_der: &[u8],
    cert: &Certificate,
    signer: &S,
    digest_oid: ObjectIdentifier,
    extra_certs: &[Certificate],
) -> Result<Vec<u8>, CodeSignError>
where
    S: Keypair + DynSignatureAlgorithmIdentifier + Signer<rsa::pkcs1v15::Signature>,
{
    // Wrap TSTInfo DER in OCTET STRING per CMS spec
    let tst_octet = OctetString::new(tst_info_der.to_vec())
        .map_err(|e| CodeSignError::Signing(format!("OctetString error: {e:?}")))?;
    let tst_octet_der = tst_octet
        .to_der()
        .map_err(|e| CodeSignError::Signing(format!("OctetString DER error: {e:?}")))?;
    let econtent = Any::from_der(&tst_octet_der)
        .map_err(|e| CodeSignError::Signing(format!("eContent Any error: {e:?}")))?;

    let encap_content_info = EncapsulatedContentInfo {
        econtent_type: ID_CT_TST_INFO,
        econtent: Some(econtent),
    };

    let sid = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
        issuer: cert.tbs_certificate.issuer.clone(),
        serial_number: cert.tbs_certificate.serial_number.clone(),
    });

    let digest_algorithm = algorithm_identifier_with_null(digest_oid);

    let mut builder = SignerInfoBuilder::new(
        signer,
        sid,
        digest_algorithm.clone(),
        &encap_content_info,
        None,
    )
    .map_err(|e| {
        CodeSignError::Signing(format!(
            "SignerInfoBuilder error (check cert/key compatibility): {e:?}"
        ))
    })?;

    // Add ESS signingCertificate (old, SHA-1) for backward compatibility with older Windows.
    if let Ok(attr) = build_signing_cert_attribute(cert) {
        builder
            .add_signed_attribute(attr)
            .map_err(|e| CodeSignError::Signing(format!("Add signingCert attr error: {e:?}")))?;
    }

    // Add ESS signingCertificateV2 (new, SHA-256) for modern verifiers.
    if let Ok(attr) = build_signing_cert_v2_attribute(cert) {
        builder
            .add_signed_attribute(attr)
            .map_err(|e| CodeSignError::Signing(format!("Add signingCertV2 attr error: {e:?}")))?;
    }

    let mut signer_info = builder
        .build::<rsa::pkcs1v15::Signature>()
        .map_err(|e| CodeSignError::Signing(format!("Build signer info error: {e:?}")))?;

    // Use rsaEncryption (not sha256WithRSAEncryption) for compatibility with
    // Windows Authenticode timestamp verification. Both DigiCert and Sectigo
    // use this convention in their timestamp tokens.
    signer_info.signature_algorithm = rsa_encryption_algorithm_identifier();

    let mut digest_algorithms: SetOfVec<AlgorithmIdentifierOwned> = Default::default();
    digest_algorithms
        .insert(digest_algorithm.clone())
        .map_err(|e| CodeSignError::Signing(format!("Digest algorithm set error: {e:?}")))?;

    let mut certificates: SetOfVec<CertificateChoices> = Default::default();
    let mut seen_certificates = HashSet::new();
    insert_certificate_if_new(&mut certificates, &mut seen_certificates, cert)?;
    for extra_cert in extra_certs {
        insert_certificate_if_new(&mut certificates, &mut seen_certificates, extra_cert)?;
    }

    let mut signer_infos = SetOfVec::new();
    signer_infos
        .insert(signer_info)
        .map_err(|e| CodeSignError::Signing(format!("Signer info set error: {e:?}")))?;

    // RFC 5652 §5.1: when eContentType is other than id-data, version MUST be 3.
    let signed_data = SignedData {
        version: CmsVersion::V3,
        digest_algorithms,
        encap_content_info,
        certificates: Some(CertificateSet(certificates)),
        crls: None,
        signer_infos: SignerInfos(signer_infos),
    };

    let signed_data_der = signed_data
        .to_der()
        .map_err(|e| CodeSignError::Signing(format!("SignedData DER error: {e:?}")))?;

    let content_info = ContentInfo {
        content_type: const_oid::db::rfc5911::ID_SIGNED_DATA,
        content: Any::from_der(&signed_data_der)
            .map_err(|e| CodeSignError::Signing(format!("ContentInfo Any error: {e:?}")))?,
    };

    content_info
        .to_der()
        .map_err(|e| CodeSignError::Signing(format!("ContentInfo DER error: {e:?}")))
}

fn build_signature<S>(
    digest: &[u8],
    cert: &Certificate,
    signer: &S,
    digest_oid: ObjectIdentifier,
    description: Option<&str>,
    url: Option<&str>,
    extra_certs: &[Certificate],
    previous_cms_entries: &[&[u8]],
) -> Result<Vec<u8>, CodeSignError>
where
    S: Keypair + DynSignatureAlgorithmIdentifier + Signer<rsa::pkcs1v15::Signature>,
{
    let encap_content_info = build_encapsulated_content_info(digest, digest_oid)?;

    let sid = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
        issuer: cert.tbs_certificate.issuer.clone(),
        serial_number: cert.tbs_certificate.serial_number.clone(),
    });

    let digest_algorithm = algorithm_identifier_with_null(digest_oid);

    let mut signer_info_builder = SignerInfoBuilder::new(
        signer,
        sid,
        digest_algorithm.clone(),
        &encap_content_info,
        None,
    )
    .map_err(|e| {
        CodeSignError::Signing(format!(
            "SignerInfoBuilder error (check cert/key compatibility): {e:?}"
        ))
    })?;

    signer_info_builder
        .add_signed_attribute(build_spc_opus_info_attribute(description, url)?)
        .map_err(|e| CodeSignError::Signing(format!("Add SpcSpOpusInfo attr error: {e:?}")))?;
    signer_info_builder
        .add_signed_attribute(build_spc_statement_type_attribute()?)
        .map_err(|e| CodeSignError::Signing(format!("Add SpcStatementType attr error: {e:?}")))?;

    let mut signer_info = signer_info_builder
        .build::<rsa::pkcs1v15::Signature>()
        .map_err(|e| CodeSignError::Signing(format!("Build signer info error: {e:?}")))?;
    signer_info.digest_alg = digest_algorithm.clone();
    signer_info.signature_algorithm = rsa_encryption_algorithm_identifier();

    // Embed each previous CMS as a separate SPC_NESTED_SIGNATURE attribute
    // at the same level, so Windows Explorer can enumerate all of them.
    if !previous_cms_entries.is_empty() {
        signer_info.unsigned_attrs = Some(build_nested_unsigned_attrs(previous_cms_entries)?);
    }

    let signed_data_der = build_signed_data(
        cert,
        extra_certs,
        encap_content_info,
        digest_algorithm,
        signer_info,
    )?;

    Ok(signed_data_der)
}

fn build_encapsulated_content_info(
    digest: &[u8],
    digest_oid: ObjectIdentifier,
) -> Result<EncapsulatedContentInfo, CodeSignError> {
    let spc_indirect_data = SpcIndirectDataContent {
        data: SpcAttributeTypeAndOptionalValue {
            type_: SPC_PE_IMAGE_DATA,
            value: build_spc_pe_image_data_value()?,
        },
        message_digest: DigestInfo {
            digest_algorithm: algorithm_identifier_with_null(digest_oid),
            digest: OctetString::new(digest.to_vec())
                .map_err(|e| CodeSignError::Signing(format!("OctetString error: {e:?}")))?,
        },
    };

    let spc_indirect_data_der = spc_indirect_data
        .to_der()
        .map_err(|e| CodeSignError::Signing(format!("DER encoding error: {e:?}")))?;

    // Authenticode stores the raw SpcIndirectDataContent directly under
    // EncapsulatedContentInfo.econtent instead of wrapping it in an OCTET STRING.
    let econtent = Any::from_der(&spc_indirect_data_der)
        .map_err(|e| CodeSignError::Signing(format!("Any encoding error: {e:?}")))?;

    Ok(EncapsulatedContentInfo {
        econtent_type: SPC_INDIRECT_DATA_CONTENT,
        econtent: Some(econtent),
    })
}

fn build_signed_data(
    cert: &Certificate,
    extra_certs: &[Certificate],
    encap_content_info: EncapsulatedContentInfo,
    digest_algorithm: AlgorithmIdentifierOwned,
    signer_info: cms::signed_data::SignerInfo,
) -> Result<Vec<u8>, CodeSignError> {
    let mut digest_algorithms: SetOfVec<AlgorithmIdentifierOwned> = Default::default();
    digest_algorithms
        .insert(digest_algorithm)
        .map_err(|e| CodeSignError::Signing(format!("Digest algorithm set error: {e:?}")))?;

    let mut certificates: SetOfVec<CertificateChoices> = Default::default();
    let mut seen_certificates = HashSet::new();
    insert_certificate_if_new(&mut certificates, &mut seen_certificates, cert)?;
    for extra_cert in extra_certs {
        insert_certificate_if_new(&mut certificates, &mut seen_certificates, extra_cert)?;
    }

    let mut signer_infos = SetOfVec::new();
    signer_infos
        .insert(signer_info)
        .map_err(|e| CodeSignError::Signing(format!("Signer info set error: {e:?}")))?;

    let signed_data = SignedData {
        version: CmsVersion::V1,
        digest_algorithms,
        encap_content_info,
        certificates: Some(CertificateSet(certificates)),
        crls: None,
        signer_infos: SignerInfos(signer_infos),
    };

    let signed_data_der = signed_data
        .to_der()
        .map_err(|e| CodeSignError::Signing(format!("SignedData DER error: {e:?}")))?;

    let content_info = ContentInfo {
        content_type: const_oid::db::rfc5911::ID_SIGNED_DATA,
        content: Any::from_der(&signed_data_der)
            .map_err(|e| CodeSignError::Signing(format!("ContentInfo Any error: {e:?}")))?,
    };

    content_info
        .to_der()
        .map_err(|e| CodeSignError::Signing(format!("ContentInfo DER error: {e:?}")))
}

/// Build the ESS signingCertificate signed attribute (RFC 2634, old).
/// Uses SHA-1 hash of the signing certificate for backward compatibility.
fn build_signing_cert_attribute(cert: &Certificate) -> Result<Attribute, CodeSignError> {
    let cert_der = cert
        .to_der()
        .map_err(|e| CodeSignError::Signing(format!("Certificate DER error: {e:?}")))?;

    let mut hasher = sha1::Sha1::new();
    hasher.update(&cert_der);
    let cert_hash = hasher.finalize().to_vec();

    let ess_cert_id = ESSCertID {
        cert_hash: OctetString::new(cert_hash)
            .map_err(|e| CodeSignError::Signing(format!("OctetString error: {e:?}")))?,
    };

    let signing_cert = SigningCertificate {
        certs: vec![ess_cert_id],
    };

    attribute_from_sequence(ID_AA_SIGNING_CERTIFICATE, &signing_cert)
}

/// Build the ESS signingCertificateV2 signed attribute (RFC 5035).
/// Contains a SHA-256 hash of the signing certificate so the verifier
/// can confidently identify which certificate was used to sign the token.
fn build_signing_cert_v2_attribute(cert: &Certificate) -> Result<Attribute, CodeSignError> {
    let cert_der = cert
        .to_der()
        .map_err(|e| CodeSignError::Signing(format!("Certificate DER error: {e:?}")))?;

    let mut hasher = sha2::Sha256::new();
    hasher.update(&cert_der);
    let cert_hash = hasher.finalize().to_vec();

    let ess_cert_id = ESSCertIDv2 {
        hash_algorithm: AlgorithmIdentifierOwned {
            oid: const_oid::db::rfc5912::ID_SHA_256,
            parameters: Some(Any::null()),
        },
        cert_hash: OctetString::new(cert_hash)
            .map_err(|e| CodeSignError::Signing(format!("OctetString error: {e:?}")))?,
    };

    let signing_cert_v2 = SigningCertificateV2 {
        certs: vec![ess_cert_id],
    };

    attribute_from_sequence(ID_AA_SIGNING_CERTIFICATE_V2, &signing_cert_v2)
}

fn insert_certificate_if_new(
    certificates: &mut SetOfVec<CertificateChoices>,
    seen_certificates: &mut HashSet<Vec<u8>>,
    cert: &Certificate,
) -> Result<(), CodeSignError> {
    let cert_der = cert
        .to_der()
        .map_err(|e| CodeSignError::Signing(format!("Certificate DER error: {e:?}")))?;
    if seen_certificates.insert(cert_der) {
        certificates
            .insert(CertificateChoices::Certificate(cert.clone()))
            .map_err(|e| CodeSignError::Signing(format!("Certificate set error: {e:?}")))?;
    }
    Ok(())
}

/// Build a single szOID_NESTED_SIGNATURE (1.3.6.1.4.1.311.2.4.1) attribute
/// containing ALL prior CMS entries as separate values inside the same SET OF.
/// Windows Explorer enumerates all values within this single attribute.
fn build_nested_unsigned_attrs(
    previous_cms_entries: &[&[u8]],
) -> Result<Attributes, CodeSignError> {
    let mut attrs: Attributes = Default::default();
    if previous_cms_entries.is_empty() {
        return Ok(attrs);
    }

    let mut values: SetOfVec<AttributeValue> = Default::default();
    for prev_cms in previous_cms_entries {
        let attr_value = AttributeValue::from_der(prev_cms).map_err(|e| {
            CodeSignError::Signing(format!("Nested signature attribute value error: {e:?}"))
        })?;
        values.insert(attr_value).map_err(|e| {
            CodeSignError::Signing(format!("Nested signature value set error: {e:?}"))
        })?;
    }

    attrs
        .insert(Attribute {
            oid: SPC_NESTED_SIGNATURE,
            values,
        })
        .map_err(|e| {
            CodeSignError::Signing(format!("Nested signature attr insert error: {e:?}"))
        })?;

    Ok(attrs)
}

fn parse_private_key(key_bytes: &[u8]) -> Result<RsaPrivateKey, CodeSignError> {
    if let Ok(key) = RsaPrivateKey::from_pkcs8_der(key_bytes) {
        return Ok(key);
    }
    if let Ok(key) = RsaPrivateKey::from_pkcs1_der(key_bytes) {
        return Ok(key);
    }
    Err(CodeSignError::Signing(
        "Failed to parse private key (tried PKCS#8 and PKCS#1)".to_string(),
    ))
}

fn build_spc_pe_image_data_value() -> Result<Any, CodeSignError> {
    let pe_image_data = SpcPeImageData {
        flags: BitString::from_bytes(&[])
            .map_err(|e| CodeSignError::Signing(format!("BitString error: {e:?}")))?,
        // Match Windows' historical Authenticode encoding for PE files.
        file: encode_spc_file("")?,
    };

    let der = pe_image_data
        .to_der()
        .map_err(|e| CodeSignError::Signing(format!("SpcPeImageData DER error: {e:?}")))?;

    Any::from_der(&der)
        .map_err(|e| CodeSignError::Signing(format!("SpcPeImageData Any error: {e:?}")))
}

fn build_spc_opus_info_attribute(
    description: Option<&str>,
    url: Option<&str>,
) -> Result<Attribute, CodeSignError> {
    let program_name = description.map(spc_program_name).transpose()?;
    let more_info = url.map(spc_more_info).transpose()?;
    let spc_opus_info = SpcSpOpusInfo {
        program_name,
        more_info,
    };
    attribute_from_sequence(SPC_SP_OPUS_INFO, &spc_opus_info)
}

fn build_spc_statement_type_attribute() -> Result<Attribute, CodeSignError> {
    let statement_type = SpcStatementType {
        purpose: SPC_INDIVIDUAL_SP_KEY_PURPOSE,
    };
    attribute_from_sequence(SPC_STATEMENT_TYPE, &statement_type)
}

fn attribute_from_sequence<T: Encode>(
    oid: ObjectIdentifier,
    value: &T,
) -> Result<Attribute, CodeSignError> {
    let der = value
        .to_der()
        .map_err(|e| CodeSignError::Signing(format!("Attribute DER error: {e:?}")))?;
    let attr_value = AttributeValue::from_der(&der)
        .map_err(|e| CodeSignError::Signing(format!("Attribute value error: {e:?}")))?;
    let mut values: SetOfVec<AttributeValue> = Default::default();
    values
        .insert(attr_value)
        .map_err(|e| CodeSignError::Signing(format!("Attribute set error: {e:?}")))?;

    Ok(Attribute { oid, values })
}

fn spc_program_name(value: &str) -> Result<Any, CodeSignError> {
    encode_spc_unicode(value)
}

fn spc_more_info(value: &str) -> Result<Any, CodeSignError> {
    encode_spc_url(value)
}

fn encode_spc_unicode(value: &str) -> Result<Any, CodeSignError> {
    let string = BmpString::from_utf8(value)
        .map_err(|e| CodeSignError::Signing(format!("BMPString error: {e:?}")))?;
    encode_any(&ContextSpecific {
        tag_number: TagNumber::new(0),
        tag_mode: TagMode::Implicit,
        value: string,
    })
}

fn encode_spc_url(value: &str) -> Result<Any, CodeSignError> {
    let url = Ia5String::new(value)
        .map_err(|e| CodeSignError::Signing(format!("URL IA5String error: {e:?}")))?;
    encode_any(&ContextSpecific {
        tag_number: TagNumber::new(0),
        tag_mode: TagMode::Implicit,
        value: url,
    })
}

fn encode_spc_file(value: &str) -> Result<Any, CodeSignError> {
    let unicode = BmpString::from_utf8(value)
        .map_err(|e| CodeSignError::Signing(format!("PE image file BMPString error: {e:?}")))?;
    let file_name = ContextSpecific {
        tag_number: TagNumber::new(0),
        tag_mode: TagMode::Implicit,
        value: unicode,
    };

    encode_any(&ContextSpecific {
        tag_number: TagNumber::new(2),
        tag_mode: TagMode::Explicit,
        value: file_name,
    })
}

fn encode_any<T: Encode>(value: &T) -> Result<Any, CodeSignError> {
    let der = value
        .to_der()
        .map_err(|e| CodeSignError::Signing(format!("ASN.1 DER error: {e:?}")))?;
    Any::from_der(&der).map_err(|e| CodeSignError::Signing(format!("ASN.1 Any error: {e:?}")))
}

fn algorithm_identifier_with_null(oid: ObjectIdentifier) -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid,
        parameters: Some(Any::null()),
    }
}

fn rsa_encryption_algorithm_identifier() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: RSA_ENCRYPTION,
        parameters: Some(Any::null()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join("-")
    }

    #[test]
    fn spc_pe_image_data_matches_windows_shape() {
        let any = build_spc_pe_image_data_value().expect("SpcPeImageData");
        assert_eq!(
            hex(&any.to_der().expect("SpcPeImageData DER")),
            "30-09-03-01-00-A0-04-A2-02-80-00"
        );
    }

    #[test]
    fn empty_opus_info_matches_windows_shape() {
        let attr = build_spc_opus_info_attribute(None, None).expect("SpcSpOpusInfo");
        let encoded = attr
            .values
            .iter()
            .next()
            .expect("attribute value")
            .to_der()
            .expect("attribute DER");
        assert_eq!(hex(&encoded), "30-00");
    }

    #[test]
    fn statement_type_matches_windows_shape() {
        let attr = build_spc_statement_type_attribute().expect("SpcStatementType");
        let encoded = attr
            .values
            .iter()
            .next()
            .expect("attribute value")
            .to_der()
            .expect("attribute DER");
        assert_eq!(hex(&encoded), "30-0C-06-0A-2B-06-01-04-01-82-37-02-01-15");
    }

    #[test]
    fn nested_cms_vs_standalone_cms_signature_is_same() {
        // Verify the outer CMS SignerInfo is structurally identical with/without
        // nesting — the signature value and signed_attrs must be identical
        // because they sign the same digest. Only unsigned_attrs differ.
        let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace root");
        let cert_path = workspace_root.join("test_data").join("test_combined.pem");
        if !cert_path.exists() {
            eprintln!("Skipping: test cert not found");
            return;
        }

        let loaded = crate::crypto::load_certificate(&cert_path, None).expect("load test cert");
        let digest = &[0xCC; 32];

        // Without nesting
        let standalone = create_signature(
            digest,
            &loaded.cert,
            &loaded.private_key,
            "sha256",
            Some("Test"),
            None,
            &loaded.extra_certs,
            &[],
        )
        .expect("standalone");

        // With nesting (use the standalone as the inner CMS)
        let nested = create_signature(
            digest,
            &loaded.cert,
            &loaded.private_key,
            "sha256",
            Some("Test"),
            None,
            &loaded.extra_certs,
            &[standalone.as_slice()],
        )
        .expect("nested");

        // Parse both as ContentInfo
        let standalone_ci =
            crate::verify::parse_content_info(&standalone).expect("parse standalone");
        let nested_ci = crate::verify::parse_content_info(&nested).expect("parse nested");

        // Parse SignedData
        let standalone_sd =
            crate::verify::parse_signed_data(&standalone_ci).expect("parse standalone sd");
        let nested_sd = crate::verify::parse_signed_data(&nested_ci).expect("parse nested sd");

        // Both should have one signer
        assert_eq!(standalone_sd.signer_infos.0.len(), 1);
        assert_eq!(nested_sd.signer_infos.0.len(), 1);

        let standalone_si = standalone_sd.signer_infos.0.iter().next().unwrap();
        let nested_si = nested_sd.signer_infos.0.iter().next().unwrap();

        // The signature bytes should be identical (same digest, same key)
        assert_eq!(
            standalone_si.signature.as_bytes(),
            nested_si.signature.as_bytes(),
            "Signature bytes must be identical: same digest + same key"
        );

        // signed_attrs should be identical
        let sa1 = standalone_si
            .signed_attrs
            .as_ref()
            .expect("standalone signed_attrs");
        let sa2 = nested_si
            .signed_attrs
            .as_ref()
            .expect("nested signed_attrs");
        assert_eq!(
            sa1.to_der().expect("encode sa1"),
            sa2.to_der().expect("encode sa2"),
            "signed_attrs must be identical"
        );

        // digest_alg must be identical
        assert_eq!(standalone_si.digest_alg.oid, nested_si.digest_alg.oid);

        // Only difference: nested has unsigned_attrs, standalone does not
        assert!(standalone_si.unsigned_attrs.is_none());
        assert!(nested_si.unsigned_attrs.is_some());

        // Check that the unsigned_attrs field uses the correct ASN.1 tag.
        // In CMS, unsignedAttrs is [1] IMPLICIT (tag byte 0xA1).
        // Find the tag byte in the DER: search for the signature value,
        // then the next constructed tag should be [1] IMPLICIT.
        let sig_bytes = nested_si.signature.as_bytes();
        // Search for signature bytes in the DER, then look at what follows
        if let Some(pos) = nested.windows(sig_bytes.len()).position(|w| w == sig_bytes) {
            let after_sig = pos + sig_bytes.len();
            eprintln!(
                "sig at offset {}, byte after sig: 0x{:02X}",
                pos,
                if after_sig < nested.len() {
                    nested[after_sig]
                } else {
                    0
                }
            );
            // Print some context around the end of the signature
            let start = after_sig.saturating_sub(2);
            let end = (after_sig + 8).min(nested.len());
            eprintln!("bytes around unsigned_attrs: {:02X?}", &nested[start..end]);
        }
    }

    #[test]
    fn nested_signature_attribute_value_round_trips() {
        // Create a real CMS signature to use as the "previous" CMS
        let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace root");
        let cert_path = workspace_root.join("test_data").join("test_combined.pem");
        if !cert_path.exists() {
            eprintln!("Skipping: test cert not found");
            return;
        }

        let loaded = crate::crypto::load_certificate(&cert_path, None).expect("load test cert");
        let previous_cms = create_signature(
            &[0xAA; 32],
            &loaded.cert,
            &loaded.private_key,
            "sha256",
            Some("Test"),
            None,
            &loaded.extra_certs,
            &[],
        )
        .expect("create CMS");
        let original_len = previous_cms.len();

        // Build the nested signature attribute using this real CMS
        let attrs = build_nested_unsigned_attrs(&[previous_cms.as_slice()])
            .expect("build_nested_unsigned_attrs");

        // Extract the attribute value and verify it round-trips
        let attr = attrs.iter().next().expect("attribute present");
        assert_eq!(
            attr.oid.to_string(),
            "1.3.6.1.4.1.311.2.4.1",
            "expected szOID_NESTED_SIGNATURE"
        );

        let value = attr.values.iter().next().expect("attribute value present");
        let value_der = value.to_der().expect("value to_der");
        assert_eq!(
            value_der.len(),
            original_len,
            "nested CMS DER length must be preserved"
        );
        assert_eq!(value_der, previous_cms, "nested CMS DER round-trips");

        // Must parse as a valid ContentInfo after round-trip
        let ci = crate::verify::parse_content_info(&value_der)
            .expect("round-tripped value must be a valid ContentInfo");
        assert_eq!(ci.content_type, const_oid::db::rfc5911::ID_SIGNED_DATA);

        // Parse the SignedData to verify it's valid
        let sd = crate::verify::parse_signed_data(&ci)
            .expect("round-tripped CMS must have valid SignedData");
        assert!(!sd.signer_infos.0.is_empty(), "must have a signer");
    }
}
