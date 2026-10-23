use crate::CodeSignError;
use der::asn1::{BitString, OctetString};
use der::{Any, Encode, Tag};
use rand::RngCore;
use rand::rngs::OsRng;
use rsa::RsaPrivateKey;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rsa::signature::{SignatureEncoding, Signer};
use sha2::Sha256;
use std::path::PathBuf;
use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::{BasicConstraints, KeyUsage, KeyUsages};
use x509_cert::name::{Name, RdnSequence, RelativeDistinguishedName};
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::time::Validity;
use x509_cert::{Certificate, TbsCertificate};

const RSA_ENCRYPTION_OID: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const SHA256_WITH_RSA_OID: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const CODE_SIGNING_EKU: &str = "1.3.6.1.5.5.7.3.3";
const KERNEL_MODE_EKU: &str = "1.3.6.1.4.1.311.61.1.1";
const TIME_STAMPING_EKU: &str = "1.3.6.1.5.5.7.3.8";

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct TestCertResult {
    pub success: bool,
    pub message: String,
    pub root_pem: String,
    pub root_key_pem: String,
    pub sign_pem: String,
    pub sign_key_pem: String,
    pub sign_pfx_path: Option<String>,
    pub output_files: Vec<String>,
}

pub fn generate_test_cert_files(
    options: CertGenOptions,
    output_dir: Option<String>,
) -> Result<TestCertResult, CodeSignError> {
    let directory = output_dir
        .filter(|path| !path.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| crate::data_dir().join("test-certs"));
    std::fs::create_dir_all(&directory)?;
    let (root_pem, root_key_pem, root_pfx, sign, names) = if options.is_root_ca {
        let (root, sign) = generate_root_ca_pair(&options)?;
        (
            root.cert_pem,
            root.key_pem,
            Some(root.pfx_der),
            sign,
            [
                "test_codesign.pem",
                "test_codesign_key.pem",
                "test_codesign.pfx",
            ],
        )
    } else {
        (
            String::new(),
            String::new(),
            None,
            generate_subordinate_cert(&options)?,
            ["test_cert.pem", "test_cert_key.pem", "test_cert.pfx"],
        )
    };
    let mut files = Vec::new();
    if let Some(root_pfx) = root_pfx {
        let path = directory.join("test_root_ca.pfx");
        std::fs::write(&path, root_pfx)?;
        files.push(path.to_string_lossy().into_owned());
    }
    if options.is_root_ca {
        for (name, data) in [
            ("test_root_ca.pem", &root_pem),
            ("test_root_ca_key.pem", &root_key_pem),
        ] {
            let path = directory.join(name);
            std::fs::write(&path, data)?;
            files.push(path.to_string_lossy().into_owned());
        }
    }
    for (name, data) in [
        (names[0], sign.cert_pem.as_bytes()),
        (names[1], sign.key_pem.as_bytes()),
        (names[2], sign.pfx_der.as_slice()),
    ] {
        let path = directory.join(name);
        std::fs::write(&path, data)?;
        files.push(path.to_string_lossy().into_owned());
    }
    Ok(TestCertResult {
        success: true,
        message: format!("Generated certificates in {}", directory.display()),
        root_pem,
        root_key_pem,
        sign_pem: sign.cert_pem,
        sign_key_pem: sign.key_pem,
        sign_pfx_path: Some(directory.join(names[2]).to_string_lossy().into_owned()),
        output_files: files,
    })
}

/// The desktop CA workflow creates an actual issuing CA. The legacy self-signed
/// WDK-compatible helper remains unchanged for existing callers.
fn generate_root_ca_pair(
    options: &CertGenOptions,
) -> Result<(GeneratedCert, GeneratedCert), CodeSignError> {
    let mut rng = OsRng;
    let root_key = RsaPrivateKey::new(&mut rng, 2048)
        .map_err(|error| CodeSignError::Certificate(format!("CA key generation: {error}")))?;
    let root_options = CertGenOptions {
        sign_cn: options.root_cn.clone(),
        include_code_signing_eku: false,
        include_kernel_eku: false,
        include_timestamp_eku: false,
        ..options.clone()
    };
    let mut root_tbs = build_self_signed_codesign_tbs(
        &random_serial(&mut rng),
        &rsa_spki(&root_key)?,
        &root_options,
    )?;
    root_tbs.extensions = Some(vec![
        encode_extension(
            &const_oid::db::rfc5280::ID_CE_KEY_USAGE,
            true,
            &KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign),
        )?,
        encode_extension(
            &const_oid::db::rfc5280::ID_CE_BASIC_CONSTRAINTS,
            true,
            &BasicConstraints {
                ca: true,
                path_len_constraint: Some(0),
            },
        )?,
    ]);
    let root = sign_tbs(&root_tbs, &root_key)?;
    let sign_key = RsaPrivateKey::new(&mut rng, 2048)
        .map_err(|error| CodeSignError::Certificate(format!("Signing key generation: {error}")))?;
    let sign_tbs_value = build_codesign_tbs(
        &random_serial(&mut rng),
        &rsa_spki(&sign_key)?,
        &root,
        options,
    )?;
    let sign = sign_tbs(&sign_tbs_value, &root_key)?;
    Ok((
        GeneratedCert {
            cert_pem: cert_to_pem(&root),
            key_pem: key_to_pem(&root_key)?,
            pfx_der: build_pfx(&root, &root_key, None, &options.password)?,
        },
        GeneratedCert {
            cert_pem: cert_to_pem(&sign),
            key_pem: key_to_pem(&sign_key)?,
            pfx_der: build_pfx(&sign, &sign_key, Some(&root), &options.password)?,
        },
    ))
}

#[derive(Clone)]
pub struct GeneratedCert {
    pub cert_pem: String,
    pub key_pem: String,
    pub pfx_der: Vec<u8>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CertGenOptions {
    /// Common Name for the root CA certificate (default: "RustSign Test Root CA")
    #[serde(default = "default_root_cn")]
    pub root_cn: String,
    /// Common Name for the code-signing certificate (default: "RustSign Test Code Signing")
    #[serde(default = "default_sign_cn")]
    pub sign_cn: String,
    /// Organization (O) for both certificates
    #[serde(default)]
    pub organization: Option<String>,
    /// Country (C) for both certificates
    #[serde(default)]
    pub country: Option<String>,
    /// Include Code Signing EKU (1.3.6.1.5.5.7.3.3)
    #[serde(default = "default_true")]
    #[serde(rename = "code_signing_eku")]
    pub include_code_signing_eku: bool,
    /// Include Kernel Mode Code Signing EKU (1.3.6.1.4.1.311.61.1.1)
    #[serde(default = "default_true")]
    #[serde(rename = "kernel_mode_eku")]
    pub include_kernel_eku: bool,
    /// Include Time Stamping EKU (1.3.6.1.5.5.7.3.8)
    #[serde(default)]
    #[serde(rename = "timestamp_eku")]
    pub include_timestamp_eku: bool,
    /// Validity period in years (default: 5)
    #[serde(default = "default_validity_years")]
    pub validity_years: u32,
    /// PFX password
    #[serde(default = "default_password")]
    #[serde(rename = "pfx_password")]
    pub password: String,
    /// Generate a self-signed root CA (true) or a subordinate cert (false)
    #[serde(default = "default_true")]
    pub is_root_ca: bool,
    /// ID of the issuer CA certificate when is_root_ca is false
    #[serde(default)]
    pub issuer_cert_id: Option<String>,
}

fn default_root_cn() -> String {
    "RustSign Test Root CA".into()
}
fn default_sign_cn() -> String {
    "RustSign Test Code Signing".into()
}
fn default_true() -> bool {
    true
}
fn default_validity_years() -> u32 {
    5
}
fn default_password() -> String {
    "test123".into()
}

impl Default for CertGenOptions {
    fn default() -> Self {
        Self {
            root_cn: default_root_cn(),
            sign_cn: default_sign_cn(),
            organization: None,
            country: None,
            include_code_signing_eku: true,
            include_kernel_eku: true,
            include_timestamp_eku: false,
            validity_years: 5,
            password: default_password(),
            is_root_ca: true,
            issuer_cert_id: None,
        }
    }
}

/// Generate a subordinate certificate signed by an issuer loaded from the certificate database.
/// Used when is_root_ca is false. Returns a single GeneratedCert.
pub fn generate_subordinate_cert(options: &CertGenOptions) -> Result<GeneratedCert, CodeSignError> {
    let issuer_id = options
        .issuer_cert_id
        .as_deref()
        .ok_or_else(|| CodeSignError::Certificate("No issuer CA certificate selected".into()))?;

    let issuer_entry = crate::cert_manager::get_certificate(issuer_id)?
        .ok_or_else(|| CodeSignError::Certificate("Issuer CA certificate not found".into()))?;

    let issuer_password = issuer_entry.password.as_deref();
    let issuer_loaded =
        crate::crypto::load_certificate(&PathBuf::from(&issuer_entry.file_path), issuer_password)?;

    let mut rng = OsRng;
    let sign_key = RsaPrivateKey::new(&mut rng, 2048)
        .map_err(|e| CodeSignError::Certificate(format!("Key gen: {e:?}")))?;
    let sign_spki = rsa_spki(&sign_key)?;

    let issuer_key = RsaPrivateKey::from_pkcs8_der(&issuer_loaded.private_key)
        .or_else(|_| RsaPrivateKey::from_pkcs1_der(&issuer_loaded.private_key))
        .map_err(|e| CodeSignError::Certificate(format!("Issuer key parse: {e:?}")))?;

    let serial = random_serial(&mut rng);
    let tbs = build_codesign_tbs(&serial, &sign_spki, &issuer_loaded.cert, options)?;
    let cert = sign_tbs(&tbs, &issuer_key)?;

    let cert_pem = cert_to_pem(&cert);
    let key_pem = key_to_pem(&sign_key)?;
    let pfx = build_pfx(
        &cert,
        &sign_key,
        Some(&issuer_loaded.cert),
        &options.password,
    )?;

    Ok(GeneratedCert {
        cert_pem,
        key_pem,
        pfx_der: pfx,
    })
}

/// Generate a self-signed code-signing certificate suitable for Windows driver
/// test signing.
///
/// This mirrors the WDK "MakeCert" test-certificate pattern (the kind of
/// certificate produced by `MakeCert` and used to sign `test_data/true.sys`):
/// a single self-signed end-entity certificate whose `issuer` equals its
/// `subject`. That one certificate is installed into the Trusted Root
/// Certification Authorities store AND used to sign drivers, so the embedded
/// Authenticode signature is self-contained — Windows can build the
/// certificate chain straight from the embedded certificate without needing a
/// separate CA certificate to be present in the signature or the store.
///
/// The previous implementation generated a two-tier hierarchy (a self-signed
/// root CA plus a leaf code-signing certificate signed by that root). Only the
/// leaf was embedded in the driver signature, and because the leaf was not
/// self-signed Windows could not build a chain to a trusted root and rejected
/// the signature with "A certificate chain could not be built to a trusted
/// root authority". Using a self-signed certificate fixes that.
///
/// The same self-signed certificate is returned as both the "root" and "sign"
/// certificate so existing callers (which save `test_root_ca.pem` for the
/// Trusted Root store and `test_codesign.pfx` for signing) keep working
/// unchanged.
pub fn generate_test_cert_pair(
    options: &CertGenOptions,
) -> Result<(GeneratedCert, GeneratedCert), CodeSignError> {
    let mut rng = OsRng;

    // Single key pair: the certificate is self-signed, so the same key signs
    // the certificate and the driver.
    let sign_key = RsaPrivateKey::new(&mut rng, 2048)
        .map_err(|e| CodeSignError::Certificate(format!("Sign key gen: {e:?}")))?;
    let sign_spki = rsa_spki(&sign_key)?;

    let serial = random_serial(&mut rng);
    let tbs = build_self_signed_codesign_tbs(&serial, &sign_spki, options)?;
    let cert = sign_tbs(&tbs, &sign_key)?;

    let cert_pem = cert_to_pem(&cert);
    let key_pem = key_to_pem(&sign_key)?;
    // No issuer cert to bundle: the certificate is self-contained.
    let pfx = build_pfx(&cert, &sign_key, None, &options.password)?;

    let generated = GeneratedCert {
        cert_pem,
        key_pem,
        pfx_der: pfx,
    };

    // The same self-signed certificate serves as both the trust anchor
    // (installed in Trusted Root) and the signing certificate.
    Ok((generated.clone(), generated))
}

fn random_serial(rng: &mut OsRng) -> SerialNumber {
    loop {
        let mut bytes = [0u8; 16];
        rng.fill_bytes(&mut bytes);
        bytes[0] &= 0x7F; // keep the integer positive

        // `SerialNumber::new` rejects leading zero bytes and an all-zero
        // value. Rather than panicking when `bytes[0]` happens to be zero
        // (~1/128 after masking), skip the leading zeros and redraw only if
        // the entire buffer is zero.
        let Some(start) = bytes.iter().position(|&b| b != 0) else {
            continue;
        };
        if let Ok(serial) = SerialNumber::new(&bytes[start..]) {
            return serial;
        }
    }
}

fn rsa_spki(key: &RsaPrivateKey) -> Result<SubjectPublicKeyInfoOwned, CodeSignError> {
    let pub_key = key.to_public_key();
    let pk_der = pub_key
        .to_pkcs1_der()
        .map_err(|e| CodeSignError::Certificate(format!("RSA public key DER: {e:?}")))?;

    let algorithm = AlgorithmIdentifierOwned {
        oid: RSA_ENCRYPTION_OID,
        parameters: Some(Any::null()),
    };

    let subject_public_key = BitString::from_bytes(pk_der.as_bytes())
        .map_err(|e| CodeSignError::Certificate(format!("BitString: {e:?}")))?;

    Ok(SubjectPublicKeyInfoOwned {
        algorithm,
        subject_public_key,
    })
}

/// Build the TBS of a self-signed code-signing certificate (issuer == subject).
///
/// This is the WDK test-certificate shape: a v3 end-entity certificate with a
/// digital-signature key usage and a code-signing (optionally also kernel-mode
/// / timestamping) EKU, signed by its own key. No BasicConstraints / CA:TRUE
/// extension is added, matching the WDK "MakeCert" output.
fn build_self_signed_codesign_tbs(
    serial: &SerialNumber,
    spki: &SubjectPublicKeyInfoOwned,
    options: &CertGenOptions,
) -> Result<TbsCertificate, CodeSignError> {
    let validity = Validity::from_now(std::time::Duration::from_secs(
        options.validity_years as u64 * 365 * 24 * 3600,
    ))
    .map_err(|e| CodeSignError::Certificate(format!("Validity: {e:?}")))?;

    // Self-signed: the issuer is the subject.
    let subject = build_distinguished_name(
        &options.sign_cn,
        options.organization.as_deref(),
        options.country.as_deref(),
    )?;
    let issuer = subject.clone();

    let key_usage = KeyUsage(KeyUsages::DigitalSignature.into());

    let mut ext_list = Vec::new();
    ext_list.push(encode_extension(
        &const_oid::db::rfc5280::ID_CE_KEY_USAGE,
        true,
        &key_usage,
    )?);

    // Conditionally add EKU extension
    if options.include_code_signing_eku
        || options.include_kernel_eku
        || options.include_timestamp_eku
    {
        let eku_der = build_eku_extension(options);
        ext_list.push(Extension {
            extn_id: const_oid::db::rfc5280::ID_CE_EXT_KEY_USAGE,
            critical: false,
            extn_value: OctetString::new(eku_der)
                .map_err(|e| CodeSignError::Certificate(format!("EKU OCTET STRING: {e:?}")))?,
        });
    }

    let signature_alg = sha256_with_rsa_alg_id();

    Ok(TbsCertificate {
        version: x509_cert::Version::V3,
        serial_number: serial.clone(),
        signature: signature_alg,
        issuer,
        validity,
        subject,
        subject_public_key_info: spki.clone(),
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(ext_list),
    })
}

fn build_codesign_tbs(
    serial: &SerialNumber,
    spki: &SubjectPublicKeyInfoOwned,
    issuer_cert: &Certificate,
    options: &CertGenOptions,
) -> Result<TbsCertificate, CodeSignError> {
    let validity = Validity::from_now(std::time::Duration::from_secs(
        options.validity_years as u64 * 365 * 24 * 3600,
    ))
    .map_err(|e| CodeSignError::Certificate(format!("Validity: {e:?}")))?;

    let issuer = issuer_cert.tbs_certificate.subject.clone();
    let subject = build_distinguished_name(
        &options.sign_cn,
        options.organization.as_deref(),
        options.country.as_deref(),
    )?;

    let key_usage = KeyUsage(KeyUsages::DigitalSignature.into());

    let mut ext_list = Vec::new();
    ext_list.push(encode_extension(
        &const_oid::db::rfc5280::ID_CE_KEY_USAGE,
        true,
        &key_usage,
    )?);

    // Conditionally add EKU extension
    if options.include_code_signing_eku
        || options.include_kernel_eku
        || options.include_timestamp_eku
    {
        let eku_der = build_eku_extension(options);
        ext_list.push(Extension {
            extn_id: const_oid::db::rfc5280::ID_CE_EXT_KEY_USAGE,
            critical: false,
            extn_value: OctetString::new(eku_der)
                .map_err(|e| CodeSignError::Certificate(format!("EKU OCTET STRING: {e:?}")))?,
        });
    }

    let signature_alg = sha256_with_rsa_alg_id();

    Ok(TbsCertificate {
        version: x509_cert::Version::V3,
        serial_number: serial.clone(),
        signature: signature_alg,
        issuer,
        validity,
        subject,
        subject_public_key_info: spki.clone(),
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(ext_list),
    })
}

/// Build the DER for ExtendedKeyUsage: SEQUENCE of OIDs
fn build_eku_extension(options: &CertGenOptions) -> Vec<u8> {
    let mut oid_ders: Vec<Vec<u8>> = Vec::new();

    if options.include_code_signing_eku {
        let oid = const_oid::ObjectIdentifier::new_unwrap(CODE_SIGNING_EKU);
        oid_ders.push(oid.to_der().unwrap_or_default());
    }
    if options.include_kernel_eku {
        let oid = const_oid::ObjectIdentifier::new_unwrap(KERNEL_MODE_EKU);
        oid_ders.push(oid.to_der().unwrap_or_default());
    }
    if options.include_timestamp_eku {
        let oid = const_oid::ObjectIdentifier::new_unwrap(TIME_STAMPING_EKU);
        oid_ders.push(oid.to_der().unwrap_or_default());
    }

    let inner_len: usize = oid_ders.iter().map(|d| d.len()).sum();
    let mut result = Vec::with_capacity(4 + inner_len);
    result.push(0x30); // SEQUENCE tag
    if inner_len < 128 {
        result.push(inner_len as u8);
    } else if inner_len < 256 {
        result.push(0x81);
        result.push(inner_len as u8);
    } else {
        result.push(0x82);
        result.push((inner_len >> 8) as u8);
        result.push(inner_len as u8);
    }
    for der in &oid_ders {
        result.extend_from_slice(der);
    }
    result
}

fn sign_tbs(
    tbs: &TbsCertificate,
    signer_key: &RsaPrivateKey,
) -> Result<Certificate, CodeSignError> {
    let tbs_der = tbs
        .to_der()
        .map_err(|e| CodeSignError::Certificate(format!("TBS DER: {e:?}")))?;

    let signing_key = SigningKey::<Sha256>::new(signer_key.clone());
    let sig = signing_key.sign(&tbs_der);

    let sig_bytes = SignatureEncoding::to_bytes(&sig);
    let signature = BitString::from_bytes(sig_bytes.as_ref())
        .map_err(|e| CodeSignError::Certificate(format!("Signature BitString: {e:?}")))?;

    Ok(Certificate {
        tbs_certificate: tbs.clone(),
        signature_algorithm: sha256_with_rsa_alg_id(),
        signature,
    })
}

/// Build a Distinguished Name with CN, optional O (organization) and C (country).
fn build_distinguished_name(
    cn: &str,
    org: Option<&str>,
    country: Option<&str>,
) -> Result<Name, CodeSignError> {
    let mut atvs: Vec<AttributeTypeAndValue> = Vec::new();

    // CN (required)
    atvs.push(make_atv(const_oid::db::rfc4519::CN, cn)?);

    // O (optional)
    if let Some(o) = org
        && !o.trim().is_empty()
    {
        atvs.push(make_atv(const_oid::db::rfc4519::ORGANIZATION_NAME, o)?);
    }

    // C (optional)
    if let Some(c) = country
        && !c.trim().is_empty()
    {
        atvs.push(make_atv(const_oid::db::rfc4519::COUNTRY_NAME, c)?);
    }

    let mut rdn: RelativeDistinguishedName = Default::default();
    for atv in atvs {
        rdn.0
            .insert(atv)
            .map_err(|e| CodeSignError::Certificate(format!("RDN insert: {e:?}")))?;
    }

    let mut rdns = RdnSequence::default();
    rdns.0.push(rdn);
    Ok(rdns)
}

fn make_atv(
    oid: const_oid::ObjectIdentifier,
    value: &str,
) -> Result<AttributeTypeAndValue, CodeSignError> {
    let any_value = Any::new(Tag::Utf8String, value.as_bytes().to_vec())
        .map_err(|e| CodeSignError::Certificate(format!("ATV value: {e:?}")))?;
    Ok(AttributeTypeAndValue {
        oid,
        value: any_value,
    })
}

fn encode_extension<T: Encode>(
    oid: &const_oid::ObjectIdentifier,
    critical: bool,
    value: &T,
) -> Result<Extension, CodeSignError> {
    let der = value
        .to_der()
        .map_err(|e| CodeSignError::Certificate(format!("Extension DER: {e:?}")))?;
    let extn_value = OctetString::new(der)
        .map_err(|e| CodeSignError::Certificate(format!("Extension OCTET STRING: {e:?}")))?;
    Ok(Extension {
        extn_id: *oid,
        critical,
        extn_value,
    })
}

fn sha256_with_rsa_alg_id() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: SHA256_WITH_RSA_OID,
        parameters: Some(Any::null()),
    }
}

fn cert_to_pem(cert: &Certificate) -> String {
    let der = cert.to_der().expect("cert DER");
    pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::LF, &der)
        .expect("cert PEM encode")
}

fn key_to_pem(key: &RsaPrivateKey) -> Result<String, CodeSignError> {
    let der = key
        .to_pkcs8_der()
        .map_err(|e| CodeSignError::Certificate(format!("Key PKCS8 DER: {e:?}")))?;
    Ok(
        pem_rfc7468::encode_string("PRIVATE KEY", pem_rfc7468::LineEnding::LF, der.as_bytes())
            .expect("key PEM encode"),
    )
}

fn build_pfx(
    cert: &Certificate,
    key: &RsaPrivateKey,
    extra_cert: Option<&Certificate>,
    password: &str,
) -> Result<Vec<u8>, CodeSignError> {
    let cert_der = cert
        .to_der()
        .map_err(|e| CodeSignError::Certificate(format!("Cert DER: {e:?}")))?;
    let key_der = key
        .to_pkcs8_der()
        .map_err(|e| CodeSignError::Certificate(format!("Key DER: {e:?}")))?;
    let key_bytes = key_der.as_bytes();

    // Collect extra cert DERs as owned Vec<u8> so we can reference slices
    let extra_der: Option<Vec<u8>> = match extra_cert {
        Some(c) => Some(
            c.to_der()
                .map_err(|e| CodeSignError::Certificate(format!("Extra cert DER: {e:?}")))?,
        ),
        None => None,
    };
    let extra_ref: Option<&[u8]> = extra_der.as_deref();

    let pfx = p12::PFX::new(
        &cert_der,
        key_bytes,
        extra_ref,
        password,
        "rustsign-test-cert",
    )
    .ok_or_else(|| CodeSignError::Certificate("PFX build failed".to_string()))?;
    Ok(pfx.to_der())
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::Decode;
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::signature::{Keypair, Verifier};

    /// Regression test for the PFX-password-ignored bug.
    ///
    /// The frontend (`src/types/index.ts` `CertGenOptions`) sends these exact
    /// JSON keys to the `generate_test_cert` command. The Rust struct must
    /// deserialize them via `#[serde(rename = ...)]` — otherwise serde cannot
    /// find the key and silently falls back to the default (`password` →
    /// "test123", EKU toggles → true), which is exactly what made the PFX
    /// password field appear to do nothing.
    #[test]
    fn cert_gen_options_deserializes_from_frontend_keys() {
        let json = r#"{
            "root_cn": "My Root CA",
            "sign_cn": "My Code Signing",
            "organization": "Acme",
            "country": "US",
            "validity_years": 3,
            "pfx_password": "hunter2",
            "code_signing_eku": false,
            "kernel_mode_eku": false,
            "timestamp_eku": true,
            "is_root_ca": true,
            "issuer_cert_id": null
        }"#;
        let opts: CertGenOptions = serde_json::from_str(json).expect("deserialize");

        // The reported bug: custom password must be honored, not defaulted.
        assert_eq!(opts.password, "hunter2", "pfx_password must be honored");
        // Same bug class: EKU toggles must be honored.
        assert!(
            !opts.include_code_signing_eku,
            "code_signing_eku must be honored"
        );
        assert!(!opts.include_kernel_eku, "kernel_mode_eku must be honored");
        assert!(opts.include_timestamp_eku, "timestamp_eku must be honored");
        assert_eq!(opts.validity_years, 3);
        assert_eq!(opts.sign_cn, "My Code Signing");
    }

    /// When the password key is absent entirely, the default ("test123")
    /// must still apply — this is the intended fallback, distinct from the
    /// bug where an *explicitly provided* password was ignored.
    #[test]
    fn cert_gen_options_defaults_password_when_absent() {
        let json = r#"{ "is_root_ca": true }"#;
        let opts: CertGenOptions = serde_json::from_str(json).expect("deserialize");
        assert_eq!(opts.password, "test123");
        assert!(opts.include_code_signing_eku);
        assert!(opts.include_kernel_eku);
    }

    #[test]
    fn generate_and_parse_test_certs() {
        let options = CertGenOptions {
            password: "test123".into(),
            ..Default::default()
        };
        let (root, sign) = generate_test_cert_pair(&options).expect("generate certs");

        // The test certificate is self-signed: the same certificate is returned
        // as both the "root" (Trusted Root anchor) and the "sign" certificate.
        assert_eq!(
            root.cert_pem, sign.cert_pem,
            "root and sign cert must match"
        );

        // Parse the certificate
        let (_, sign_der) =
            pem_rfc7468::decode_vec(sign.cert_pem.as_bytes()).expect("decode sign PEM");
        let sign_cert = Certificate::from_der(&sign_der).expect("parse sign cert");

        // Self-signed: issuer == subject, matching the WDK test-certificate shape.
        assert_eq!(
            sign_cert.tbs_certificate.issuer.to_string(),
            sign_cert.tbs_certificate.subject.to_string(),
            "test certificate must be self-signed"
        );
        assert!(
            sign_cert
                .tbs_certificate
                .subject
                .to_string()
                .contains("RustSign Test Code Signing")
        );

        // Parse PFX
        let _pfx = p12::PFX::parse(&sign.pfx_der).expect("parse PFX");

        // Parse key
        let (_, key_der) =
            pem_rfc7468::decode_vec(sign.key_pem.as_bytes()).expect("decode sign key PEM");
        let key = RsaPrivateKey::from_pkcs8_der(&key_der).expect("parse sign key");

        // The self-signed certificate's signature must verify against its own
        // public key — this is what lets Windows build the chain from the
        // embedded signature alone.
        let signing_key = SigningKey::<Sha256>::new(key);
        let verifying_key = signing_key.verifying_key();
        let tbs_der = sign_cert.tbs_certificate.to_der().expect("TBS DER");
        let sig_bytes = sign_cert.signature.as_bytes().expect("signature bytes");
        let sig = rsa::pkcs1v15::Signature::try_from(sig_bytes).expect("decode signature");
        verifying_key
            .verify(&tbs_der, &sig)
            .expect("self-signed certificate signature must verify");
    }

    /// End-to-end check that a custom PFX password is actually used when
    /// building the PFX (the user-facing symptom of the rename bug was that
    /// the password was always "test123" regardless of the field).
    #[test]
    fn pfx_password_is_honored() {
        let options = CertGenOptions {
            password: "hunter2".into(),
            ..Default::default()
        };
        let (_root, sign) = generate_test_cert_pair(&options).expect("generate certs");

        // The PFX must open with the requested password...
        let pfx = p12::PFX::parse(&sign.pfx_der).expect("parse PFX");
        pfx.cert_bags("hunter2")
            .expect("open PFX with correct password");

        // ...and must NOT open with the old default that the bug always fell
        // back to.
        assert!(
            pfx.cert_bags("test123").is_err(),
            "PFX must not open with the default password when a custom one was set"
        );
    }
}
