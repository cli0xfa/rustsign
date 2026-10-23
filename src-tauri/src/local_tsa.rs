use crate::CodeSignError;
use crate::cert_manager;
use crate::crypto::{self, LoadedCertificate};
use crate::signer;
use crate::timestamp::{MessageImprint, PkiStatusInfo, TimeStampReq, TimeStampResp};
use cms::content_info::ContentInfo;
use const_oid::ObjectIdentifier;
use der::asn1::{Any, GeneralizedTime, SetOfVec};
use der::{DateTime, Decode, Encode, Sequence, Tag};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::name::{Name, RelativeDistinguishedName};

const LOCAL_TSA_POLICY_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.4146.1.1");

static SERIAL_COUNTER: AtomicU64 = AtomicU64::new(1);

struct ServerHandle {
    shutdown: Arc<AtomicBool>,
    thread: std::thread::JoinHandle<()>,
}

static SERVER: Mutex<Option<ServerHandle>> = Mutex::new(None);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalTsaConfig {
    pub port: u16,
    pub bind_address: String,
    pub cert_id: Option<String>,
    /// Unix timestamp (seconds since epoch). None means use current system time.
    pub fixed_time_secs: Option<i64>,
    pub digest_algorithm: String,
    /// Display name for this TSA. Included in the timestamp token.
    pub tsa_name: Option<String>,
}

impl Default for LocalTsaConfig {
    fn default() -> Self {
        Self {
            port: 18080,
            bind_address: "127.0.0.1".to_string(),
            cert_id: None,
            fixed_time_secs: None,
            digest_algorithm: "sha256".to_string(),
            tsa_name: None,
        }
    }
}

impl LocalTsaConfig {
    fn config_path() -> PathBuf {
        crate::data_dir().join("local_tsa.json")
    }

    pub fn load() -> Result<Self, CodeSignError> {
        let path = Self::config_path();
        if path.exists() {
            let data =
                std::fs::read_to_string(&path).map_err(|e| CodeSignError::Tsa(e.to_string()))?;
            serde_json::from_str(&data).map_err(|e| CodeSignError::Tsa(e.to_string()))
        } else {
            Ok(Self::default())
        }
    }

    pub fn save(&self) -> Result<(), CodeSignError> {
        let path = Self::config_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| CodeSignError::Tsa(format!("Failed to create config dir: {e}")))?;
        }
        let data =
            serde_json::to_string_pretty(self).map_err(|e| CodeSignError::Tsa(e.to_string()))?;
        std::fs::write(&path, data).map_err(|e| CodeSignError::Tsa(e.to_string()))?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalTsaStatus {
    pub running: bool,
    pub port: u16,
    pub bind_address: String,
    pub url: String,
}

#[derive(Clone, Debug, Sequence)]
struct TSTInfo {
    version: u8,
    policy: ObjectIdentifier,
    message_imprint: MessageImprint,
    serial_number: u64,
    gen_time: GeneralizedTime,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    tsa: Option<GeneralName>,
}

pub fn start_local_tsa(config: &LocalTsaConfig) -> Result<LocalTsaStatus, CodeSignError> {
    let mut guard = SERVER
        .lock()
        .map_err(|e| CodeSignError::Tsa(format!("Lock error: {e}")))?;
    if guard.is_some() {
        return Err(CodeSignError::Tsa("Server is already running".into()));
    }

    // Validate config
    let cert_id = config
        .cert_id
        .as_deref()
        .ok_or_else(|| CodeSignError::Tsa("No certificate selected".into()))?;

    let entry = cert_manager::get_certificate(cert_id)?
        .ok_or_else(|| CodeSignError::Tsa("Certificate not found".into()))?;

    let cert_password = entry.password.as_deref();
    let loaded_cert = crypto::load_certificate(&PathBuf::from(entry.file_path), cert_password)
        .map_err(|e| CodeSignError::Tsa(format!("Failed to load certificate: {e}")))?;

    if config.port == 0 {
        return Err(CodeSignError::Tsa(
            "Port must be between 1 and 65535".into(),
        ));
    }
    let address = format!("{}:{}", config.bind_address, config.port);
    let server = bind_server(&address)?;
    // Do not report success until binding has actually succeeded.
    config.save()?;

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    let cfg = config.clone();

    let builder = std::thread::Builder::new().name("tsa-server".into());
    let thread = builder
        .spawn(move || {
            run_server(server, cfg, loaded_cert, shutdown_clone);
        })
        .map_err(|e| CodeSignError::Tsa(format!("Failed to spawn server thread: {e}")))?;

    *guard = Some(ServerHandle { shutdown, thread });

    Ok(build_status(true, config))
}

fn bind_server(address: &str) -> Result<tiny_http::Server, CodeSignError> {
    // tiny_http closes its detached accept thread asynchronously on drop.
    // A short bounded retry accommodates immediate stop/start on Windows.
    for attempt in 0..20 {
        match tiny_http::Server::http(address) {
            Ok(server) => return Ok(server),
            Err(error) => {
                let in_use = error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::AddrInUse);
                if in_use && attempt < 19 {
                    std::thread::sleep(Duration::from_millis(25));
                } else {
                    return Err(CodeSignError::Tsa(format!(
                        "Failed to bind {address}: {error}"
                    )));
                }
            }
        }
    }
    unreachable!("the final bind attempt always returns")
}

pub fn stop_local_tsa() -> Result<LocalTsaStatus, CodeSignError> {
    let mut guard = SERVER
        .lock()
        .map_err(|e| CodeSignError::Tsa(format!("Lock error: {e}")))?;

    if let Some(handle) = guard.take() {
        handle.shutdown.store(true, Ordering::Relaxed);
        // Release the listener before returning so an immediate restart can bind.
        let _ = handle.thread.join();
    }

    // Load config to return current settings
    let config = LocalTsaConfig::load().unwrap_or_default();
    Ok(build_status(false, &config))
}

pub fn load_local_tsa_config() -> Result<LocalTsaConfig, CodeSignError> {
    LocalTsaConfig::load()
}

pub fn get_local_tsa_status() -> LocalTsaStatus {
    let running = SERVER
        .lock()
        .map(|guard| {
            guard
                .as_ref()
                .is_some_and(|handle| !handle.thread.is_finished())
        })
        .unwrap_or(false);
    let config = LocalTsaConfig::load().unwrap_or_default();
    build_status(running, &config)
}

fn build_status(running: bool, config: &LocalTsaConfig) -> LocalTsaStatus {
    LocalTsaStatus {
        running,
        port: config.port,
        bind_address: config.bind_address.clone(),
        url: format!(
            "http://{}:{}",
            if config.bind_address == "0.0.0.0" {
                "127.0.0.1"
            } else {
                &config.bind_address
            },
            config.port
        ),
    }
}

fn run_server(
    server: tiny_http::Server,
    config: LocalTsaConfig,
    loaded_cert: LoadedCertificate,
    shutdown: Arc<AtomicBool>,
) {
    while !shutdown.load(Ordering::Relaxed) {
        match server.try_recv() {
            Ok(Some(request)) => {
                handle_tsa_request(request, &loaded_cert, &config);
            }
            Ok(None) => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                eprintln!("TSA server recv error: {e}");
                break;
            }
        }
    }
}

fn handle_tsa_request(
    mut request: tiny_http::Request,
    cert: &LoadedCertificate,
    config: &LocalTsaConfig,
) {
    let resp_der = process_request(&mut request, cert, config);

    let response = tiny_http::Response::from_data(resp_der).with_header(
        tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/timestamp-reply"[..])
            .unwrap(),
    );

    if let Err(e) = request.respond(response) {
        eprintln!("TSA server response error: {e}");
    }
}

fn process_request(
    request: &mut tiny_http::Request,
    cert: &LoadedCertificate,
    config: &LocalTsaConfig,
) -> Vec<u8> {
    let mut body = Vec::new();
    if request.as_reader().read_to_end(&mut body).is_err() {
        return build_error_response(1);
    }

    let ts_req = match TimeStampReq::from_der(&body) {
        Ok(req) => req,
        Err(_) => return build_error_response(1),
    };

    if ts_req.version != 1 {
        return build_error_response(1);
    }

    let serial = SERIAL_COUNTER.fetch_add(1, Ordering::Relaxed);

    let ts_secs = match config.fixed_time_secs {
        Some(fixed) if fixed > 0 => fixed as u64,
        _ => match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => d.as_secs(),
            Err(_) => return build_error_response(2),
        },
    };

    let gen_time = match DateTime::from_unix_duration(Duration::from_secs(ts_secs)) {
        Ok(dt) => GeneralizedTime::from_date_time(dt),
        Err(_) => return build_error_response(2),
    };

    let tsa_general_name = match &config.tsa_name {
        Some(name) if !name.trim().is_empty() => build_tsa_general_name(name).ok(),
        _ => None,
    };

    let tst_info = TSTInfo {
        version: 1,
        policy: LOCAL_TSA_POLICY_OID,
        message_imprint: ts_req.message_imprint,
        serial_number: serial,
        gen_time,
        tsa: tsa_general_name,
    };

    let tst_der = match tst_info.to_der() {
        Ok(der) => der,
        Err(_) => return build_error_response(2),
    };

    let token_der = match signer::create_timestamp_token(
        &tst_der,
        &cert.cert,
        &cert.private_key,
        &config.digest_algorithm,
        &cert.extra_certs,
    ) {
        Ok(der) => der,
        Err(e) => {
            eprintln!("TSA signing error: {e}");
            return build_error_response(2);
        }
    };

    let token_ci = match ContentInfo::from_der(&token_der) {
        Ok(ci) => ci,
        Err(_) => return build_error_response(2),
    };

    let resp = TimeStampResp {
        status: PkiStatusInfo {
            status: 0,
            status_string: None,
            fail_info: None,
        },
        time_stamp_token: Some(token_ci),
    };

    resp.to_der().unwrap_or_else(|_| build_error_response(2))
}

/// Build a GeneralName::DirectoryName with a single commonName attribute
/// encoding the given human-readable name.
fn build_tsa_general_name(name: &str) -> Result<GeneralName, CodeSignError> {
    let value = Any::new(Tag::Utf8String, name.as_bytes().to_vec())
        .map_err(|e| CodeSignError::Tsa(format!("Any from name error: {e:?}")))?;

    let atv = AttributeTypeAndValue {
        oid: const_oid::db::rfc4519::COMMON_NAME,
        value,
    };

    let mut rdn = SetOfVec::new();
    rdn.insert(atv)
        .map_err(|e| CodeSignError::Tsa(format!("RDN insert error: {e:?}")))?;

    Ok(GeneralName::DirectoryName(Name::from(vec![
        RelativeDistinguishedName::from(rdn),
    ])))
}

fn build_error_response(status: u8) -> Vec<u8> {
    let resp = TimeStampResp {
        status: PkiStatusInfo {
            status,
            status_string: None,
            fail_info: None,
        },
        time_stamp_token: None,
    };
    resp.to_der().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::asn1::Any;

    #[test]
    fn wildcard_binding_advertises_a_connectable_local_url() {
        let config = LocalTsaConfig {
            bind_address: "0.0.0.0".into(),
            ..Default::default()
        };
        let status = build_status(true, &config);
        assert_eq!(status.bind_address, "0.0.0.0");
        assert_eq!(status.url, "http://127.0.0.1:18080");
    }

    #[test]
    fn tst_info_round_trip() {
        let mi = MessageImprint {
            hash_algorithm: x509_cert::spki::AlgorithmIdentifierOwned {
                oid: const_oid::db::rfc5912::ID_SHA_256,
                parameters: Some(Any::null()),
            },
            hashed_message: der::asn1::OctetString::new(vec![0xAA; 32]).unwrap(),
        };
        let dt = DateTime::from_unix_duration(Duration::from_secs(1700000000)).unwrap();
        let tst = TSTInfo {
            version: 1,
            policy: LOCAL_TSA_POLICY_OID,
            message_imprint: mi,
            serial_number: 42,
            gen_time: GeneralizedTime::from_date_time(dt),
            tsa: None,
        };
        let der = tst.to_der().expect("encode TSTInfo");
        let decoded = TSTInfo::from_der(&der).expect("decode TSTInfo");
        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.serial_number, 42);
    }

    #[test]
    fn serial_counter_increments() {
        let a = SERIAL_COUNTER.fetch_add(1, Ordering::Relaxed);
        let b = SERIAL_COUNTER.fetch_add(1, Ordering::Relaxed);
        assert_eq!(b, a + 1);
    }

    #[test]
    fn error_response_encodes() {
        let der = build_error_response(1);
        let resp = TimeStampResp::from_der(&der).expect("decode TimeStampResp");
        assert_eq!(resp.status.status, 1);
        assert!(resp.time_stamp_token.is_none());
    }

    #[test]
    fn error_response_rejection_encodes() {
        let der = build_error_response(2);
        let resp = TimeStampResp::from_der(&der).expect("decode TimeStampResp");
        assert_eq!(resp.status.status, 2);
    }
}
