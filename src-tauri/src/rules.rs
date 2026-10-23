use crate::CodeSignError;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRules {
    pub default_sign_mode: String,   // "app" or "driver"
    pub default_digest_algo: String, // "sha256", "sha384", "sha512"
    pub default_timestamp: Option<String>,
    pub auto_download_cross_cert: bool,
    pub cross_cert_store_path: String,
}

impl Default for SignRules {
    fn default() -> Self {
        Self {
            default_sign_mode: "app".to_string(),
            default_digest_algo: "sha256".to_string(),
            default_timestamp: Some("http://timestamp.digicert.com".to_string()),
            auto_download_cross_cert: true,
            cross_cert_store_path: String::new(),
        }
    }
}

impl SignRules {
    fn config_path() -> PathBuf {
        crate::data_dir().join("rules.json")
    }

    pub fn load() -> Result<Self, CodeSignError> {
        let path = Self::config_path();
        if path.exists() {
            let data = fs::read_to_string(&path)?;
            let rules: SignRules = serde_json::from_str(&data)
                .map_err(|e| CodeSignError::Certificate(format!("Parse rules error: {e:?}")))?;
            Ok(rules)
        } else {
            let rules = SignRules::default();
            rules.save()?;
            Ok(rules)
        }
    }

    pub fn save(&self) -> Result<(), CodeSignError> {
        let path = Self::config_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let data = serde_json::to_string_pretty(self)
            .map_err(|e| CodeSignError::Certificate(format!("Serialize rules error: {e:?}")))?;
        fs::write(&path, data)?;
        Ok(())
    }
}
