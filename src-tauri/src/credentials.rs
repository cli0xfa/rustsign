//! OS-backed storage for certificate passwords.

use crate::CodeSignError;
#[cfg(debug_assertions)]
use std::collections::HashMap;
#[cfg(debug_assertions)]
use std::sync::{Mutex, OnceLock};

const SERVICE: &str = "com.codesigntool.app.certificate-passwords";

#[cfg(debug_assertions)]
static ISOLATED_PASSWORDS: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();

pub(crate) fn uses_isolated_debug_store() -> bool {
    cfg!(debug_assertions) && std::env::var_os("RUSTSIGN_DATA_DIR").is_some()
}

pub fn store_password(id: &str, password: &str) -> Result<(), CodeSignError> {
    if uses_isolated_debug_store() {
        #[cfg(debug_assertions)]
        isolated_passwords()
            .lock()
            .map_err(|_| credential_error("access the test credential store", "lock poisoned"))?
            .insert(id.to_owned(), password.to_owned());
        return Ok(());
    }

    let entry = keyring::Entry::new(SERVICE, id)
        .map_err(|error| credential_error("open the OS credential store", error))?;
    entry
        .set_password(password)
        .map_err(|error| credential_error("save the PFX password", error))
}

pub fn load_password(id: &str) -> Result<Option<String>, CodeSignError> {
    if uses_isolated_debug_store() {
        #[cfg(debug_assertions)]
        return Ok(isolated_passwords()
            .lock()
            .map_err(|_| credential_error("access the test credential store", "lock poisoned"))?
            .get(id)
            .cloned());
        #[cfg(not(debug_assertions))]
        return Ok(None);
    }

    let entry = keyring::Entry::new(SERVICE, id)
        .map_err(|error| credential_error("open the OS credential store", error))?;
    match entry.get_password() {
        Ok(password) => Ok(Some(password)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => Err(credential_error("read the saved PFX password", error)),
    }
}

pub fn delete_password(id: &str) -> Result<(), CodeSignError> {
    if uses_isolated_debug_store() {
        #[cfg(debug_assertions)]
        isolated_passwords()
            .lock()
            .map_err(|_| credential_error("access the test credential store", "lock poisoned"))?
            .remove(id);
        return Ok(());
    }

    let entry = keyring::Entry::new(SERVICE, id)
        .map_err(|error| credential_error("open the OS credential store", error))?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(error) => Err(credential_error("delete the saved PFX password", error)),
    }
}

fn credential_error(action: &str, error: impl std::fmt::Display) -> CodeSignError {
    CodeSignError::Certificate(format!(
        "Could not {action}: {error}. Ensure the OS credential store is available."
    ))
}

#[cfg(debug_assertions)]
fn isolated_passwords() -> &'static Mutex<HashMap<String, String>> {
    ISOLATED_PASSWORDS.get_or_init(|| Mutex::new(HashMap::new()))
}
