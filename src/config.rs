//! Configuration resolution: explicit argument > environment > default.

use crate::error::{Error, Result};

pub(crate) const DEFAULT_API_URL: &str = "https://api.xshellz.com/v1";
pub(crate) const API_KEY_ENV: &str = "XSHELLZ_API_KEY";
pub(crate) const API_URL_ENV: &str = "XSHELLZ_API_URL";

/// Resolve the API key or return a helpful [`Error::Auth`].
pub(crate) fn resolve_api_key(explicit: Option<&str>) -> Result<String> {
    let key = explicit
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .or_else(|| std::env::var(API_KEY_ENV).ok())
        .unwrap_or_default();
    let key = key.trim().to_owned();
    if key.is_empty() {
        return Err(Error::Auth(format!(
            "No xShellz API key found. Pass an explicit api_key or set the \
             {API_KEY_ENV} environment variable. Create a personal access \
             token with `read` and `write` scopes from your xShellz dashboard \
             (Settings -> API tokens) or via POST /v1/auth/tokens."
        )));
    }
    Ok(key)
}

/// Resolve the API base URL (no trailing slash).
pub(crate) fn resolve_api_url(explicit: Option<&str>) -> String {
    explicit
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .or_else(|| std::env::var(API_URL_ENV).ok())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_API_URL.to_owned())
        .trim_end_matches('/')
        .to_owned()
}

#[cfg(test)]
mod tests {
    use std::sync::{Mutex, MutexGuard, OnceLock};

    use super::*;

    /// Serializes env-var mutation across tests in this binary.
    fn env_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(Mutex::default)
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    fn explicit_key_beats_env() {
        let _guard = env_lock();
        std::env::set_var(API_KEY_ENV, "env-key");
        assert_eq!(
            resolve_api_key(Some("explicit-key")).unwrap(),
            "explicit-key"
        );
        std::env::remove_var(API_KEY_ENV);
    }

    #[test]
    fn env_key_used_when_no_explicit() {
        let _guard = env_lock();
        std::env::set_var(API_KEY_ENV, "env-key");
        assert_eq!(resolve_api_key(None).unwrap(), "env-key");
        std::env::remove_var(API_KEY_ENV);
    }

    #[test]
    fn missing_key_is_auth_error() {
        let _guard = env_lock();
        std::env::remove_var(API_KEY_ENV);
        let err = resolve_api_key(None).unwrap_err();
        assert!(matches!(err, Error::Auth(_)));
        assert!(err.to_string().contains("XSHELLZ_API_KEY"));
    }

    #[test]
    fn whitespace_key_is_auth_error() {
        let _guard = env_lock();
        std::env::remove_var(API_KEY_ENV);
        assert!(matches!(resolve_api_key(Some("   ")), Err(Error::Auth(_))));
    }

    #[test]
    fn url_precedence_and_trailing_slash() {
        let _guard = env_lock();
        std::env::set_var(API_URL_ENV, "https://env.example.com/v1/");
        assert_eq!(
            resolve_api_url(Some("https://explicit.example.com/v1/")),
            "https://explicit.example.com/v1"
        );
        assert_eq!(resolve_api_url(None), "https://env.example.com/v1");
        std::env::remove_var(API_URL_ENV);
        assert_eq!(resolve_api_url(None), DEFAULT_API_URL);
    }
}
