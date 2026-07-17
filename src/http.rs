//! Thin HTTP client for the xShellz control plane with typed error mapping.

use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION};
use reqwest::Method;
use serde::de::DeserializeOwned;

use crate::config::{resolve_api_key, resolve_api_url};
use crate::error::{Error, Result};

const USER_AGENT: &str = concat!("xshellz-rust/", env!("CARGO_PKG_VERSION"));

/// 403 message fragments emitted by the control plane's guard chain. All
/// guards abort with 403 + message; quota/entitlement are distinguished by
/// message text.
const QUOTA_FRAGMENTS: [&str; 2] = [
    // "You've reached your plan's agent shell limit (N)."
    "agent shell limit",
    // entitlement gate
    "plan does not include agent shells",
];

/// Bearer-authenticated JSON client for `https://api.xshellz.com/v1`.
#[derive(Clone)]
pub(crate) struct ApiClient {
    pub(crate) http: reqwest::Client,
    pub(crate) base_url: String,
}

fn transport_err(err: reqwest::Error) -> Error {
    Error::Io(std::io::Error::other(err))
}

impl ApiClient {
    pub fn new(api_key: Option<&str>, api_url: Option<&str>, timeout: Duration) -> Result<Self> {
        let key = resolve_api_key(api_key)?;
        let base_url = resolve_api_url(api_url);

        let mut headers = HeaderMap::new();
        let mut auth = HeaderValue::from_str(&format!("Bearer {key}"))
            .map_err(|_| Error::Auth("the API key contains invalid header characters".into()))?;
        auth.set_sensitive(true);
        headers.insert(AUTHORIZATION, auth);
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));

        let http = reqwest::Client::builder()
            .default_headers(headers)
            .user_agent(USER_AGENT)
            .timeout(timeout)
            .build()
            .map_err(transport_err)?;

        Ok(Self { http, base_url })
    }

    async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<String> {
        let mut request = self
            .http
            .request(method, format!("{}{path}", self.base_url));
        if let Some(json) = body {
            request = request.json(&json);
        }
        let response = request.send().await.map_err(transport_err)?;
        let status = response.status().as_u16();
        let text = response.text().await.map_err(transport_err)?;
        if status >= 400 {
            return Err(map_error(status, &text));
        }
        Ok(text)
    }

    async fn request_json<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<T> {
        let text = self.request(method, path, body).await?;
        serde_json::from_str(&text).map_err(|e| Error::Api {
            status: 200,
            body: format!("the API returned unparseable JSON: {e}"),
        })
    }

    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.request_json(Method::GET, path, None).await
    }

    pub async fn post<T: DeserializeOwned>(
        &self,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<T> {
        self.request_json(Method::POST, path, body).await
    }

    pub async fn put<T: DeserializeOwned>(
        &self,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<T> {
        self.request_json(Method::PUT, path, body).await
    }

    pub async fn delete(&self, path: &str) -> Result<()> {
        self.request(Method::DELETE, path, None).await.map(|_| ())
    }
}

/// Map a non-success control-plane response to a typed [`Error`].
fn map_error(status: u16, text: &str) -> Error {
    let body: serde_json::Value = serde_json::from_str(text).unwrap_or(serde_json::Value::Null);
    let error_code = body.get("error").and_then(|v| v.as_str()).unwrap_or("");
    let mut message = body
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();
    if message.is_empty() {
        message = if text.is_empty() {
            format!("HTTP {status}")
        } else {
            text.to_owned()
        };
    }

    match status {
        401 => Error::Auth(format!(
            "Authentication failed (401): the API key is missing, invalid, \
             expired, or revoked. Create a personal access token with `read` \
             and `write` scopes from your xShellz dashboard (Settings -> API \
             tokens) or via POST /v1/auth/tokens. Server said: {message}"
        )),
        403 => {
            let lowered = message.to_lowercase();
            if QUOTA_FRAGMENTS.iter().any(|f| lowered.contains(f)) {
                Error::Quota(format!(
                    "{message} Tip: on the free tier only one sandbox may \
                     exist at a time - use Sandbox::list() and \
                     Sandbox::connect() to attach to the existing box, or \
                     kill() it first."
                ))
            } else if error_code == "verification_required" {
                Error::Auth(format!("Account verification required (403): {message}"))
            } else {
                Error::Auth(format!("Forbidden (403): {message}"))
            }
        }
        _ => Error::Api {
            status,
            body: if text.is_empty() {
                message
            } else {
                text.to_owned()
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quota_fragments_map_to_quota() {
        for message in [
            "You've reached your plan's agent shell limit (1).",
            "Your plan does not include agent shells.",
        ] {
            let err = map_error(403, &format!(r#"{{"message":"{message}"}}"#));
            assert!(
                matches!(err, Error::Quota(_)),
                "{message} must map to Quota"
            );
        }
    }

    #[test]
    fn other_403s_map_to_auth() {
        for body in [
            r#"{"message":"Agent shells are in limited preview."}"#,
            r#"{"error":"verification_required","message":"Verify your account to unlock."}"#,
            "",
        ] {
            let err = map_error(403, body);
            assert!(matches!(err, Error::Auth(_)), "{body:?} must map to Auth");
        }
    }

    #[test]
    fn throttle_and_capacity_map_to_api() {
        assert!(matches!(
            map_error(429, r#"{"message":"Too Many Attempts."}"#),
            Error::Api { status: 429, .. }
        ));
        assert!(matches!(
            map_error(503, r#"{"message":"No host capacity."}"#),
            Error::Api { status: 503, .. }
        ));
    }

    #[test]
    fn non_json_body_is_preserved() {
        match map_error(500, "<html>oops</html>") {
            Error::Api { status: 500, body } => assert_eq!(body, "<html>oops</html>"),
            other => panic!("expected Api error, got {other:?}"),
        }
    }
}
