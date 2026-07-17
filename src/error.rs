//! Typed errors returned by the xShellz SDK.

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Every error the xShellz SDK can return.
///
/// A non-zero command exit code is **not** an error - it is data on
/// [`CommandResult`](crate::CommandResult).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Authentication or authorization failed (HTTP 401/403).
    ///
    /// Returned for a missing/invalid API key, insufficient token scopes,
    /// account verification requirements, and other access gates.
    #[error("{0}")]
    Auth(String),

    /// The account's sandbox quota or plan entitlement blocks the operation.
    ///
    /// The control plane returns HTTP 403 both when the plan's concurrent
    /// sandbox limit is reached ("agent shell limit") and when the plan does
    /// not include sandboxes at all. On the free tier the limit is 1
    /// concurrent box - use [`Sandbox::list`](crate::Sandbox::list) +
    /// [`Sandbox::connect`](crate::Sandbox::connect) to attach to the
    /// existing one instead of creating a new box.
    #[error("{0}")]
    Quota(String),

    /// The sandbox is not in the `running` state (or no longer exists).
    #[error("{0}")]
    NotRunning(String),

    /// [`Sandbox::get_or_create`](crate::Sandbox::get_or_create) found an
    /// existing sandbox with the requested name but no private key for it -
    /// neither an explicit `private_key` option nor a keystore file.
    ///
    /// The message says where a key was expected. Recover by passing the key
    /// explicitly, restoring the keystore file, or destroying the box.
    #[error("{0}")]
    MissingKey(String),

    /// [`Sandbox::run_code`](crate::Sandbox::run_code) was called with a
    /// language the SDK does not support. The message lists the supported
    /// languages.
    #[error("{0}")]
    UnsupportedLanguage(String),

    /// A command executed with a [`RunOptions::timeout`](crate::RunOptions::timeout)
    /// exceeded its deadline.
    #[error("{0}")]
    CommandTimeout(String),

    /// Any other non-success API response (4xx/5xx), e.g. the 429 create
    /// throttle or a 503 host-capacity error.
    #[error("API error (HTTP {status}): {body}")]
    Api {
        /// The HTTP status code.
        status: u16,
        /// The raw response body (JSON text when the API returned JSON).
        body: String,
    },

    /// An SSH data-plane failure (connect, auth, or channel error).
    #[error("SSH error: {0}")]
    Ssh(String),

    /// A local I/O or network-transport failure.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
