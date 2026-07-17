//! In-memory ed25519 SSH keypair generation and private-key loading.
//!
//! A keypair is generated per [`Sandbox::create`](crate::Sandbox::create) and
//! never touches disk; the control plane only ever sees the public half.

use ssh_key::getrandom::SysRng;
use ssh_key::rand_core::UnwrapErr;
use ssh_key::{Algorithm, LineEnding, PrivateKey};

use crate::error::{Error, Result};

pub(crate) const DEFAULT_KEY_COMMENT: &str = "xshellz-sdk";

/// An in-memory ed25519 keypair.
pub(crate) struct KeyPair {
    /// The key object used to authenticate SSH sessions.
    pub private_key: PrivateKey,
    /// The private key serialized in OpenSSH PEM format (persist it if you
    /// plan to `detach()` and `connect()` again later from another process).
    pub private_key_openssh: String,
    /// The single-line OpenSSH public key (`ssh-ed25519 <base64> <comment>`)
    /// sent to the control plane.
    pub public_key_line: String,
}

fn key_err(context: &str, err: impl std::fmt::Display) -> Error {
    Error::Ssh(format!("{context}: {err}"))
}

/// Generate a fresh in-memory ed25519 keypair.
pub(crate) fn generate_keypair(comment: &str) -> Result<KeyPair> {
    let mut rng = UnwrapErr(SysRng);
    let mut private_key = PrivateKey::random(&mut rng, Algorithm::Ed25519)
        .map_err(|e| key_err("could not generate an ed25519 keypair", e))?;
    private_key.set_comment(comment);

    let private_key_openssh = private_key
        .to_openssh(LineEnding::LF)
        .map_err(|e| key_err("could not serialize the private key", e))?
        .to_string();
    let public_key_line = private_key
        .public_key()
        .to_openssh()
        .map_err(|e| key_err("could not serialize the public key", e))?;

    Ok(KeyPair {
        private_key,
        private_key_openssh,
        public_key_line,
    })
}

/// Load a private key from its OpenSSH PEM serialization.
///
/// Any OpenSSH-format key type parses (ed25519 is the SDK's native type);
/// encrypted (passphrase-protected) keys are rejected.
pub(crate) fn load_private_key(openssh_pem: &str) -> Result<PrivateKey> {
    let key = PrivateKey::from_openssh(openssh_pem).map_err(|e| {
        Error::Ssh(format!(
            "could not parse the private key: expected an unencrypted \
             OpenSSH-format private key (the value of \
             Sandbox::private_key_openssh()). Details: {e}"
        ))
    })?;
    if key.is_encrypted() {
        return Err(Error::Ssh(
            "the private key is passphrase-protected; the SDK only supports \
             unencrypted in-memory keys"
                .to_owned(),
        ));
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use regex::Regex;

    use super::*;

    /// The server-side `ssh_public_key` validation pattern
    /// (`AgentShellSpawnRequest`), narrowed to the only algorithm the SDK
    /// emits.
    const SERVER_PUBLIC_KEY_PATTERN: &str = r"^ssh-ed25519\s+[A-Za-z0-9+/=]+(\s+.*)?$";

    #[test]
    fn ed25519_round_trip() {
        let keypair = generate_keypair(DEFAULT_KEY_COMMENT).expect("keypair generates");

        // 1. The public line matches the control plane's validation regex.
        let regex = Regex::new(SERVER_PUBLIC_KEY_PATTERN).expect("pattern compiles");
        assert!(
            regex.is_match(&keypair.public_key_line),
            "public key line {:?} must match the server validation pattern",
            keypair.public_key_line
        );
        assert!(keypair.public_key_line.ends_with(" xshellz-sdk"));

        // 2. The private PEM parses back and yields the same public half.
        assert!(keypair
            .private_key_openssh
            .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
        let reloaded = load_private_key(&keypair.private_key_openssh).expect("PEM parses back");
        assert_eq!(
            reloaded.public_key().key_data(),
            keypair.private_key.public_key().key_data(),
            "reloaded private key must produce the same public key"
        );
        assert_eq!(reloaded.algorithm(), Algorithm::Ed25519);
    }

    #[test]
    fn keypairs_are_unique() {
        let a = generate_keypair(DEFAULT_KEY_COMMENT).unwrap();
        let b = generate_keypair(DEFAULT_KEY_COMMENT).unwrap();
        assert_ne!(a.public_key_line, b.public_key_line);
    }

    #[test]
    fn garbage_private_key_is_rejected() {
        let err = load_private_key("not a key").unwrap_err();
        assert!(matches!(err, Error::Ssh(_)));
    }
}
