//! Local private-key store for persistent named sandboxes.
//!
//! [`Sandbox::get_or_create`](crate::Sandbox::get_or_create) persists the
//! generated private key here (default `~/.xshellz/keys/`, one file per
//! sanitized sandbox name, mode 0600) so a later run - or another process -
//! can re-attach to the same named box without re-plumbing keys.
//!
//! **Security note:** keys are stored in plaintext on disk, protected only by
//! the 0600 file mode. Delete a key file to revoke local access; destroy the
//! box to revoke it for real.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// The default keystore directory: `~/.xshellz/keys/` (resolved via `$HOME`).
pub(crate) fn default_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .map(|home| PathBuf::from(home).join(".xshellz").join("keys"))
}

/// Reduce a sandbox name to a safe file stem: `[A-Za-z0-9._-]` kept, every
/// other character replaced with `_`.
pub(crate) fn sanitize_name(name: &str) -> String {
    let sanitized: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if sanitized.is_empty() {
        "_".to_owned()
    } else {
        sanitized
    }
}

/// The keystore file path for a sandbox name.
pub(crate) fn key_path(dir: &Path, name: &str) -> PathBuf {
    dir.join(format!("{}.key", sanitize_name(name)))
}

/// Load the stored private key for `name`, or `None` when no file exists.
pub(crate) fn load(dir: &Path, name: &str) -> Result<Option<String>> {
    match std::fs::read_to_string(key_path(dir, name)) {
        Ok(pem) => Ok(Some(pem)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::Io(e)),
    }
}

/// Persist a private key for `name` (directory 0700, file 0600).
pub(crate) fn save(dir: &Path, name: &str, private_key_openssh: &str) -> Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let path = key_path(dir, name);
    std::fs::write(&path, private_key_openssh)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitizes_hostile_names() {
        assert_eq!(sanitize_name("my box/../../etc"), "my_box_.._.._etc");
        assert_eq!(sanitize_name("build-box_2.0"), "build-box_2.0");
        assert_eq!(sanitize_name(""), "_");
    }

    #[test]
    fn save_load_round_trip_with_0600_perms() {
        let dir = tempfile::tempdir().unwrap();
        let path = save(dir.path(), "demo", "PRIVATE KEY").unwrap();
        assert_eq!(path, dir.path().join("demo.key"));
        assert_eq!(
            load(dir.path(), "demo").unwrap().as_deref(),
            Some("PRIVATE KEY")
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "key file must be 0600");
            let dir_mode = std::fs::metadata(dir.path()).unwrap().permissions().mode();
            assert_eq!(dir_mode & 0o777, 0o700, "keystore dir must be 0700");
        }
    }

    #[test]
    fn load_missing_is_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load(dir.path(), "absent").unwrap().is_none());
    }

    #[test]
    fn save_creates_nested_directories() {
        let root = tempfile::tempdir().unwrap();
        let nested = root.path().join("a").join("b");
        save(&nested, "demo", "K").unwrap();
        assert!(nested.join("demo.key").is_file());
    }
}
