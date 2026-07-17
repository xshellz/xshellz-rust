//! Data objects returned by the xShellz SDK.

use serde::Deserialize;

/// The outcome of a single [`Sandbox::run`](crate::Sandbox::run) invocation.
///
/// A non-zero [`exit_code`](Self::exit_code) does **not** produce an `Err` -
/// it is data, exactly like a local subprocess call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandResult {
    /// Everything the command wrote to stdout (UTF-8, lossily decoded).
    pub stdout: String,
    /// Everything the command wrote to stderr (UTF-8, lossily decoded).
    pub stderr: String,
    /// The command's exit status.
    pub exit_code: i32,
}

impl CommandResult {
    /// True when the command exited with status 0.
    #[must_use]
    pub fn ok(&self) -> bool {
        self.exit_code == 0
    }
}

/// A sandbox as reported by the control plane (snake_case wire shape).
///
/// Deserialization is tolerant of missing keys so a newer/older API version
/// never breaks the SDK.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct SandboxInfo {
    /// The sandbox's unique identifier.
    #[serde(default)]
    pub uuid: String,
    /// Human-readable name.
    #[serde(default)]
    pub name: String,
    /// Lifecycle state, e.g. `"running"` or `"stopped"`.
    #[serde(default)]
    pub status: String,
    /// Ready-to-copy `ssh -p <port> root@<host>` command line.
    #[serde(default)]
    pub ssh_command: Option<String>,
    /// SSH host, e.g. `"shellus1.xshellz.com"`.
    #[serde(default)]
    pub ssh_host: Option<String>,
    /// SSH port.
    #[serde(default)]
    pub ssh_port: Option<u16>,
    /// Whether the web terminal is provisioned.
    #[serde(default)]
    pub web_terminal_ready: bool,
    /// Whether the box is exempt from idle-stopping.
    #[serde(default)]
    pub always_on: bool,
    /// Remaining metered trial hours (free tier).
    #[serde(default)]
    pub trial_hours_remaining: f64,
    /// When the box was spawned (ISO-8601), if known.
    #[serde(default)]
    pub spawned_at: Option<String>,
    /// When the sandbox record was created (ISO-8601), if known.
    #[serde(default)]
    pub created_at: Option<String>,
    /// Isolation backend, e.g. `"gvisor"`.
    #[serde(default)]
    pub isolation: Option<String>,
    /// Whether the box runs under gVisor kernel isolation.
    #[serde(default)]
    pub gvisor: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_result_ok() {
        let ok = CommandResult {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
        };
        let failed = CommandResult {
            exit_code: 1,
            ..ok.clone()
        };
        assert!(ok.ok());
        assert!(!failed.ok());
    }

    #[test]
    fn sandbox_info_tolerates_missing_and_unknown_fields() {
        let info: SandboxInfo =
            serde_json::from_str(r#"{"uuid":"u-1","status":"running","brand_new_field":42}"#)
                .expect("partial payload deserializes");
        assert_eq!(info.uuid, "u-1");
        assert_eq!(info.status, "running");
        assert_eq!(info.ssh_port, None);
        assert!(!info.gvisor);
    }
}
