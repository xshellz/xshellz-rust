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

/// Live resource usage for a running sandbox, as returned by
/// [`Sandbox::stats`](crate::Sandbox::stats) (snake_case wire shape of
/// `GET /v1/shells/agent/{uuid}/stats`).
///
/// `*_allowed_*` fields are the plan's ceilings; the rest is live usage.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct SandboxStats {
    /// Memory currently in use, in MB.
    #[serde(default)]
    pub mem_used_mb: f64,
    /// The cgroup memory limit, in MB.
    #[serde(default)]
    pub mem_limit_mb: f64,
    /// The plan's memory ceiling, in MB.
    #[serde(default)]
    pub mem_allowed_mb: f64,
    /// Current CPU utilization percentage.
    #[serde(default)]
    pub cpu_percent: f64,
    /// The plan's CPU ceiling, in vCPUs.
    #[serde(default)]
    pub cpu_allowed_vcpus: f64,
    /// Number of cgroup periods in which the box was CPU-throttled.
    #[serde(default)]
    pub cpu_throttled_periods: u64,
    /// Number of processes currently running.
    #[serde(default)]
    pub pids_current: u64,
    /// The plan's process-count ceiling.
    #[serde(default)]
    pub pids_allowed: u64,
    /// Disk space used, in MB.
    #[serde(default)]
    pub disk_used_mb: f64,
    /// The plan's disk ceiling, in MB.
    #[serde(default)]
    pub disk_allowed_mb: f64,
    /// Network bytes received, in MB.
    #[serde(default)]
    pub net_rx_mb: f64,
    /// Network bytes transmitted, in MB.
    #[serde(default)]
    pub net_tx_mb: f64,
    /// Block-device bytes read, in MB.
    #[serde(default)]
    pub blk_read_mb: f64,
    /// Block-device bytes written, in MB.
    #[serde(default)]
    pub blk_write_mb: f64,
}

/// One process inside the sandbox, as reported by
/// [`Sandbox::procs`](crate::Sandbox::procs).
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct ProcessInfo {
    /// Process id.
    #[serde(default)]
    pub pid: u32,
    /// Command name (`ps -o comm`).
    #[serde(default)]
    pub comm: String,
    /// CPU usage percentage.
    #[serde(default)]
    pub cpu: f64,
    /// Memory usage percentage.
    #[serde(default)]
    pub mem: f64,
}

/// Top processes + session count + disk usage for a running sandbox, as
/// returned by [`Sandbox::procs`](crate::Sandbox::procs) (wire shape of
/// `GET /v1/shells/agent/{uuid}/procs`).
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct SandboxProcs {
    /// The box's top processes.
    #[serde(default)]
    pub procs: Vec<ProcessInfo>,
    /// Number of active SSH sessions.
    #[serde(default)]
    pub sessions: u64,
    /// Names of detected coding agents running inside the box.
    #[serde(default)]
    pub agents: Vec<String>,
    /// Disk space used, in MB.
    #[serde(default)]
    pub disk_used_mb: f64,
    /// The plan's disk ceiling, in MB.
    #[serde(default)]
    pub disk_allowed_mb: f64,
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
    fn stats_tolerates_missing_fields_and_int_or_float_numbers() {
        let stats: SandboxStats = serde_json::from_str(
            r#"{"mem_used_mb":123,"cpu_percent":4.5,"pids_current":17,"brand_new":1}"#,
        )
        .expect("partial payload deserializes");
        assert_eq!(stats.mem_used_mb, 123.0);
        assert_eq!(stats.cpu_percent, 4.5);
        assert_eq!(stats.pids_current, 17);
        assert_eq!(stats.disk_used_mb, 0.0);
    }

    #[test]
    fn procs_deserializes_nested_process_list() {
        let procs: SandboxProcs = serde_json::from_str(
            r#"{"procs":[{"pid":42,"comm":"node","cpu":1.5,"mem":2.0}],"sessions":2,"agents":["claude"],"disk_used_mb":100,"disk_allowed_mb":2048}"#,
        )
        .expect("payload deserializes");
        assert_eq!(procs.procs.len(), 1);
        assert_eq!(procs.procs[0].pid, 42);
        assert_eq!(procs.procs[0].comm, "node");
        assert_eq!(procs.sessions, 2);
        assert_eq!(procs.agents, vec!["claude"]);
        assert_eq!(procs.disk_allowed_mb, 2048.0);
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
