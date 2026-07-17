//! Background processes: [`Sandbox::spawn`](crate::Sandbox::spawn) and the
//! [`JobHandle`] it returns.
//!
//! Jobs run inside the sandbox under `nohup`, detached from the SSH session,
//! with stdout+stderr redirected to `~/.xshellz/jobs/<job_id>.log` (and the
//! pid recorded in `<job_id>.pid` so [`Sandbox::jobs`](crate::Sandbox::jobs)
//! can report liveness later). They survive the SSH connection closing and
//! your process exiting - but not the box stopping or restarting.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::{Error, Result};
use crate::sandbox::Sandbox;
use crate::transport::ExecRequest;

/// Generate a short (8 hex chars) process-unique job id.
pub(crate) fn short_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or_default();
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mixed = nanos
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(u64::from(std::process::id()))
        .wrapping_add(count.wrapping_mul(0x1000_0000_0000_003F));
    format!("{:08x}", (mixed >> 32) as u32 ^ mixed as u32)
}

/// The in-box log file path for a job id (display form; `~` is the box's
/// `/root` home).
pub(crate) fn log_path_for(id: &str) -> String {
    format!("~/.xshellz/jobs/{id}.log")
}

/// Options for [`Sandbox::spawn`](crate::Sandbox::spawn).
#[derive(Debug, Clone, Default)]
pub struct SpawnOptions {
    pub(crate) name: Option<String>,
}

impl SpawnOptions {
    /// Human-readable prefix for the job id (sanitized to `[A-Za-z0-9._-]`),
    /// e.g. `.name("worker")` yields job ids like `worker-1a2b3c4d`.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }
}

/// A background process started with [`Sandbox::spawn`](crate::Sandbox::spawn).
///
/// Borrows the [`Sandbox`] it runs in - keep the sandbox alive for as long as
/// you want to control the job. The job itself lives in the box regardless;
/// [`Sandbox::jobs`](crate::Sandbox::jobs) rediscovers it later by id.
#[derive(Debug)]
pub struct JobHandle<'sbx> {
    pub(crate) sandbox: &'sbx Sandbox,
    pub(crate) id: String,
    pub(crate) pid: u32,
}

impl JobHandle<'_> {
    /// The job's id (the log/pid file stem under `~/.xshellz/jobs/`).
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The pid of the job's `bash -c` process inside the sandbox.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// The in-box path of the job's combined stdout+stderr log file.
    #[must_use]
    pub fn log_path(&self) -> String {
        log_path_for(&self.id)
    }

    /// Whether the job's process is still alive (`kill -0` probe).
    pub async fn is_running(&self) -> Result<bool> {
        let output = self
            .sandbox
            .exec(ExecRequest::plain(format!(
                "kill -0 {} 2>/dev/null",
                self.pid
            )))
            .await?;
        Ok(output.exit_code == 0)
    }

    /// The last `tail_lines` lines of the job's log file (100 is a sensible
    /// default).
    pub async fn logs(&self, tail_lines: usize) -> Result<String> {
        let output = self
            .sandbox
            .exec(ExecRequest::plain(format!(
                "tail -n {tail_lines} \"$HOME/.xshellz/jobs/{}.log\"",
                self.id
            )))
            .await?;
        if output.exit_code != 0 {
            return Err(Error::Io(std::io::Error::other(format!(
                "could not read job log {} (exit {}): {}",
                self.log_path(),
                output.exit_code,
                String::from_utf8_lossy(&output.stderr).trim()
            ))));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    /// Stop the job: SIGTERM, then SIGKILL if it is still alive after a ~5s
    /// grace period. Idempotent - stopping a finished job is a no-op.
    pub async fn stop(&self) -> Result<()> {
        let pid = self.pid;
        let script = format!(
            "kill -TERM {pid} 2>/dev/null\n\
             for i in 1 2 3 4 5 6 7 8 9 10; do\n\
             kill -0 {pid} 2>/dev/null || exit 0\n\
             sleep 0.5\n\
             done\n\
             kill -KILL {pid} 2>/dev/null\n\
             exit 0"
        );
        self.sandbox.exec(ExecRequest::plain(script)).await?;
        Ok(())
    }
}

/// One job as listed by [`Sandbox::jobs`](crate::Sandbox::jobs).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct JobInfo {
    /// The job's id (log/pid file stem).
    pub id: String,
    /// The recorded pid (0 when the pid file was empty/unreadable).
    pub pid: u32,
    /// Whether the process is currently alive (`kill -0` probe).
    pub running: bool,
    /// The in-box path of the job's log file.
    pub log_path: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_ids_are_hex_and_unique() {
        let a = short_id();
        let b = short_id();
        assert_eq!(a.len(), 8);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    #[test]
    fn log_path_is_under_jobs_dir() {
        assert_eq!(log_path_for("worker-1a"), "~/.xshellz/jobs/worker-1a.log");
    }
}
