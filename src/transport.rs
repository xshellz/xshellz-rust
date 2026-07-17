//! SSH data plane, behind a small transport trait for testability.
//!
//! The real implementation ([`RusshTransport`]) speaks SSH as `root` to the
//! sandbox. Host keys are auto-accepted: sandboxes are throwaway boxes whose
//! host keys are generated at spawn time, so there is nothing to pin against.
//!
//! File transfer is exec-based (`cat` over the SSH exec channel) rather than
//! SFTP: it needs no extra subsystem or dependency and is binary-safe in both
//! directions, matching the Go SDK's approach.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use russh::client;
use russh::keys::{PrivateKey, PrivateKeyWithHashAlg, PublicKey};
use russh::ChannelMsg;

use crate::error::{Error, Result};

/// Streaming output callback: receives decoded chunks as they arrive.
pub(crate) type OutputCallback = Box<dyn FnMut(&str) + Send>;

/// A boxed future, used to keep the [`Transport`] trait object-safe.
pub(crate) type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// One remote command execution.
pub(crate) struct ExecRequest {
    /// The full shell command line (already wrapped with env/cwd).
    pub command: String,
    /// Bytes to feed to the command's stdin (stdin is closed either way).
    pub stdin: Option<Vec<u8>>,
    /// Wall-clock deadline for the command.
    pub timeout: Option<Duration>,
    /// Streaming stdout callback.
    pub on_stdout: Option<OutputCallback>,
    /// Streaming stderr callback.
    pub on_stderr: Option<OutputCallback>,
}

impl ExecRequest {
    pub(crate) fn plain(command: String) -> Self {
        Self {
            command,
            stdin: None,
            timeout: None,
            on_stdout: None,
            on_stderr: None,
        }
    }
}

/// Raw outcome of an execution (bytes, so file reads stay binary-safe).
pub(crate) struct ExecOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: i32,
}

/// Minimal data-plane surface the [`Sandbox`](crate::Sandbox) needs.
pub(crate) trait Transport: Send {
    fn exec(&mut self, request: ExecRequest) -> BoxFuture<'_, Result<ExecOutput>>;
}

/// Quote a string for POSIX `sh`.
pub(crate) fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

fn is_valid_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() || first == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Wrap a command with optional `cd` and environment exports.
///
/// Environment variable names are validated (sshd rarely honours `AcceptEnv`,
/// so variables are exported in the remote shell instead). Exports are sorted
/// by name for determinism.
pub(crate) fn build_shell_command(
    command: &str,
    cwd: Option<&str>,
    env: &HashMap<String, String>,
) -> Result<String> {
    let mut parts: Vec<String> = Vec::new();
    if !env.is_empty() {
        let mut names: Vec<&String> = env.keys().collect();
        names.sort();
        let mut exports: Vec<String> = Vec::with_capacity(names.len());
        for name in names {
            if !is_valid_env_name(name) {
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("invalid environment variable name: {name:?}"),
                )));
            }
            exports.push(format!("{name}={}", shell_quote(&env[name])));
        }
        parts.push(format!("export {}", exports.join(" ")));
    }
    if let Some(cwd) = cwd {
        parts.push(format!("cd {}", shell_quote(cwd)));
    }
    parts.push(command.to_owned());
    Ok(parts.join(" && "))
}

fn ssh_err(err: russh::Error) -> Error {
    Error::Ssh(err.to_string())
}

/// Accepts any host key: sandbox host keys are minted at spawn time, so
/// there is no out-of-band fingerprint to verify against.
struct AcceptAllHostKeys;

impl client::Handler for AcceptAllHostKeys {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &PublicKey,
    ) -> std::result::Result<bool, Self::Error> {
        Ok(true)
    }
}

/// Real SSH transport: everything runs over exec channels as `root`.
pub(crate) struct RusshTransport {
    session: client::Handle<AcceptAllHostKeys>,
}

impl RusshTransport {
    pub(crate) async fn connect(
        host: &str,
        port: u16,
        private_key: &PrivateKey,
        connect_timeout: Duration,
    ) -> Result<Self> {
        let config = Arc::new(client::Config::default());
        let mut session = tokio::time::timeout(
            connect_timeout,
            client::connect(config, (host, port), AcceptAllHostKeys),
        )
        .await
        .map_err(|_| Error::Ssh(format!("timed out connecting to {host}:{port}")))?
        .map_err(|e| Error::Ssh(format!("could not connect to {host}:{port}: {e}")))?;

        let auth = session
            .authenticate_publickey(
                "root",
                PrivateKeyWithHashAlg::new(Arc::new(private_key.clone()), None),
            )
            .await
            .map_err(|e| Error::Ssh(format!("public key authentication failed: {e}")))?;
        if !auth.success() {
            return Err(Error::Ssh(
                "the sandbox rejected the SSH key. Make sure the private key \
                 is the one whose public half the sandbox was created with."
                    .to_owned(),
            ));
        }

        Ok(Self { session })
    }

    async fn exec_inner(&mut self, mut request: ExecRequest) -> Result<ExecOutput> {
        let mut channel = self.session.channel_open_session().await.map_err(ssh_err)?;
        channel
            .exec(true, request.command.as_bytes())
            .await
            .map_err(ssh_err)?;
        if let Some(stdin) = request.stdin.take() {
            channel.data(&stdin[..]).await.map_err(ssh_err)?;
        }
        channel.eof().await.map_err(ssh_err)?;

        let mut stdout: Vec<u8> = Vec::new();
        let mut stderr: Vec<u8> = Vec::new();
        let mut exit_code: Option<i32> = None;

        let drain = async {
            while let Some(msg) = channel.wait().await {
                match msg {
                    ChannelMsg::Data { ref data } => {
                        stdout.extend_from_slice(data);
                        if let Some(callback) = request.on_stdout.as_mut() {
                            callback(&String::from_utf8_lossy(data));
                        }
                    }
                    ChannelMsg::ExtendedData { ref data, ext: 1 } => {
                        stderr.extend_from_slice(data);
                        if let Some(callback) = request.on_stderr.as_mut() {
                            callback(&String::from_utf8_lossy(data));
                        }
                    }
                    ChannelMsg::ExitStatus { exit_status } => {
                        exit_code = Some(exit_status as i32);
                    }
                    _ => {}
                }
            }
        };

        match request.timeout {
            Some(deadline) => tokio::time::timeout(deadline, drain).await.map_err(|_| {
                Error::CommandTimeout(format!(
                    "Command did not finish within {deadline:?}: {:?}",
                    request.command
                ))
            })?,
            None => drain.await,
        }

        Ok(ExecOutput {
            stdout,
            stderr,
            exit_code: exit_code.unwrap_or(-1),
        })
    }
}

impl Transport for RusshTransport {
    fn exec(&mut self, request: ExecRequest) -> BoxFuture<'_, Result<ExecOutput>> {
        Box::pin(self.exec_inner(request))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_single_quotes_safely() {
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
        assert_eq!(shell_quote("plain"), "'plain'");
    }

    #[test]
    fn builds_plain_command() {
        assert_eq!(
            build_shell_command("echo hi", None, &HashMap::new()).unwrap(),
            "echo hi"
        );
    }

    #[test]
    fn builds_command_with_cwd_and_env() {
        let env = HashMap::from([
            ("CI".to_owned(), "1".to_owned()),
            ("APP_ENV".to_owned(), "two words".to_owned()),
        ]);
        assert_eq!(
            build_shell_command("make test", Some("/srv/app"), &env).unwrap(),
            "export APP_ENV='two words' CI='1' && cd '/srv/app' && make test"
        );
    }

    #[test]
    fn rejects_invalid_env_names() {
        for bad in ["1BAD", "SP ACE", "DASH-ED", "", "$(evil)"] {
            let env = HashMap::from([(bad.to_owned(), "x".to_owned())]);
            let err = build_shell_command("true", None, &env).unwrap_err();
            assert!(matches!(err, Error::Io(_)), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn quotes_hostile_cwd() {
        assert_eq!(
            build_shell_command("ls", Some("/tmp/it's; rm -rf /"), &HashMap::new()).unwrap(),
            r"cd '/tmp/it'\''s; rm -rf /' && ls"
        );
    }
}
