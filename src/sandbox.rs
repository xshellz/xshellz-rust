//! The [`Sandbox`] - a throwaway, gVisor-isolated Linux box.

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::RwLock;
use std::time::Duration;

use serde_json::json;
use ssh_key::PrivateKey;

use crate::error::{Error, Result};
use crate::http::ApiClient;
use crate::keys;
use crate::models::{CommandResult, SandboxInfo};
use crate::transport::{
    build_shell_command, shell_quote, ExecOutput, ExecRequest, OutputCallback, RusshTransport,
    Transport,
};

const STATUS_RUNNING: &str = "running";
const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(120);
const SSH_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Options for [`Sandbox::create`].
///
/// ```no_run
/// # use xshellz::{CreateOptions, Sandbox};
/// # async fn demo() -> xshellz::Result<()> {
/// let sbx = Sandbox::create(CreateOptions::default().name("demo")).await?;
/// # Ok(()) }
/// ```
#[derive(Debug, Clone)]
pub struct CreateOptions {
    pub(crate) name: Option<String>,
    pub(crate) api_key: Option<String>,
    pub(crate) api_url: Option<String>,
    pub(crate) timeout: Duration,
}

impl Default for CreateOptions {
    fn default() -> Self {
        Self {
            name: None,
            api_key: None,
            api_url: None,
            timeout: DEFAULT_HTTP_TIMEOUT,
        }
    }
}

impl CreateOptions {
    /// Human-readable name for the sandbox.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Explicit API key (overrides `XSHELLZ_API_KEY`).
    #[must_use]
    pub fn api_key(mut self, api_key: impl Into<String>) -> Self {
        self.api_key = Some(api_key.into());
        self
    }

    /// Explicit API base URL (overrides `XSHELLZ_API_URL`).
    #[must_use]
    pub fn api_url(mut self, api_url: impl Into<String>) -> Self {
        self.api_url = Some(api_url.into());
        self
    }

    /// HTTP timeout for control-plane requests (default 120s - spawning is
    /// synchronous and can take a few seconds).
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// Options for [`Sandbox::connect`].
#[derive(Debug, Clone, Default)]
pub struct ConnectOptions {
    pub(crate) api_key: Option<String>,
    pub(crate) api_url: Option<String>,
}

impl ConnectOptions {
    /// Explicit API key (overrides `XSHELLZ_API_KEY`).
    #[must_use]
    pub fn api_key(mut self, api_key: impl Into<String>) -> Self {
        self.api_key = Some(api_key.into());
        self
    }

    /// Explicit API base URL (overrides `XSHELLZ_API_URL`).
    #[must_use]
    pub fn api_url(mut self, api_url: impl Into<String>) -> Self {
        self.api_url = Some(api_url.into());
        self
    }
}

/// Options for [`Sandbox::list`].
#[derive(Debug, Clone, Default)]
pub struct ListOptions {
    pub(crate) api_key: Option<String>,
    pub(crate) api_url: Option<String>,
}

impl ListOptions {
    /// Explicit API key (overrides `XSHELLZ_API_KEY`).
    #[must_use]
    pub fn api_key(mut self, api_key: impl Into<String>) -> Self {
        self.api_key = Some(api_key.into());
        self
    }

    /// Explicit API base URL (overrides `XSHELLZ_API_URL`).
    #[must_use]
    pub fn api_url(mut self, api_url: impl Into<String>) -> Self {
        self.api_url = Some(api_url.into());
        self
    }
}

/// Options for [`Sandbox::run`].
///
/// ```no_run
/// # use std::time::Duration;
/// # use xshellz::RunOptions;
/// let options = RunOptions::default()
///     .cwd("/srv/app")
///     .env_var("CI", "1")
///     .timeout(Duration::from_secs(300))
///     .on_stdout(|chunk| print!("{chunk}"));
/// ```
#[derive(Default)]
pub struct RunOptions {
    pub(crate) cwd: Option<String>,
    pub(crate) env: HashMap<String, String>,
    pub(crate) timeout: Option<Duration>,
    pub(crate) on_stdout: Option<OutputCallback>,
    pub(crate) on_stderr: Option<OutputCallback>,
}

impl RunOptions {
    /// Working directory for the command.
    #[must_use]
    pub fn cwd(mut self, cwd: impl Into<String>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }

    /// Environment variables for the command (replaces the whole map).
    #[must_use]
    pub fn env(mut self, env: HashMap<String, String>) -> Self {
        self.env = env;
        self
    }

    /// Add a single environment variable.
    #[must_use]
    pub fn env_var(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(name.into(), value.into());
        self
    }

    /// Wall-clock deadline; exceeding it returns [`Error::CommandTimeout`].
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Streaming callback receiving decoded stdout chunks as they arrive
    /// (the full output is still returned in the [`CommandResult`]).
    #[must_use]
    pub fn on_stdout(mut self, callback: impl FnMut(&str) + Send + 'static) -> Self {
        self.on_stdout = Some(Box::new(callback));
        self
    }

    /// Streaming callback receiving decoded stderr chunks as they arrive.
    #[must_use]
    pub fn on_stderr(mut self, callback: impl FnMut(&str) + Send + 'static) -> Self {
        self.on_stderr = Some(Box::new(callback));
        self
    }
}

/// A remote sandbox: control plane over HTTPS, data plane over SSH.
///
/// Create one with [`Sandbox::create`], attach to an existing one with
/// [`Sandbox::connect`], or enumerate them with [`Sandbox::list`].
///
/// Dropping a `Sandbox` fires a best-effort, fire-and-forget destroy request
/// unless [`detach`](Self::detach) or [`kill`](Self::kill) was called first -
/// but `Drop` cannot block on async work, so [`kill`](Self::kill) is the
/// reliable way to destroy the box.
pub struct Sandbox {
    info: RwLock<SandboxInfo>,
    api: ApiClient,
    private_key: Option<PrivateKey>,
    private_key_openssh: Option<String>,
    transport: tokio::sync::Mutex<Option<Box<dyn Transport>>>,
    detached: AtomicBool,
    killed: AtomicBool,
}

impl Sandbox {
    // ------------------------------------------------------------------ //
    // Constructors (control plane)
    // ------------------------------------------------------------------ //

    /// Spawn a new sandbox and return it once it is RUNNING.
    ///
    /// An in-memory ed25519 keypair is generated for the box; the private key
    /// never leaves this process and the server never sees it. Spawning is
    /// synchronous - the box is reachable when this returns.
    ///
    /// # Errors
    ///
    /// - [`Error::Auth`]: missing/invalid API key, insufficient scope, or an
    ///   account gate (verification, preview).
    /// - [`Error::Quota`]: the plan's concurrent sandbox limit is reached or
    ///   the plan has no sandbox entitlement.
    /// - [`Error::Api`]: other API failures (throttle 429, capacity 503, ...).
    pub async fn create(options: CreateOptions) -> Result<Self> {
        let keypair = keys::generate_keypair(keys::DEFAULT_KEY_COMMENT)?;
        let api = ApiClient::new(
            options.api_key.as_deref(),
            options.api_url.as_deref(),
            options.timeout,
        )?;

        let mut body = json!({ "ssh_public_key": keypair.public_key_line });
        if let Some(name) = &options.name {
            body["name"] = json!(name);
        }
        let info: SandboxInfo = api.post("/shells/agent", Some(body)).await?;

        Ok(Self::assemble(
            info,
            api,
            Some(keypair.private_key),
            Some(keypair.private_key_openssh),
        ))
    }

    /// Attach to an existing sandbox by UUID.
    ///
    /// `private_key` is the OpenSSH serialization of the key whose public
    /// half the box was created with (the value of
    /// [`private_key_openssh`](Self::private_key_openssh) on the original
    /// `Sandbox`).
    ///
    /// # Errors
    ///
    /// [`Error::NotRunning`] when the UUID is not among the account's active
    /// sandboxes (there is no GET-one endpoint; the SDK resolves the UUID via
    /// the list endpoint).
    pub async fn connect(uuid: &str, private_key: &str, options: ConnectOptions) -> Result<Self> {
        let key = keys::load_private_key(private_key)?;
        let api = ApiClient::new(
            options.api_key.as_deref(),
            options.api_url.as_deref(),
            DEFAULT_HTTP_TIMEOUT,
        )?;
        let info = Self::find(&api, uuid).await?;
        Ok(Self::assemble(
            info,
            api,
            Some(key),
            Some(private_key.to_owned()),
        ))
    }

    /// List the account's active sandboxes (a bare array on the wire).
    pub async fn list(options: ListOptions) -> Result<Vec<SandboxInfo>> {
        let api = ApiClient::new(
            options.api_key.as_deref(),
            options.api_url.as_deref(),
            DEFAULT_HTTP_TIMEOUT,
        )?;
        api.get("/shells/agent").await
    }

    /// Resolve one sandbox via the list endpoint (there is no GET show).
    async fn find(api: &ApiClient, uuid: &str) -> Result<SandboxInfo> {
        let all: Vec<SandboxInfo> = api.get("/shells/agent").await?;
        all.into_iter()
            .find(|info| info.uuid == uuid)
            .ok_or_else(|| {
                Error::NotRunning(format!(
                    "Sandbox {uuid} was not found among this account's active sandboxes."
                ))
            })
    }

    fn assemble(
        info: SandboxInfo,
        api: ApiClient,
        private_key: Option<PrivateKey>,
        private_key_openssh: Option<String>,
    ) -> Self {
        Self {
            info: RwLock::new(info),
            api,
            private_key,
            private_key_openssh,
            transport: tokio::sync::Mutex::new(None),
            detached: AtomicBool::new(false),
            killed: AtomicBool::new(false),
        }
    }

    // ------------------------------------------------------------------ //
    // Accessors
    // ------------------------------------------------------------------ //

    fn read_info(&self) -> SandboxInfo {
        self.info
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn store_info(&self, info: SandboxInfo) {
        *self
            .info
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = info;
    }

    /// The last-known control-plane state of the sandbox.
    #[must_use]
    pub fn info(&self) -> SandboxInfo {
        self.read_info()
    }

    /// The sandbox's unique identifier.
    #[must_use]
    pub fn uuid(&self) -> String {
        self.read_info().uuid
    }

    /// The sandbox's human-readable name.
    #[must_use]
    pub fn name(&self) -> String {
        self.read_info().name
    }

    /// Lifecycle state, e.g. `"running"` or `"stopped"`.
    #[must_use]
    pub fn status(&self) -> String {
        self.read_info().status
    }

    /// SSH host, e.g. `"shellus1.xshellz.com"`.
    #[must_use]
    pub fn ssh_host(&self) -> Option<String> {
        self.read_info().ssh_host
    }

    /// SSH port.
    #[must_use]
    pub fn ssh_port(&self) -> Option<u16> {
        self.read_info().ssh_port
    }

    /// Ready-to-copy `ssh -p <port> root@<host>` command line.
    #[must_use]
    pub fn ssh_command(&self) -> Option<String> {
        self.read_info().ssh_command
    }

    /// OpenSSH serialization of the private key authenticating this
    /// sandbox's SSH (persist it to reconnect later via
    /// [`connect`](Self::connect)).
    #[must_use]
    pub fn private_key_openssh(&self) -> Option<String> {
        self.private_key_openssh.clone()
    }

    // ------------------------------------------------------------------ //
    // Data plane (SSH exec)
    // ------------------------------------------------------------------ //

    /// Run a shell command in the sandbox and wait for it to finish.
    ///
    /// A non-zero exit code does NOT return an `Err` - inspect
    /// [`CommandResult::exit_code`]. Streaming callbacks on [`RunOptions`]
    /// receive decoded output chunks as they arrive (the full output is
    /// still returned in the result).
    ///
    /// # Errors
    ///
    /// - [`Error::NotRunning`]: the box is not in the `running` state.
    /// - [`Error::CommandTimeout`]: the [`RunOptions::timeout`] elapsed.
    /// - [`Error::Ssh`]: the SSH connection failed.
    pub async fn run(&self, command: &str, options: RunOptions) -> Result<CommandResult> {
        let full_command = build_shell_command(command, options.cwd.as_deref(), &options.env)?;
        let output = self
            .exec(ExecRequest {
                command: full_command,
                stdin: None,
                timeout: options.timeout,
                on_stdout: options.on_stdout,
                on_stderr: options.on_stderr,
            })
            .await?;
        Ok(CommandResult {
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            exit_code: output.exit_code,
        })
    }

    /// Write `data` to `path` inside the sandbox.
    pub async fn write_file(&self, path: &str, data: &[u8]) -> Result<()> {
        self.write_bytes(path, data.to_vec()).await
    }

    async fn write_bytes(&self, path: &str, data: Vec<u8>) -> Result<()> {
        let output = self
            .exec(ExecRequest {
                stdin: Some(data),
                ..ExecRequest::plain(format!("cat > {}", shell_quote(path)))
            })
            .await?;
        if output.exit_code != 0 {
            return Err(remote_file_error("write", path, &output));
        }
        Ok(())
    }

    /// Read and return the contents of `path` inside the sandbox.
    pub async fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        let output = self
            .exec(ExecRequest::plain(format!("cat {}", shell_quote(path))))
            .await?;
        if output.exit_code != 0 {
            return Err(remote_file_error("read", path, &output));
        }
        Ok(output.stdout)
    }

    /// Upload a local file into the sandbox.
    pub async fn upload(&self, local_path: impl AsRef<Path>, remote_path: &str) -> Result<()> {
        let data = tokio::fs::read(local_path).await?;
        self.write_bytes(remote_path, data).await
    }

    /// Download a file from the sandbox to a local path.
    pub async fn download(&self, remote_path: &str, local_path: impl AsRef<Path>) -> Result<()> {
        let data = self.read_file(remote_path).await?;
        tokio::fs::write(local_path, data).await?;
        Ok(())
    }

    async fn exec(&self, request: ExecRequest) -> Result<ExecOutput> {
        let mut guard = self.transport.lock().await;
        let transport = match &mut *guard {
            Some(transport) => transport,
            slot @ None => {
                *slot = Some(self.open_transport().await?);
                slot.as_mut().expect("transport was just inserted")
            }
        };
        transport.exec(request).await
    }

    async fn open_transport(&self) -> Result<Box<dyn Transport>> {
        let info = self.read_info();
        if info.status != STATUS_RUNNING {
            return Err(Error::NotRunning(format!(
                "Sandbox {} is {:?}, not 'running'. Call start() to resume an \
                 idle-stopped box.",
                info.uuid, info.status
            )));
        }
        let (Some(host), Some(port)) = (info.ssh_host, info.ssh_port) else {
            return Err(Error::NotRunning(format!(
                "Sandbox {} has no SSH endpoint yet (host/port unknown).",
                info.uuid
            )));
        };
        let Some(private_key) = self.private_key.as_ref() else {
            return Err(Error::Ssh(
                "No private key available for this sandbox - attach with \
                 Sandbox::connect(uuid, private_key, ...)."
                    .to_owned(),
            ));
        };
        let transport =
            RusshTransport::connect(&host, port, private_key, SSH_CONNECT_TIMEOUT).await?;
        Ok(Box::new(transport))
    }

    // ------------------------------------------------------------------ //
    // Lifecycle (control plane)
    // ------------------------------------------------------------------ //

    /// Resume an idle-stopped box (`POST /shells/agent/{uuid}/start`).
    ///
    /// Free-tier boxes idle-stop after ~30 minutes; this brings the same box
    /// (same `/home`, same authorized key) back to `running`.
    ///
    /// # Errors
    ///
    /// [`Error::NotRunning`] when there is no stopped box to start (the API's
    /// 404: the box may already be running, suspended, or deleted).
    pub async fn start(&self) -> Result<()> {
        let uuid = self.uuid();
        let info: SandboxInfo = match self
            .api
            .post(&format!("/shells/agent/{uuid}/start"), None)
            .await
        {
            Ok(info) => info,
            Err(Error::Api { status: 404, .. }) => {
                return Err(Error::NotRunning(format!(
                    "Sandbox {uuid} has no stopped box to start - it may \
                     already be running, suspended, or deleted."
                )));
            }
            Err(other) => return Err(other),
        };
        self.store_info(info);
        // The old SSH connection (if any) points at the pre-start box.
        self.transport.lock().await.take();
        Ok(())
    }

    /// Destroy the sandbox (`DELETE /shells/agent/{uuid}`). Idempotent: a
    /// 404 (already gone) is swallowed, and repeat calls are no-ops.
    pub async fn kill(&self) -> Result<()> {
        self.transport.lock().await.take();
        if self.killed.load(Ordering::SeqCst) {
            return Ok(());
        }
        match self
            .api
            .delete(&format!("/shells/agent/{}", self.uuid()))
            .await
        {
            Ok(()) => {}
            Err(Error::Api { status: 404, .. }) => {}
            Err(other) => return Err(other),
        }
        self.killed.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Keep the sandbox alive when this `Sandbox` is dropped.
    ///
    /// Persist [`private_key_openssh`](Self::private_key_openssh) and
    /// [`uuid`](Self::uuid) to re-attach later with [`connect`](Self::connect).
    pub fn detach(&self) {
        self.detached.store(true, Ordering::SeqCst);
    }

    /// Re-fetch this sandbox's state from the control plane.
    pub async fn refresh(&self) -> Result<SandboxInfo> {
        let info = Self::find(&self.api, &self.uuid()).await?;
        self.store_info(info.clone());
        Ok(info)
    }

    /// Close the SSH connection (keeps the box alive).
    pub async fn close(&self) {
        self.transport.lock().await.take();
    }

    #[cfg(test)]
    pub(crate) fn new_for_tests(
        info: SandboxInfo,
        api: ApiClient,
        transport: Option<Box<dyn Transport>>,
    ) -> Self {
        let sandbox = Self::assemble(info, api, None, None);
        *sandbox
            .transport
            .try_lock()
            .expect("fresh sandbox mutex is uncontended") = transport;
        sandbox
    }
}

fn remote_file_error(action: &str, path: &str, output: &ExecOutput) -> Error {
    let stderr = String::from_utf8_lossy(&output.stderr);
    Error::Io(std::io::Error::other(format!(
        "could not {action} remote file {path:?} (exit {}): {}",
        output.exit_code,
        stderr.trim()
    )))
}

impl std::fmt::Debug for Sandbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let info = self.read_info();
        f.debug_struct("Sandbox")
            .field("uuid", &info.uuid)
            .field("status", &info.status)
            .field("ssh_host", &info.ssh_host)
            .field("ssh_port", &info.ssh_port)
            .finish_non_exhaustive()
    }
}

impl Drop for Sandbox {
    /// Best-effort destroy on drop (unless [`detach`](Self::detach)ed or
    /// already [`kill`](Self::kill)ed).
    ///
    /// `Drop` cannot block on async work: when a Tokio runtime is available a
    /// fire-and-forget DELETE is spawned on it; otherwise nothing happens.
    /// Call [`kill`](Self::kill) for guaranteed destruction.
    fn drop(&mut self) {
        if self.detached.load(Ordering::SeqCst) || self.killed.load(Ordering::SeqCst) {
            return;
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let url = format!("{}/shells/agent/{}", self.api.base_url, self.uuid());
        let client = self.api.http.clone();
        handle.spawn(async move {
            let _ = client.delete(url).send().await;
        });
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::transport::BoxFuture;

    struct RecordedExec {
        command: String,
        stdin: Option<Vec<u8>>,
    }

    /// Scripted fake data plane: records requests, replays canned outputs,
    /// and feeds the canned output through the streaming callbacks.
    struct FakeTransport {
        recorded: Arc<Mutex<Vec<RecordedExec>>>,
        script: Arc<Mutex<VecDeque<ExecOutput>>>,
    }

    impl FakeTransport {
        fn scripted(
            outputs: Vec<ExecOutput>,
        ) -> (Box<dyn Transport>, Arc<Mutex<Vec<RecordedExec>>>) {
            let recorded = Arc::new(Mutex::new(Vec::new()));
            let fake = FakeTransport {
                recorded: Arc::clone(&recorded),
                script: Arc::new(Mutex::new(outputs.into())),
            };
            (Box::new(fake), recorded)
        }
    }

    impl Transport for FakeTransport {
        fn exec(&mut self, mut request: ExecRequest) -> BoxFuture<'_, Result<ExecOutput>> {
            Box::pin(async move {
                self.recorded.lock().unwrap().push(RecordedExec {
                    command: request.command.clone(),
                    stdin: request.stdin.take(),
                });
                let output = self
                    .script
                    .lock()
                    .unwrap()
                    .pop_front()
                    .unwrap_or(ExecOutput {
                        stdout: Vec::new(),
                        stderr: Vec::new(),
                        exit_code: 0,
                    });
                if let Some(callback) = request.on_stdout.as_mut() {
                    callback(&String::from_utf8_lossy(&output.stdout));
                }
                if let Some(callback) = request.on_stderr.as_mut() {
                    callback(&String::from_utf8_lossy(&output.stderr));
                }
                Ok(output)
            })
        }
    }

    fn running_info() -> SandboxInfo {
        serde_json::from_value(serde_json::json!({
            "uuid": "sbx-1",
            "name": "demo",
            "status": "running",
            "ssh_host": "shellus1.xshellz.com",
            "ssh_port": 42001,
        }))
        .unwrap()
    }

    fn test_api() -> ApiClient {
        ApiClient::new(
            Some("test-key"),
            Some("http://127.0.0.1:1"),
            Duration::from_secs(1),
        )
        .unwrap()
    }

    fn sandbox_with(
        info: SandboxInfo,
        outputs: Vec<ExecOutput>,
    ) -> (Sandbox, Arc<Mutex<Vec<RecordedExec>>>) {
        let (transport, recorded) = FakeTransport::scripted(outputs);
        let sandbox = Sandbox::new_for_tests(info, test_api(), Some(transport));
        sandbox.detach();
        (sandbox, recorded)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn run_returns_output_and_nonzero_exit_is_data() {
        let (sandbox, _) = sandbox_with(
            running_info(),
            vec![ExecOutput {
                stdout: b"out".to_vec(),
                stderr: b"err".to_vec(),
                exit_code: 3,
            }],
        );
        let result = sandbox.run("exit 3", RunOptions::default()).await.unwrap();
        assert_eq!(result.stdout, "out");
        assert_eq!(result.stderr, "err");
        assert_eq!(result.exit_code, 3);
        assert!(!result.ok());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn run_wraps_command_with_env_and_cwd() {
        let (sandbox, recorded) = sandbox_with(running_info(), vec![]);
        sandbox
            .run(
                "make test",
                RunOptions::default().cwd("/srv/app").env_var("CI", "1"),
            )
            .await
            .unwrap();
        assert_eq!(
            recorded.lock().unwrap()[0].command,
            "export CI='1' && cd '/srv/app' && make test"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn run_streams_output_through_callbacks() {
        let (sandbox, _) = sandbox_with(
            running_info(),
            vec![ExecOutput {
                stdout: b"hello".to_vec(),
                stderr: b"warn".to_vec(),
                exit_code: 0,
            }],
        );
        let streamed_out = Arc::new(Mutex::new(String::new()));
        let streamed_err = Arc::new(Mutex::new(String::new()));
        let (out_sink, err_sink) = (Arc::clone(&streamed_out), Arc::clone(&streamed_err));
        sandbox
            .run(
                "echo hello",
                RunOptions::default()
                    .on_stdout(move |chunk| out_sink.lock().unwrap().push_str(chunk))
                    .on_stderr(move |chunk| err_sink.lock().unwrap().push_str(chunk)),
            )
            .await
            .unwrap();
        assert_eq!(*streamed_out.lock().unwrap(), "hello");
        assert_eq!(*streamed_err.lock().unwrap(), "warn");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn write_file_pipes_stdin_through_cat() {
        let (sandbox, recorded) = sandbox_with(running_info(), vec![]);
        sandbox.write_file("/tmp/a's.bin", b"data").await.unwrap();
        let recorded = recorded.lock().unwrap();
        assert_eq!(recorded[0].command, r"cat > '/tmp/a'\''s.bin'");
        assert_eq!(recorded[0].stdin.as_deref(), Some(&b"data"[..]));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn read_file_returns_raw_bytes_and_maps_failure() {
        let (sandbox, recorded) = sandbox_with(
            running_info(),
            vec![
                ExecOutput {
                    stdout: vec![0, 159, 146, 150],
                    stderr: Vec::new(),
                    exit_code: 0,
                },
                ExecOutput {
                    stdout: Vec::new(),
                    stderr: b"cat: /missing: No such file or directory".to_vec(),
                    exit_code: 1,
                },
            ],
        );
        let data = sandbox.read_file("/tmp/a.bin").await.unwrap();
        assert_eq!(data, vec![0, 159, 146, 150]);
        assert_eq!(recorded.lock().unwrap()[0].command, "cat '/tmp/a.bin'");

        let err = sandbox.read_file("/missing").await.unwrap_err();
        assert!(matches!(err, Error::Io(_)));
        assert!(err.to_string().contains("No such file"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn upload_and_download_round_trip_local_files() {
        let dir = std::env::temp_dir().join(format!("xshellz-test-{}", std::process::id()));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let local_in = dir.join("in.bin");
        let local_out = dir.join("out.bin");
        tokio::fs::write(&local_in, b"payload").await.unwrap();

        let (sandbox, recorded) = sandbox_with(
            running_info(),
            vec![
                ExecOutput {
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                    exit_code: 0,
                },
                ExecOutput {
                    stdout: b"payload".to_vec(),
                    stderr: Vec::new(),
                    exit_code: 0,
                },
            ],
        );
        sandbox.upload(&local_in, "/tmp/in.bin").await.unwrap();
        sandbox.download("/tmp/in.bin", &local_out).await.unwrap();

        assert_eq!(
            recorded.lock().unwrap()[0].stdin.as_deref(),
            Some(&b"payload"[..])
        );
        assert_eq!(tokio::fs::read(&local_out).await.unwrap(), b"payload");
        tokio::fs::remove_dir_all(&dir).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn run_on_stopped_box_is_not_running_error() {
        let mut info = running_info();
        info.status = "stopped".to_owned();
        let sandbox = Sandbox::new_for_tests(info, test_api(), None);
        sandbox.detach();
        let err = sandbox
            .run("true", RunOptions::default())
            .await
            .unwrap_err();
        assert!(matches!(err, Error::NotRunning(_)));
        assert!(err.to_string().contains("start()"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn run_without_private_key_is_ssh_error() {
        let sandbox = Sandbox::new_for_tests(running_info(), test_api(), None);
        sandbox.detach();
        let err = sandbox
            .run("true", RunOptions::default())
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Ssh(_)));
        assert!(err.to_string().contains("connect"));
    }
}
