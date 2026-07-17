//! The [`Sandbox`] - a throwaway, gVisor-isolated Linux box.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::RwLock;
use std::time::Duration;

use serde::Deserialize;
use serde_json::json;
use ssh_key::PrivateKey;

use crate::error::{Error, Result};
use crate::http::ApiClient;
use crate::jobs::{self, JobHandle, JobInfo, SpawnOptions};
use crate::keys;
use crate::keystore;
use crate::models::{CommandResult, SandboxInfo, SandboxProcs, SandboxStats};
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

/// Where [`Sandbox::get_or_create`] looks for / persists private keys.
#[derive(Debug, Clone, Default)]
enum KeystoreSetting {
    /// `~/.xshellz/keys/` (resolved via `$HOME`).
    #[default]
    Default,
    /// A custom directory.
    Dir(PathBuf),
    /// No keystore: create-only-or-error semantics.
    Disabled,
}

/// Options for [`Sandbox::get_or_create`].
///
/// ```no_run
/// # use xshellz::{GetOrCreateOptions, Sandbox};
/// # async fn demo() -> xshellz::Result<()> {
/// let sbx = Sandbox::get_or_create("build-box", GetOrCreateOptions::default()).await?;
/// # Ok(()) }
/// ```
#[derive(Debug, Clone)]
pub struct GetOrCreateOptions {
    pub(crate) api_key: Option<String>,
    pub(crate) api_url: Option<String>,
    pub(crate) timeout: Duration,
    pub(crate) private_key: Option<String>,
    keystore: KeystoreSetting,
}

impl Default for GetOrCreateOptions {
    fn default() -> Self {
        Self {
            api_key: None,
            api_url: None,
            timeout: DEFAULT_HTTP_TIMEOUT,
            private_key: None,
            keystore: KeystoreSetting::Default,
        }
    }
}

impl GetOrCreateOptions {
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

    /// HTTP timeout for control-plane requests (default 120s).
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Explicit OpenSSH private key for an *existing* box with this name
    /// (wins over any keystore lookup).
    #[must_use]
    pub fn private_key(mut self, private_key_openssh: impl Into<String>) -> Self {
        self.private_key = Some(private_key_openssh.into());
        self
    }

    /// Use a custom keystore directory instead of `~/.xshellz/keys/`.
    #[must_use]
    pub fn keystore_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.keystore = KeystoreSetting::Dir(dir.into());
        self
    }

    /// Disable the keystore entirely: newly generated keys are not persisted,
    /// and attaching to an existing box requires an explicit
    /// [`private_key`](Self::private_key).
    #[must_use]
    pub fn no_keystore(mut self) -> Self {
        self.keystore = KeystoreSetting::Disabled;
        self
    }

    fn resolved_keystore(&self) -> Option<PathBuf> {
        match &self.keystore {
            KeystoreSetting::Default => keystore::default_dir(),
            KeystoreSetting::Dir(dir) => Some(dir.clone()),
            KeystoreSetting::Disabled => None,
        }
    }
}

/// Options for [`Sandbox::get_boxfile`] / [`Sandbox::set_boxfile`].
#[derive(Debug, Clone, Default)]
pub struct BoxfileOptions {
    pub(crate) api_key: Option<String>,
    pub(crate) api_url: Option<String>,
}

impl BoxfileOptions {
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
        let api = ApiClient::new(
            options.api_key.as_deref(),
            options.api_url.as_deref(),
            options.timeout,
        )?;
        let (info, keypair) = Self::spawn_new(&api, options.name.as_deref()).await?;

        Ok(Self::assemble(
            info,
            api,
            Some(keypair.private_key),
            Some(keypair.private_key_openssh),
        ))
    }

    /// Generate a keypair and POST the create request.
    async fn spawn_new(
        api: &ApiClient,
        name: Option<&str>,
    ) -> Result<(SandboxInfo, keys::KeyPair)> {
        let keypair = keys::generate_keypair(keys::DEFAULT_KEY_COMMENT)?;
        let mut body = json!({ "ssh_public_key": keypair.public_key_line });
        if let Some(name) = name {
            body["name"] = json!(name);
        }
        let info: SandboxInfo = api.post("/shells/agent", Some(body)).await?;
        Ok((info, keypair))
    }

    /// Attach to the sandbox named `name`, creating it if it does not exist -
    /// the "permanent named box" workflow.
    ///
    /// - **Not found**: the box is created (like [`create`](Self::create) with
    ///   that name) and, unless the keystore is disabled, the generated
    ///   private key is persisted to `<keystore>/<sanitized-name>.key`
    ///   (default keystore: `~/.xshellz/keys/`, file mode 0600).
    /// - **Found**: the private key is resolved - an explicit
    ///   [`private_key`](GetOrCreateOptions::private_key) wins, else the
    ///   keystore file is loaded - and the SDK attaches to the existing box.
    ///   If the box is idle-stopped it is [`start`](Self::start)ed first.
    ///
    /// **Security note:** the keystore stores the private key in plaintext on
    /// disk (0600). Delete the key file to revoke local access; destroy the
    /// box to rotate for real.
    ///
    /// The returned `Sandbox` is [`detach`](Self::detach)ed: this is a
    /// *permanent* box, so dropping the handle (or calling
    /// [`close`](Self::close)) leaves the box running. Destroy it explicitly
    /// with [`kill`](Self::kill).
    ///
    /// # Errors
    ///
    /// - [`Error::MissingKey`]: the box exists but no private key was found
    ///   (the message says which keystore path was checked).
    /// - Everything [`create`](Self::create), [`list`](Self::list), and
    ///   [`start`](Self::start) can return.
    pub async fn get_or_create(name: &str, options: GetOrCreateOptions) -> Result<Self> {
        let api = ApiClient::new(
            options.api_key.as_deref(),
            options.api_url.as_deref(),
            options.timeout,
        )?;
        let keystore_dir = options.resolved_keystore();

        let all: Vec<SandboxInfo> = api.get("/shells/agent").await?;
        let Some(info) = all.into_iter().find(|info| info.name == name) else {
            let (info, keypair) = Self::spawn_new(&api, Some(name)).await?;
            if let Some(dir) = &keystore_dir {
                keystore::save(dir, name, &keypair.private_key_openssh)?;
            }
            let sandbox = Self::assemble(
                info,
                api,
                Some(keypair.private_key),
                Some(keypair.private_key_openssh),
            );
            // Permanent box: never destroy it on drop - only kill() does.
            sandbox.detach();
            return Ok(sandbox);
        };

        let pem = match options.private_key {
            Some(pem) => pem,
            None => match &keystore_dir {
                Some(dir) => keystore::load(dir, name)?.ok_or_else(|| {
                    Error::MissingKey(format!(
                        "Sandbox {name:?} already exists but no private key was \
                         found at {:?}. Pass GetOrCreateOptions::private_key(...) \
                         with the key it was created with, restore that file, or \
                         destroy the box and let get_or_create recreate it.",
                        keystore::key_path(dir, name)
                    ))
                })?,
                None => {
                    return Err(Error::MissingKey(format!(
                        "Sandbox {name:?} already exists and the keystore is \
                         disabled - pass GetOrCreateOptions::private_key(...) \
                         with the key it was created with."
                    )));
                }
            },
        };
        let key = keys::load_private_key(&pem)?;
        let running = info.status == STATUS_RUNNING;
        let sandbox = Self::assemble(info, api, Some(key), Some(pem));
        // Permanent box: never destroy it on drop - only kill() does.
        sandbox.detach();
        if !running {
            sandbox.start().await?;
        }
        Ok(sandbox)
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

    /// Fetch the account's saved `xshellz.box` manifest (the provisioning
    /// template seeded into `~/xshellz.box` on every **newly created** box -
    /// preinstall packages, etc.). `None` when no manifest is saved.
    ///
    /// Account-level: `GET /v1/shells/agent/boxfile`.
    pub async fn get_boxfile(options: BoxfileOptions) -> Result<Option<String>> {
        let api = ApiClient::new(
            options.api_key.as_deref(),
            options.api_url.as_deref(),
            DEFAULT_HTTP_TIMEOUT,
        )?;
        let response: BoxfileManifest = api.get("/shells/agent/boxfile").await?;
        Ok(response.manifest)
    }

    /// Save (or clear, with `None`) the account's `xshellz.box` manifest and
    /// return the stored value.
    ///
    /// The manifest applies when the **next** box is created - existing boxes
    /// are not touched. Account-level: `PUT /v1/shells/agent/boxfile`
    /// (`manifest` is capped at 16 KiB server-side).
    pub async fn set_boxfile(
        manifest: Option<&str>,
        options: BoxfileOptions,
    ) -> Result<Option<String>> {
        let api = ApiClient::new(
            options.api_key.as_deref(),
            options.api_url.as_deref(),
            DEFAULT_HTTP_TIMEOUT,
        )?;
        let response: BoxfileManifest = api
            .put(
                "/shells/agent/boxfile",
                Some(json!({ "manifest": manifest })),
            )
            .await?;
        Ok(response.manifest)
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

    /// Start a background process in the sandbox and return a [`JobHandle`].
    ///
    /// The command runs under `nohup bash -c`, detached from the SSH session,
    /// with stdout+stderr redirected to `~/.xshellz/jobs/<job_id>.log` (pid
    /// recorded next to it in `<job_id>.pid`). The job keeps running after
    /// this process exits - but not across a box stop/restart.
    ///
    /// # Errors
    ///
    /// Everything [`run`](Self::run) can return, plus an [`Error::Io`] when
    /// the box did not report a pid back.
    pub async fn spawn(&self, command: &str, options: SpawnOptions) -> Result<JobHandle<'_>> {
        let id = match &options.name {
            Some(name) => format!("{}-{}", keystore::sanitize_name(name), jobs::short_id()),
            None => jobs::short_id(),
        };
        let script = format!(
            "mkdir -p \"$HOME/.xshellz/jobs\"\n\
             nohup bash -c {command} > \"$HOME/.xshellz/jobs/{id}.log\" 2>&1 < /dev/null &\n\
             pid=$!\n\
             echo \"$pid\" > \"$HOME/.xshellz/jobs/{id}.pid\"\n\
             echo \"$pid\"",
            command = shell_quote(command),
        );
        let output = self.exec(ExecRequest::plain(script)).await?;
        if output.exit_code != 0 {
            return Err(Error::Io(std::io::Error::other(format!(
                "could not spawn background job (exit {}): {}",
                output.exit_code,
                String::from_utf8_lossy(&output.stderr).trim()
            ))));
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let pid: u32 = stdout.trim().parse().map_err(|_| {
            Error::Io(std::io::Error::other(format!(
                "spawn did not report a pid (got {:?})",
                stdout.trim()
            )))
        })?;
        Ok(JobHandle {
            sandbox: self,
            id,
            pid,
        })
    }

    /// List the sandbox's background jobs (every `~/.xshellz/jobs/*.pid`
    /// file) with a `kill -0` liveness probe for each.
    pub async fn jobs(&self) -> Result<Vec<JobInfo>> {
        const LIST_SCRIPT: &str = "[ -d \"$HOME/.xshellz/jobs\" ] || exit 0\n\
             cd \"$HOME/.xshellz/jobs\" || exit 0\n\
             for p in *.pid; do\n\
             [ -e \"$p\" ] || continue\n\
             id=\"${p%.pid}\"\n\
             pid=\"$(cat \"$p\" 2>/dev/null)\"\n\
             if [ -n \"$pid\" ] && kill -0 \"$pid\" 2>/dev/null; then alive=1; else alive=0; fi\n\
             printf '%s %s %s\\n' \"$id\" \"${pid:-0}\" \"$alive\"\n\
             done";
        let output = self
            .exec(ExecRequest::plain(LIST_SCRIPT.to_owned()))
            .await?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout
            .lines()
            .filter_map(|line| {
                let mut fields = line.split_whitespace();
                let id = fields.next()?.to_owned();
                let pid = fields.next()?.parse().unwrap_or(0);
                let running = fields.next()? == "1";
                Some(JobInfo {
                    log_path: jobs::log_path_for(&id),
                    id,
                    pid,
                    running,
                })
            })
            .collect())
    }

    /// Run a snippet of code in the sandbox: the code is written to a temp
    /// file, executed with the language's interpreter, and the temp file is
    /// always deleted afterwards. Returns the same [`CommandResult`] as
    /// [`run`](Self::run) - a non-zero exit code is data, not an `Err`.
    ///
    /// Supported languages: `python` (runs `python3`), `node`, `bash`,
    /// `ruby`, `php`. The interpreter must be installed in the box (python3
    /// and bash ship in the base image; install others via
    /// [`run`](Self::run) or the account boxfile).
    ///
    /// # Errors
    ///
    /// - [`Error::UnsupportedLanguage`]: unknown `language`.
    /// - Everything [`run`](Self::run) can return.
    pub async fn run_code(
        &self,
        language: &str,
        code: &str,
        options: RunOptions,
    ) -> Result<CommandResult> {
        const LANGUAGES: [(&str, &str, &str); 5] = [
            ("python", "python3", "py"),
            ("node", "node", "js"),
            ("bash", "bash", "sh"),
            ("ruby", "ruby", "rb"),
            ("php", "php", "php"),
        ];
        let lowered = language.to_ascii_lowercase();
        let Some((_, interpreter, extension)) =
            LANGUAGES.iter().find(|(name, _, _)| *name == lowered)
        else {
            return Err(Error::UnsupportedLanguage(format!(
                "unsupported language {language:?}; supported: python, node, \
                 bash, ruby, php"
            )));
        };
        let path = format!("/tmp/.xshellz-code-{}.{extension}", jobs::short_id());
        self.write_file(&path, code.as_bytes()).await?;
        let result = self
            .run(&format!("{interpreter} {}", shell_quote(&path)), options)
            .await;
        let _cleanup = self
            .exec(ExecRequest::plain(format!("rm -f {}", shell_quote(&path))))
            .await;
        result
    }

    pub(crate) async fn exec(&self, request: ExecRequest) -> Result<ExecOutput> {
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

    /// Reboot a running box (`POST /shells/agent/{uuid}/restart`).
    ///
    /// The box's entrypoint re-runs and `/home` is preserved. Any live SSH
    /// connection and background jobs die with the reboot; the SDK drops its
    /// cached connection and reconnects on the next command.
    pub async fn restart(&self) -> Result<()> {
        let info: SandboxInfo = self
            .api
            .post(&format!("/shells/agent/{}/restart", self.uuid()), None)
            .await?;
        self.store_info(info);
        self.transport.lock().await.take();
        Ok(())
    }

    /// Live resource usage - memory, CPU, pids, disk, network - with the
    /// plan's ceilings (`GET /shells/agent/{uuid}/stats`).
    ///
    /// # Errors
    ///
    /// [`Error::Api`] with status 503 when the box's host or its live stats
    /// are momentarily unavailable.
    pub async fn stats(&self) -> Result<SandboxStats> {
        self.api
            .get(&format!("/shells/agent/{}/stats", self.uuid()))
            .await
    }

    /// Top processes, active SSH session count, detected coding agents, and
    /// disk usage (`GET /shells/agent/{uuid}/procs`).
    pub async fn procs(&self) -> Result<SandboxProcs> {
        self.api
            .get(&format!("/shells/agent/{}/procs", self.uuid()))
            .await
    }

    /// Mint a fresh signed web-terminal URL for this box
    /// (`GET /shells/agent/{uuid}/terminal`).
    ///
    /// The URL embeds a short-lived HMAC token (valid ~1 hour); mint a fresh
    /// one each time a terminal is opened rather than storing it.
    ///
    /// # Errors
    ///
    /// [`Error::Api`] with status 404 when the box is not running.
    pub async fn terminal_url(&self) -> Result<String> {
        let response: TerminalUrlResponse = self
            .api
            .get(&format!("/shells/agent/{}/terminal", self.uuid()))
            .await?;
        Ok(response.url)
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

/// Wire shape of `GET`/`PUT /shells/agent/boxfile`.
#[derive(Deserialize)]
struct BoxfileManifest {
    #[serde(default)]
    manifest: Option<String>,
}

/// Wire shape of `GET /shells/agent/{uuid}/terminal`.
#[derive(Deserialize)]
struct TerminalUrlResponse {
    url: String,
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

    fn stdout_output(stdout: &[u8], exit_code: i32) -> ExecOutput {
        ExecOutput {
            stdout: stdout.to_vec(),
            stderr: Vec::new(),
            exit_code,
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn spawn_builds_nohup_script_and_parses_pid() {
        let (sandbox, recorded) = sandbox_with(running_info(), vec![stdout_output(b"12345\n", 0)]);
        let job = sandbox
            .spawn("sleep 99", SpawnOptions::default().name("my worker"))
            .await
            .unwrap();

        assert_eq!(job.pid(), 12345);
        assert!(job.id().starts_with("my_worker-"), "id: {:?}", job.id());
        assert_eq!(job.log_path(), format!("~/.xshellz/jobs/{}.log", job.id()));

        let script = recorded.lock().unwrap()[0].command.clone();
        assert!(script.contains("mkdir -p \"$HOME/.xshellz/jobs\""));
        assert!(script.contains("nohup bash -c 'sleep 99' > \"$HOME/.xshellz/jobs/my_worker-"));
        assert!(script.contains("2>&1 < /dev/null &"));
        assert!(script.contains(".pid\""));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn spawn_without_pid_output_is_io_error() {
        let (sandbox, _) = sandbox_with(running_info(), vec![stdout_output(b"not-a-pid", 0)]);
        let err = sandbox
            .spawn("true", SpawnOptions::default())
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Io(_)));
        assert!(err.to_string().contains("pid"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn job_is_running_probes_with_kill_zero() {
        let (sandbox, recorded) = sandbox_with(
            running_info(),
            vec![
                stdout_output(b"42\n", 0),
                stdout_output(b"", 0),
                stdout_output(b"", 1),
            ],
        );
        let job = sandbox
            .spawn("true", SpawnOptions::default())
            .await
            .unwrap();
        assert!(job.is_running().await.unwrap());
        assert!(!job.is_running().await.unwrap());
        assert_eq!(
            recorded.lock().unwrap()[1].command,
            "kill -0 42 2>/dev/null"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn job_logs_tails_the_log_file() {
        let (sandbox, recorded) = sandbox_with(
            running_info(),
            vec![
                stdout_output(b"7\n", 0),
                stdout_output(b"line1\nline2\n", 0),
            ],
        );
        let job = sandbox
            .spawn("true", SpawnOptions::default())
            .await
            .unwrap();
        let logs = job.logs(50).await.unwrap();
        assert_eq!(logs, "line1\nline2\n");
        assert_eq!(
            recorded.lock().unwrap()[1].command,
            format!("tail -n 50 \"$HOME/.xshellz/jobs/{}.log\"", job.id())
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn job_stop_sends_term_then_kill_with_grace() {
        let (sandbox, recorded) = sandbox_with(
            running_info(),
            vec![stdout_output(b"7\n", 0), stdout_output(b"", 0)],
        );
        let job = sandbox
            .spawn("true", SpawnOptions::default())
            .await
            .unwrap();
        job.stop().await.unwrap();
        let script = recorded.lock().unwrap()[1].command.clone();
        assert!(script.contains("kill -TERM 7 2>/dev/null"));
        assert!(script.contains("kill -0 7 2>/dev/null || exit 0"));
        assert!(script.contains("kill -KILL 7 2>/dev/null"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn jobs_lists_pid_files_with_liveness() {
        let (sandbox, _) = sandbox_with(
            running_info(),
            vec![stdout_output(b"worker-aa 123 1\nold-bb 456 0\n", 0)],
        );
        let jobs = sandbox.jobs().await.unwrap();
        assert_eq!(
            jobs,
            vec![
                JobInfo {
                    id: "worker-aa".to_owned(),
                    pid: 123,
                    running: true,
                    log_path: "~/.xshellz/jobs/worker-aa.log".to_owned(),
                },
                JobInfo {
                    id: "old-bb".to_owned(),
                    pid: 456,
                    running: false,
                    log_path: "~/.xshellz/jobs/old-bb.log".to_owned(),
                },
            ]
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn jobs_empty_when_no_jobs_dir() {
        let (sandbox, _) = sandbox_with(running_info(), vec![stdout_output(b"", 0)]);
        assert!(sandbox.jobs().await.unwrap().is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn run_code_writes_temp_file_runs_interpreter_and_cleans_up() {
        let (sandbox, recorded) = sandbox_with(
            running_info(),
            vec![
                stdout_output(b"", 0),
                stdout_output(b"hi\n", 0),
                stdout_output(b"", 0),
            ],
        );
        let result = sandbox
            .run_code("python", "print('hi')", RunOptions::default())
            .await
            .unwrap();
        assert_eq!(result.stdout, "hi\n");
        assert_eq!(result.exit_code, 0);

        let recorded = recorded.lock().unwrap();
        assert_eq!(recorded.len(), 3);
        assert!(recorded[0]
            .command
            .starts_with("cat > '/tmp/.xshellz-code-"));
        assert!(recorded[0].command.ends_with(".py'"));
        assert_eq!(recorded[0].stdin.as_deref(), Some(&b"print('hi')"[..]));
        assert!(recorded[1]
            .command
            .starts_with("python3 '/tmp/.xshellz-code-"));
        assert!(recorded[2]
            .command
            .starts_with("rm -f '/tmp/.xshellz-code-"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn run_code_maps_languages_to_interpreters() {
        for (language, interpreter, extension) in [
            ("node", "node", ".js"),
            ("BASH", "bash", ".sh"),
            ("ruby", "ruby", ".rb"),
            ("php", "php", ".php"),
        ] {
            let (sandbox, recorded) = sandbox_with(
                running_info(),
                vec![
                    stdout_output(b"", 0),
                    stdout_output(b"", 0),
                    stdout_output(b"", 0),
                ],
            );
            sandbox
                .run_code(language, "1", RunOptions::default())
                .await
                .unwrap();
            let recorded = recorded.lock().unwrap();
            assert!(
                recorded[0].command.contains(extension),
                "{language}: temp file must use {extension}"
            );
            assert!(
                recorded[1].command.starts_with(&format!("{interpreter} '")),
                "{language}: must run {interpreter}"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn run_code_unknown_language_is_typed_error() {
        let (sandbox, recorded) = sandbox_with(running_info(), vec![]);
        let err = sandbox
            .run_code("cobol", "DISPLAY 'HI'", RunOptions::default())
            .await
            .unwrap_err();
        assert!(matches!(err, Error::UnsupportedLanguage(_)));
        assert!(err.to_string().contains("python"));
        assert!(recorded.lock().unwrap().is_empty(), "nothing must execute");
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
