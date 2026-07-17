# xshellz Rust SDK - API reference

Everything the crate exports, with parameters, return shapes, and the errors
each call can return. All public items are re-exported from the crate root:

```rust
use xshellz::{
    Sandbox, JobHandle, JobInfo, SpawnOptions,
    CommandResult, SandboxInfo, SandboxStats, SandboxProcs, ProcessInfo,
    CreateOptions, GetOrCreateOptions, ConnectOptions, ListOptions,
    BoxfileOptions, RunOptions,
    Error, Result,
};
```

The SDK is **async** (Tokio); every method that talks to the box or the control
plane is `async` and returns [`Result<T>`](#result--error).

**Shared options.** Every constructor/static method that talks to the API takes
an options struct with builder methods for `api_key` (defaults to
`$XSHELLZ_API_KEY`) and `api_url` (defaults to `$XSHELLZ_API_URL`, then
`https://api.xshellz.com/v1`). Options structs are created with `::default()`
and configured fluently, e.g.
`CreateOptions::default().name("demo").timeout(Duration::from_secs(60))`.

---

## `struct Sandbox`

A remote sandbox: control plane over HTTPS, data plane over SSH.

Dropping a `Sandbox` fires a best-effort, fire-and-forget destroy request on
the current Tokio runtime **unless** [`detach`](#detach) or [`kill`](#kill) was
called first. `Drop` cannot block on async work, so this is not guaranteed -
`kill().await` is the reliable way to destroy a box.

### Constructors

#### `Sandbox::create(options: CreateOptions) -> Result<Sandbox>`

Spawn a new sandbox and return it once it is running. Generates a fresh
in-memory ed25519 keypair; only the public half is sent to the server.

`CreateOptions` builders: `name(impl Into<String>)`, `api_key(...)`,
`api_url(...)`, `timeout(Duration)` (default 120s - spawning is synchronous).

Errors: `Error::Auth` (bad key/scopes/account gates), `Error::Quota` (plan
sandbox limit / no entitlement), `Error::Api` (429 throttle, 503 capacity, ...).

#### `Sandbox::get_or_create(name: &str, options: GetOrCreateOptions) -> Result<Sandbox>`

"Permanent mode": return the sandbox named `name`, creating it if it doesn't
exist. On create, the generated private key is persisted to the keystore; on
attach, the key is loaded (an explicit `private_key` option wins, else the
keystore). A `stopped` box is started before returning.

The returned `Sandbox` is **detached** - dropping it or calling `close()` keeps
the (permanent) box running; only `kill()` destroys it.

`GetOrCreateOptions` builders:

| Builder | Effect |
|---|---|
| `api_key(...)` / `api_url(...)` / `timeout(Duration)` | As for `CreateOptions`. |
| `private_key(impl Into<String>)` | OpenSSH private key for an existing box; overrides the keystore lookup. |
| `keystore_dir(impl Into<PathBuf>)` | Use a custom keystore directory instead of `~/.xshellz/keys/`. |
| `no_keystore()` | Disable persistence: new keys are not saved, and attaching to an existing box requires `private_key(...)`. |

Errors: `Error::MissingKey` (box exists but no key found - the message says
where a key was expected), plus everything `create` and `start` return.

#### `Sandbox::connect(uuid: &str, private_key: &str, options: ConnectOptions) -> Result<Sandbox>`

Attach to an existing sandbox by UUID. `private_key` is the OpenSSH
serialization of the key whose public half the box was created with (the value
of [`private_key_openssh()`](#accessors) on the original `Sandbox`). There is no
GET-one endpoint; the UUID is resolved via the list endpoint.

`ConnectOptions` builders: `api_key(...)`, `api_url(...)`.

Errors: `Error::NotRunning` if the UUID isn't among the account's sandboxes.

#### `Sandbox::list(options: ListOptions) -> Result<Vec<SandboxInfo>>`

The account's sandboxes (a bare JSON array on the wire).

`ListOptions` builders: `api_key(...)`, `api_url(...)`.

### Account-level template (boxfile)

#### `Sandbox::get_boxfile(options: BoxfileOptions) -> Result<Option<String>>`

The saved `xshellz.box` provisioning manifest, or `None` if unset.
Wire: `GET /v1/shells/agent/boxfile` -> `{"manifest": string|null}`.

#### `Sandbox::set_boxfile(manifest: Option<&str>, options: BoxfileOptions) -> Result<Option<String>>`

Save (or clear, with `None`) the manifest; returns it as stored (the server
normalizes CRLF to LF and stores blank as `None`). Max 16 KiB. **Applied only
when a NEW box is created** - think of it as a template that preinstalls your
dependencies; existing boxes are not re-provisioned.
Wire: `PUT /v1/shells/agent/boxfile` with `{"manifest": ...}`.

`BoxfileOptions` builders: `api_key(...)`, `api_url(...)`.

### Accessors

Cheap, synchronous reads of the last-known control-plane state.

| Method | Type | Meaning |
|---|---|---|
| `info()` | `SandboxInfo` | Last-known control-plane state (cloned) |
| `uuid()` | `String` | Sandbox id |
| `name()` | `String` | Display name |
| `status()` | `String` | `"running"`, `"stopped"`, ... |
| `ssh_host()` | `Option<String>` | SSH host |
| `ssh_port()` | `Option<u16>` | SSH port |
| `ssh_command()` | `Option<String>` | Copy-paste `ssh -p ... root@...` line |
| `private_key_openssh()` | `Option<String>` | OpenSSH serialization of the SSH key (persist to reconnect via `connect`) |

### Commands & code

#### `run(&self, command: &str, options: RunOptions) -> Result<CommandResult>`

Run a shell command and wait. A non-zero exit code does **not** return an
`Err` - check `result.exit_code` / `result.ok()`. Streaming callbacks receive
decoded chunks as they arrive.

`RunOptions` builders:

| Builder | Effect |
|---|---|
| `cwd(impl Into<String>)` | Working directory for the command. |
| `env(HashMap<String, String>)` | Replace the whole environment map. |
| `env_var(name, value)` | Add a single environment variable. |
| `timeout(Duration)` | Wall-clock deadline; exceeding it returns `Error::CommandTimeout`. |
| `on_stdout(impl FnMut(&str) + Send + 'static)` | Stream stdout chunks as they arrive. |
| `on_stderr(impl FnMut(&str) + Send + 'static)` | Stream stderr chunks as they arrive. |

Errors: `Error::NotRunning` (box not running), `Error::CommandTimeout`,
`Error::Ssh` (connection/auth failure).

#### `run_code(&self, language: &str, code: &str, options: RunOptions) -> Result<CommandResult>`

Write `code` to a temp file in the box, execute it with the matching
interpreter, always delete the temp file. Languages (case-insensitive):
`python` (runs `python3`), `node`, `bash`, `ruby`, `php`. Returns
`Error::UnsupportedLanguage` for anything else; otherwise identical semantics to
`run`.

### Background jobs

#### `spawn(&self, command: &str, options: SpawnOptions) -> Result<JobHandle<'_>>`

Start `command` as a `nohup`-detached background process. Combined stdout+stderr
goes to `~/.xshellz/jobs/<job_id>.log` in the box (pid recorded in
`<job_id>.pid`). Jobs survive disconnects, not box stops/restarts. The returned
`JobHandle` borrows the `Sandbox`.

`SpawnOptions` builders: `name(impl Into<String>)` - prefixes the generated job
id (sanitized to `[A-Za-z0-9._-]`).

Errors: everything `run` can return, plus `Error::Io` when the box reported no
pid.

#### `jobs(&self) -> Result<Vec<JobInfo>>`

All jobs (every `~/.xshellz/jobs/*.pid` file) with a `kill -0` liveness probe.

### Files

| Method | Direction |
|---|---|
| `write_file(&self, path: &str, data: &[u8]) -> Result<()>` | bytes -> box |
| `read_file(&self, path: &str) -> Result<Vec<u8>>` | box -> bytes |
| `upload(&self, local_path: impl AsRef<Path>, remote_path: &str) -> Result<()>` | local file -> box |
| `download(&self, remote_path: &str, local_path: impl AsRef<Path>) -> Result<()>` | box -> local file |

Transfers are exec-based (`cat` over the SSH exec channel) - binary-safe.

### Introspection

#### `stats(&self) -> Result<SandboxStats>`

Live resource usage (`GET /v1/shells/agent/{uuid}/stats`): memory, CPU, pids,
disk, network, block-IO - each paired with the plan ceiling. Poll politely.

#### `procs(&self) -> Result<SandboxProcs>`

Top processes, active SSH session count, detected agents, disk usage
(`GET /v1/shells/agent/{uuid}/procs`).

#### `terminal_url(&self) -> Result<String>`

Mint a fresh signed web-terminal URL (`GET /v1/shells/agent/{uuid}/terminal`).
The embedded HMAC token expires after **~1 hour**; the URL grants a root shell
until then, so treat it like a credential and mint fresh rather than storing.

### Lifecycle

| Method | Effect |
|---|---|
| `start(&self) -> Result<()>` | Resume an idle-stopped box (same `/home`, same key). Returns `Error::NotRunning` if there is nothing to start. |
| `restart(&self) -> Result<()>` | Reboot a running box (re-runs the entrypoint; `/home` preserved; processes and jobs are killed). |
| `kill(&self) -> Result<()>` | Destroy the box (`DELETE`). Idempotent - a 404 is swallowed and repeat calls are no-ops. |
| `detach(&self)` | Suppress the best-effort destroy on `Drop`; the box stays alive. |
| `refresh(&self) -> Result<SandboxInfo>` | Re-fetch state from the control plane. |
| `close(&self)` | Close the SSH connection (box stays alive). |

---

## `struct JobHandle<'sbx>`

Returned by `Sandbox::spawn`. Borrows the `Sandbox` it runs in.

| Method | Description |
|---|---|
| `id() -> &str` | Job id (the log/pid file stem under `~/.xshellz/jobs/`) |
| `pid() -> u32` | Pid of the job's `bash -c` process inside the box |
| `log_path() -> String` | In-box path of the combined stdout+stderr log |
| `is_running(&self) -> Result<bool>` | `kill -0` liveness probe |
| `logs(&self, tail_lines: usize) -> Result<String>` | Tail of the log file (100 is a sensible default) |
| `stop(&self) -> Result<()>` | SIGTERM, then SIGKILL if still alive after a ~5s grace. Idempotent. |

## Data types

All deserialize tolerantly from the snake_case wire shapes (missing/unknown
fields never break the SDK) and are `#[non_exhaustive]`.

- **`CommandResult`** - `stdout: String`, `stderr: String`, `exit_code: i32`;
  method `ok() -> bool` (`exit_code == 0`).
- **`SandboxInfo`** - `uuid`, `name`, `status`, `ssh_command`, `ssh_host`,
  `ssh_port`, `web_terminal_ready`, `always_on`, `trial_hours_remaining`,
  `spawned_at`, `created_at`, `isolation`, `gvisor`.
- **`SandboxStats`** - `mem_used_mb`, `mem_limit_mb`, `mem_allowed_mb`,
  `cpu_percent`, `cpu_allowed_vcpus`, `cpu_throttled_periods`, `pids_current`,
  `pids_allowed`, `disk_used_mb`, `disk_allowed_mb`, `net_rx_mb`, `net_tx_mb`,
  `blk_read_mb`, `blk_write_mb`.
- **`SandboxProcs`** - `procs: Vec<ProcessInfo>`, `sessions: u64`,
  `agents: Vec<String>`, `disk_used_mb`, `disk_allowed_mb`.
- **`ProcessInfo`** - `pid: u32`, `comm: String`, `cpu: f64`, `mem: f64`.
- **`JobInfo`** - `id: String`, `pid: u32` (0 when unreadable),
  `running: bool`, `log_path: String`.

## Keystore

`get_or_create` persists each box's private key to a local directory (default
`~/.xshellz/keys/`, resolved via `$HOME`) as one `<sanitized-name>.key` file
per name, mode `0600`. The name is sanitized to `[A-Za-z0-9._-]` for the
filename. Configure the location with `GetOrCreateOptions::keystore_dir(...)`
or disable it with `GetOrCreateOptions::no_keystore()`.

**Security:** keys are stored in plaintext on disk. Deleting the file revokes
local access only - the key stays authorized on the box until the box is
destroyed.

## `Result` & `Error`

`type Result<T> = std::result::Result<T, Error>`.

`Error` is a `#[non_exhaustive]` enum (`thiserror`):

| Variant | Returned when |
|---|---|
| `Error::Auth(String)` | 401/403 - missing/invalid/expired token, scopes, verification gates |
| `Error::Quota(String)` | 403 - plan's concurrent sandbox limit reached, or no sandbox entitlement |
| `Error::NotRunning(String)` | Box not `running` / not found / nothing to start |
| `Error::MissingKey(String)` | `get_or_create` found the box but no private key (message says where it looked) |
| `Error::UnsupportedLanguage(String)` | `run_code` language not in: python, node, bash, ruby, php |
| `Error::CommandTimeout(String)` | A `RunOptions::timeout` deadline was exceeded |
| `Error::Api { status: u16, body: String }` | Any other 4xx/5xx (429 throttle, 503 capacity, ...) |
| `Error::Ssh(String)` | SSH data-plane failure (connect, auth, channel) |
| `Error::Io(std::io::Error)` | Local I/O or network-transport failure |

A non-zero command exit code is **never** an error - it is data on
`CommandResult`.
