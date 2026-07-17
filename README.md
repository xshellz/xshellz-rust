# xshellz

[![CI](https://github.com/xshellz/xshellz-rust/actions/workflows/ci.yml/badge.svg)](https://github.com/xshellz/xshellz-rust/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/xshellz)](https://crates.io/crates/xshellz)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

The official Rust SDK for [xShellz](https://xshellz.com) sandboxes - spin up a
real Linux box from your code, run anything in it, throw it away.

**What is a sandbox?** A sandbox is a small, isolated Linux computer that lives
in the cloud and belongs only to you: it has a root shell, a package manager,
its own files and network, and it is walled off from everything else by
[gVisor](https://gvisor.dev) kernel isolation. Because it's disposable, it's the
safe place to run untrusted or AI-generated code, heavy builds, or experiments
you don't want anywhere near your own machine.

The SDK is async and runs on [Tokio](https://tokio.rs). TLS is pure-Rust
([rustls](https://github.com/rustls/rustls)) and the SSH client is pure-Rust
([russh](https://github.com/Eugeny/russh)) - no OpenSSL, no system `ssh`.

## Quickstart

1. **Install the SDK** (adds it to your `Cargo.toml`):

   ```bash
   cargo add xshellz
   ```

   You also need an async runtime - `cargo add tokio --features full`.

2. **Get an API key.** Sign up at [app.xshellz.com](https://app.xshellz.com),
   then create a personal access token with `read` and `write` scopes
   (Settings -> API tokens, or via the API: `POST /v1/auth/tokens`). Export it:

   ```bash
   export XSHELLZ_API_KEY="your-token"
   ```

3. **Run your first command in a sandbox:**

   ```rust
   use xshellz::{CreateOptions, RunOptions, Sandbox};

   #[tokio::main]
   async fn main() -> Result<(), Box<dyn std::error::Error>> {
       let sbx = Sandbox::create(CreateOptions::default()).await?;
       let result = sbx.run("echo hello from $(hostname)", RunOptions::default()).await?;
       println!("{}", result.stdout);
       sbx.kill().await?; // destroy the box
       Ok(())
   }
   ```

`Sandbox::create()` returns once the box is running - typically a few seconds.

## Recipes

### Run a command

```rust
use std::time::Duration;
use xshellz::{CreateOptions, RunOptions, Sandbox};

let sbx = Sandbox::create(CreateOptions::default().name("build-box")).await?;

let r = sbx
    .run(
        "apt-get update && apt-get install -y jq",
        RunOptions::default().timeout(Duration::from_secs(300)),
    )
    .await?;
println!("{} {} {}", r.exit_code, r.stdout, r.stderr);

// A non-zero exit code does NOT return an Err - it's data, like a subprocess:
assert_eq!(sbx.run("false", RunOptions::default()).await?.exit_code, 1);

// Working directory and environment variables:
sbx.run("make test", RunOptions::default().cwd("/srv/app").env_var("CI", "1")).await?;

// Stream long-running output as it happens:
sbx.run(
    "npm run build",
    RunOptions::default()
        .on_stdout(|chunk| print!("{chunk}"))
        .on_stderr(|chunk| eprint!("{chunk}")),
)
.await?;
```

### A permanent named box that survives restarts

`get_or_create` gives you the same box back every time you call it with the
same name - from any process, any day. The SSH private key is saved to a local
keystore (`~/.xshellz/keys/`, file permissions `0600`) on first creation and
loaded from there on every reconnect. If the box was idle-stopped, it is
started for you.

```rust
use xshellz::{GetOrCreateOptions, RunOptions, Sandbox};

let sbx = Sandbox::get_or_create("my-dev-box", GetOrCreateOptions::default()).await?;
sbx.run("echo 'this file survives' >> ~/notes.txt", RunOptions::default()).await?;
sbx.close().await; // close the connection; the box stays alive
```

A `get_or_create` box is **detached**: dropping the handle (or `close()`) keeps
the box running, because permanent boxes shouldn't vanish when a variable goes
out of scope. Destroy it explicitly with `sbx.kill().await?`.

Security note: the key sits in plaintext on your disk (0600, owner-only).
Delete the file to revoke local access. Use `GetOrCreateOptions::no_keystore()`
to disable persistence, or `GetOrCreateOptions::keystore_dir("/path")` to
relocate it.

### Background job (keeps running after you disconnect)

```rust
use xshellz::{Sandbox, SpawnOptions};

let job = sbx.spawn("python3 train.py", SpawnOptions::default().name("train")).await?;

job.is_running().await?;             // true while the process is alive
println!("{}", job.logs(50).await?); // last 50 lines of its combined output
job.stop().await?;                   // SIGTERM, then SIGKILL after a grace period

for info in sbx.jobs().await? {      // every job's log file + liveness
    println!("{} {} {}", info.id, info.pid, info.running);
}
```

Jobs survive your program exiting; they do not survive the box stopping or
restarting.

### Run AI-generated code safely

`run_code` writes the code to a temp file inside the sandbox, runs the right
interpreter, and always cleans the file up. The code executes in the sandbox,
never on your machine.

```rust
let llm_output = "print(sum(range(101)))";

let sbx = Sandbox::create(CreateOptions::default()).await?;
let result = sbx.run_code("python", llm_output, RunOptions::default()).await?;
println!("{}", result.stdout); // "5050"
sbx.kill().await?;
```

Supported languages: `python` (runs `python3`), `node`, `bash`, `ruby`, `php`.
Anything else returns `Error::UnsupportedLanguage`.

### Files: upload & download

```rust
sbx.write_file("/tmp/config.json", br#"{"debug": true}"#).await?; // bytes -> box
let data: Vec<u8> = sbx.read_file("/tmp/config.json").await?;      // box -> bytes

sbx.upload("local.txt", "/tmp/remote.txt").await?;                 // local file -> box
sbx.download("/tmp/results.csv", "results.csv").await?;            // box -> local file
```

File transfer is exec-based (`cat` over the SSH exec channel) - binary-safe in
both directions, no separate SFTP subsystem needed.

### Check resource usage

```rust
let stats = sbx.stats().await?;
println!(
    "mem {}/{} MB, cpu {}%",
    stats.mem_used_mb, stats.mem_allowed_mb, stats.cpu_percent
);

let top = sbx.procs().await?;
for p in top.procs {
    println!("{} {} {} {}", p.pid, p.comm, p.cpu, p.mem);
}
```

### Open a web terminal in the browser

```rust
let url = sbx.terminal_url().await?; // fresh signed URL, valid ~1 hour
println!("Open this in a browser: {url}");
```

The URL grants a root shell until it expires - treat it like a password. Mint a
fresh one each time instead of storing it.

### Provision every new box the same way (boxfile template)

The account-level *boxfile* is a provisioning manifest applied when a **new**
box is created - use it to preinstall your dependencies so destroy+recreate
reproduces your environment:

```rust
use xshellz::{BoxfileOptions, Sandbox};

Sandbox::set_boxfile(Some("apt: jq ripgrep\npip: httpx rich"), BoxfileOptions::default()).await?;
let current = Sandbox::get_boxfile(BoxfileOptions::default()).await?;
Sandbox::set_boxfile(None, BoxfileOptions::default()).await?; // clear it
```

## API reference

Every public type, method, parameter, return shape, and error is documented in
**[docs/API.md](docs/API.md)** (and inline - run `cargo doc --open`).

## Configuration

| Environment variable | Meaning | Default |
|---|---|---|
| `XSHELLZ_API_KEY` | Your personal access token | (required) |
| `XSHELLZ_API_URL` | Control-plane base URL | `https://api.xshellz.com/v1` |

Precedence: explicit option (e.g. `CreateOptions::default().api_key(...)`) >
environment variable > default.

## Errors

Every fallible call returns `Result<T, xshellz::Error>`. `Error` is a
`#[non_exhaustive]` enum - match the variants you care about and fall through
on the rest.

| Variant | When it's returned |
|---|---|
| `Error::Auth` | 401/403: missing/invalid token, scopes, account gates |
| `Error::Quota` | Plan sandbox limit reached, or plan has no sandbox entitlement |
| `Error::NotRunning` | The operation needs a `running` box (or the box is gone) |
| `Error::CommandTimeout` | A `RunOptions::timeout` deadline was exceeded |
| `Error::MissingKey` | `get_or_create` found the box but no private key |
| `Error::UnsupportedLanguage` | `run_code` got a language other than python/node/bash/ruby/php |
| `Error::Api { status, body }` | Any other 4xx/5xx (throttle 429, capacity 503, ...) |
| `Error::Ssh` / `Error::Io` | Data-plane (SSH) and local I/O failures |

A non-zero command exit code is **never** an error - inspect
`CommandResult::exit_code` / `CommandResult::ok()`.

```rust
use xshellz::{CreateOptions, Error, Sandbox};

match Sandbox::create(CreateOptions::default()).await {
    Ok(sbx) => { /* ... */ }
    Err(Error::Quota(msg)) => eprintln!("no free slot: {msg}"), // attach instead
    Err(Error::Auth(msg)) => eprintln!("bad token: {msg}"),
    Err(other) => return Err(other.into()),
}
```

## v0 limits

- **Free tier: 1 concurrent sandbox.** A second `Sandbox::create()` returns
  `Error::Quota` while one exists - use `Sandbox::list()` +
  `Sandbox::connect()` (or `get_or_create`) to attach to the existing box, or
  `kill()` it first. Paid plans raise the limit.
- **Free boxes idle-stop after ~30 minutes.** The box (its `/home` and your
  key) is preserved; `sbx.start().await?` - or simply `get_or_create` - resumes
  it.
- Sandbox creation is throttled to 10 requests/minute per account.

## How it works

- **Control plane**: HTTPS to `api.xshellz.com/v1` (create / list / start /
  restart / destroy / stats), authenticated by your personal access token.
- **Data plane**: SSH directly to the box as `root` via russh.
  `Sandbox::create()` generates an in-memory ed25519 keypair per sandbox; the
  private key never leaves your process and the server only ever sees the
  public half, which is installed in the box's `authorized_keys`.
- **Host keys are auto-accepted.** Sandbox host keys are generated at spawn
  time, so there is no out-of-band fingerprint to pin. If your threat model
  requires host-key verification, connect manually with your own SSH tooling
  using `sbx.ssh_command()`.

## Local development (Docker)

No local Rust toolchain needed - run the full lint + test suite in a container
(`rust:1.91`, cargo registry and build artifacts persisted in named volumes so
re-runs are fast):

```bash
docker compose run --rm test
```

The repo is mounted at `/work`; the container runs `cargo fmt --check`,
`cargo clippy --all-targets -- -D warnings`, and `cargo test`. The container's
`target/` is a named volume, so host and container build artifacts never mix.

With a local toolchain, the same three commands apply:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

The **80% line-coverage gate** runs in CI (via
[`cargo-llvm-cov`](https://github.com/taiki-e/cargo-llvm-cov)) rather than in
the Docker suite, because the llvm-cov toolchain is heavy to provision locally.
To run it yourself: `cargo llvm-cov --fail-under-lines 80`.

Tests never touch the real network: the control-plane client is exercised
against a local mock HTTP server, and the SSH data plane is tested behind a
transport trait with a scripted fake.

## License

MIT
