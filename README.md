# xshellz

Official Rust SDK for [xShellz](https://xshellz.com) sandboxes: throwaway,
gVisor-isolated Linux boxes you can spawn and run commands in from your own
program - in a few lines.

```bash
cargo add xshellz
```

```rust
use xshellz::{CreateOptions, RunOptions, Sandbox};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sbx = Sandbox::create(CreateOptions::default()).await?;
    let result = sbx.run("echo 42", RunOptions::default()).await?;
    println!("{}", result.stdout); // 42
    sbx.kill().await?;
    Ok(())
}
```

Each sandbox is a real Linux box (root shell, package manager, network) running
under [gVisor](https://gvisor.dev) kernel isolation. Spawning is synchronous -
`Sandbox::create()` returns once the box is running, typically in a few
seconds. The SDK is async and runs on [Tokio](https://tokio.rs).

## Authentication

The SDK authenticates with an xShellz personal access token (PAT) carrying the
`read` and `write` scopes:

1. Create a token from your [xShellz dashboard](https://app.xshellz.com)
   (Settings -> API tokens), or via the API: `POST /v1/auth/tokens`.
2. Export it:

```bash
export XSHELLZ_API_KEY="your-token"
```

or pass it explicitly: `CreateOptions::default().api_key("your-token")`.

Config precedence: explicit option > `XSHELLZ_API_KEY` / `XSHELLZ_API_URL`
environment variables > default (`https://api.xshellz.com/v1`).

To target a staging or self-hosted control plane:

```bash
export XSHELLZ_API_URL="https://api.staging.example.com/v1"
```

## Usage

### Run commands

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

// A non-zero exit code does NOT return an Err - it's data:
let r = sbx.run("false", RunOptions::default()).await?;
assert_eq!(r.exit_code, 1);

// cwd and env:
sbx.run(
    "make test",
    RunOptions::default().cwd("/srv/app").env_var("CI", "1"),
)
.await?;

// Stream long-running output as it arrives:
sbx.run(
    "npm run build",
    RunOptions::default()
        .on_stdout(|chunk| print!("{chunk}"))
        .on_stderr(|chunk| eprint!("{chunk}")),
)
.await?;
```

### Files

```rust
sbx.write_file("/tmp/config.json", br#"{"debug": true}"#).await?;
let data: Vec<u8> = sbx.read_file("/tmp/config.json").await?;

sbx.upload("local.txt", "/tmp/remote.txt").await?;
sbx.download("/tmp/remote.txt", "out.txt").await?;
```

File transfer is exec-based (`cat` over the SSH exec channel) rather than
SFTP - binary-safe in both directions with no extra subsystem or dependency.

### Lifecycle

```rust
sbx.uuid();          // sandbox id
sbx.ssh_host();      // e.g. Some("shellus1.xshellz.com")
sbx.ssh_port();      // e.g. Some(42001)
sbx.ssh_command();   // ready-to-copy "ssh -p 42001 root@..."
sbx.status();        // "running", "stopped", ...

sbx.detach();        // keep the box alive when the Sandbox is dropped
sbx.kill().await?;   // destroy the box explicitly
sbx.start().await?;  // resume an idle-stopped box

// Re-attach later (persist sbx.private_key_openssh() + sbx.uuid() for this):
let sbx = Sandbox::connect(&uuid, &saved_private_key, ConnectOptions::default()).await?;

// Enumerate your sandboxes:
for info in Sandbox::list(ListOptions::default()).await? {
    println!("{} {}", info.uuid, info.status);
}
```

Dropping a `Sandbox` without `detach()` or `kill()` fires a best-effort,
fire-and-forget destroy request on the current Tokio runtime. `Drop` cannot
block on async work, so this is not guaranteed - `kill().await` is the
reliable way to destroy a box.

### Typed errors

```rust
use xshellz::{CreateOptions, Error, Sandbox};

match Sandbox::create(CreateOptions::default()).await {
    Ok(sbx) => { /* ... */ }
    Err(Error::Quota(_)) => {
        // plan limit reached - attach to the existing box instead
        let existing = &Sandbox::list(Default::default()).await?[0];
        let sbx = Sandbox::connect(&existing.uuid, &saved_key, Default::default()).await?;
    }
    Err(Error::Auth(msg)) => eprintln!("{msg}"), // missing/invalid token, scope, verification
    Err(other) => return Err(other.into()),
}
```

- `Error::Auth` - 401/403: bad or missing token, scopes, account gates
- `Error::Quota` - plan sandbox limit reached / plan has no sandbox entitlement
- `Error::NotRunning` - operation needs a `running` box
- `Error::CommandTimeout` - a `RunOptions::timeout` was exceeded
- `Error::Api { status, body }` - any other 4xx/5xx (throttle 429, capacity 503, ...)
- `Error::Ssh` / `Error::Io` - data-plane and local failures

A non-zero command exit code is never an error - inspect
`CommandResult::exit_code`.

## How it works

- **Control plane**: HTTPS to `api.xshellz.com/v1` (create / list / start /
  destroy), authenticated by your PAT. TLS is pure-Rust
  ([rustls](https://github.com/rustls/rustls)); no OpenSSL.
- **Data plane**: SSH directly to the box as `root` via
  [russh](https://github.com/Eugeny/russh) (pure Rust). `Sandbox::create()`
  generates an in-memory ed25519 keypair per sandbox; the private key never
  leaves your process and the server never sees it - only the public half is
  installed in the box's `authorized_keys`.
- **Host keys are auto-accepted.** Sandbox host keys are generated at spawn
  time, so there is no out-of-band fingerprint to pin. If your threat model
  requires host-key verification, connect manually with your own SSH tooling
  using `sbx.ssh_command()`.

## v0 limits

- **Free tier: 1 concurrent sandbox.** A second `Sandbox::create()` returns
  `Error::Quota` while one exists - use `Sandbox::list()` +
  `Sandbox::connect()` to attach to the existing box, or `kill()` it first.
  Paid plans raise the limit.
- **Free boxes idle-stop after ~30 minutes.** The box (its `/home` and your
  key) is preserved; call `sbx.start()` to resume it.
- Sandbox creation is throttled to 10 requests/minute per account.

## Local development (Docker)

No local Rust toolchain needed - run the full lint + test suite in a
container (`rust:1.91`, cargo registry and build artifacts persisted in named
volumes so re-runs are fast):

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

Tests never touch the real network: the control-plane client is exercised
against a local mock HTTP server, and the SSH data plane is tested behind a
transport trait with a scripted fake.

## License

MIT
