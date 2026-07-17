//! Spawn a sandbox, run a command, round-trip a file, destroy the box.
//!
//! ```bash
//! export XSHELLZ_API_KEY="your-token"
//! cargo run --example basic
//! ```

use xshellz::{CreateOptions, RunOptions, Sandbox};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sbx = Sandbox::create(CreateOptions::default().name("rust-sdk-demo")).await?;
    println!(
        "sandbox {} is {} ({})",
        sbx.uuid(),
        sbx.status(),
        sbx.ssh_command().unwrap_or_default()
    );

    // Run a command. A non-zero exit code is data, not an error.
    let result = sbx
        .run("echo 42 && uname -a", RunOptions::default())
        .await?;
    println!("exit={} stdout={}", result.exit_code, result.stdout.trim());

    // Stream long-running output as it arrives.
    sbx.run(
        "for i in 1 2 3; do echo tick $i; sleep 1; done",
        RunOptions::default().on_stdout(|chunk| print!("{chunk}")),
    )
    .await?;

    // Files.
    sbx.write_file("/tmp/hello.bin", b"hello from the xshellz rust sdk\n")
        .await?;
    let data = sbx.read_file("/tmp/hello.bin").await?;
    println!("read back {} bytes", data.len());

    // Destroy the box. (Dropping the Sandbox also fires a best-effort
    // destroy, but kill() is the reliable path.)
    sbx.kill().await?;
    println!("sandbox destroyed");
    Ok(())
}
