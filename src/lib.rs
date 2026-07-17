//! Official Rust SDK for [xShellz](https://xshellz.com) sandboxes:
//! throwaway, gVisor-isolated Linux boxes you can spawn and run commands in
//! from your own program - in a few lines.
//!
//! ```no_run
//! use xshellz::{CreateOptions, RunOptions, Sandbox};
//!
//! # async fn demo() -> xshellz::Result<()> {
//! let sbx = Sandbox::create(CreateOptions::default().name("demo")).await?;
//! let result = sbx.run("echo 42", RunOptions::default()).await?;
//! println!("{}", result.stdout); // 42
//! sbx.kill().await?;
//! # Ok(()) }
//! ```
//!
//! - **Control plane**: HTTPS to `api.xshellz.com/v1` (create / list / start
//!   / destroy), authenticated by your personal access token
//!   (`XSHELLZ_API_KEY`).
//! - **Data plane**: SSH directly to the box as `root`, authenticated by an
//!   in-memory ed25519 keypair generated per [`Sandbox::create`] - the
//!   private key never leaves your process.

#![warn(missing_docs)]

mod config;
mod error;
mod http;
mod jobs;
mod keys;
mod keystore;
mod models;
mod sandbox;
mod transport;

pub use error::{Error, Result};
pub use jobs::{JobHandle, JobInfo, SpawnOptions};
pub use models::{CommandResult, ProcessInfo, SandboxInfo, SandboxProcs, SandboxStats};
pub use sandbox::{
    BoxfileOptions, ConnectOptions, CreateOptions, GetOrCreateOptions, ListOptions, RunOptions,
    Sandbox,
};
