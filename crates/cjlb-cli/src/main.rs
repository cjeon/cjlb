// CJLB — Unified CLI for cjeon's lockbox.
//
// Dispatches to pack, view, or deploy based on the "command" field in a JSON
// config file.  See `cjlb help` for usage.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

use cjlb_crypto::MasterKey;
use cjlb_pack::pack::{run_pack, PackConfig};
use cjlb_view::bundle::BundleReader;
use cjlb_view::commands::{cmd_cat, cmd_extract, cmd_info, cmd_ls};

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    match args.get(1).map(String::as_str) {
        None | Some("help" | "--help" | "-h") => {
            let subcommand = args.get(2).map(String::as_str);
            print_help(subcommand);
            Ok(())
        }
        Some("version" | "--version" | "-V") => {
            println!("cjlb {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some(config_path) => run_config(config_path),
    }
}

// ---------------------------------------------------------------------------
// Config dispatch
// ---------------------------------------------------------------------------

fn run_config(path: &str) -> Result<()> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read config file: {path}"))?;
    let value: serde_json::Value =
        serde_json::from_str(&content).with_context(|| "invalid JSON in config file")?;
    let command = value
        .get("command")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("config missing 'command' field"))?;

    // Init logger from config (default: info).
    let log_level = value
        .get("log_level")
        .and_then(|v| v.as_str())
        .unwrap_or("info");
    init_logger(log_level);

    match command {
        "pack" => cmd_pack(&content),
        "view" => cmd_view(&content),
        "deploy" => cmd_deploy(&content),
        other => bail!("unknown command: '{other}'. Run 'cjlb help' for usage."),
    }
}

fn init_logger(level: &str) {
    let filter = match level.to_ascii_lowercase().as_str() {
        "off" => log::LevelFilter::Off,
        "error" => log::LevelFilter::Error,
        "warn" => log::LevelFilter::Warn,
        "debug" => log::LevelFilter::Debug,
        "trace" => log::LevelFilter::Trace,
        _ => log::LevelFilter::Info,
    };
    env_logger::Builder::new().filter_level(filter).init();
}

// ---------------------------------------------------------------------------
// pack
// ---------------------------------------------------------------------------

fn cmd_pack(config_json: &str) -> Result<()> {
    let config: PackConfig =
        serde_json::from_str(config_json).context("invalid pack config JSON")?;

    log::info!("input_dir  = {}", config.input_dir);
    log::info!("output_dir = {}", config.output_dir);

    let output = run_pack(&config)?;

    // SECURITY: The master key is printed to stdout so a parent process can
    // capture it via pipe.  Never redirect stdout to a log file -- the key
    // would be persisted in the clear on hostile storage.
    println!("KEY:{}", output.master_key_hex);
    println!("BUNDLE_ID:{}", output.bundle_id_hex);

    Ok(())
}

// ---------------------------------------------------------------------------
// view
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Deserialize)]
struct ViewConfig {
    bundle_dir: String,
    key_hex: String,
    action: String,
    #[serde(default = "default_path")]
    path: String,
    output_dir: Option<PathBuf>,
}

fn default_path() -> String {
    "/".to_string()
}

fn cmd_view(config_json: &str) -> Result<()> {
    let config: ViewConfig =
        serde_json::from_str(config_json).context("invalid view config JSON")?;

    let bundle_dir = PathBuf::from(&config.bundle_dir);

    // Stream action requires a running shim — no disk fallback.
    if config.action == "stream" {
        return cjlb_view::socket_client::stream(&bundle_dir, &config.path);
    }

    // Try IPC socket first (zero decryption cost when shim is running).
    if let Some(result) = cjlb_view::socket_client::try_via_socket(
        &bundle_dir,
        &config.action,
        &config.path,
        config.output_dir.as_deref(),
    ) {
        return result;
    }

    // Fall back to direct disk access.
    let key_bytes = hex_to_32_bytes(&config.key_hex)?;
    let master_key = MasterKey::from_bytes(key_bytes);

    let reader = BundleReader::open(&bundle_dir, &master_key).context("failed to open bundle")?;

    match config.action.as_str() {
        "ls" => cmd_ls(&reader, &config.path)?,
        "cat" => cmd_cat(&reader, &config.path)?,
        "extract" => {
            let output_dir = config
                .output_dir
                .as_ref()
                .context("output_dir is required for extract action")?;
            cmd_extract(&reader, &config.path, output_dir)?;
        }
        "info" => cmd_info(&reader)?,
        other => bail!("unknown action: {other} (expected: ls, cat, extract, info, stream)"),
    }

    Ok(())
}

/// Decode a 64-char hex string into 32 bytes.
fn hex_to_32_bytes(hex: &str) -> Result<[u8; 32]> {
    if hex.len() != 64 {
        bail!(
            "key_hex must be exactly 64 hex characters (32 bytes), got {} chars",
            hex.len()
        );
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .with_context(|| format!("invalid hex at position {}", i * 2))?;
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// deploy
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Deserialize)]
struct DeployConfig {
    bundle_dir: String,
    remote_host: String,
    remote_path: String,
    ssh_key: Option<String>,
    #[serde(default = "default_ssh_port")]
    ssh_port: u16,
    #[serde(default)]
    rsync_extra_args: Vec<String>,
}

const fn default_ssh_port() -> u16 {
    22
}

fn cmd_deploy(config_json: &str) -> Result<()> {
    let config: DeployConfig =
        serde_json::from_str(config_json).context("invalid deploy config JSON")?;

    // Validate bundle directory.
    validate_bundle_dir(&config.bundle_dir)?;

    if let Some(ref key) = config.ssh_key {
        let key_path = Path::new(key);
        if !key_path.exists() {
            bail!("ssh_key does not exist: {key}");
        }
    }

    log::info!(
        "deploying {} -> {}:{}",
        config.bundle_dir,
        config.remote_host,
        config.remote_path
    );

    // Check rsync is available.
    let rsync_check = Command::new("which")
        .arg("rsync")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    match rsync_check {
        Ok(s) if s.success() => {}
        _ => bail!("rsync is not installed or not found on PATH"),
    }

    // Build rsync command.
    let mut cmd = Command::new("rsync");
    cmd.args(["-avz", "--partial", "--progress"]);

    let mut ssh_cmd = format!("ssh -p {}", config.ssh_port);
    if let Some(ref key) = config.ssh_key {
        let _ = write!(ssh_cmd, " -i {key}");
    }
    cmd.args(["-e", &ssh_cmd]);

    for arg in &config.rsync_extra_args {
        cmd.arg(arg);
    }

    let source = format!("{}/", config.bundle_dir.trim_end_matches('/'));
    cmd.arg(&source);

    let dest = format!(
        "{}:{}/",
        config.remote_host,
        config.remote_path.trim_end_matches('/')
    );
    cmd.arg(&dest);

    log::info!("running: rsync {:?}", cmd.get_args().collect::<Vec<_>>());

    let status = cmd
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .map_err(|e| anyhow::anyhow!("failed to execute rsync: {e}"))?;

    if !status.success() {
        bail!("rsync failed with exit code: {:?}", status.code());
    }

    println!(
        "deploy complete: {} -> {}:{}",
        config.bundle_dir, config.remote_host, config.remote_path
    );
    Ok(())
}

fn validate_bundle_dir(bundle_dir: &str) -> Result<()> {
    let bundle = Path::new(bundle_dir);
    if !bundle.exists() {
        bail!("bundle_dir does not exist: {bundle_dir}");
    }
    if !bundle.is_dir() {
        bail!("bundle_dir is not a directory: {bundle_dir}");
    }
    let manifest = bundle.join("manifest.enc");
    if !manifest.exists() {
        bail!(
            "bundle_dir is missing manifest.enc: {}",
            manifest.display()
        );
    }
    let chunks = bundle.join("chunks");
    if !chunks.is_dir() {
        bail!(
            "bundle_dir is missing chunks/ directory: {}",
            chunks.display()
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Help
// ---------------------------------------------------------------------------

fn print_help(subcommand: Option<&str>) {
    match subcommand {
        Some("pack") => print_help_pack(),
        Some("view") => print_help_view(),
        Some("deploy") => print_help_deploy(),
        _ => print_help_main(),
    }
}

fn print_help_main() {
    println!(
        "\
CJLB \u{2014} cjeon's lockbox

Usage:
  cjlb <config.json>       Run a command defined in the config file
  cjlb help [command]      Show help for a specific command
  cjlb version             Show version

Commands:
  pack      Encrypt a directory into an CJLB bundle
  view      Browse or extract files from an encrypted bundle
  deploy    Transfer a bundle to a remote host via rsync

Run 'cjlb help <command>' for config schema and examples."
    );
}

fn print_help_pack() {
    println!(
        r#"cjlb pack -- Encrypt a directory into an CJLB bundle

Config schema (JSON):
{{
  "command": "pack",
  "input_dir": "/path/to/source/directory",
  "output_dir": "/path/to/output/bundle",
  "log_level": "info"                        // optional: trace|debug|info|warn|error
}}

Example:
  echo '{{"command":"pack","input_dir":"./data","output_dir":"./bundle"}}' > pack.json
  cjlb pack.json

Output:
  KEY:<hex>            Master key (64 hex chars). Capture securely.
  BUNDLE_ID:<hex>      Bundle identifier (32 hex chars).

The master key is always freshly generated. Never reuse keys across deployments."#
    );
}

fn print_help_view() {
    println!(
        r#"cjlb view -- Browse or extract files from an encrypted bundle

Config schema (JSON):
{{
  "command": "view",
  "bundle_dir": "/path/to/bundle",
  "key_hex": "<64 hex chars>",
  "action": "ls|cat|extract|info|stream",
  "path": "/",                               // optional: virtual path (default "/")
  "output_dir": "/path/to/extract/to",       // required for action=extract
  "log_level": "info"                        // optional
}}

Actions:
  ls [path]     List directory contents
  cat <path>    Print file to stdout
  extract       Extract file or directory to output_dir
  info          Show bundle metadata
  stream <path> Stream a file's writes in real-time (requires running shim)

Example:
  echo '{{"command":"view","bundle_dir":"./bundle","key_hex":"abcd...","action":"ls"}}' > view.json
  cjlb view.json"#
    );
}

fn print_help_deploy() {
    println!(
        r#"cjlb deploy -- Transfer a bundle to a remote host via rsync

Config schema (JSON):
{{
  "command": "deploy",
  "bundle_dir": "/local/path/to/bundle",
  "remote_host": "user@hostname",
  "remote_path": "/remote/path",
  "ssh_key": "/path/to/key",                // optional
  "ssh_port": 22,                            // optional (default 22)
  "rsync_extra_args": [],                    // optional
  "log_level": "info"                        // optional
}}

Requires rsync installed on both local and remote hosts.
Supports resumable transfers (--partial) for TB-scale bundles."#
    );
}
