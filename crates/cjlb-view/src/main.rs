use std::path::PathBuf;

use anyhow::{bail, Context, Result};

use cjlb_crypto::MasterKey;

use cjlb_view::bundle::BundleReader;
use cjlb_view::commands::{cmd_cat, cmd_extract, cmd_info, cmd_ls};

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Deserialize)]
struct ViewConfig {
    bundle_dir: String,
    key_hex: String,
    action: String,
    #[serde(default = "default_path")]
    path: String,
    output_dir: Option<PathBuf>,
    #[serde(default = "default_log_level")]
    log_level: String,
}

fn default_path() -> String {
    "/".to_string()
}

fn default_log_level() -> String {
    "info".to_string()
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
// Main
// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    let config_path = std::env::args()
        .nth(1)
        .context("usage: cjlb-view <config.json>")?;

    let config_bytes = std::fs::read_to_string(&config_path)
        .with_context(|| format!("failed to read config file: {config_path}"))?;

    let config: ViewConfig = serde_json::from_str(&config_bytes)
        .with_context(|| format!("failed to parse config JSON: {config_path}"))?;

    // Init logger from config log_level
    let level_filter = match config.log_level.to_lowercase().as_str() {
        "off" => log::LevelFilter::Off,
        "error" => log::LevelFilter::Error,
        "warn" => log::LevelFilter::Warn,
        "info" => log::LevelFilter::Info,
        "debug" => log::LevelFilter::Debug,
        "trace" => log::LevelFilter::Trace,
        other => bail!("invalid log_level: {other}"),
    };
    env_logger::Builder::new().filter_level(level_filter).init();

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
