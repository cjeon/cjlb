// e2e-helper — Utility binary for CJLB end-to-end tests.
//
// Takes exactly one argument: a path to a JSON config file.
// The "command" field selects the operation:
//   pack              — wrapper around cjlb-pack, prints KEY_HEX and BUNDLE_ID_HEX
//   encrypt-runtime   — encrypts runtime binary into runtime.enc format
//   prepare-config    — writes the binary config blob that the shim expects on FD 200
//   pipe-key          — writes raw 48 bytes (key + bundle_id) to stdout for piping to bootstrap

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result};
use rand::RngCore;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use serde_json::Value;
use cjlb_crypto::MasterKey;
use cjlb_pack::pack::{run_pack, PackConfig};

/// AAD used when encrypting the runtime blob (must match bootstrap).
const RUNTIME_AAD: &[u8] = b"cjlb-runtime-v1";

fn main() -> Result<()> {
    let config_path = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: e2e-helper <config.json>"))?;

    let raw = fs::read_to_string(&config_path)
        .with_context(|| format!("cannot read config file: {config_path}"))?;
    let cfg: Value =
        serde_json::from_str(&raw).with_context(|| format!("invalid JSON in {config_path}"))?;

    // Log level: honour config field, fall back to "info"
    let log_level = cfg
        .get("log_level")
        .and_then(|v| v.as_str())
        .unwrap_or("info");
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", log_level);
    }
    env_logger::init();

    let command = cfg
        .get("command")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("config missing \"command\" field"))?;

    match command {
        "pack" => {
            let input_dir = str_field(&cfg, "input_dir")?;
            let output_dir = str_field(&cfg, "output_dir")?;
            cmd_pack(PathBuf::from(input_dir), PathBuf::from(output_dir))
        }
        "encrypt-runtime" => {
            let key_hex = str_field(&cfg, "key_hex")?;
            let runtime_bin = str_field(&cfg, "runtime_bin")?;
            let output = str_field(&cfg, "output")?;
            cmd_encrypt_runtime(key_hex, &PathBuf::from(runtime_bin), &PathBuf::from(output))
        }
        "prepare-config" => {
            let key_hex = str_field(&cfg, "key_hex")?;
            let bundle_id_hex = str_field(&cfg, "bundle_id_hex")?;
            let bundle_dir = str_field(&cfg, "bundle_dir")?;
            let virtual_root = str_field_or(&cfg, "virtual_root", "/vroot");
            let write_dir = str_field_or(&cfg, "write_dir", "/tmp/cjlb-write");
            let memory_budget_mb = cfg
                .get("memory_budget_mb")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32;
            let log_level_val = str_field_or(&cfg, "log_level", "info");
            let output = str_field(&cfg, "output")?;
            cmd_prepare_config(
                key_hex,
                bundle_id_hex,
                &PathBuf::from(bundle_dir),
                virtual_root,
                write_dir,
                memory_budget_mb,
                log_level_val,
                &PathBuf::from(output),
            )
        }
        "pipe-key" => {
            let key_hex = str_field(&cfg, "key_hex")?;
            let bundle_id_hex = str_field(&cfg, "bundle_id_hex")?;
            cmd_pipe_key(key_hex, bundle_id_hex)
        }
        other => anyhow::bail!("unknown command: {other}"),
    }
}

/// Extract a required string field from the JSON config.
fn str_field<'a>(cfg: &'a Value, key: &str) -> Result<&'a str> {
    cfg.get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("config missing \"{key}\" field"))
}

/// Extract an optional string field with a default.
fn str_field_or<'a>(cfg: &'a Value, key: &str, default: &'a str) -> &'a str {
    cfg.get(key).and_then(|v| v.as_str()).unwrap_or(default)
}

// ---------------------------------------------------------------------------
// pack
// ---------------------------------------------------------------------------

fn cmd_pack(input_dir: PathBuf, output_dir: PathBuf) -> Result<()> {
    let config = PackConfig {
        input_dir: input_dir.to_string_lossy().to_string(),
        output_dir: output_dir.to_string_lossy().to_string(),
        log_level: None,
    };
    let output = run_pack(&config).context("pack failed")?;
    println!("KEY:{}", output.master_key_hex);
    println!("BUNDLE_ID:{}", output.bundle_id_hex);
    Ok(())
}

// ---------------------------------------------------------------------------
// encrypt-runtime
// ---------------------------------------------------------------------------

fn cmd_encrypt_runtime(key_hex: &str, runtime_bin: &PathBuf, output: &PathBuf) -> Result<()> {
    let key_bytes = hex_decode(key_hex).context("invalid key hex")?;
    anyhow::ensure!(key_bytes.len() == 32, "key must be 32 bytes");

    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);

    // Derive runtime_dek from master key
    let master = MasterKey::from_bytes(key);
    let dk = master.derive_keys();

    let plaintext = fs::read(runtime_bin)
        .with_context(|| format!("cannot read runtime binary: {}", runtime_bin.display()))?;

    // Generate random 12-byte nonce
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

    // Encrypt with AES-256-GCM using runtime_dek and AAD (ring, hardware-accelerated)
    let unbound_key = UnboundKey::new(&AES_256_GCM, &dk.runtime_dek)
        .map_err(|e| anyhow::anyhow!("failed to create key: {e}"))?;
    let key = LessSafeKey::new(unbound_key);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let mut data = plaintext.clone();
    let tag = key
        .seal_in_place_separate_tag(nonce, Aad::from(RUNTIME_AAD), &mut data)
        .map_err(|e| anyhow::anyhow!("encryption failed: {e}"))?;

    // Write: nonce(12) || ciphertext || tag(16)
    let mut out = Vec::with_capacity(12 + data.len() + tag.as_ref().len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&data);
    out.extend_from_slice(tag.as_ref());

    fs::write(output, &out)
        .with_context(|| format!("cannot write output: {}", output.display()))?;

    eprintln!(
        "Encrypted runtime: {} bytes plaintext -> {} bytes ciphertext",
        plaintext.len(),
        out.len()
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// prepare-config
// ---------------------------------------------------------------------------

/// Write the config blob in the format the shim expects.
///
/// Wire format (matches both cjlb-runtime's serialize_config_blob and the shim's
/// parse_config_blob):
///   version(u32)=1 | virtual_root_len(u32) | virtual_root
///   | bundle_dir_len(u32) | bundle_dir | write_dir_len(u32) | write_dir
///   | bundle_id(16) | master_key(32) | memory_budget_mb(u32)
///   | log_level_len(u32) | log_level | memory_pressure_monitor(u8)
///   | ipc_socket(u8)
#[allow(clippy::too_many_arguments)]
fn cmd_prepare_config(
    key_hex: &str,
    bundle_id_hex: &str,
    bundle_dir: &std::path::Path,
    virtual_root: &str,
    write_dir: &str,
    memory_budget_mb: u32,
    log_level: &str,
    output: &PathBuf,
) -> Result<()> {
    let key_bytes = hex_decode(key_hex).context("invalid key hex")?;
    anyhow::ensure!(key_bytes.len() == 32, "key must be 32 bytes");
    let bid_bytes = hex_decode(bundle_id_hex).context("invalid bundle_id hex")?;
    anyhow::ensure!(bid_bytes.len() == 16, "bundle_id must be 16 bytes");

    let mut master_key = [0u8; 32];
    master_key.copy_from_slice(&key_bytes);
    let mut bundle_id = [0u8; 16];
    bundle_id.copy_from_slice(&bid_bytes);

    let bundle_dir_str = bundle_dir.to_string_lossy();

    // Build config blob matching the shim's parse_config_blob wire format.
    let mut buf = Vec::new();

    // version prefix (u32 LE = 1)
    buf.extend_from_slice(&1u32.to_le_bytes());

    // virtual_root
    buf.extend_from_slice(&(virtual_root.len() as u32).to_le_bytes());
    buf.extend_from_slice(virtual_root.as_bytes());

    // bundle_dir
    buf.extend_from_slice(&(bundle_dir_str.len() as u32).to_le_bytes());
    buf.extend_from_slice(bundle_dir_str.as_bytes());

    // write_dir
    buf.extend_from_slice(&(write_dir.len() as u32).to_le_bytes());
    buf.extend_from_slice(write_dir.as_bytes());

    // bundle_id (16 bytes)
    buf.extend_from_slice(&bundle_id);

    // master_key (32 bytes)
    buf.extend_from_slice(&master_key);

    // memory_budget_mb (u32)
    buf.extend_from_slice(&memory_budget_mb.to_le_bytes());

    // log_level
    buf.extend_from_slice(&(log_level.len() as u32).to_le_bytes());
    buf.extend_from_slice(log_level.as_bytes());

    // memory_pressure_monitor (default: enabled)
    buf.push(1u8);

    // ipc_socket (default: enabled)
    buf.push(1u8);

    fs::write(output, &buf)
        .with_context(|| format!("cannot write config blob: {}", output.display()))?;

    eprintln!(
        "Config blob: {} bytes written to {}",
        buf.len(),
        output.display()
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// pipe-key
// ---------------------------------------------------------------------------

fn cmd_pipe_key(key_hex: &str, bundle_id_hex: &str) -> Result<()> {
    let key_bytes = hex_decode(key_hex).context("invalid key hex")?;
    anyhow::ensure!(key_bytes.len() == 32, "key must be 32 bytes");
    let bid_bytes = hex_decode(bundle_id_hex).context("invalid bundle_id hex")?;
    anyhow::ensure!(bid_bytes.len() == 16, "bundle_id must be 16 bytes");

    let mut payload = [0u8; 48];
    payload[..32].copy_from_slice(&key_bytes);
    payload[32..48].copy_from_slice(&bid_bytes);

    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    handle
        .write_all(&payload)
        .context("failed to write to stdout")?;
    handle.flush().context("failed to flush stdout")?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    anyhow::ensure!(s.len().is_multiple_of(2), "hex string has odd length");
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .with_context(|| format!("invalid hex at position {i}"))
        })
        .collect()
}
