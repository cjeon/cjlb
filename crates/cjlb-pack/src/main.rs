use std::fs;
use std::process;

use anyhow::{Context, Result};

use cjlb_pack::pack::{run_pack, PackConfig};

fn main() -> Result<()> {
    let Some(config_path) = std::env::args().nth(1) else {
        eprintln!("usage: cjlb-pack <config.json>");
        process::exit(1);
    };

    let config_str = fs::read_to_string(&config_path)
        .with_context(|| format!("cannot read config file: {config_path}"))?;

    let config: PackConfig =
        serde_json::from_str(&config_str).with_context(|| "invalid JSON in config file")?;

    // Initialise logger from config (default: info).
    let level = config.log_level_filter();
    env_logger::Builder::new().filter_level(level).init();

    log::info!("input_dir  = {}", config.input_dir);
    log::info!("output_dir = {}", config.output_dir);

    let output = run_pack(&config)?;

    // SECURITY: The master key is printed to stdout so a parent process can
    // capture it via pipe.  Never redirect stdout to a log file — the key
    // would be persisted in the clear on hostile storage.
    println!("KEY:{}", output.master_key_hex);
    println!("BUNDLE_ID:{}", output.bundle_id_hex);

    Ok(())
}
