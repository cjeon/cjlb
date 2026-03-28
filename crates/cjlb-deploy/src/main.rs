mod config;
mod deploy;

use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    let config_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("usage: cjlb-deploy <config.json>"))?;

    let config = config::DeployConfig::from_file(&config_path)?;

    // Init logger from config (default "info") instead of RUST_LOG env var.
    env_logger::Builder::new()
        .filter_level(config.log_level())
        .init();

    log::info!("loading config from {}", config_path.display());

    log::info!("validating bundle at {}", config.bundle_dir);
    config.validate()?;

    log::info!(
        "deploying {} -> {}:{}",
        config.bundle_dir,
        config.remote_host,
        config.remote_path
    );
    deploy::run_deploy(&config)?;

    println!(
        "deploy complete: {} -> {}:{}",
        config.bundle_dir, config.remote_host, config.remote_path
    );
    Ok(())
}
