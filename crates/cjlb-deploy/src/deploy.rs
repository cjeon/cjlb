use std::fmt::Write as _;
use std::process::Command;

use crate::config::DeployConfig;

/// Check that rsync is available on PATH.
fn check_rsync() -> anyhow::Result<()> {
    let status = Command::new("which")
        .arg("rsync")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    match status {
        Ok(s) if s.success() => Ok(()),
        _ => anyhow::bail!("rsync is not installed or not found on PATH"),
    }
}

/// Build and execute the rsync command, streaming output to the terminal.
pub fn run_deploy(config: &DeployConfig) -> anyhow::Result<()> {
    check_rsync()?;

    let mut cmd = Command::new("rsync");
    cmd.args(["-avz", "--partial", "--progress"]);

    // Build ssh command
    let mut ssh_cmd = format!("ssh -p {}", config.ssh_port);
    if let Some(ref key) = config.ssh_key {
        let _ = write!(ssh_cmd, " -i {key}");
    }
    cmd.args(["-e", &ssh_cmd]);

    // Extra args
    for arg in &config.rsync_extra_args {
        cmd.arg(arg);
    }

    // Source (trailing / means contents, not the dir itself)
    let source = format!("{}/", config.bundle_dir.trim_end_matches('/'));
    cmd.arg(&source);

    // Destination
    let dest = format!(
        "{}:{}/",
        config.remote_host,
        config.remote_path.trim_end_matches('/')
    );
    cmd.arg(&dest);

    log::info!("running: rsync {:?}", cmd.get_args().collect::<Vec<_>>());

    // Run with inherited stdio so output streams to the terminal
    let status = cmd
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .map_err(|e| anyhow::anyhow!("failed to execute rsync: {e}"))?;

    if !status.success() {
        anyhow::bail!("rsync failed with exit code: {:?}", status.code());
    }

    log::info!("deploy completed successfully");
    Ok(())
}
