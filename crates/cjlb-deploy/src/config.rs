use std::path::Path;

#[derive(Debug, serde::Deserialize)]
pub struct DeployConfig {
    pub bundle_dir: String,
    pub remote_host: String,
    pub remote_path: String,
    pub ssh_key: Option<String>,
    #[serde(default = "default_port")]
    pub ssh_port: u16,
    #[serde(default)]
    pub rsync_extra_args: Vec<String>,
    #[serde(default = "default_log_level")]
    log_level: String,
}

const fn default_port() -> u16 {
    22
}

fn default_log_level() -> String {
    "info".to_string()
}

impl DeployConfig {
    /// Return the configured log level (default: info).
    pub fn log_level(&self) -> log::LevelFilter {
        match self.log_level.to_ascii_lowercase().as_str() {
            "off" => log::LevelFilter::Off,
            "error" => log::LevelFilter::Error,
            "warn" => log::LevelFilter::Warn,
            "debug" => log::LevelFilter::Debug,
            "trace" => log::LevelFilter::Trace,
            // "info" and anything unrecognised both map to Info
            _ => log::LevelFilter::Info,
        }
    }

    /// Load config from a JSON file.
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("failed to read config file {}: {}", path.display(), e))?;
        let config: Self = serde_json::from_str(&contents).map_err(|e| {
            anyhow::anyhow!("failed to parse config file {}: {}", path.display(), e)
        })?;
        Ok(config)
    }

    /// Validate that `bundle_dir` exists and contains the expected structure.
    pub fn validate(&self) -> anyhow::Result<()> {
        let bundle = Path::new(&self.bundle_dir);

        if !bundle.exists() {
            anyhow::bail!("bundle_dir does not exist: {}", self.bundle_dir);
        }
        if !bundle.is_dir() {
            anyhow::bail!("bundle_dir is not a directory: {}", self.bundle_dir);
        }

        let manifest = bundle.join("manifest.enc");
        if !manifest.exists() {
            anyhow::bail!("bundle_dir is missing manifest.enc: {}", manifest.display());
        }

        let chunks = bundle.join("chunks");
        if !chunks.is_dir() {
            anyhow::bail!(
                "bundle_dir is missing chunks/ directory: {}",
                chunks.display()
            );
        }

        if let Some(ref key) = self.ssh_key {
            let key_path = Path::new(key);
            if !key_path.exists() {
                anyhow::bail!("ssh_key does not exist: {key}");
            }
        }

        Ok(())
    }
}
