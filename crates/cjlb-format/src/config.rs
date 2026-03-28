use serde::{Deserialize, Serialize};
use std::collections::HashMap;

fn default_log_level() -> String {
    "info".to_string()
}

const fn default_true() -> bool {
    true
}

/// Client configuration — deserialized from `configs.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub entrypoint: String,
    pub virtual_root: String,
    #[serde(default)]
    pub memory_budget_mb: Option<u32>,
    #[serde(default)]
    pub env: HashMap<String, String>,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default = "default_true")]
    pub memory_pressure_monitor: bool,
    #[serde(default = "default_true")]
    pub ipc_socket: bool,
}

/// Paths that must never be used as `virtual_root` (exact match).
const FORBIDDEN_EXACT_ROOTS: &[&str] = &["/"];

/// Prefix paths that must never be used as `virtual_root`.
/// A `virtual_root` that equals or starts with any of these (followed by `/` or end)
/// is rejected — e.g. `/proc`, `/proc/`, `/proc/1/maps` are all forbidden.
const FORBIDDEN_PREFIX_ROOTS: &[&str] = &["/proc", "/sys", "/dev"];

/// Environment variable keys that are never allowed.
const FORBIDDEN_ENV_KEYS: &[&str] = &["LD_PRELOAD", "LD_LIBRARY_PATH"];

/// Prefix for env keys that are reserved by the runtime.
const RESERVED_ENV_PREFIX: &str = "CJLB_";

/// Minimum allowed memory budget in MiB.
const MIN_MEMORY_BUDGET_MB: u32 = 10;

#[derive(Debug, thiserror::Error)]
pub enum ConfigValidationError {
    #[error("virtual_root must not be a system path: {0}")]
    ForbiddenVirtualRoot(String),

    #[error("virtual_root must not contain '..'")]
    TraversalInVirtualRoot,

    #[error("forbidden environment variable: {0}")]
    ForbiddenEnvKey(String),
}

impl ClientConfig {
    /// Validate and sanitise the configuration in place.
    ///
    /// - Rejects dangerous `virtual_root` values (normalizes trailing slashes,
    ///   uses prefix matching for `/proc`, `/sys`, `/dev`).
    /// - Rejects forbidden env keys (`LD_PRELOAD`, `LD_LIBRARY_PATH`, `CJLB_*`).
    /// - Clamps `memory_budget_mb` to at least 10.
    ///
    /// # Errors
    ///
    /// Returns `ConfigValidationError` if `virtual_root` is a forbidden system
    /// path or contains path traversal (`..`), or if env contains a forbidden key.
    pub fn validate(&mut self) -> Result<(), ConfigValidationError> {
        // --- virtual_root checks ---
        let vr = self.virtual_root.trim_end_matches('/');
        // Empty after stripping means the input was "/" or "///…"
        let vr = if vr.is_empty() { "/" } else { vr };

        if FORBIDDEN_EXACT_ROOTS.contains(&vr) {
            return Err(ConfigValidationError::ForbiddenVirtualRoot(vr.to_string()));
        }
        for prefix in FORBIDDEN_PREFIX_ROOTS {
            if vr == *prefix || vr.starts_with(&format!("{prefix}/")) {
                return Err(ConfigValidationError::ForbiddenVirtualRoot(vr.to_string()));
            }
        }
        if vr.contains("..") {
            return Err(ConfigValidationError::TraversalInVirtualRoot);
        }

        // --- env key rejection ---
        if let Some(bad_key) = self.env.keys().find(|k| {
            FORBIDDEN_ENV_KEYS.contains(&k.as_str()) || k.starts_with(RESERVED_ENV_PREFIX)
        }) {
            return Err(ConfigValidationError::ForbiddenEnvKey(bad_key.clone()));
        }

        // --- memory budget clamping ---
        if let Some(ref mut mb) = self.memory_budget_mb {
            if *mb < MIN_MEMORY_BUDGET_MB {
                *mb = MIN_MEMORY_BUDGET_MB;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_config() -> ClientConfig {
        ClientConfig {
            entrypoint: "/app/main".to_string(),
            virtual_root: "/mnt/data".to_string(),
            memory_budget_mb: Some(64),
            env: HashMap::new(),
            log_level: "info".to_string(),
            memory_pressure_monitor: true,
            ipc_socket: true,
        }
    }

    #[test]
    fn valid_config_passes() {
        let mut cfg = base_config();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn rejects_root_virtual_root() {
        let mut cfg = base_config();
        cfg.virtual_root = "/".to_string();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_proc() {
        let mut cfg = base_config();
        cfg.virtual_root = "/proc".to_string();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_sys() {
        let mut cfg = base_config();
        cfg.virtual_root = "/sys".to_string();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_dev() {
        let mut cfg = base_config();
        cfg.virtual_root = "/dev".to_string();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_proc_trailing_slash() {
        let mut cfg = base_config();
        cfg.virtual_root = "/proc/".to_string();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_proc_subpath() {
        let mut cfg = base_config();
        cfg.virtual_root = "/proc/1/maps".to_string();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_sys_trailing_slash() {
        let mut cfg = base_config();
        cfg.virtual_root = "/sys/".to_string();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_dev_trailing_slash() {
        let mut cfg = base_config();
        cfg.virtual_root = "/dev/".to_string();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_root_trailing_slashes() {
        let mut cfg = base_config();
        cfg.virtual_root = "///".to_string();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_traversal() {
        let mut cfg = base_config();
        cfg.virtual_root = "/mnt/../etc".to_string();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_ld_preload() {
        let mut cfg = base_config();
        cfg.env.insert("LD_PRELOAD".into(), "evil.so".into());
        cfg.env.insert("SAFE_KEY".into(), "ok".into());
        assert!(matches!(
            cfg.validate(),
            Err(ConfigValidationError::ForbiddenEnvKey(ref k)) if k == "LD_PRELOAD"
        ));
    }

    #[test]
    fn rejects_ld_library_path() {
        let mut cfg = base_config();
        cfg.env.insert("LD_LIBRARY_PATH".into(), "/tmp/lib".into());
        assert!(matches!(
            cfg.validate(),
            Err(ConfigValidationError::ForbiddenEnvKey(ref k)) if k == "LD_LIBRARY_PATH"
        ));
    }

    #[test]
    fn rejects_cjlb_prefix() {
        let mut cfg = base_config();
        cfg.env.insert("CJLB_SECRET".into(), "val".into());
        assert!(matches!(
            cfg.validate(),
            Err(ConfigValidationError::ForbiddenEnvKey(ref k)) if k == "CJLB_SECRET"
        ));
    }

    #[test]
    fn clamps_memory_budget() {
        let mut cfg = base_config();
        cfg.memory_budget_mb = Some(2);
        cfg.validate().unwrap();
        assert_eq!(cfg.memory_budget_mb, Some(10));
    }

    #[test]
    fn memory_budget_none_untouched() {
        let mut cfg = base_config();
        cfg.memory_budget_mb = None;
        cfg.validate().unwrap();
        assert_eq!(cfg.memory_budget_mb, None);
    }

    #[test]
    fn serde_roundtrip() {
        let cfg = base_config();
        let json = serde_json::to_string(&cfg).unwrap();
        let cfg2: ClientConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg2.entrypoint, cfg.entrypoint);
        assert_eq!(cfg2.virtual_root, cfg.virtual_root);
    }

    #[test]
    fn serde_defaults() {
        let json = r#"{"entrypoint":"/app","virtual_root":"/mnt"}"#;
        let cfg: ClientConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.log_level, "info");
        assert_eq!(cfg.memory_budget_mb, None);
        assert!(cfg.env.is_empty());
    }
}
