// config_blob.rs — Serialize the shim config blob to a memfd.
//
// Binary format:
//   [4 bytes] version: u32 LE = 1
//   [4 bytes] virtual_root_len: u32 LE
//   [N bytes] virtual_root (UTF-8, no null terminator)
//   [4 bytes] bundle_dir_len: u32 LE
//   [N bytes] bundle_dir (UTF-8)
//   [4 bytes] write_dir_len: u32 LE
//   [N bytes] write_dir (UTF-8)
//   [16 bytes] bundle_id
//   [32 bytes] master_key
//   [4 bytes] memory_budget_mb: u32 LE (0 = auto)
//   [4 bytes] log_level_len: u32 LE
//   [N bytes] log_level (UTF-8)
//   [1 byte]  memory_pressure_monitor: u8 (1 = enabled, 0 = disabled)
//   [1 byte]  ipc_socket: u8 (1 = enabled, 0 = disabled)

use std::path::Path;

use anyhow::{Context, Result};

/// Current config blob version.
const CONFIG_BLOB_VERSION: u32 = 1;

/// Write a length-prefixed string field into the buffer.
fn write_len_prefixed(buf: &mut Vec<u8>, data: &[u8], field: &str) -> Result<()> {
    let len =
        u32::try_from(data.len()).with_context(|| format!("{field} length exceeds u32::MAX"))?;
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(data);
    Ok(())
}

/// Serialize the shim config blob into a byte vector.
#[allow(clippy::too_many_arguments)]
pub fn serialize_config_blob(
    virtual_root: &str,
    bundle_dir: &Path,
    write_dir: &Path,
    bundle_id: &[u8; 16],
    master_key: &[u8; 32],
    memory_budget_mb: u32,
    log_level: &str,
    memory_pressure_monitor: bool,
    ipc_socket: bool,
) -> Result<Vec<u8>> {
    let bundle_dir_str = bundle_dir.to_string_lossy();
    let write_dir_str = write_dir.to_string_lossy();

    // Pre-calculate total size
    let total = 4  // version
        + 4 + virtual_root.len()
        + 4 + bundle_dir_str.len()
        + 4 + write_dir_str.len()
        + 16 // bundle_id
        + 32 // master_key
        + 4  // memory_budget_mb
        + 4 + log_level.len()
        + 1  // memory_pressure_monitor
        + 1; // ipc_socket

    let mut buf = Vec::with_capacity(total);

    // version
    buf.extend_from_slice(&CONFIG_BLOB_VERSION.to_le_bytes());

    // virtual_root
    write_len_prefixed(&mut buf, virtual_root.as_bytes(), "virtual_root")?;

    // bundle_dir
    write_len_prefixed(&mut buf, bundle_dir_str.as_bytes(), "bundle_dir")?;

    // write_dir
    write_len_prefixed(&mut buf, write_dir_str.as_bytes(), "write_dir")?;

    // bundle_id
    buf.extend_from_slice(bundle_id);

    // master_key
    buf.extend_from_slice(master_key);

    // memory_budget_mb
    buf.extend_from_slice(&memory_budget_mb.to_le_bytes());

    // log_level
    write_len_prefixed(&mut buf, log_level.as_bytes(), "log_level")?;

    // memory_pressure_monitor
    buf.push(u8::from(memory_pressure_monitor));

    // ipc_socket
    buf.push(u8::from(ipc_socket));

    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_serialize_roundtrip() {
        let blob = serialize_config_blob(
            "/mnt/data",
            &PathBuf::from("/opt/bundle"),
            &PathBuf::from("/opt/bundle/write_layer"),
            &[0xAA; 16],
            &[0xBB; 32],
            64,
            "debug",
            true,
            true,
        )
        .expect("serialize should succeed");

        let mut pos = 0;

        // version
        let version = u32::from_le_bytes(blob[pos..pos + 4].try_into().unwrap());
        assert_eq!(version, 1);
        pos += 4;

        // virtual_root
        let vr_len = u32::from_le_bytes(blob[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        let vr = std::str::from_utf8(&blob[pos..pos + vr_len]).unwrap();
        assert_eq!(vr, "/mnt/data");
        pos += vr_len;

        // bundle_dir
        let bd_len = u32::from_le_bytes(blob[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        let bd = std::str::from_utf8(&blob[pos..pos + bd_len]).unwrap();
        assert_eq!(bd, "/opt/bundle");
        pos += bd_len;

        // write_dir
        let wd_len = u32::from_le_bytes(blob[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        let wd = std::str::from_utf8(&blob[pos..pos + wd_len]).unwrap();
        assert_eq!(wd, "/opt/bundle/write_layer");
        pos += wd_len;

        // bundle_id
        assert_eq!(&blob[pos..pos + 16], &[0xAA; 16]);
        pos += 16;

        // master_key
        assert_eq!(&blob[pos..pos + 32], &[0xBB; 32]);
        pos += 32;

        // memory_budget_mb
        let mb = u32::from_le_bytes(blob[pos..pos + 4].try_into().unwrap());
        assert_eq!(mb, 64);
        pos += 4;

        // log_level
        let ll_len = u32::from_le_bytes(blob[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        let ll = std::str::from_utf8(&blob[pos..pos + ll_len]).unwrap();
        assert_eq!(ll, "debug");
        pos += ll_len;

        // memory_pressure_monitor
        assert_eq!(blob[pos], 1);
        pos += 1;

        // ipc_socket
        assert_eq!(blob[pos], 1);
        pos += 1;

        assert_eq!(pos, blob.len());
    }
}
