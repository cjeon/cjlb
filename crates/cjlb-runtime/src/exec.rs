// exec.rs — Exec the client process with LD_PRELOAD and environment.

use std::collections::HashMap;
use std::ffi::CString;
use std::os::unix::io::RawFd;
use std::path::Path;

use anyhow::{bail, Context, Result};

/// The well-known FD used to pass config blob to the shim.
const CONFIG_FD: RawFd = 200;

// ---------------------------------------------------------------------------
// Platform-specific: memfd + dup2
// ---------------------------------------------------------------------------

/// Create a memfd (Linux) or temp file (macOS stub), write data, and dup2 to
/// the target FD.
pub fn write_blob_to_fd(data: &[u8], target_fd: RawFd) -> Result<()> {
    let memfd = memfd_create("cjlb-config")?;

    write_all_fd(memfd, data).context("failed to write config blob to memfd")?;

    // Seek to beginning so the reader can read from start
    let ret = unsafe { libc::lseek(memfd, 0, libc::SEEK_SET) };
    if ret < 0 {
        close_fd(memfd);
        bail!("failed to lseek memfd to 0");
    }

    // dup2 to the target FD
    if unsafe { libc::dup2(memfd, target_fd) } < 0 {
        close_fd(memfd);
        bail!("failed to dup2 memfd to FD {target_fd}");
    }

    if memfd != target_fd {
        close_fd(memfd);
    }

    // Restore CLOEXEC on the target FD — dup2 clears it. The shim reads
    // FD 200 in the *same* process (before any exec), so CLOEXEC is fine:
    // if the client later forks+execs a grandchild, FD 200 will be closed
    // in the grandchild, preventing master-key leakage.
    let ret = unsafe { libc::fcntl(target_fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    if ret < 0 {
        bail!(
            "failed to set CLOEXEC on FD {target_fd}: {}",
            std::io::Error::last_os_error()
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Exec
// ---------------------------------------------------------------------------

/// Parse the entrypoint string into command + args and exec.
///
/// The entrypoint is a shell-style string, e.g. "/usr/bin/python3 -u /app/main.py".
/// We split on whitespace (no shell quoting support — keep it simple).
///
/// **Limitation**: `split_whitespace` does not handle quoted paths or escaped
/// spaces. Paths containing spaces (e.g. `"/my app/run"`) will be split
/// incorrectly. Entrypoint paths must not contain whitespace.
pub fn exec_entrypoint(
    entrypoint: &str,
    config_blob: &[u8],
    client_env: &HashMap<String, String>,
    ld_preload_path: Option<&str>,
) -> Result<()> {
    // Write config blob to FD 200
    write_blob_to_fd(config_blob, CONFIG_FD).context("failed to prepare config blob on FD 200")?;

    // Parse entrypoint
    let parts: Vec<&str> = entrypoint.split_whitespace().collect();
    if parts.is_empty() {
        bail!("entrypoint is empty");
    }

    let program = parts[0];

    // Build argv as CStrings
    let argv_cstrings: Vec<CString> = parts
        .iter()
        .map(|s| CString::new(*s).context("invalid null byte in argv"))
        .collect::<Result<Vec<_>>>()?;

    let argv_ptrs: Vec<*const libc::c_char> = argv_cstrings
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    // Build envp: client env + LD_PRELOAD (if set)
    let mut env_strings: Vec<CString> = Vec::new();

    // Add LD_PRELOAD if we have a shim path
    // (Placeholder: when shim is ready, uncomment and set the real path)
    if let Some(preload_path) = ld_preload_path {
        let val = format!("LD_PRELOAD={preload_path}");
        env_strings.push(CString::new(val).context("invalid null byte in LD_PRELOAD")?);
    }

    // Add client env vars
    for (key, value) in client_env {
        let val = format!("{key}={value}");
        env_strings.push(CString::new(val).context("invalid null byte in env var")?);
    }

    let envp_ptrs: Vec<*const libc::c_char> = env_strings
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    // Resolve program path
    let program_cstr = CString::new(program).context("invalid null byte in program path")?;

    // execve replaces the process
    log::info!("exec: {} (argc={})", entrypoint, parts.len());
    let ret = unsafe {
        libc::execve(
            program_cstr.as_ptr(),
            argv_ptrs.as_ptr(),
            envp_ptrs.as_ptr(),
        )
    };

    // execve only returns on error
    bail!(
        "execve failed (returned {}): {}",
        ret,
        std::io::Error::last_os_error()
    );
}

// ---------------------------------------------------------------------------
// prctl: disable core dumps
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
pub fn set_non_dumpable() {
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0);
    }
}

#[cfg(not(target_os = "linux"))]
pub const fn set_non_dumpable() {
    // prctl is Linux-only. Stub for macOS compilation.
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn write_all_fd(fd: RawFd, mut buf: &[u8]) -> Result<()> {
    while !buf.is_empty() {
        let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if n <= 0 {
            bail!(
                "write to fd {} failed: {}",
                fd,
                std::io::Error::last_os_error()
            );
        }
        // n is guaranteed > 0 by the check above, so the cast is safe.
        buf = &buf[n.cast_unsigned()..];
    }
    Ok(())
}

fn close_fd(fd: RawFd) {
    unsafe {
        libc::close(fd);
    }
}

// -- Platform-specific memfd_create --

#[cfg(target_os = "linux")]
fn memfd_create(name: &str) -> Result<RawFd> {
    let cname = CString::new(name).context("invalid memfd name")?;
    let fd = unsafe {
        libc::syscall(
            libc::SYS_memfd_create,
            cname.as_ptr(),
            libc::MFD_CLOEXEC as libc::c_uint,
        )
    } as i32;
    if fd < 0 {
        bail!("memfd_create failed: {}", std::io::Error::last_os_error());
    }
    Ok(fd)
}

#[cfg(not(target_os = "linux"))]
fn memfd_create(_name: &str) -> Result<RawFd> {
    // macOS stub: create a temp file, unlink it, return the fd.
    let template = CString::new("/tmp/cjlb-runtime-XXXXXX").context("invalid template")?;
    let mut buf = template.into_bytes_with_nul();
    let fd = unsafe { libc::mkstemp(buf.as_mut_ptr().cast()) };
    if fd < 0 {
        bail!("mkstemp failed: {}", std::io::Error::last_os_error());
    }
    unsafe {
        libc::unlink(buf.as_ptr().cast());
    }
    Ok(fd)
}

// ---------------------------------------------------------------------------
// Bundle directory resolution
// ---------------------------------------------------------------------------

/// Resolve the bundle directory. Use CWD as the bundle directory.
pub fn resolve_bundle_dir() -> Result<std::path::PathBuf> {
    std::env::current_dir().context("failed to get current working directory")
}

/// Compute the write layer directory path.
pub fn write_layer_dir(bundle_dir: &Path) -> std::path::PathBuf {
    bundle_dir.join("write_layer")
}
