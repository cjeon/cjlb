// cjlb-bootstrap — Layer 0 plaintext binary.
//
// Reads key material from stdin, decrypts the runtime from runtime.enc,
// and fexecve's it from a memfd. No logging, no error messages.

use std::io::Read;
use std::os::unix::io::RawFd;

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use cjlb_crypto::MasterKey;
use zeroize::Zeroize;

/// Well-known file descriptor the runtime reads its key material from.
const KEY_FD: RawFd = 200;

/// AAD used when encrypting/decrypting the runtime blob.
const RUNTIME_AAD: &[u8] = b"cjlb-runtime-v1";

/// Minimum size of runtime.enc: 12 (nonce) + 0 (ciphertext) + 16 (tag).
const MIN_BLOB_SIZE: usize = 12 + 16;

fn main() {
    // On any error: zeroize and _exit(1). The guard ensures zeroize even on
    // unexpected unwind (though we never panic — every path is Result-based).
    if run().is_err() {
        unsafe { libc::_exit(1) }
    }
    // If run() returned Ok, fexecve replaced this process — we never reach here.
    // If we somehow do, bail.
    unsafe { libc::_exit(1) }
}

fn run() -> Result<(), ()> {
    // ── 1. Read 48 bytes from stdin: key(32) || bundle_id(16) ────────
    let mut input = [0u8; 48];
    std::io::stdin().read_exact(&mut input).map_err(drop)?;

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&input[..32]);
    let mut bundle_id = [0u8; 16];
    bundle_id.copy_from_slice(&input[32..48]);
    input.zeroize();

    // Wrap in a guard so key material is zeroized on every exit path.
    let result = run_inner(&mut key_bytes, &mut bundle_id);

    // Zeroize regardless of success/failure. On success fexecve replaced us,
    // so this line only runs on failure.
    key_bytes.zeroize();
    bundle_id.zeroize();

    result
}

fn run_inner(key_bytes: &mut [u8; 32], bundle_id: &mut [u8; 16]) -> Result<(), ()> {
    // ── 2. Derive runtime_dek ────────────────────────────────────────
    let master = MasterKey::from_bytes(*key_bytes);
    let mut dk = master.derive_keys();
    let mut runtime_dek = dk.runtime_dek;
    // Eagerly zeroize the parts we don't need.
    dk.bundle_dek.zeroize();
    dk.manifest_dek.zeroize();
    dk.write_dek.zeroize();
    dk.hmac_key.zeroize();
    // dk.runtime_dek is already copied out; dk will be dropped and zeroized.
    drop(dk);

    // ── 3. Read runtime.enc from the bootstrap binary's directory ────
    let enc_path = runtime_enc_path()?;
    let mut runtime_enc = std::fs::read(&enc_path).map_err(drop)?;

    // ── 4. Decrypt ───────────────────────────────────────────────────
    if runtime_enc.len() < MIN_BLOB_SIZE {
        runtime_enc.zeroize();
        runtime_dek.zeroize();
        return Err(());
    }

    let nonce_bytes: [u8; 12] = runtime_enc[..12].try_into().map_err(drop)?;
    let mut ct_and_tag = runtime_enc[12..].to_vec();

    let unbound_key = UnboundKey::new(&AES_256_GCM, &runtime_dek).map_err(drop)?;
    let key = LessSafeKey::new(unbound_key);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let decrypted = key
        .open_in_place(nonce, Aad::from(RUNTIME_AAD), &mut ct_and_tag)
        .map_err(|_| {
            // Zeroize on decrypt failure before returning.
        })?;
    let mut plaintext = decrypted.to_vec();
    ct_and_tag.zeroize();

    // Zeroize ciphertext and key — we have the plaintext now.
    runtime_enc.zeroize();
    runtime_dek.zeroize();

    // ── 5–6. Create memfd and write decrypted runtime ────────────────
    let memfd = memfd_create()?;
    write_all_fd(memfd, &plaintext)?;
    plaintext.zeroize();

    // ── 7–8. Create pipe and write key material for the runtime ──────
    let (pipe_read, pipe_write) = pipe2()?;
    {
        let mut payload = [0u8; 48];
        payload[..32].copy_from_slice(key_bytes);
        payload[32..48].copy_from_slice(bundle_id);
        write_all_fd(pipe_write, &payload)?;
        payload.zeroize();
    }
    close_fd(pipe_write);

    // ── 9–10. dup2 read end to well-known FD 200 ────────────────────
    if unsafe { libc::dup2(pipe_read, KEY_FD) } < 0 {
        close_fd(pipe_read);
        return Err(());
    }
    if pipe_read != KEY_FD {
        close_fd(pipe_read);
    }

    // ── 11. fexecve ──────────────────────────────────────────────────
    // Zeroize key material right before exec — after this we don't need it.
    key_bytes.zeroize();
    bundle_id.zeroize();

    fexecve(memfd)?;

    // fexecve only returns on error.
    Err(())
}

// ── Helpers ──────────────────────────────────────────────────────────────

/// Resolve the path to `runtime.enc` next to this binary.
fn runtime_enc_path() -> Result<std::path::PathBuf, ()> {
    let mut exe = std::env::current_exe().map_err(drop)?;
    exe.pop(); // remove binary name
    exe.push("runtime.enc");
    Ok(exe)
}

/// Write an entire buffer to a raw fd, handling partial writes.
fn write_all_fd(fd: RawFd, mut buf: &[u8]) -> Result<(), ()> {
    while !buf.is_empty() {
        let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if n <= 0 {
            return Err(());
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

// ── Platform-specific: Linux ─────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn memfd_create() -> Result<RawFd, ()> {
    let fd = unsafe {
        libc::syscall(
            libc::SYS_memfd_create,
            b"\0".as_ptr(),
            libc::MFD_CLOEXEC as libc::c_uint,
        )
    } as i32;
    if fd < 0 {
        return Err(());
    }
    Ok(fd)
}

#[cfg(target_os = "linux")]
fn pipe2() -> Result<(RawFd, RawFd), ()> {
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), 0) } != 0 {
        return Err(());
    }
    Ok((fds[0], fds[1]))
}

#[cfg(target_os = "linux")]
fn fexecve(memfd: RawFd) -> Result<(), ()> {
    // argv = ["cjlb-runtime", NULL]
    let arg0 = b"cjlb-runtime\0";
    let argv: [*const libc::c_char; 2] = [arg0.as_ptr().cast(), std::ptr::null()];
    let envp: [*const libc::c_char; 1] = [std::ptr::null()];
    unsafe {
        libc::fexecve(memfd, argv.as_ptr(), envp.as_ptr());
    }
    // fexecve only returns on error.
    Err(())
}

// ── Platform stub: non-Linux (macOS build, CI) ───────────────────────────

#[cfg(not(target_os = "linux"))]
fn memfd_create() -> Result<RawFd, ()> {
    // memfd_create is Linux-only. On other platforms we create a temp file,
    // unlink it, and return the fd. This is only for compilation — bootstrap
    // only runs on Linux.
    use std::ffi::CString;

    let template = CString::new("/tmp/cjlb-bootstrap-XXXXXX").map_err(drop)?;
    let mut buf = template.into_bytes_with_nul();
    let fd = unsafe { libc::mkstemp(buf.as_mut_ptr().cast()) };
    if fd < 0 {
        return Err(());
    }
    // Unlink immediately so nothing persists on disk.
    unsafe {
        libc::unlink(buf.as_ptr().cast());
    }
    Ok(fd)
}

#[cfg(not(target_os = "linux"))]
fn pipe2() -> Result<(RawFd, RawFd), ()> {
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(());
    }
    Ok(fds.into())
}

#[cfg(not(target_os = "linux"))]
const fn fexecve(_memfd: RawFd) -> Result<(), ()> {
    // fexecve is Linux-only. This stub exists so the crate compiles on macOS.
    // Bootstrap never actually runs on non-Linux.
    Err(())
}
