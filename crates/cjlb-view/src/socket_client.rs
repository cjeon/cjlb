//! IPC socket client for communicating with the running shim process.
//!
//! Connects to a Unix domain socket at `{bundle_dir}/cjlb.sock` using a
//! length-prefixed binary protocol:
//!
//! ```text
//! Request:  [4 bytes: payload_len LE u32] [payload bytes (UTF-8 command)]
//! Response: [4 bytes: payload_len LE u32] [1 byte: status] [payload bytes]
//! ```
//!
//! Status bytes: `0x00` = OK, `0x01` = error, `0x02` = stream chunk, `0xFF` =
//! end-of-stream.

use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context};

// ---------------------------------------------------------------------------
// Protocol constants
// ---------------------------------------------------------------------------

const STATUS_OK: u8 = 0x00;
const STATUS_ERROR: u8 = 0x01;
const STATUS_STREAM_CHUNK: u8 = 0x02;
const STATUS_END_OF_STREAM: u8 = 0xFF;

const SOCKET_NAME: &str = "cjlb.sock";

const READ_TIMEOUT: Duration = Duration::from_secs(30);
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum single-response payload we are willing to allocate (256 MiB).
/// Prevents a malicious or buggy server from causing OOM.
const MAX_PAYLOAD_LEN: u32 = 256 * 1024 * 1024;

/// Buffer size for chunked stdout writes (64 KiB).
const WRITE_BUF_SIZE: usize = 64 * 1024;

// ---------------------------------------------------------------------------
// Helpers (private)
// ---------------------------------------------------------------------------

/// Attempt to connect to the shim's IPC socket.  Returns `None` if the socket
/// file does not exist or the connection cannot be established (meaning the
/// shim is not running and the caller should fall back to direct disk access).
fn connect(bundle_dir: &Path) -> Option<UnixStream> {
    let sock_path = bundle_dir.join(SOCKET_NAME);
    if !sock_path.exists() {
        return None;
    }
    UnixStream::connect(&sock_path).ok()
}

/// Send a length-prefixed request over the socket.
fn send_request(stream: &mut UnixStream, cmd: &str) -> anyhow::Result<()> {
    let payload = cmd.as_bytes();
    let len = u32::try_from(payload.len()).context("command too long for u32 length prefix")?;
    stream
        .write_all(&len.to_le_bytes())
        .context("failed to write request length")?;
    stream
        .write_all(payload)
        .context("failed to write request payload")?;
    stream.flush().context("failed to flush request")?;
    Ok(())
}

/// Read a single length-prefixed response frame.  Returns `(status, payload)`.
fn read_response(stream: &mut UnixStream) -> anyhow::Result<(u8, Vec<u8>)> {
    // Read 4-byte length prefix.
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .context("failed to read response length")?;
    let total_len = u32::from_le_bytes(len_buf);

    if total_len == 0 {
        bail!("server sent zero-length response frame");
    }
    if total_len > MAX_PAYLOAD_LEN {
        bail!(
            "server response too large ({total_len} bytes, max {MAX_PAYLOAD_LEN})"
        );
    }

    // Read status byte.
    let mut status_buf = [0u8; 1];
    stream
        .read_exact(&mut status_buf)
        .context("failed to read response status byte")?;
    let status = status_buf[0];

    // Remaining bytes are the payload (total_len includes the status byte).
    let payload_len = (total_len - 1) as usize;
    let mut payload = vec![0u8; payload_len];
    stream
        .read_exact(&mut payload)
        .context("failed to read response payload")?;

    Ok((status, payload))
}

/// Read a response whose payload may be large and write it to `writer` in
/// chunks, avoiding a single large allocation.
fn read_response_chunked(
    stream: &mut UnixStream,
    writer: &mut dyn Write,
) -> anyhow::Result<u8> {
    // Read 4-byte length prefix.
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .context("failed to read response length")?;
    let total_len = u32::from_le_bytes(len_buf);

    if total_len == 0 {
        bail!("server sent zero-length response frame");
    }
    if total_len > MAX_PAYLOAD_LEN {
        bail!(
            "server response too large ({total_len} bytes, max {MAX_PAYLOAD_LEN})"
        );
    }

    // Read status byte.
    let mut status_buf = [0u8; 1];
    stream
        .read_exact(&mut status_buf)
        .context("failed to read response status byte")?;
    let status = status_buf[0];

    // For error responses, read fully into memory so we can return the message.
    // For OK responses, stream to `writer` in chunks.
    let payload_len = (total_len - 1) as usize;
    if status == STATUS_ERROR {
        let mut payload = vec![0u8; payload_len];
        stream
            .read_exact(&mut payload)
            .context("failed to read error payload")?;
        let msg = String::from_utf8_lossy(&payload);
        bail!("socket error: {msg}");
    }

    let mut remaining = payload_len;
    let mut buf = vec![0u8; WRITE_BUF_SIZE.min(remaining)];
    while remaining > 0 {
        let to_read = buf.len().min(remaining);
        stream
            .read_exact(&mut buf[..to_read])
            .context("failed to read response chunk")?;
        writer
            .write_all(&buf[..to_read])
            .context("failed to write response chunk")?;
        remaining -= to_read;
    }

    Ok(status)
}

/// Validate that an extraction filename is safe (no path traversal).
///
/// Mirrors the validation in `commands.rs`.
fn validate_extract_name(name: &str) -> anyhow::Result<()> {
    if name.is_empty() {
        bail!("empty filename from socket response");
    }
    if name.contains('/')
        || name.contains('\\')
        || name.contains("..")
        || Path::new(name).is_absolute()
    {
        bail!("unsafe filename from socket (path traversal attempt): {name:?}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Try to execute a view action via the shim's IPC socket.
///
/// Returns `None` if the socket is unavailable (caller should fall back to
/// direct disk access).  Returns `Some(Ok(()))` on success, or
/// `Some(Err(...))` on a socket-level or protocol error.
///
/// # Errors
///
/// Returns an error (wrapped in `Some`) if the socket is reachable but the
/// command fails at the protocol level, or if writing output fails.
#[must_use]
pub fn try_via_socket(
    bundle_dir: &Path,
    action: &str,
    path: &str,
    output_dir: Option<&Path>,
) -> Option<anyhow::Result<()>> {
    let mut stream = connect(bundle_dir)?;

    // Connection succeeded — from here on, errors are hard failures.
    Some(execute_action(&mut stream, action, path, output_dir))
}

/// Inner implementation for `try_via_socket`, separated so that the `Option`
/// wrapping stays clean.
fn execute_action(
    stream: &mut UnixStream,
    action: &str,
    path: &str,
    output_dir: Option<&Path>,
) -> anyhow::Result<()> {
    stream
        .set_read_timeout(Some(READ_TIMEOUT))
        .context("failed to set read timeout")?;
    stream
        .set_write_timeout(Some(WRITE_TIMEOUT))
        .context("failed to set write timeout")?;

    // Build command string.
    let cmd = match action {
        "info" => "info\n".to_string(),
        other => format!("{other} {path}\n"),
    };

    send_request(stream, &cmd)?;

    if action == "extract" {
        handle_extract_response(stream, path, output_dir)
    } else {
        // ls, cat, info — write payload to stdout.
        let stdout = io::stdout();
        let mut handle = stdout.lock();
        let status = read_response_chunked(stream, &mut handle)?;
        if status == STATUS_ERROR {
            // `read_response_chunked` already bails on error status, but
            // guard defensively.
            bail!("unexpected error status from socket");
        }
        Ok(())
    }
}

/// Handle the response for an `extract` action, writing data to `output_dir`.
fn handle_extract_response(
    stream: &mut UnixStream,
    path: &str,
    output_dir: Option<&Path>,
) -> anyhow::Result<()> {
    let output_dir = output_dir.context("output_dir is required for extract action")?;

    let (status, payload) = read_response(stream)?;

    match status {
        STATUS_OK => {
            // Derive the filename from the requested path (last component).
            let name = Path::new(path)
                .file_name()
                .and_then(|n| n.to_str())
                .context("could not derive filename from path")?;
            validate_extract_name(name)?;

            fs::create_dir_all(output_dir).with_context(|| {
                format!("failed to create output dir {}", output_dir.display())
            })?;

            let out_path = output_dir.join(name);
            fs::write(&out_path, &payload)
                .with_context(|| format!("failed to write {}", out_path.display()))?;

            // Post-write canonicalization check (same pattern as commands.rs).
            let canonical_dir = output_dir.canonicalize().with_context(|| {
                format!("failed to canonicalize output dir {}", output_dir.display())
            })?;
            let canonical_out = out_path.canonicalize().with_context(|| {
                format!("failed to canonicalize output path {}", out_path.display())
            })?;
            if !canonical_out.starts_with(&canonical_dir) {
                // Remove the escaped file before returning the error.
                let _ = fs::remove_file(&out_path);
                bail!(
                    "path traversal: {} escapes output dir {}",
                    canonical_out.display(),
                    canonical_dir.display()
                );
            }

            log::info!("extracted via socket: {}", out_path.display());
            Ok(())
        }
        STATUS_ERROR => {
            let msg = String::from_utf8_lossy(&payload);
            bail!("socket error: {msg}");
        }
        other => bail!("unexpected status byte from socket: {other:#04x}"),
    }
}

/// Stream a file's writes in real-time.
///
/// Only works when the shim process is running (the socket must be available).
/// Each chunk is written to stdout as it arrives.
///
/// # Errors
///
/// Returns an error if the socket is unavailable, the initial handshake fails,
/// or writing to stdout fails.
pub fn stream(bundle_dir: &Path, path: &str) -> anyhow::Result<()> {
    let sock_path = bundle_dir.join(SOCKET_NAME);
    let mut stream = UnixStream::connect(&sock_path).with_context(|| {
        format!(
            "cannot connect to shim socket at {} — is the shim running?",
            sock_path.display()
        )
    })?;

    stream
        .set_write_timeout(Some(WRITE_TIMEOUT))
        .context("failed to set write timeout")?;
    // No read timeout for streaming — we block indefinitely waiting for chunks.

    let cmd = format!("stream {path}\n");
    send_request(&mut stream, &cmd)?;

    // Read initial response to check for immediate errors.
    let (status, payload) = read_response(&mut stream)?;
    match status {
        STATUS_ERROR => {
            let msg = String::from_utf8_lossy(&payload);
            bail!("stream error: {msg}");
        }
        STATUS_OK | STATUS_STREAM_CHUNK => {
            // Write any initial payload to stdout.
            if !payload.is_empty() {
                let stdout = io::stdout();
                let mut handle = stdout.lock();
                handle
                    .write_all(&payload)
                    .context("failed to write initial stream chunk to stdout")?;
                handle.flush().context("failed to flush stdout")?;
            }
        }
        STATUS_END_OF_STREAM => return Ok(()),
        other => bail!("unexpected initial status byte: {other:#04x}"),
    }

    // Streaming loop: read frames until end-of-stream or connection close.
    let stdout = io::stdout();
    let mut handle = stdout.lock();

    loop {
        let frame = read_response(&mut stream);
        match frame {
            Ok((STATUS_STREAM_CHUNK, data)) => {
                handle
                    .write_all(&data)
                    .context("failed to write stream chunk to stdout")?;
                handle.flush().context("failed to flush stdout")?;
            }
            Ok((STATUS_END_OF_STREAM, _)) => break,
            Ok((STATUS_ERROR, data)) => {
                let msg = String::from_utf8_lossy(&data);
                bail!("stream error: {msg}");
            }
            Ok((other, _)) => {
                bail!("unexpected status byte during stream: {other:#04x}");
            }
            Err(_) => {
                // Connection closed or read error — end of stream.
                break;
            }
        }
    }

    Ok(())
}
