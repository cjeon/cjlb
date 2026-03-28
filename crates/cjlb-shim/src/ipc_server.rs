// ipc_server.rs — Unix domain socket server for IPC with cjlb-view / CLI.
//
// Protocol (length-prefixed framing):
//   Request:  [4 bytes: len LE u32] [payload]
//   Response: [4 bytes: len LE u32] [1 byte: status] [payload]
//
// Status codes:
//   0x00 = OK
//   0x01 = error
//   0x02 = stream chunk
//   0xFF = end-of-stream

use std::io::{self, Read as _, Write as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::route_table_view::ResolvedEntry;
use crate::state::ShimState;

// -- Constants ----------------------------------------------------------------

/// Maximum request payload size (64 KiB) to prevent abuse.
const MAX_REQUEST_SIZE: u32 = 64 * 1024;

/// Status byte: success.
const STATUS_OK: u8 = 0x00;

/// Status byte: error.
const STATUS_ERR: u8 = 0x01;

/// Status byte: stream data chunk.
const STATUS_STREAM_CHUNK: u8 = 0x02;

/// Status byte: end of stream.
const STATUS_EOS: u8 = 0xFF;

/// Poll interval for the non-blocking accept loop.
const ACCEPT_POLL_MS: u64 = 100;

// -- IpcServer ----------------------------------------------------------------

/// Unix domain socket server that exposes the virtual filesystem to external
/// tools (cjlb-view, CLI) via a simple length-prefixed protocol.
#[allow(dead_code)] // wired up in Phase 4
pub struct IpcServer {
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
    socket_path: String,
}

impl std::fmt::Debug for IpcServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IpcServer")
            .field("socket_path", &self.socket_path)
            .field("running", &!self.stop.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl IpcServer {
    /// Start the IPC socket server, binding to `{bundle_dir}/cjlb.sock`.
    ///
    /// The server runs in a background thread and accepts connections until
    /// the `IpcServer` is dropped.
    #[allow(dead_code)] // wired up in Phase 4
    pub fn start(state: &'static ShimState) -> io::Result<Self> {
        let socket_path = format!("{}/cjlb.sock", state.bundle_dir);

        // Remove stale socket file if present.
        let _ = std::fs::remove_file(&socket_path);

        let listener = UnixListener::bind(&socket_path)?;
        listener.set_nonblocking(true)?;

        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = Arc::clone(&stop);

        let handle = thread::Builder::new()
            .name("cjlb-ipc-accept".into())
            .spawn(move || accept_loop(&listener, state, &stop_clone))
            .map_err(io::Error::other)?;

        Ok(Self {
            stop,
            handle: Some(handle),
            socket_path,
        })
    }
}

impl Drop for IpcServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

// -- Accept loop --------------------------------------------------------------

fn accept_loop(listener: &UnixListener, state: &'static ShimState, stop: &AtomicBool) {
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _addr)) => {
                thread::Builder::new()
                    .name("cjlb-ipc-client".into())
                    .spawn(move || handle_client(stream, state))
                    .ok();
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(ACCEPT_POLL_MS));
            }
            Err(_) => {
                // Transient error — back off briefly and retry.
                thread::sleep(Duration::from_millis(ACCEPT_POLL_MS));
            }
        }
    }
}

// -- Client handler -----------------------------------------------------------

fn handle_client(mut stream: UnixStream, state: &'static ShimState) {
    // Set a read timeout so we don't block forever on a misbehaving client.
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));

    let request = match read_request(&mut stream) {
        Ok(r) => r,
        Err(_) => return,
    };

    let request = request.trim_end_matches('\n');

    // Parse "COMMAND [arg]" format.
    let (cmd, arg) = match request.find(' ') {
        Some(pos) => (&request[..pos], request[pos + 1..].trim()),
        None => (request, ""),
    };

    match cmd {
        "LS" => handle_ls(&mut stream, state, arg),
        "CAT" => handle_cat(&mut stream, state, arg),
        "INFO" => handle_info(&mut stream, state),
        "STREAM" => handle_stream(&mut stream, state, arg),
        _ => {
            let msg = format!("unknown command: {cmd}");
            let _ = send_response(&mut stream, STATUS_ERR, msg.as_bytes());
        }
    }
}

// -- Command handlers ---------------------------------------------------------

fn handle_ls(stream: &mut UnixStream, state: &'static ShimState, path: &str) {
    let path = path.trim_matches('/');

    // Resolve the directory in the route table.
    let dir_idx = match state.route_table.resolve_path(path) {
        Some(ResolvedEntry::Dir { dir_idx }) => dir_idx,
        Some(ResolvedEntry::File { .. }) => {
            let _ = send_response(stream, STATUS_ERR, b"not a directory");
            return;
        }
        None if path.is_empty() => 0, // root
        None => {
            let _ = send_response(stream, STATUS_ERR, b"directory not found");
            return;
        }
    };

    let dir = &state.route_table.dirs()[dir_idx];
    let (child_dirs, child_files) = state.route_table.dir_entries(dir_idx);

    let mut output = String::new();

    // List child directories.
    for child_dir in child_dirs {
        let name = state.route_table.dir_name(child_dir);
        output.push_str("D ");
        output.push_str(name);
        output.push('\n');
    }

    // List child files from the base bundle.
    for child_file in child_files {
        let name = state.route_table.file_name(child_file, dir);
        let size = child_file.file_size();
        output.push_str("F ");
        output.push_str(&size.to_string());
        output.push(' ');
        output.push_str(name);
        output.push('\n');
    }

    // List overlay files under this directory prefix.
    let prefix = if path.is_empty() {
        String::new()
    } else {
        format!("{path}/")
    };
    let overlay_files = state.overlay.list_files_under(&prefix);
    for (name, size) in overlay_files {
        output.push_str("F ");
        output.push_str(&size.to_string());
        output.push(' ');
        output.push_str(&name);
        output.push('\n');
    }

    let _ = send_response(stream, STATUS_OK, output.as_bytes());
}

fn handle_cat(stream: &mut UnixStream, state: &'static ShimState, path: &str) {
    let path = path.trim_matches('/');

    // SAFETY: read_entire_file delegates to read_page which calls raw libc
    // functions through state.real. The state is valid for the lifetime of the
    // process (static), and we are on a dedicated IPC thread — not in an
    // LD_PRELOAD hook context, so re-entrancy is not a concern.
    let data = unsafe { crate::page_read::read_entire_file(state, path) };

    match data {
        Some(bytes) => {
            let _ = send_response(stream, STATUS_OK, &bytes);
        }
        None => {
            let _ = send_response(stream, STATUS_ERR, b"file not found or read error");
        }
    }
}

fn handle_info(stream: &mut UnixStream, state: &'static ShimState) {
    let hits = state
        .cache
        .hits
        .load(std::sync::atomic::Ordering::Relaxed);
    let misses = state
        .cache
        .misses
        .load(std::sync::atomic::Ordering::Relaxed);
    let budget = state.cache.budget();

    let bundle_id_hex = state.bundle_id.iter().fold(String::with_capacity(32), |mut acc, b| {
        use std::fmt::Write as _;
        let _ = write!(acc, "{b:02x}");
        acc
    });

    let json = format!(
        concat!(
            "{{",
            "\"bundle_dir\":\"{}\",",
            "\"virtual_root\":\"{}\",",
            "\"bundle_id\":\"{}\",",
            "\"cache_hits\":{},",
            "\"cache_misses\":{},",
            "\"cache_budget\":{}",
            "}}"
        ),
        state.bundle_dir, state.virtual_root, bundle_id_hex, hits, misses, budget,
    );

    let _ = send_response(stream, STATUS_OK, json.as_bytes());
}

fn handle_stream(stream: &mut UnixStream, _state: &'static ShimState, path: &str) {
    let path = path.trim_matches('/');

    let hub = match crate::stream_hub::STREAM_HUB.get() {
        Some(h) => h,
        None => {
            let _ = send_response(stream, STATUS_ERR, b"stream hub not initialized");
            return;
        }
    };

    let rx = hub.subscribe(path);

    // Send OK handshake (empty payload) to signal subscription is active.
    if send_response(stream, STATUS_OK, &[]).is_err() {
        return;
    }

    // Relay chunks from the channel to the client.
    loop {
        match rx.recv() {
            Ok(chunk) => {
                // Skip zero-length probes sent by GC.
                if chunk.is_empty() {
                    continue;
                }
                if send_frame(stream, STATUS_STREAM_CHUNK, &chunk).is_err() {
                    // Client disconnected — drop the receiver and return.
                    return;
                }
            }
            Err(_) => {
                // Publisher closed (writer done) — send EOS sentinel.
                let _ = send_frame(stream, STATUS_EOS, &[]);
                return;
            }
        }
    }
}

// -- Wire helpers -------------------------------------------------------------

/// Read a length-prefixed request from the stream.
///
/// Returns the payload as a UTF-8 string.
fn read_request(stream: &mut UnixStream) -> io::Result<String> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf);

    if len > MAX_REQUEST_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "request too large",
        ));
    }

    let mut payload = vec![0u8; len as usize];
    stream.read_exact(&mut payload)?;

    String::from_utf8(payload)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Send a length-prefixed response: [4 bytes len][1 byte status][payload].
///
/// `len` covers status byte + payload.
fn send_response(stream: &mut UnixStream, status: u8, payload: &[u8]) -> io::Result<()> {
    send_frame(stream, status, payload)
}

/// Write a single protocol frame to the stream.
fn send_frame(stream: &mut UnixStream, status: u8, payload: &[u8]) -> io::Result<()> {
    let total_len: u32 = 1 + payload.len() as u32;
    stream.write_all(&total_len.to_le_bytes())?;
    stream.write_all(&[status])?;
    stream.write_all(payload)?;
    stream.flush()
}
