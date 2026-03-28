// init.rs -- One-shot initialization, called from .init_array constructor.
//
// 1. Harden process (disable core dumps)
// 2. Read config blob from FD 200
// 3. Parse config, derive keys
// 4. Load and decrypt the manifest + route table
// 5. Resolve real libc symbols
// 6. Initialize caches and overlay
// 7. Store everything in the global OnceLock<ShimState>

use std::io::Cursor;

use cjlb_crypto::{decrypt_page, MasterKey};
use cjlb_format::manifest::{ManifestPreamble, MANIFEST_MAGIC, MANIFEST_PREAMBLE_SIZE};
use cjlb_format::page::{PAGE_BODY_SIZE, PAGE_TOTAL_SIZE};
use zeroize::Zeroize;

use crate::cache::PageCache;
use crate::fd_table::FdTable;
use crate::overlay::OverlayIndex;
use crate::pressure::PressureMonitor;
use crate::real_fns;
use crate::route_table_view::RouteTableView;
use crate::state::{ShimState, IPC_SERVER, PRESSURE_MONITOR, STATE};

/// Well-known FD the runtime writes the config blob to before exec.
const CONFIG_FD: i32 = 200;

// ---------------------------------------------------------------------------
// Raw syscall helpers — bypass LD_PRELOAD hooks during init
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
unsafe fn raw_sys_read(fd: i32, buf: *mut libc::c_void, count: usize) -> isize {
    unsafe { libc::syscall(libc::SYS_read, fd, buf, count) as isize }
}

#[cfg(not(target_os = "linux"))]
unsafe fn raw_sys_read(fd: i32, buf: *mut libc::c_void, count: usize) -> isize {
    unsafe {
        let sym = libc::dlsym(libc::RTLD_NEXT, b"read\0".as_ptr().cast());
        if sym.is_null() {
            return -1;
        }
        let f: unsafe extern "C" fn(i32, *mut libc::c_void, usize) -> isize =
            std::mem::transmute(sym);
        f(fd, buf, count)
    }
}

#[cfg(target_os = "linux")]
unsafe fn raw_sys_close(fd: i32) {
    unsafe {
        libc::syscall(libc::SYS_close, fd);
    }
}

#[cfg(not(target_os = "linux"))]
unsafe fn raw_sys_close(fd: i32) {
    unsafe {
        let sym = libc::dlsym(libc::RTLD_NEXT, b"close\0".as_ptr().cast());
        if !sym.is_null() {
            let f: unsafe extern "C" fn(i32) -> i32 = std::mem::transmute(sym);
            f(fd);
        }
    }
}

#[cfg(target_os = "linux")]
unsafe fn raw_sys_open(path: *const libc::c_char, flags: i32, mode: i32) -> i32 {
    unsafe { libc::syscall(libc::SYS_openat, libc::AT_FDCWD, path, flags, mode) as i32 }
}

#[cfg(not(target_os = "linux"))]
unsafe fn raw_sys_open(path: *const libc::c_char, flags: i32, _mode: i32) -> i32 {
    unsafe {
        let sym = libc::dlsym(libc::RTLD_NEXT, b"open\0".as_ptr().cast());
        if sym.is_null() {
            return -1;
        }
        let f: unsafe extern "C" fn(*const libc::c_char, i32, i32) -> i32 =
            std::mem::transmute(sym);
        f(path, flags, 0)
    }
}

/// Read a small file into a fixed buffer using raw syscalls (bypass hooks).
/// Path must be null-terminated. Returns bytes read, or None.
fn read_small_file(path: &[u8], buf: &mut [u8]) -> Option<usize> {
    unsafe {
        let fd = raw_sys_open(path.as_ptr().cast(), libc::O_RDONLY, 0);
        if fd < 0 {
            return None;
        }
        let n = raw_sys_read(fd, buf.as_mut_ptr().cast(), buf.len());
        raw_sys_close(fd);
        if n <= 0 {
            None
        } else {
            Some(n.cast_unsigned())
        }
    }
}

/// Write a debug message to stderr using raw syscall (safe during init).
#[cfg(target_os = "linux")]
unsafe fn debug_msg(msg: &[u8]) {
    unsafe {
        libc::syscall(
            libc::SYS_write,
            2i32,
            msg.as_ptr() as *const libc::c_void,
            msg.len(),
        );
    }
}

#[cfg(not(target_os = "linux"))]
const unsafe fn debug_msg(_msg: &[u8]) {}

/// Format a usize as ASCII decimal into a buffer. Returns number of bytes written.
fn fmt_usize(mut val: usize, buf: &mut [u8]) -> usize {
    if val == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 20];
    let mut len = 0;
    while val > 0 {
        tmp[len] = b'0' + u8::try_from(val % 10).unwrap_or(0);
        val /= 10;
        len += 1;
    }
    for i in 0..len {
        buf[i] = tmp[len - 1 - i];
    }
    len
}

/// Minimum memory budget (floor): 64 MiB.
const DEFAULT_MEMORY_BUDGET: usize = 64 * 1024 * 1024;

/// Fraction of available memory to use for the page cache.
const MEMORY_BUDGET_FRACTION: usize = 4; // 25%

/// Auto-detect memory budget from cgroup limits or system RAM.
/// Returns 25% of the available memory. Falls back to 256 MiB.
fn detect_memory_budget() -> usize {
    // Try cgroup v2 first (most modern Docker)
    if let Some(limit) = read_cgroup_v2_limit() {
        return limit / MEMORY_BUDGET_FRACTION;
    }
    // Try cgroup v1
    if let Some(limit) = read_cgroup_v1_limit() {
        return limit / MEMORY_BUDGET_FRACTION;
    }
    // Fall back to system total RAM via sysinfo
    if let Some(total) = read_system_memory() {
        return total / MEMORY_BUDGET_FRACTION;
    }
    // Final fallback: 256 MiB
    256 * 1024 * 1024
}

/// Read cgroup v2 memory limit from /sys/fs/cgroup/memory.max
fn read_cgroup_v2_limit() -> Option<usize> {
    let mut buf = [0u8; 64];
    let n = read_small_file(b"/sys/fs/cgroup/memory.max\0", &mut buf)?;
    let s = std::str::from_utf8(&buf[..n]).ok()?.trim();
    if s == "max" {
        // No limit set — fall through to system RAM
        return None;
    }
    s.parse::<usize>().ok()
}

/// Read cgroup v1 memory limit from /`sys/fs/cgroup/memory/memory.limit_in_bytes`
fn read_cgroup_v1_limit() -> Option<usize> {
    let mut buf = [0u8; 64];
    let n = read_small_file(b"/sys/fs/cgroup/memory/memory.limit_in_bytes\0", &mut buf)?;
    let s = std::str::from_utf8(&buf[..n]).ok()?.trim();
    let val = s.parse::<usize>().ok()?;
    // cgroup v1 reports a very large number (PAGE_COUNTER_MAX * PAGE_SIZE) when unlimited
    if val > 1024 * 1024 * 1024 * 1024 {
        // > 1 TiB = probably unlimited
        return None;
    }
    Some(val)
}

/// Read total system memory from /proc/meminfo
fn read_system_memory() -> Option<usize> {
    let mut buf = [0u8; 256];
    let n = read_small_file(b"/proc/meminfo\0", &mut buf)?;
    let s = std::str::from_utf8(&buf[..n]).ok()?;
    // First line: "MemTotal:       16384000 kB"
    for line in s.lines() {
        if line.starts_with("MemTotal:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let kb = parts[1].parse::<usize>().ok()?;
                return Some(kb * 1024); // convert to bytes
            }
        }
    }
    None
}

/// Initialize the shim. Returns `Err(())` on any failure; the caller `_exit(1)`s.
#[allow(clippy::too_many_lines)]
pub fn initialize() -> Result<(), ()> {
    // ---- 1. Harden: disable core dumps -----------------------------------
    harden();

    // ---- 2. Read config blob from FD 200 ---------------------------------
    unsafe { debug_msg(b"cjlb-shim: init step 2 (read config blob)\n") };
    let mut config_blob = read_config_blob()?;
    unsafe { debug_msg(b"cjlb-shim: config blob read OK\n") };

    // ---- 3. Parse config blob --------------------------------------------
    unsafe { debug_msg(b"cjlb-shim: init step 3 (parse config blob)\n") };
    let (
        virtual_root,
        bundle_dir,
        write_dir,
        bundle_id,
        mut master_key_bytes,
        memory_budget_mb,
        memory_pressure_monitor,
        ipc_socket,
    ) = parse_config_blob(&config_blob)?;
    // Zeroize the config blob — it contains the master key.
    config_blob.zeroize();
    unsafe { debug_msg(b"cjlb-shim: config parsed OK\n") };

    // mlock the key material so it isn't swapped to disk.
    #[cfg(target_os = "linux")]
    unsafe {
        if libc::mlock(master_key_bytes.as_ptr() as *const libc::c_void, 32) != 0 {
            debug_msg(b"cjlb-shim: WARNING: mlock failed for key material\n");
        }
    }

    // ---- 4. Derive keys --------------------------------------------------
    unsafe { debug_msg(b"cjlb-shim: init step 4 (derive keys)\n") };
    let master = MasterKey::from_bytes(master_key_bytes);
    master_key_bytes.zeroize();
    let derived_keys = master.derive_keys();
    drop(master);

    // ---- 5. Load manifest + route table ----------------------------------
    unsafe { debug_msg(b"cjlb-shim: init step 5 (load route table)\n") };
    let route_table = load_route_table(&bundle_dir, &derived_keys, &bundle_id)?;
    unsafe { debug_msg(b"cjlb-shim: route table loaded OK\n") };

    // ---- 6. Resolve real libc symbols ------------------------------------
    unsafe { debug_msg(b"cjlb-shim: init step 6 (resolve real fns)\n") };
    let real = unsafe { real_fns::resolve().map_err(|_| ())? };
    unsafe { debug_msg(b"cjlb-shim: real fns resolved OK\n") };

    // ---- 7. Initialize caches and overlay --------------------------------
    let budget = match memory_budget_mb {
        Some(mb) if mb > 0 => usize::try_from(mb).unwrap_or(0) * 1024 * 1024, // explicit: respect exactly (allows benchmarking with tiny cache)
        _ => detect_memory_budget().max(DEFAULT_MEMORY_BUDGET),               // auto: enforce floor
    };
    // Log actual budget for diagnostics
    {
        let mb = budget / (1024 * 1024);
        let mut buf = [0u8; 64];
        let prefix = b"cjlb-shim: cache budget = ";
        buf[..prefix.len()].copy_from_slice(prefix);
        let n = prefix.len() + fmt_usize(mb, &mut buf[prefix.len()..]);
        let suffix = b" MB\n";
        buf[n..n + suffix.len()].copy_from_slice(suffix);
        unsafe { debug_msg(&buf[..n + suffix.len()]) };
    }
    let cache = PageCache::new(budget);
    let fd_table = FdTable::new();

    // Try to load existing WAL manifest from a previous run.
    let overlay = {
        let manifest_path = format!("{write_dir}/wal_manifest.enc");
        let exists = std::path::Path::new(&manifest_path).exists();
        if exists {
            OverlayIndex::load_index(&write_dir, &derived_keys.write_dek, &bundle_id)
                .unwrap_or_else(|| {
                    OverlayIndex::new(write_dir.clone(), derived_keys.write_dek, bundle_id, 0)
                })
        } else {
            OverlayIndex::new(write_dir.clone(), derived_keys.write_dek, bundle_id, 0)
        }
    };

    // ---- 8. Store in global state ----------------------------------------
    let state = ShimState {
        virtual_root,
        bundle_dir,
        write_dir,
        bundle_id,
        derived_keys,
        route_table,
        cache,
        fd_table,
        overlay,
        real,
    };

    STATE.set(state).map_err(|_| ())?;

    // ---- 9. Optionally start memory pressure monitor --------------------
    if memory_pressure_monitor {
        let s = STATE.get().unwrap();
        let monitor = PressureMonitor::start(&s.cache, budget);
        let _ = PRESSURE_MONITOR.set(monitor);
    }

    // ---- 10. Start IPC socket server ------------------------------------
    if ipc_socket {
        let _ = crate::stream_hub::STREAM_HUB.set(crate::stream_hub::StreamHub::new());
        let state_ref: &'static ShimState = STATE.get().unwrap();
        if let Ok(server) = crate::ipc_server::IpcServer::start(state_ref) {
            let _ = IPC_SERVER.set(server);
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Process hardening
// ---------------------------------------------------------------------------

fn harden() {
    // Disable core dumps.
    #[cfg(target_os = "linux")]
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0);
    }

    // Set RLIMIT_CORE to 0 on all platforms.
    let zero_limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    unsafe {
        libc::setrlimit(libc::RLIMIT_CORE, &raw const zero_limit);
    }
}

// ---------------------------------------------------------------------------
// Config blob I/O
// ---------------------------------------------------------------------------

fn read_config_blob() -> Result<Vec<u8>, ()> {
    // Read all bytes from CONFIG_FD then close it.
    //
    // We use raw syscalls instead of libc::read/libc::close because at this point
    // during init, our LD_PRELOAD hooks are active but STATE is not yet set.
    // Calling libc::read would route through our hooked `read` function, causing
    // infinite recursion. Raw syscalls bypass the PLT entirely.
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    loop {
        let n = unsafe { raw_sys_read(CONFIG_FD, tmp.as_mut_ptr().cast(), tmp.len()) };
        if n < 0 {
            // Retry on EINTR; fail on any other error.
            #[cfg(target_os = "linux")]
            {
                let errno = unsafe { *libc::__errno_location() };
                if errno == libc::EINTR {
                    continue;
                }
            }
            unsafe { raw_sys_close(CONFIG_FD) };
            return Err(());
        }
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n.cast_unsigned()]);
    }
    unsafe { raw_sys_close(CONFIG_FD) };
    if buf.is_empty() {
        return Err(());
    }
    Ok(buf)
}

/// Parsed config blob fields: (`virtual_root`, `bundle_dir`, `write_dir`, `bundle_id`, `master_key`, `memory_budget_mb`, `memory_pressure_monitor`, `ipc_socket`)
type ConfigBlobResult = (
    String,
    String,
    String,
    [u8; 16],
    [u8; 32],
    Option<u32>,
    bool,
    bool,
);

fn parse_config_blob(blob: &[u8]) -> Result<ConfigBlobResult, ()> {
    let mut pos = 0;

    let read_u32 = |pos: &mut usize| -> Result<u32, ()> {
        if *pos + 4 > blob.len() {
            return Err(());
        }
        let val = u32::from_le_bytes(blob[*pos..*pos + 4].try_into().map_err(|_| ())?);
        *pos += 4;
        Ok(val)
    };

    let read_str = |pos: &mut usize| -> Result<String, ()> {
        let len = read_u32(pos)? as usize;
        if *pos + len > blob.len() {
            return Err(());
        }
        let s = std::str::from_utf8(&blob[*pos..*pos + len]).map_err(|_| ())?;
        *pos += len;
        Ok(s.to_string())
    };

    // Read and validate version prefix (written by cjlb-runtime config_blob.rs)
    let version = read_u32(&mut pos)?;
    if version != 1 {
        return Err(());
    }

    let virtual_root = read_str(&mut pos)?;
    let bundle_dir = read_str(&mut pos)?;
    let write_dir = read_str(&mut pos)?;

    // bundle_id (16 bytes)
    if pos + 16 > blob.len() {
        return Err(());
    }
    let mut bundle_id = [0u8; 16];
    bundle_id.copy_from_slice(&blob[pos..pos + 16]);
    pos += 16;

    // master_key (32 bytes)
    if pos + 32 > blob.len() {
        return Err(());
    }
    let mut master_key = [0u8; 32];
    master_key.copy_from_slice(&blob[pos..pos + 32]);
    pos += 32;

    // memory_budget_mb (optional u32)
    let memory_budget_mb = if pos + 4 <= blob.len() {
        Some(read_u32(&mut pos)?)
    } else {
        None
    };

    // log_level (optional, skip over it)
    if pos + 4 <= blob.len() {
        let _log_level = read_str(&mut pos).ok();
    }

    // memory_pressure_monitor (optional u8: 1=enabled, 0=disabled, default=true)
    let memory_pressure_monitor = if pos < blob.len() {
        let val = blob[pos];
        pos += 1;
        val != 0
    } else {
        true // default: enabled
    };

    // ipc_socket (optional u8: 1=enabled, 0=disabled, default=true)
    let ipc_socket = if pos < blob.len() {
        let val = blob[pos];
        pos += 1;
        val != 0
    } else {
        true // default: enabled
    };
    let _ = pos; // suppress unused warning

    Ok((
        virtual_root,
        bundle_dir,
        write_dir,
        bundle_id,
        master_key,
        memory_budget_mb,
        memory_pressure_monitor,
        ipc_socket,
    ))
}

// ---------------------------------------------------------------------------
// Manifest / route table loading
// ---------------------------------------------------------------------------

fn load_route_table(
    bundle_dir: &str,
    dk: &cjlb_crypto::DerivedKeys,
    bundle_id: &[u8; 16],
) -> Result<RouteTableView, ()> {
    let manifest_path = format!("{bundle_dir}/manifest.enc");

    unsafe { debug_msg(b"cjlb-shim: reading manifest.enc\n") };
    let manifest_bytes = read_file_raw(&manifest_path)?;

    if manifest_bytes.len() < MANIFEST_PREAMBLE_SIZE {
        return Err(());
    }

    // Parse preamble.
    let preamble: &ManifestPreamble =
        bytemuck::from_bytes(&manifest_bytes[..MANIFEST_PREAMBLE_SIZE]);
    if preamble.magic != MANIFEST_MAGIC {
        return Err(());
    }

    let header_page_count = usize::try_from(preamble.header_page_count).map_err(|_| ())?;
    let rt_page_count = usize::try_from(preamble.route_table_page_count).map_err(|_| ())?;

    // ---- Decrypt manifest header to get compressed route table size ----
    // The header JSON contains "route_table_compressed_size" which tells us
    // how many bytes of the decrypted RT pages are actual zstd data (the rest
    // is zero-padding from page quantization).
    let mut header_data = Vec::new();
    for i in 0..header_page_count {
        let offset = MANIFEST_PREAMBLE_SIZE + i * PAGE_TOTAL_SIZE;
        let end = offset + PAGE_TOTAL_SIZE;
        if end > manifest_bytes.len() {
            return Err(());
        }
        let decrypted = decrypt_page(&manifest_bytes[offset..end], &dk.manifest_dek, bundle_id)
            .map_err(|_| ())?;
        header_data.extend_from_slice(&decrypted);
    }
    // Trim trailing zeros from header JSON
    let hdr_end = header_data
        .iter()
        .rposition(|&b| b != 0)
        .map_or(0, |p| p + 1);
    let rt_compressed_size: Option<usize> = if hdr_end > 0 {
        serde_json::from_slice::<serde_json::Value>(&header_data[..hdr_end])
            .ok()
            .and_then(|v| v.get("route_table_compressed_size")?.as_u64())
            .and_then(|n| usize::try_from(n).ok())
    } else {
        None
    };

    // ---- Decrypt route table pages ----
    let mut rt_encrypted_data = Vec::with_capacity(rt_page_count * PAGE_BODY_SIZE);
    for i in 0..rt_page_count {
        let offset = MANIFEST_PREAMBLE_SIZE + (header_page_count + i) * PAGE_TOTAL_SIZE;
        let end = offset + PAGE_TOTAL_SIZE;
        if end > manifest_bytes.len() {
            return Err(());
        }
        let page_bytes = &manifest_bytes[offset..end];
        let decrypted = decrypt_page(page_bytes, &dk.manifest_dek, bundle_id).map_err(|_| ())?;
        rt_encrypted_data.extend_from_slice(&decrypted);
    }

    // Truncate to actual compressed size if known, otherwise use full data.
    if let Some(cs) = rt_compressed_size {
        if cs < rt_encrypted_data.len() {
            rt_encrypted_data.truncate(cs);
        }
    }

    unsafe { debug_msg(b"cjlb-shim: decompressing route table\n") };
    let rt_raw = zstd::decode_all(Cursor::new(&rt_encrypted_data)).map_err(|_| {
        unsafe { debug_msg(b"cjlb-shim: zstd decompress failed\n") };
    })?;

    unsafe { debug_msg(b"cjlb-shim: parsing route table\n") };
    RouteTableView::from_bytes(&rt_raw).map_err(|_| {
        unsafe { debug_msg(b"cjlb-shim: route table parse failed\n") };
    })
}

/// Read an entire file using raw kernel syscalls (used before `real_fns` are resolved).
///
/// Uses raw syscalls to bypass `LD_PRELOAD` hooks which would recurse.
fn read_file_raw(path: &str) -> Result<Vec<u8>, ()> {
    use std::ffi::CString;

    let c_path = CString::new(path).map_err(|_| ())?;
    let fd = unsafe { raw_sys_open(c_path.as_ptr(), libc::O_RDONLY, 0) };
    if fd < 0 {
        return Err(());
    }

    let mut buf = Vec::new();
    let mut tmp = vec![0u8; 65536];
    loop {
        let n = unsafe { raw_sys_read(fd, tmp.as_mut_ptr().cast(), tmp.len()) };
        if n < 0 {
            unsafe { raw_sys_close(fd) };
            return Err(());
        }
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n.cast_unsigned()]);
    }
    unsafe { raw_sys_close(fd) };
    Ok(buf)
}
