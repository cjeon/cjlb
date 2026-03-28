// pressure.rs -- Background cgroup memory pressure monitor.
//
// Monitors /sys/fs/cgroup/memory.pressure (PSI) and dynamically resizes the
// page cache to avoid OOM kills. Uses raw syscalls to read the PSI file so
// we never recurse through our own LD_PRELOAD hooks.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::cache::PageCache;

const CHECK_INTERVAL: Duration = Duration::from_secs(5);
const PSI_PATH: &[u8] = b"/sys/fs/cgroup/memory.pressure\0";
const MIN_BUDGET: usize = 16 * 1024 * 1024; // 16 MB

#[allow(missing_debug_implementations)] // contains thread handle
pub struct PressureMonitor {
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl PressureMonitor {
    /// Start the background pressure monitor thread.
    ///
    /// `cache` must be a `&'static PageCache` (the global `ShimState` cache).
    /// `max_budget` is the configured maximum cache budget in bytes; the monitor
    /// will never grow the cache beyond this value.
    pub fn start(cache: &'static PageCache, max_budget: usize) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = stop.clone();

        let handle = thread::spawn(move || {
            monitor_loop(cache, max_budget, &stop_clone);
        });

        Self {
            stop,
            handle: Some(handle),
        }
    }

    /// Signal the monitor thread to stop. Non-blocking — the thread will exit
    /// on its next wake-up (at most `CHECK_INTERVAL` later).
    #[allow(dead_code)]
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl Drop for PressureMonitor {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn monitor_loop(cache: &PageCache, max_budget: usize, stop: &AtomicBool) {
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        thread::sleep(CHECK_INTERVAL);
        if stop.load(Ordering::Relaxed) {
            break;
        }

        let pressure = read_pressure();
        let current = cache.budget();

        let new_budget = if pressure > 50.0 {
            (max_budget / 4).max(MIN_BUDGET)
        } else if pressure > 25.0 {
            (max_budget / 2).max(MIN_BUDGET)
        } else if pressure > 10.0 {
            (max_budget * 3 / 4).max(MIN_BUDGET)
        } else if pressure < 5.0 && current < max_budget {
            // Grow back slowly: 10% of max per check.
            (current + max_budget / 10).min(max_budget)
        } else {
            current // no change
        };

        if new_budget != current {
            cache.set_budget(new_budget);
        }
    }
}

/// Read memory pressure from the cgroup PSI file.
///
/// Parses the `some avg10=XX.XX` value from the first line.
/// Uses raw syscalls to avoid recursing through our `LD_PRELOAD` hooks.
/// Returns 0.0 on any error (assume no pressure).
fn read_pressure() -> f64 {
    let mut buf = [0u8; 256];
    let n = match read_psi_file(&mut buf) {
        Some(n) => n,
        None => return 0.0,
    };

    let s = match std::str::from_utf8(&buf[..n]) {
        Ok(s) => s,
        Err(_) => return 0.0,
    };

    // First line looks like: "some avg10=0.00 avg60=0.00 avg300=0.00 total=0"
    // We want the avg10 value.
    for line in s.lines() {
        if line.starts_with("some ") {
            // Find "avg10=" and parse the float after it.
            if let Some(idx) = line.find("avg10=") {
                let after = &line[idx + 6..];
                // Take characters until whitespace.
                let val_str: &str = after.split_whitespace().next().unwrap_or("0.0");
                return val_str.parse::<f64>().unwrap_or(0.0);
            }
        }
    }

    0.0
}

/// Read the PSI file using raw syscalls (bypass `LD_PRELOAD` hooks).
fn read_psi_file(buf: &mut [u8]) -> Option<usize> {
    unsafe {
        let fd = raw_sys_open(PSI_PATH.as_ptr().cast(), libc::O_RDONLY, 0);
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

// ---------------------------------------------------------------------------
// Raw syscall helpers — duplicated from init.rs to keep pressure.rs
// self-contained. These bypass the PLT / LD_PRELOAD hooks entirely.
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
unsafe fn raw_sys_read(fd: i32, buf: *mut libc::c_void, count: usize) -> isize {
    unsafe { libc::syscall(libc::SYS_read, fd, buf, count) as isize }
}

#[cfg(not(target_os = "linux"))]
unsafe fn raw_sys_read(fd: i32, buf: *mut libc::c_void, count: usize) -> isize {
    unsafe {
        let sym = libc::dlsym(libc::RTLD_NEXT, c"read".as_ptr());
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
        let sym = libc::dlsym(libc::RTLD_NEXT, c"close".as_ptr());
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
        let sym = libc::dlsym(libc::RTLD_NEXT, c"open".as_ptr());
        if sym.is_null() {
            return -1;
        }
        let f: unsafe extern "C" fn(*const libc::c_char, i32, i32) -> i32 =
            std::mem::transmute(sym);
        f(path, flags, 0)
    }
}
