// hooks.rs -- Intercepted libc functions (#[no_mangle] pub unsafe extern "C").
//
// Each hook checks:
//   1. Is the shim initialized? (STATE.get())
//   2. Is the path/FD under our virtual root?
//   3. If yes -> handle it ourselves.
//   4. If no  -> delegate to the real libc function.
//
// Phase 2: read+write with encrypted overlay persistence.

use std::collections::HashMap;
use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_void};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Mutex;

use cjlb_format::page::PAGE_BODY_SIZE;

use crate::fd_table::{FileSource, VirtualFile};
use crate::overlay::{OverlayFile, OverlayPageRef};
use crate::route_table_view::ResolvedEntry;
use crate::state::{ShimState, STATE};

// ===========================================================================
// Raw syscall fallbacks — used when STATE is not yet initialized.
//
// We MUST NOT call libc functions (e.g., libc::read) from hooks when STATE is
// None because LD_PRELOAD causes those symbols to resolve back to our own hooks,
// creating infinite recursion. Instead we use libc::syscall(SYS_*) which goes
// directly to the kernel.
//
// On macOS (used only for compilation, not runtime), we resolve the real
// function via dlsym(RTLD_NEXT) at call time.
// ===========================================================================

/// Helper: resolve a real libc function via `dlsym(RTLD_NEXT, name)`.
unsafe fn dlsym_next(name: &CStr) -> *mut c_void {
    unsafe { libc::dlsym(libc::RTLD_NEXT, name.as_ptr()) }
}

#[cfg(target_os = "linux")]
unsafe fn raw_open(path: *const c_char, flags: c_int, mode: libc::mode_t) -> c_int {
    unsafe { libc::syscall(libc::SYS_openat, libc::AT_FDCWD, path, flags, mode) as c_int }
}

#[cfg(not(target_os = "linux"))]
unsafe fn raw_open(path: *const c_char, flags: c_int, mode: libc::mode_t) -> c_int {
    unsafe {
        let sym = dlsym_next(c"open");
        if sym.is_null() {
            return -1;
        }
        let f: unsafe extern "C" fn(*const c_char, c_int, libc::mode_t) -> c_int =
            std::mem::transmute(sym);
        f(path, flags, mode)
    }
}

#[cfg(target_os = "linux")]
unsafe fn raw_openat(dirfd: c_int, path: *const c_char, flags: c_int, mode: libc::mode_t) -> c_int {
    unsafe { libc::syscall(libc::SYS_openat, dirfd, path, flags, mode) as c_int }
}

#[cfg(not(target_os = "linux"))]
unsafe fn raw_openat(dirfd: c_int, path: *const c_char, flags: c_int, mode: libc::mode_t) -> c_int {
    unsafe {
        let sym = dlsym_next(c"openat");
        if sym.is_null() {
            return -1;
        }
        let f: unsafe extern "C" fn(c_int, *const c_char, c_int, libc::mode_t) -> c_int =
            std::mem::transmute(sym);
        f(dirfd, path, flags, mode)
    }
}

#[cfg(target_os = "linux")]
unsafe fn raw_read(fd: c_int, buf: *mut c_void, count: libc::size_t) -> libc::ssize_t {
    unsafe { libc::syscall(libc::SYS_read, fd, buf, count) as libc::ssize_t }
}

#[cfg(not(target_os = "linux"))]
unsafe fn raw_read(fd: c_int, buf: *mut c_void, count: libc::size_t) -> libc::ssize_t {
    unsafe {
        let sym = dlsym_next(c"read");
        if sym.is_null() {
            return -1;
        }
        let f: unsafe extern "C" fn(c_int, *mut c_void, libc::size_t) -> libc::ssize_t =
            std::mem::transmute(sym);
        f(fd, buf, count)
    }
}

#[cfg(target_os = "linux")]
unsafe fn raw_write(fd: c_int, buf: *const c_void, count: libc::size_t) -> libc::ssize_t {
    unsafe { libc::syscall(libc::SYS_write, fd, buf, count) as libc::ssize_t }
}

#[cfg(not(target_os = "linux"))]
unsafe fn raw_write(fd: c_int, buf: *const c_void, count: libc::size_t) -> libc::ssize_t {
    unsafe {
        let sym = dlsym_next(c"write");
        if sym.is_null() {
            return -1;
        }
        let f: unsafe extern "C" fn(c_int, *const c_void, libc::size_t) -> libc::ssize_t =
            std::mem::transmute(sym);
        f(fd, buf, count)
    }
}

#[cfg(target_os = "linux")]
unsafe fn raw_close(fd: c_int) -> c_int {
    unsafe { libc::syscall(libc::SYS_close, fd) as c_int }
}

#[cfg(not(target_os = "linux"))]
unsafe fn raw_close(fd: c_int) -> c_int {
    unsafe {
        let sym = dlsym_next(c"close");
        if sym.is_null() {
            return -1;
        }
        let f: unsafe extern "C" fn(c_int) -> c_int = std::mem::transmute(sym);
        f(fd)
    }
}

#[cfg(target_os = "linux")]
unsafe fn raw_lseek(fd: c_int, offset: libc::off_t, whence: c_int) -> libc::off_t {
    unsafe { libc::syscall(libc::SYS_lseek, fd, offset, whence) as libc::off_t }
}

#[cfg(not(target_os = "linux"))]
unsafe fn raw_lseek(fd: c_int, offset: libc::off_t, whence: c_int) -> libc::off_t {
    unsafe {
        let sym = dlsym_next(c"lseek");
        if sym.is_null() {
            return -1;
        }
        let f: unsafe extern "C" fn(c_int, libc::off_t, c_int) -> libc::off_t =
            std::mem::transmute(sym);
        f(fd, offset, whence)
    }
}

#[cfg(target_os = "linux")]
unsafe fn raw_fstat(fd: c_int, buf: *mut libc::stat) -> c_int {
    unsafe { libc::syscall(libc::SYS_fstat, fd, buf) as c_int }
}

#[cfg(not(target_os = "linux"))]
unsafe fn raw_fstat(fd: c_int, buf: *mut libc::stat) -> c_int {
    unsafe {
        let sym = dlsym_next(c"fstat");
        if sym.is_null() {
            return -1;
        }
        let f: unsafe extern "C" fn(c_int, *mut libc::stat) -> c_int = std::mem::transmute(sym);
        f(fd, buf)
    }
}

#[cfg(target_os = "linux")]
unsafe fn raw_stat(path: *const c_char, buf: *mut libc::stat) -> c_int {
    unsafe { libc::syscall(libc::SYS_newfstatat, libc::AT_FDCWD, path, buf, 0i32) as c_int }
}

#[cfg(not(target_os = "linux"))]
unsafe fn raw_stat(path: *const c_char, buf: *mut libc::stat) -> c_int {
    unsafe {
        let sym = dlsym_next(c"stat");
        if sym.is_null() {
            return -1;
        }
        let f: unsafe extern "C" fn(*const c_char, *mut libc::stat) -> c_int =
            std::mem::transmute(sym);
        f(path, buf)
    }
}

#[cfg(target_os = "linux")]
unsafe fn raw_lstat(path: *const c_char, buf: *mut libc::stat) -> c_int {
    unsafe {
        libc::syscall(
            libc::SYS_newfstatat,
            libc::AT_FDCWD,
            path,
            buf,
            libc::AT_SYMLINK_NOFOLLOW,
        ) as c_int
    }
}

#[cfg(not(target_os = "linux"))]
unsafe fn raw_lstat(path: *const c_char, buf: *mut libc::stat) -> c_int {
    unsafe {
        let sym = dlsym_next(c"lstat");
        if sym.is_null() {
            return -1;
        }
        let f: unsafe extern "C" fn(*const c_char, *mut libc::stat) -> c_int =
            std::mem::transmute(sym);
        f(path, buf)
    }
}

#[cfg(target_os = "linux")]
unsafe fn raw_access(path: *const c_char, amode: c_int) -> c_int {
    unsafe { libc::syscall(libc::SYS_faccessat, libc::AT_FDCWD, path, amode, 0i32) as c_int }
}

#[cfg(not(target_os = "linux"))]
unsafe fn raw_access(path: *const c_char, amode: c_int) -> c_int {
    unsafe {
        let sym = dlsym_next(c"access");
        if sym.is_null() {
            return -1;
        }
        let f: unsafe extern "C" fn(*const c_char, c_int) -> c_int = std::mem::transmute(sym);
        f(path, amode)
    }
}

#[cfg(target_os = "linux")]
unsafe fn raw_fsync(fd: c_int) -> c_int {
    unsafe { libc::syscall(libc::SYS_fsync, fd) as c_int }
}

#[cfg(not(target_os = "linux"))]
unsafe fn raw_fsync(fd: c_int) -> c_int {
    unsafe {
        let sym = dlsym_next(c"fsync");
        if sym.is_null() {
            return -1;
        }
        let f: unsafe extern "C" fn(c_int) -> c_int = std::mem::transmute(sym);
        f(fd)
    }
}

/// Raw syscall-based getdents64 for opendir/readdir fallback.
/// Since opendir/readdir/closedir involve glibc-internal DIR state, for the None
/// fallback we resolve the real function via `dlsym(RTLD_NEXT)` at call time.
unsafe fn raw_opendir(path: *const c_char) -> *mut libc::DIR {
    unsafe {
        let sym = libc::dlsym(libc::RTLD_NEXT, c"opendir".as_ptr());
        if sym.is_null() {
            return std::ptr::null_mut();
        }
        let real_opendir: unsafe extern "C" fn(*const c_char) -> *mut libc::DIR =
            std::mem::transmute(sym);
        real_opendir(path)
    }
}

unsafe fn raw_readdir(dirp: *mut libc::DIR) -> *mut libc::dirent {
    unsafe {
        let sym = libc::dlsym(libc::RTLD_NEXT, c"readdir".as_ptr());
        if sym.is_null() {
            return std::ptr::null_mut();
        }
        let real_readdir: unsafe extern "C" fn(*mut libc::DIR) -> *mut libc::dirent =
            std::mem::transmute(sym);
        real_readdir(dirp)
    }
}

unsafe fn raw_closedir(dirp: *mut libc::DIR) -> c_int {
    unsafe {
        let sym = libc::dlsym(libc::RTLD_NEXT, c"closedir".as_ptr());
        if sym.is_null() {
            return -1;
        }
        let real_closedir: unsafe extern "C" fn(*mut libc::DIR) -> c_int = std::mem::transmute(sym);
        real_closedir(dirp)
    }
}

// ===========================================================================
// Helpers
// ===========================================================================

/// Strip the virtual root prefix from a path. Returns None if not under root.
fn strip_virtual_root<'a>(path: &'a str, root: &str) -> Option<&'a str> {
    if root.is_empty() {
        return None;
    }
    if path == root {
        return Some("");
    }
    path.strip_prefix(root)
        .and_then(|rest| rest.strip_prefix('/'))
}

/// Fill the user buffer from virtual file data at the current cursor position.
/// Returns the number of bytes copied. Delegates to the shared `page_read` module.
unsafe fn read_virtual_file(
    state: &ShimState,
    buf: *mut u8,
    count: usize,
    file_idx: usize,
    cursor: u64,
    file_size: u64,
) -> usize {
    unsafe { crate::page_read::read_virtual_file_into_buf(state, buf, count, file_idx, cursor, file_size) }
}

/// Populate a `libc::stat` struct for a virtual file.
#[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)] // libc::stat fields are signed/narrow
unsafe fn fill_file_stat(st: *mut libc::stat, file_size: u64) {
    unsafe {
        std::ptr::write_bytes(st, 0, 1);
        (*st).st_mode = libc::S_IFREG | 0o444;
        (*st).st_nlink = 1;
        (*st).st_size = file_size as libc::off_t;
        (*st).st_blksize = PAGE_BODY_SIZE as i32;
        (*st).st_blocks = file_size.div_ceil(512) as i64;
    }
}

/// Populate a `libc::stat` struct for a virtual directory.
#[allow(clippy::cast_possible_wrap)] // libc::stat fields are signed
unsafe fn fill_dir_stat(st: *mut libc::stat) {
    unsafe {
        std::ptr::write_bytes(st, 0, 1);
        (*st).st_mode = libc::S_IFDIR | 0o555;
        (*st).st_nlink = 2;
        (*st).st_blksize = 4096;
    }
}

// ===========================================================================
// Virtual directory handle tracking
// ===========================================================================

static NEXT_DIR_HANDLE: AtomicI32 = AtomicI32::new(-1_000_000);

struct VirtualDir {
    dir_idx: usize,
    /// Iteration position: `0..child_dir_count` -> dirs, then files.
    pos: usize,
}

// Global mutex-protected map for virtual DIR handles.
static DIR_TABLE: Mutex<Option<HashMap<usize, VirtualDir>>> = Mutex::new(None);

fn dir_table_init() {
    let mut table = DIR_TABLE.lock().unwrap();
    if table.is_none() {
        *table = Some(HashMap::new());
    }
}

fn dir_table_insert(key: usize, vdir: VirtualDir) {
    let mut table = DIR_TABLE.lock().unwrap();
    if let Some(ref mut map) = *table {
        map.insert(key, vdir);
    }
}

fn dir_table_get_mut<F, R>(key: usize, f: F) -> Option<R>
where
    F: FnOnce(&mut VirtualDir) -> R,
{
    let mut table = DIR_TABLE.lock().unwrap();
    if let Some(ref mut map) = *table {
        map.get_mut(&key).map(f)
    } else {
        None
    }
}

fn dir_table_remove(key: usize) -> bool {
    let mut table = DIR_TABLE.lock().unwrap();
    if let Some(ref mut map) = *table {
        map.remove(&key).is_some()
    } else {
        false
    }
}

fn is_virtual_dir(ptr: *mut libc::DIR) -> bool {
    let key = ptr as usize;
    let table = DIR_TABLE.lock().unwrap();
    if let Some(ref map) = *table {
        map.contains_key(&key)
    } else {
        false
    }
}

// ===========================================================================
// errno helper
// ===========================================================================

#[cfg(target_os = "linux")]
unsafe fn set_errno(val: c_int) {
    unsafe {
        *libc::__errno_location() = val;
    }
}

#[cfg(target_os = "macos")]
unsafe fn set_errno(val: c_int) {
    unsafe {
        *libc::__error() = val;
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
unsafe fn set_errno(_val: c_int) {}

// ===========================================================================
// open / open64
// ===========================================================================
//
// On the x86-64 / aarch64 ABI, variadic and non-variadic calls use the same
// register convention. So we declare open with a fixed 3rd `mode` argument
// instead of `...` (which requires nightly Rust). The kernel / libc always
// passes mode in the 3rd argument register regardless.

#[no_mangle]
pub unsafe extern "C" fn open(path: *const c_char, flags: c_int, mode: libc::mode_t) -> c_int {
    unsafe {
        let Some(state) = STATE.get() else {
            return raw_open(path, flags, mode);
        };

        let Ok(path_str) = CStr::from_ptr(path).to_str() else {
            return state.real.real_open(path, flags, mode);
        };

        let Some(vpath) = strip_virtual_root(path_str, &state.virtual_root) else {
            return state.real.real_open(path, flags, mode);
        };

        open_virtual(state, vpath, flags)
    }
}

#[no_mangle]
pub unsafe extern "C" fn open64(path: *const c_char, flags: c_int, mode: libc::mode_t) -> c_int {
    unsafe { open(path, flags, mode) }
}

// (state_fallback_open removed — use raw_open instead)

#[allow(clippy::too_many_lines)]
unsafe fn open_virtual(state: &ShimState, vpath: &str, flags: c_int) -> c_int {
    unsafe {
        let access_mode = flags & libc::O_ACCMODE;
        let is_write = access_mode == libc::O_WRONLY || access_mode == libc::O_RDWR;
        let has_creat = (flags & libc::O_CREAT) != 0;
        let has_trunc = (flags & libc::O_TRUNC) != 0;
        let has_append = (flags & libc::O_APPEND) != 0;

        // Check overlay first, then base bundle.
        let overlay_exists = state.overlay.contains(vpath);
        let base_resolved = state.route_table.resolve_path(vpath);

        match (&base_resolved, overlay_exists) {
            // --- File exists in overlay ---
            (_, true) => {
                let file_size = state.overlay.file_size(vpath).unwrap_or(0);

                if has_trunc && is_write {
                    state.overlay.truncate_file(vpath);
                    let vf = VirtualFile {
                        path: vpath.to_string(),
                        cursor: 0,
                        file_size: 0,
                        flags,
                        source: FileSource::WriteLayer,
                        write_buf: Vec::new(),
                    };
                    return state.fd_table.allocate(vf);
                }

                let cursor = if has_append { file_size } else { 0 };
                let vf = VirtualFile {
                    path: vpath.to_string(),
                    cursor,
                    file_size,
                    flags,
                    source: FileSource::WriteLayer,
                    write_buf: Vec::new(),
                };
                state.fd_table.allocate(vf)
            }

            // --- File exists in base bundle ---
            (Some(ResolvedEntry::File { file_idx, .. }), false) => {
                let file_rec = state.route_table.file_record(*file_idx);
                let base_size = file_rec.file_size();

                if is_write || has_trunc {
                    // Opening a base file for writing: promote to write layer.
                    if has_trunc {
                        // O_TRUNC: start fresh in write layer.
                        let vf = VirtualFile {
                            path: vpath.to_string(),
                            cursor: 0,
                            file_size: 0,
                            flags,
                            source: FileSource::WriteLayer,
                            write_buf: Vec::new(),
                        };
                        // Register an empty file in the overlay so subsequent
                        // operations know it's in the write layer.
                        state.overlay.register_file(
                            vpath,
                            OverlayFile {
                                size: 0,
                                pages: Vec::new(),
                            },
                        );
                        return state.fd_table.allocate(vf);
                    }

                    // Write without truncate to a base file: for now, we need to
                    // copy the base data into overlay on first write. Mark as
                    // WriteLayer; the actual copy happens lazily.
                    let cursor = if has_append { base_size } else { 0 };
                    let vf = VirtualFile {
                        path: vpath.to_string(),
                        cursor,
                        file_size: base_size,
                        flags,
                        source: FileSource::BaseBundle {
                            file_idx: *file_idx,
                        },
                        write_buf: Vec::new(),
                    };
                    return state.fd_table.allocate(vf);
                }

                // Read-only open of base file.
                let vf = VirtualFile {
                    path: vpath.to_string(),
                    cursor: 0,
                    file_size: base_size,
                    flags,
                    source: FileSource::BaseBundle {
                        file_idx: *file_idx,
                    },
                    write_buf: Vec::new(),
                };
                state.fd_table.allocate(vf)
            }

            // --- Directory ---
            (Some(ResolvedEntry::Dir { .. }), false) => {
                if is_write {
                    set_errno(libc::EISDIR);
                    return -1;
                }
                let vf = VirtualFile {
                    path: vpath.to_string(),
                    cursor: 0,
                    file_size: 0,
                    flags,
                    source: FileSource::BaseBundle {
                        file_idx: usize::MAX,
                    },
                    write_buf: Vec::new(),
                };
                state.fd_table.allocate(vf)
            }

            // --- File doesn't exist anywhere ---
            (None, false) => {
                if has_creat && is_write {
                    // Create new file in write layer.
                    state.overlay.register_file(
                        vpath,
                        OverlayFile {
                            size: 0,
                            pages: Vec::new(),
                        },
                    );
                    let vf = VirtualFile {
                        path: vpath.to_string(),
                        cursor: 0,
                        file_size: 0,
                        flags,
                        source: FileSource::NewFile,
                        write_buf: Vec::new(),
                    };
                    return state.fd_table.allocate(vf);
                }

                set_errno(libc::ENOENT);
                -1
            }
        }
    }
}

// ===========================================================================
// openat / openat64
// ===========================================================================

#[no_mangle]
pub unsafe extern "C" fn openat(
    dirfd: c_int,
    path: *const c_char,
    flags: c_int,
    mode: libc::mode_t,
) -> c_int {
    unsafe {
        let Some(state) = STATE.get() else {
            return raw_openat(dirfd, path, flags, mode);
        };

        let Ok(path_str) = CStr::from_ptr(path).to_str() else {
            return raw_openat(dirfd, path, flags, mode);
        };

        // If path is absolute, treat like open().
        if path_str.starts_with('/') {
            if let Some(vpath) = strip_virtual_root(path_str, &state.virtual_root) {
                return open_virtual(state, vpath, flags);
            }
            return state.real.real_open(path, flags, mode);
        }

        // Relative path with AT_FDCWD: we cannot reliably determine if cwd is
        // under virtual root without calling getcwd, so delegate to real openat.
        if dirfd == libc::AT_FDCWD {
            return raw_openat(dirfd, path, flags, mode);
        }

        // If dirfd is a virtual FD, resolve relative to its path.
        if let Some(guard) = state.fd_table.get(dirfd) {
            let base = guard.file().path.clone();
            drop(guard);
            let combined = if base.is_empty() {
                path_str.to_string()
            } else {
                format!("{base}/{path_str}")
            };
            return open_virtual(state, &combined, flags);
        }

        raw_openat(dirfd, path, flags, mode)
    }
}

#[no_mangle]
pub unsafe extern "C" fn openat64(
    dirfd: c_int,
    path: *const c_char,
    flags: c_int,
    mode: libc::mode_t,
) -> c_int {
    unsafe { openat(dirfd, path, flags, mode) }
}

// ===========================================================================
// read
// ===========================================================================

#[no_mangle]
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]
pub unsafe extern "C" fn read(fd: c_int, buf: *mut c_void, count: libc::size_t) -> libc::ssize_t {
    unsafe {
        let Some(state) = STATE.get() else {
            return raw_read(fd, buf, count);
        };

        let mut guard = match state.fd_table.get_mut(fd) {
            Some(g) => g,
            None => return state.real.real_read(fd, buf, count),
        };

        let vf = guard.file_mut();

        match &vf.source {
            FileSource::BaseBundle { file_idx } => {
                let file_idx = *file_idx;

                // Directory FDs opened via open() -- read returns EISDIR.
                if file_idx == usize::MAX {
                    set_errno(libc::EISDIR);
                    return -1;
                }

                let cursor = vf.cursor;
                let file_size = vf.file_size;

                let n =
                    read_virtual_file(state, buf.cast::<u8>(), count, file_idx, cursor, file_size);
                vf.cursor += n as u64;
                n as libc::ssize_t
            }
            FileSource::WriteLayer | FileSource::NewFile => {
                // Read from overlay pages.
                let path = vf.path.clone();
                let cursor = vf.cursor;

                if let Some(data) = state.overlay.read_file_data(&path, cursor, count) {
                    let n = data.len();
                    if n > 0 {
                        std::ptr::copy_nonoverlapping(data.as_ptr(), buf.cast::<u8>(), n);
                    }
                    vf.cursor += n as u64;
                    n as libc::ssize_t
                } else {
                    set_errno(libc::EIO);
                    -1
                }
            }
        }
    }
}

// ===========================================================================
// write — accumulate to write_buf, flush full pages as encrypted overlay pages
// ===========================================================================

#[no_mangle]
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]
pub unsafe extern "C" fn write(
    fd: c_int,
    buf: *const c_void,
    count: libc::size_t,
) -> libc::ssize_t {
    unsafe {
        let Some(state) = STATE.get() else {
            return raw_write(fd, buf, count);
        };

        let mut guard = match state.fd_table.get_mut(fd) {
            Some(g) => g,
            None => return state.real.real_write(fd, buf, count),
        };

        let vf = guard.file_mut();

        // Check that the FD was opened for writing.
        let access_mode = vf.flags & libc::O_ACCMODE;
        if access_mode == libc::O_RDONLY {
            set_errno(libc::EBADF);
            return -1;
        }

        // If this is a BaseBundle file being written for the first time,
        // promote its source to WriteLayer. The existing base data is not
        // copied — reads would need to go to the base bundle for the
        // pre-existing portion. For simplicity, once a write happens we
        // switch to NewFile source (existing data is not preserved unless
        // the file was opened with O_APPEND on an overlay file).
        match &vf.source {
            FileSource::BaseBundle { .. } => {
                // Promote: this FD is now writing to the overlay.
                vf.source = FileSource::NewFile;
                // Register in overlay if not yet there.
                if !state.overlay.contains(&vf.path) {
                    state.overlay.register_file(
                        &vf.path,
                        OverlayFile {
                            size: 0,
                            pages: Vec::new(),
                        },
                    );
                }
            }
            FileSource::WriteLayer | FileSource::NewFile => {}
        }

        // Append the incoming data to write_buf.
        let data = std::slice::from_raw_parts(buf.cast::<u8>(), count);
        vf.write_buf.extend_from_slice(data);

        // Publish pre-encryption plaintext to streaming subscribers (if any).
        if let Some(hub) = crate::stream_hub::STREAM_HUB.get() {
            hub.publish(&vf.path, data);
        }

        // Flush full pages from write_buf.
        let path = vf.path.clone();
        let mut new_pages: Vec<OverlayPageRef> = Vec::new();

        while vf.write_buf.len() >= PAGE_BODY_SIZE {
            // Copy data before draining so we don't lose it on flush failure.
            let page_data: Vec<u8> = vf.write_buf[..PAGE_BODY_SIZE].to_vec();
            match state.overlay.flush_page(&page_data) {
                Ok(page_id) => {
                    vf.write_buf.drain(..PAGE_BODY_SIZE);
                    new_pages.push(OverlayPageRef {
                        page_id,
                        offset_in_page: 0,
                        size_in_page: PAGE_BODY_SIZE as u32,
                    });
                }
                Err(()) => {
                    set_errno(libc::EIO);
                    return -1;
                }
            }
        }

        // If we flushed any pages, update the overlay index.
        if new_pages.is_empty() {
            // Update file_size to include unflushed write_buf.
            let existing_pages = state.overlay.get_file_pages(&path);
            let pages_size: u64 = existing_pages
                .iter()
                .map(|p| u64::from(p.size_in_page))
                .sum();
            vf.file_size = pages_size + vf.write_buf.len() as u64;
        } else {
            let mut existing_pages = state.overlay.get_file_pages(&path);
            existing_pages.extend(new_pages);
            // Compute new file size: sum of all page sizes + remaining write_buf.
            let pages_size: u64 = existing_pages
                .iter()
                .map(|p| u64::from(p.size_in_page))
                .sum();
            let total_size = pages_size + vf.write_buf.len() as u64;
            state.overlay.register_file(
                &path,
                OverlayFile {
                    size: total_size,
                    pages: existing_pages,
                },
            );
            vf.file_size = total_size;
        }

        // Advance cursor.
        vf.cursor += count as u64;

        count as libc::ssize_t
    }
}

// ===========================================================================
// close
// ===========================================================================

#[no_mangle]
#[allow(clippy::cast_possible_truncation)]
pub unsafe extern "C" fn close(fd: c_int) -> c_int {
    unsafe {
        let Some(state) = STATE.get() else {
            return raw_close(fd);
        };

        // Flush any remaining write_buf before closing.
        if let Some(mut guard) = state.fd_table.get_mut(fd) {
            let vf = guard.file_mut();
            let has_data = !vf.write_buf.is_empty();
            let is_writable = matches!(vf.source, FileSource::WriteLayer | FileSource::NewFile);

            if has_data && is_writable {
                let path = vf.path.clone();
                let remaining: Vec<u8> = vf.write_buf.drain(..).collect();
                let remaining_len = remaining.len() as u32;

                if let Ok(page_id) = state.overlay.flush_page(&remaining) {
                    let mut existing_pages = state.overlay.get_file_pages(&path);
                    existing_pages.push(OverlayPageRef {
                        page_id,
                        offset_in_page: 0,
                        size_in_page: remaining_len,
                    });
                    let total_size: u64 = existing_pages
                        .iter()
                        .map(|p| u64::from(p.size_in_page))
                        .sum();
                    state.overlay.register_file(
                        &path,
                        OverlayFile {
                            size: total_size,
                            pages: existing_pages,
                        },
                    );
                }
            }
            // Drop the write guard before remove (which also takes a write lock).
            drop(guard);
        }
        // If remove returns Some, the fd was virtual — we're done.
        // If None, it's a real fd — delegate to real_close.
        if state.fd_table.remove(fd).is_some() {
            return 0;
        }

        state.real.real_close(fd)
    }
}

// ===========================================================================
// lseek / lseek64
// ===========================================================================

#[no_mangle]
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]
pub unsafe extern "C" fn lseek(fd: c_int, offset: libc::off_t, whence: c_int) -> libc::off_t {
    unsafe {
        let Some(state) = STATE.get() else {
            return raw_lseek(fd, offset, whence);
        };

        let mut guard = match state.fd_table.get_mut(fd) {
            Some(g) => g,
            None => return state.real.real_lseek(fd, offset, whence),
        };

        let vf = guard.file_mut();
        let new_pos: i64 = match whence {
            libc::SEEK_SET => offset,
            libc::SEEK_CUR => vf.cursor as i64 + offset,
            libc::SEEK_END => vf.file_size as i64 + offset,
            _ => {
                set_errno(libc::EINVAL);
                return -1;
            }
        };

        if new_pos < 0 {
            set_errno(libc::EINVAL);
            return -1;
        }

        vf.cursor = new_pos as u64;
        new_pos as libc::off_t
    }
}

#[no_mangle]
pub unsafe extern "C" fn lseek64(fd: c_int, offset: libc::off_t, whence: c_int) -> libc::off_t {
    unsafe { lseek(fd, offset, whence) }
}

// ===========================================================================
// stat / lstat / fstat
// ===========================================================================

#[no_mangle]
pub unsafe extern "C" fn stat(path: *const c_char, buf: *mut libc::stat) -> c_int {
    unsafe {
        let Some(state) = STATE.get() else {
            return raw_stat(path, buf);
        };

        let Ok(path_str) = CStr::from_ptr(path).to_str() else {
            return state.real.real_stat(path, buf);
        };

        let Some(vpath) = strip_virtual_root(path_str, &state.virtual_root) else {
            return state.real.real_stat(path, buf);
        };

        stat_virtual(state, vpath, buf)
    }
}

#[no_mangle]
pub unsafe extern "C" fn lstat(path: *const c_char, buf: *mut libc::stat) -> c_int {
    unsafe {
        let Some(state) = STATE.get() else {
            return raw_lstat(path, buf);
        };

        let Ok(path_str) = CStr::from_ptr(path).to_str() else {
            return state.real.real_lstat(path, buf);
        };

        let Some(vpath) = strip_virtual_root(path_str, &state.virtual_root) else {
            return state.real.real_lstat(path, buf);
        };

        stat_virtual(state, vpath, buf)
    }
}

#[no_mangle]
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]
pub unsafe extern "C" fn fstat(fd: c_int, buf: *mut libc::stat) -> c_int {
    unsafe {
        let Some(state) = STATE.get() else {
            return raw_fstat(fd, buf);
        };

        let guard = match state.fd_table.get(fd) {
            Some(g) => g,
            None => return state.real.real_fstat(fd, buf),
        };

        let vf = guard.file();

        match &vf.source {
            FileSource::BaseBundle { file_idx } if *file_idx == usize::MAX => {
                fill_dir_stat(buf);
            }
            FileSource::WriteLayer | FileSource::NewFile => {
                fill_file_stat(buf, vf.file_size);
                // Mark writable.
                (*buf).st_mode = libc::S_IFREG | 0o644;
            }
            FileSource::BaseBundle { .. } => {
                fill_file_stat(buf, vf.file_size);
            }
        }

        0
    }
}

// ===========================================================================
// fstatat / fstatat64 — needed on aarch64 where glibc implements fstat() as
// fstatat(fd, "", buf, AT_EMPTY_PATH)
// ===========================================================================

#[no_mangle]
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]
pub unsafe extern "C" fn fstatat(
    dirfd: c_int,
    path: *const c_char,
    buf: *mut libc::stat,
    flags: c_int,
) -> c_int {
    unsafe {
        let Some(state) = STATE.get() else {
            return raw_fstatat(dirfd, path, buf, flags);
        };

        // Handle fstat-via-fstatat: fstatat(fd, "", buf, AT_EMPTY_PATH)
        #[allow(clippy::items_after_statements)]
        const AT_EMPTY_PATH: c_int = 0x1000;
        if (flags & AT_EMPTY_PATH) != 0 {
            let path_str = CStr::from_ptr(path).to_bytes();
            if path_str.is_empty() {
                // This is fstat(virtual_fd) — delegate to our fstat hook
                // which handles both virtual and real FDs atomically.
                return fstat(dirfd, buf);
            }
        }

        // Handle absolute path
        if let Ok(path_str) = CStr::from_ptr(path).to_str() {
            if path_str.starts_with('/') {
                if let Some(vpath) = strip_virtual_root(path_str, &state.virtual_root) {
                    let is_lstat = (flags & libc::AT_SYMLINK_NOFOLLOW) != 0;
                    let _ = is_lstat; // reserved for future lstat-specific handling
                                      // We don't distinguish stat/lstat for virtual files.
                    return stat_virtual(state, vpath, buf);
                }
            }
        }

        raw_fstatat(dirfd, path, buf, flags)
    }
}

#[no_mangle]
pub unsafe extern "C" fn fstatat64(
    dirfd: c_int,
    path: *const c_char,
    buf: *mut libc::stat,
    flags: c_int,
) -> c_int {
    unsafe { fstatat(dirfd, path, buf, flags) }
}

#[cfg(target_os = "linux")]
unsafe fn raw_fstatat(
    dirfd: c_int,
    path: *const c_char,
    buf: *mut libc::stat,
    flags: c_int,
) -> c_int {
    unsafe { libc::syscall(libc::SYS_newfstatat, dirfd, path, buf, flags) as c_int }
}

#[cfg(not(target_os = "linux"))]
unsafe fn raw_fstatat(
    dirfd: c_int,
    path: *const c_char,
    buf: *mut libc::stat,
    flags: c_int,
) -> c_int {
    unsafe {
        let sym = dlsym_next(c"fstatat");
        if sym.is_null() {
            return -1;
        }
        let f: unsafe extern "C" fn(c_int, *const c_char, *mut libc::stat, c_int) -> c_int =
            std::mem::transmute(sym);
        f(dirfd, path, buf, flags)
    }
}

#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
unsafe fn stat_virtual(state: &ShimState, vpath: &str, buf: *mut libc::stat) -> c_int {
    unsafe {
        // Check overlay first.
        if let Some(size) = state.overlay.file_size(vpath) {
            fill_file_stat(buf, size);
            (*buf).st_mode = libc::S_IFREG | 0o644;
            return 0;
        }

        match state.route_table.resolve_path(vpath) {
            Some(ResolvedEntry::File { file_idx, .. }) => {
                let file_rec = state.route_table.file_record(file_idx);
                fill_file_stat(buf, file_rec.file_size());
                0
            }
            Some(ResolvedEntry::Dir { .. }) => {
                fill_dir_stat(buf);
                0
            }
            None => {
                set_errno(libc::ENOENT);
                -1
            }
        }
    }
}

// ===========================================================================
// access
// ===========================================================================

#[no_mangle]
#[allow(clippy::cast_possible_truncation)]
pub unsafe extern "C" fn access(path: *const c_char, amode: c_int) -> c_int {
    unsafe {
        let Some(state) = STATE.get() else {
            return raw_access(path, amode);
        };

        let Ok(path_str) = CStr::from_ptr(path).to_str() else {
            return state.real.real_access(path, amode);
        };

        let Some(vpath) = strip_virtual_root(path_str, &state.virtual_root) else {
            return state.real.real_access(path, amode);
        };

        // Check overlay first.
        if state.overlay.contains(vpath) {
            // Overlay files are writable.
            // X_OK on a file is denied.
            if (amode & libc::X_OK) != 0 {
                set_errno(libc::EACCES);
                return -1;
            }
            return 0;
        }

        let resolved = state.route_table.resolve_path(vpath);
        if resolved.is_none() {
            set_errno(libc::ENOENT);
            return -1;
        }

        // F_OK / R_OK: always satisfied.
        // W_OK: denied for base bundle files (read-only).
        if (amode & libc::W_OK) != 0 {
            set_errno(libc::EROFS);
            return -1;
        }

        // X_OK: only directories have execute permission.
        if (amode & libc::X_OK) != 0 {
            if let Some(ResolvedEntry::Dir { .. }) = resolved {
            } else {
                set_errno(libc::EACCES);
                return -1;
            }
        }

        0
    }
}

// ===========================================================================
// fsync — flush write_buf remainder, persist overlay index atomically
// ===========================================================================

#[no_mangle]
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub unsafe extern "C" fn fsync(fd: c_int) -> c_int {
    unsafe {
        let Some(state) = STATE.get() else {
            return raw_fsync(fd);
        };

        let mut guard = match state.fd_table.get_mut(fd) {
            Some(g) => g,
            None => return state.real.real_fsync(fd),
        };

        let vf = guard.file_mut();

        let is_writable = matches!(vf.source, FileSource::WriteLayer | FileSource::NewFile);

        if !is_writable {
            // Read-only FD: fsync is a no-op.
            return 0;
        }

        // Flush any remaining data in write_buf as a short page.
        if !vf.write_buf.is_empty() {
            let path = vf.path.clone();
            let remaining: Vec<u8> = vf.write_buf.drain(..).collect();
            let remaining_len = remaining.len() as u32;

            if let Ok(page_id) = state.overlay.flush_page(&remaining) {
                let mut existing_pages = state.overlay.get_file_pages(&path);
                existing_pages.push(OverlayPageRef {
                    page_id,
                    offset_in_page: 0,
                    size_in_page: remaining_len,
                });
                let total_size: u64 = existing_pages
                    .iter()
                    .map(|p| u64::from(p.size_in_page))
                    .sum();
                state.overlay.register_file(
                    &path,
                    OverlayFile {
                        size: total_size,
                        pages: existing_pages,
                    },
                );
                vf.file_size = total_size;
            } else {
                set_errno(libc::EIO);
                return -1;
            }
        }

        // Persist the overlay index to wal_manifest.enc.
        if state.overlay.persist_index().is_err() {
            set_errno(libc::EIO);
            return -1;
        }

        0
    }
}

// ===========================================================================
// opendir / readdir / readdir64 / closedir
// ===========================================================================

#[no_mangle]
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub unsafe extern "C" fn opendir(path: *const c_char) -> *mut libc::DIR {
    unsafe {
        let Some(state) = STATE.get() else {
            return raw_opendir(path);
        };

        let Ok(path_str) = CStr::from_ptr(path).to_str() else {
            return state.real.real_opendir(path);
        };

        let Some(vpath) = strip_virtual_root(path_str, &state.virtual_root) else {
            return state.real.real_opendir(path);
        };

        if let Some(dir_idx) = state.route_table.resolve_dir(vpath) {
            dir_table_init();
            let handle_val = NEXT_DIR_HANDLE.fetch_sub(1, Ordering::Relaxed);
            let ptr = handle_val as usize;
            dir_table_insert(ptr, VirtualDir { dir_idx, pos: 0 });
            ptr as *mut libc::DIR
        } else {
            set_errno(libc::ENOENT);
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]
pub unsafe extern "C" fn readdir(dirp: *mut libc::DIR) -> *mut libc::dirent {
    unsafe {
        let Some(state) = STATE.get() else {
            return raw_readdir(dirp);
        };

        let key = dirp as usize;
        if !is_virtual_dir(dirp) {
            return state.real.real_readdir(dirp);
        }

        // Thread-local dirent buffer (readdir returns a pointer to an internal buffer).
        thread_local! {
            static DIRENT_BUF: std::cell::RefCell<libc::dirent> =
                const { std::cell::RefCell::new(unsafe { std::mem::zeroed() }) };
        }

        dir_table_get_mut(key, |vdir| {
            let (child_dirs, child_files) = state.route_table.dir_entries(vdir.dir_idx);
            let total = child_dirs.len() + child_files.len();

            if vdir.pos >= total {
                return std::ptr::null_mut();
            }

            let (name, is_dir) = if vdir.pos < child_dirs.len() {
                let d = &child_dirs[vdir.pos];
                (state.route_table.dir_name(d), true)
            } else {
                let fi = vdir.pos - child_dirs.len();
                let parent = &state.route_table.dirs()[vdir.dir_idx];
                let f = &child_files[fi];
                (state.route_table.file_name(f, parent), false)
            };

            vdir.pos += 1;

            DIRENT_BUF.with(|cell| {
                let dirent = &mut *cell.borrow_mut();
                *dirent = std::mem::zeroed();
                dirent.d_ino = 1;
                dirent.d_type = if is_dir { libc::DT_DIR } else { libc::DT_REG };

                // Copy name into d_name (truncate if necessary).
                let name_bytes = name.as_bytes();
                let max_len = dirent.d_name.len() - 1;
                let copy_len = name_bytes.len().min(max_len);
                for (i, &b) in name_bytes[..copy_len].iter().enumerate() {
                    dirent.d_name[i] = b as libc::c_char;
                }
                dirent.d_name[copy_len] = 0;
                dirent.d_reclen = std::mem::size_of::<libc::dirent>() as u16;

                std::ptr::from_mut::<libc::dirent>(dirent)
            })
        })
        .unwrap_or(std::ptr::null_mut())
    }
}

#[no_mangle]
pub unsafe extern "C" fn readdir64(dirp: *mut libc::DIR) -> *mut libc::dirent {
    unsafe { readdir(dirp) }
}

#[no_mangle]
pub unsafe extern "C" fn closedir(dirp: *mut libc::DIR) -> c_int {
    unsafe {
        let Some(state) = STATE.get() else {
            return raw_closedir(dirp);
        };

        let key = dirp as usize;
        if dir_table_remove(key) {
            return 0;
        }

        state.real.real_closedir(dirp)
    }
}

// ===========================================================================
// fcntl — handle F_GETFL / F_SETFL / F_GETFD / F_SETFD on virtual FDs
// ===========================================================================

#[no_mangle]
#[allow(clippy::cast_possible_truncation)]
pub unsafe extern "C" fn fcntl(fd: c_int, cmd: c_int, arg: libc::c_ulong) -> c_int {
    unsafe {
        let Some(state) = STATE.get() else {
            return raw_fcntl(fd, cmd, arg);
        };

        // Virtual FD: handle common fcntl commands.
        match cmd {
            libc::F_GETFL => {
                // Return the flags the file was opened with.
                if let Some(guard) = state.fd_table.get(fd) {
                    guard.file().flags
                } else {
                    raw_fcntl(fd, cmd, arg)
                }
            }
            libc::F_DUPFD | libc::F_DUPFD_CLOEXEC => {
                if state.fd_table.get(fd).is_some() {
                    // Not supported for virtual FDs.
                    set_errno(libc::EBADF);
                    -1
                } else {
                    raw_fcntl(fd, cmd, arg)
                }
            }
            // F_SETFL, F_GETFD, F_SETFD: pretend success for virtual, delegate otherwise.
            _ => {
                if state.fd_table.get(fd).is_some() {
                    0
                } else {
                    raw_fcntl(fd, cmd, arg)
                }
            }
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn fcntl64(fd: c_int, cmd: c_int, arg: libc::c_ulong) -> c_int {
    unsafe { fcntl(fd, cmd, arg) }
}

#[cfg(target_os = "linux")]
unsafe fn raw_fcntl(fd: c_int, cmd: c_int, arg: libc::c_ulong) -> c_int {
    unsafe { libc::syscall(libc::SYS_fcntl, fd, cmd, arg) as c_int }
}

#[cfg(not(target_os = "linux"))]
unsafe fn raw_fcntl(fd: c_int, cmd: c_int, arg: libc::c_ulong) -> c_int {
    unsafe {
        let sym = dlsym_next(c"fcntl");
        if sym.is_null() {
            return -1;
        }
        let f: unsafe extern "C" fn(c_int, c_int, libc::c_ulong) -> c_int =
            std::mem::transmute(sym);
        f(fd, cmd, arg)
    }
}

// ===========================================================================
// ioctl — pass-through for real FDs, return -1/ENOTTY for virtual FDs
// ===========================================================================

#[no_mangle]
#[allow(clippy::cast_possible_truncation)]
pub unsafe extern "C" fn ioctl(fd: c_int, request: libc::c_ulong, arg: *mut c_void) -> c_int {
    unsafe {
        let Some(state) = STATE.get() else {
            return raw_ioctl(fd, request, arg);
        };

        // Virtual FDs don't support ioctl.
        if state.fd_table.get(fd).is_some() {
            set_errno(libc::ENOTTY);
            return -1;
        }

        raw_ioctl(fd, request, arg)
    }
}

#[cfg(target_os = "linux")]
unsafe fn raw_ioctl(fd: c_int, request: libc::c_ulong, arg: *mut c_void) -> c_int {
    unsafe { libc::syscall(libc::SYS_ioctl, fd, request, arg) as c_int }
}

#[cfg(not(target_os = "linux"))]
unsafe fn raw_ioctl(fd: c_int, request: libc::c_ulong, arg: *mut c_void) -> c_int {
    unsafe {
        let sym = dlsym_next(c"ioctl");
        if sym.is_null() {
            return -1;
        }
        let f: unsafe extern "C" fn(c_int, libc::c_ulong, *mut c_void) -> c_int =
            std::mem::transmute(sym);
        f(fd, request, arg)
    }
}
