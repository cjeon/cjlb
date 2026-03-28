// real_fns.rs -- Resolve real libc function pointers via dlsym.
//
// We MUST NOT call libc functions directly from hooks (that would recurse
// into our own interpositions). Instead we resolve the real implementations
// via dlopen/dlsym at init time and call through these pointers.

use std::os::raw::{c_char, c_int, c_void};

/// Holds raw function pointers to the real libc implementations.
#[allow(missing_debug_implementations)] // contains raw fn pointers
pub struct RealFunctions {
    pub open: unsafe extern "C" fn(*const c_char, c_int, libc::mode_t) -> c_int,
    pub read: unsafe extern "C" fn(c_int, *mut c_void, libc::size_t) -> libc::ssize_t,
    pub write: unsafe extern "C" fn(c_int, *const c_void, libc::size_t) -> libc::ssize_t,
    pub close: unsafe extern "C" fn(c_int) -> c_int,
    pub lseek: unsafe extern "C" fn(c_int, libc::off_t, c_int) -> libc::off_t,
    pub fstat: unsafe extern "C" fn(c_int, *mut libc::stat) -> c_int,
    pub access: unsafe extern "C" fn(*const c_char, c_int) -> c_int,
    pub fsync: unsafe extern "C" fn(c_int) -> c_int,

    // stat/lstat -- on Linux these may be __xstat or stat; on macOS just stat.
    pub stat_fn: unsafe extern "C" fn(*const c_char, *mut libc::stat) -> c_int,
    pub lstat_fn: unsafe extern "C" fn(*const c_char, *mut libc::stat) -> c_int,

    // Directory operations
    pub opendir: unsafe extern "C" fn(*const c_char) -> *mut libc::DIR,
    pub readdir: unsafe extern "C" fn(*mut libc::DIR) -> *mut libc::dirent,
    pub closedir: unsafe extern "C" fn(*mut libc::DIR) -> c_int,
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

/// Resolve all real libc symbols. Called once during initialization.
///
/// On Linux: dlopen("libc.so.6") + dlsym(handle, name).
/// On macOS: `dlsym(RTLD_NEXT`, name) for dev builds.
pub unsafe fn resolve() -> Result<RealFunctions, &'static str> {
    unsafe {
        let handle = get_libc_handle()?;

        Ok(RealFunctions {
            open: lookup(handle, b"open\0")?,
            read: lookup(handle, b"read\0")?,
            write: lookup(handle, b"write\0")?,
            close: lookup(handle, b"close\0")?,
            lseek: lookup(handle, b"lseek\0")?,
            fstat: lookup(handle, b"fstat\0")?,
            access: lookup(handle, b"access\0")?,
            fsync: lookup(handle, b"fsync\0")?,
            stat_fn: lookup(handle, b"stat\0")?,
            lstat_fn: lookup(handle, b"lstat\0")?,
            opendir: lookup(handle, b"opendir\0")?,
            readdir: lookup(handle, b"readdir\0")?,
            closedir: lookup(handle, b"closedir\0")?,
        })
    }
}

// ---------------------------------------------------------------------------
// Platform helpers
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
unsafe fn get_libc_handle() -> Result<*mut c_void, &'static str> {
    unsafe {
        let name = b"libc.so.6\0";
        let handle = libc::dlopen(name.as_ptr().cast(), libc::RTLD_LAZY | libc::RTLD_NOLOAD);
        if handle.is_null() {
            // Fallback: try loading it explicitly.
            let handle = libc::dlopen(name.as_ptr().cast(), libc::RTLD_LAZY);
            if handle.is_null() {
                return Err("dlopen libc.so.6 failed");
            }
            return Ok(handle);
        }
        Ok(handle)
    }
}

#[cfg(not(target_os = "linux"))]
#[allow(clippy::unnecessary_wraps)] // must match Linux signature
const unsafe fn get_libc_handle() -> Result<*mut c_void, &'static str> {
    // macOS: use RTLD_NEXT so we get the real symbol, not our interposition.
    // SAFETY: RTLD_NEXT is a constant sentinel, not a real pointer dereference.
    Ok(libc::RTLD_NEXT)
}

unsafe fn lookup<T>(handle: *mut c_void, name: &[u8]) -> Result<T, &'static str> {
    unsafe {
        let sym = libc::dlsym(handle, name.as_ptr().cast());
        if sym.is_null() {
            return Err("dlsym returned NULL");
        }
        Ok(std::mem::transmute_copy(&sym))
    }
}

// ---------------------------------------------------------------------------
// Convenience wrappers used throughout the shim
// ---------------------------------------------------------------------------

impl RealFunctions {
    /// Call the real `open(path, flags, mode)`.
    pub unsafe fn real_open(&self, path: *const c_char, flags: c_int, mode: libc::mode_t) -> c_int {
        unsafe { (self.open)(path, flags, mode) }
    }

    /// Call the real `read(fd, buf, count)`.
    pub unsafe fn real_read(
        &self,
        fd: c_int,
        buf: *mut c_void,
        count: libc::size_t,
    ) -> libc::ssize_t {
        unsafe { (self.read)(fd, buf, count) }
    }

    /// Call the real `write(fd, buf, count)`.
    pub unsafe fn real_write(
        &self,
        fd: c_int,
        buf: *const c_void,
        count: libc::size_t,
    ) -> libc::ssize_t {
        unsafe { (self.write)(fd, buf, count) }
    }

    /// Call the real `close(fd)`.
    pub unsafe fn real_close(&self, fd: c_int) -> c_int {
        unsafe { (self.close)(fd) }
    }

    /// Call the real `lseek(fd, offset, whence)`.
    pub unsafe fn real_lseek(&self, fd: c_int, offset: libc::off_t, whence: c_int) -> libc::off_t {
        unsafe { (self.lseek)(fd, offset, whence) }
    }

    /// Call the real `fstat(fd, buf)`.
    pub unsafe fn real_fstat(&self, fd: c_int, buf: *mut libc::stat) -> c_int {
        unsafe { (self.fstat)(fd, buf) }
    }

    /// Call the real `stat(path, buf)`.
    pub unsafe fn real_stat(&self, path: *const c_char, buf: *mut libc::stat) -> c_int {
        unsafe { (self.stat_fn)(path, buf) }
    }

    /// Call the real `lstat(path, buf)`.
    pub unsafe fn real_lstat(&self, path: *const c_char, buf: *mut libc::stat) -> c_int {
        unsafe { (self.lstat_fn)(path, buf) }
    }

    /// Call the real `access(path, mode)`.
    pub unsafe fn real_access(&self, path: *const c_char, mode: c_int) -> c_int {
        unsafe { (self.access)(path, mode) }
    }

    /// Call the real `fsync(fd)`.
    pub unsafe fn real_fsync(&self, fd: c_int) -> c_int {
        unsafe { (self.fsync)(fd) }
    }

    /// Call the real `opendir(path)`.
    pub unsafe fn real_opendir(&self, path: *const c_char) -> *mut libc::DIR {
        unsafe { (self.opendir)(path) }
    }

    /// Call the real `readdir(dir)`.
    pub unsafe fn real_readdir(&self, dir: *mut libc::DIR) -> *mut libc::dirent {
        unsafe { (self.readdir)(dir) }
    }

    /// Call the real `closedir(dir)`.
    pub unsafe fn real_closedir(&self, dir: *mut libc::DIR) -> c_int {
        unsafe { (self.closedir)(dir) }
    }
}
