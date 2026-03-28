// fd_table.rs -- Virtual file descriptor management.
//
// Virtual FDs live in the range [1_000_000, ...) to avoid colliding with real
// kernel FDs. Each virtual FD maps to a VirtualFile that tracks the open path,
// cursor position, file size, and data source.

use std::collections::HashMap;
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

/// Allocate a real kernel FD by opening `/dev/null`.
/// Uses raw syscalls to avoid recursion through our `LD_PRELOAD` hooks.
fn allocate_real_fd() -> i32 {
    #[cfg(target_os = "linux")]
    unsafe {
        libc::syscall(
            libc::SYS_openat,
            libc::AT_FDCWD,
            c"/dev/null".as_ptr() as *const libc::c_char,
            libc::O_RDWR,
            0i32,
        ) as i32
    }
    #[cfg(not(target_os = "linux"))]
    {
        // macOS stub: use dlsym to call real open.
        unsafe {
            let sym = libc::dlsym(libc::RTLD_NEXT, c"open".as_ptr());
            if sym.is_null() {
                return -1;
            }
            let f: unsafe extern "C" fn(*const libc::c_char, i32, i32) -> i32 =
                std::mem::transmute(sym);
            f(c"/dev/null".as_ptr().cast(), libc::O_RDWR, 0)
        }
    }
}

// Virtual FDs are backed by real kernel FDs (opened from /dev/null) so that
// kernel-level fstatat / fcntl calls don't fail with EBADF. The FdTable
// tracks which real FDs are "virtual" and intercepts I/O on them.

/// Thread-safe table of all open virtual file descriptors.
#[derive(Debug)]
pub struct FdTable {
    inner: RwLock<HashMap<i32, VirtualFile>>,
}

/// A file opened through the virtual filesystem.
#[derive(Debug)]
#[allow(dead_code)]
pub struct VirtualFile {
    /// Virtual path (with the root prefix stripped).
    pub path: String,
    /// Current read/write cursor position.
    pub cursor: u64,
    /// Logical file size in bytes.
    pub file_size: u64,
    /// Open flags (`O_RDONLY`, `O_WRONLY`, etc.).
    pub flags: i32,
    /// Where the data comes from.
    pub source: FileSource,
    /// Per-fd write accumulator (Phase 2).
    pub write_buf: Vec<u8>,
}

/// Origin of a virtual file's data.
#[derive(Debug)]
#[allow(dead_code)]
pub enum FileSource {
    /// File backed by the base encrypted bundle.
    BaseBundle {
        /// Index into the route table's file record array.
        file_idx: usize,
    },
    /// File from the write overlay layer.
    WriteLayer,
    /// Newly created file (not yet in any layer).
    NewFile,
}

#[allow(clippy::significant_drop_tightening)] // lock must be held across operations
impl FdTable {
    /// Create an empty file descriptor table.
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    /// Allocate a new virtual FD for the given file, returning the FD number.
    ///
    /// On Linux, opens `/dev/null` to get a real kernel FD so that syscalls
    /// like `fstatat(fd, "", buf, AT_EMPTY_PATH)` don't fail with EBADF.
    /// The actual I/O is intercepted by our hooks.
    pub fn allocate(&self, file: VirtualFile) -> i32 {
        let fd = allocate_real_fd();
        if fd < 0 {
            return -1;
        }
        let mut map = self.inner.write().unwrap();
        map.insert(fd, file);
        fd
    }

    /// Borrow a virtual file immutably (read lock).
    pub fn get(&self, fd: i32) -> Option<ReadGuard<'_>> {
        let map = self.inner.read().unwrap();
        if !map.contains_key(&fd) {
            return None;
        }
        Some(ReadGuard { guard: map, fd })
    }

    /// Borrow a virtual file mutably (write lock).
    pub fn get_mut(&self, fd: i32) -> Option<WriteGuard<'_>> {
        let map = self.inner.write().unwrap();
        if !map.contains_key(&fd) {
            return None;
        }
        Some(WriteGuard { guard: map, fd })
    }

    /// Remove a virtual FD from the table, returning the `VirtualFile` if present.
    /// Also closes the underlying real kernel FD.
    pub fn remove(&self, fd: i32) -> Option<VirtualFile> {
        let mut map = self.inner.write().unwrap();
        let vf = map.remove(&fd);
        if vf.is_some() {
            // Close the real kernel FD using raw syscall.
            #[cfg(target_os = "linux")]
            unsafe {
                libc::syscall(libc::SYS_close, fd);
            }
            #[cfg(not(target_os = "linux"))]
            unsafe {
                let sym = libc::dlsym(libc::RTLD_NEXT, c"close".as_ptr());
                if !sym.is_null() {
                    let f: unsafe extern "C" fn(i32) -> i32 = std::mem::transmute(sym);
                    f(fd);
                }
            }
        }
        vf
    }
}

// ---------------------------------------------------------------------------
// Guard wrappers -- hold the RwLock and provide access to the VirtualFile
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct ReadGuard<'a> {
    guard: RwLockReadGuard<'a, HashMap<i32, VirtualFile>>,
    fd: i32,
}

impl ReadGuard<'_> {
    pub fn file(&self) -> &VirtualFile {
        self.guard.get(&self.fd).unwrap()
    }
}

#[allow(missing_debug_implementations)] // WriteGuard holds mutable reference
pub struct WriteGuard<'a> {
    guard: RwLockWriteGuard<'a, HashMap<i32, VirtualFile>>,
    fd: i32,
}

impl WriteGuard<'_> {
    #[allow(dead_code)]
    pub fn file(&self) -> &VirtualFile {
        self.guard.get(&self.fd).unwrap()
    }

    pub fn file_mut(&mut self) -> &mut VirtualFile {
        self.guard.get_mut(&self.fd).unwrap()
    }
}
