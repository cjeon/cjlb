// CJLB Shim -- LD_PRELOAD .so for transparent encrypted filesystem interception.
//
// Intercepts libc calls (open, read, stat, etc.) for paths under a configurable
// virtual root. Reads are decrypted from the CJLB page/chunk format; writes are
// encrypted and persisted to the overlay write layer.
//
// Crate-level lint overrides: this is a low-level FFI LD_PRELOAD shim where
// certain pedantic/nursery lints are unavoidable false positives:
// - manual_let_else: match+return patterns are clearer than let...else in FFI
// - option_if_let_else: same rationale — explicit control flow at FFI boundary
// - significant_drop_tightening: locks must be held across multi-step operations
// - manual_c_str_literals: many byte strings include \0 for raw syscall use
// - cast_possible_truncation / cast_sign_loss / cast_possible_wrap:
//   inherent to FFI — libc types are i32/i64, our types are u32/u64/usize
#![allow(
    clippy::manual_let_else,
    clippy::option_if_let_else,
    clippy::significant_drop_tightening,
    clippy::manual_c_str_literals,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::single_match_else
)]

mod cache;
mod fd_table;
mod hooks;
mod init;
mod overlay;
pub(crate) mod page_read;
mod pressure;
mod real_fns;
mod route_table_view;
mod state;
pub(crate) mod stream_hub;
pub(crate) mod ipc_server;

// ---------------------------------------------------------------------------
// .init_array constructor -- runs before main()
// ---------------------------------------------------------------------------

// Linux (ELF): .init_array
#[cfg(target_os = "linux")]
#[link_section = ".init_array"]
#[used]
static INIT: unsafe extern "C" fn() = shim_init;

// macOS (Mach-O): __DATA,__mod_init_func
#[cfg(target_os = "macos")]
#[link_section = "__DATA,__mod_init_func"]
#[used]
static INIT: unsafe extern "C" fn() = shim_init;

unsafe extern "C" fn shim_init() {
    unsafe {
        if init::initialize().is_err() {
            libc::_exit(1);
        }
        // Register atexit handler to print cache stats
        libc::atexit(print_cache_stats);
    }
}

#[allow(clippy::cast_precision_loss)] // display-only hit rate percentage
extern "C" fn print_cache_stats() {
    if let Some(state) = state::STATE.get() {
        let hits = state.cache.hits.load(std::sync::atomic::Ordering::Relaxed);
        let misses = state
            .cache
            .misses
            .load(std::sync::atomic::Ordering::Relaxed);
        let total = hits + misses;
        let rate = if total > 0 {
            hits as f64 / total as f64 * 100.0
        } else {
            0.0
        };
        eprintln!("cjlb-shim: cache stats: {hits} hits, {misses} misses, {rate:.1}% hit rate");
    }
}
