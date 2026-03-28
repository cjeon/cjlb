// state.rs -- Global shim state, initialized once via OnceLock.

use std::sync::OnceLock;

use cjlb_crypto::DerivedKeys;

use crate::cache::PageCache;
use crate::fd_table::FdTable;
use crate::overlay::OverlayIndex;
use crate::pressure::PressureMonitor;
use crate::real_fns::RealFunctions;
use crate::route_table_view::RouteTableView;

pub static STATE: OnceLock<ShimState> = OnceLock::new();
pub static PRESSURE_MONITOR: OnceLock<PressureMonitor> = OnceLock::new();
pub static IPC_SERVER: OnceLock<crate::ipc_server::IpcServer> = OnceLock::new();

#[allow(dead_code, missing_debug_implementations)] // contains crypto keys
pub struct ShimState {
    pub virtual_root: String,
    pub bundle_dir: String,
    pub write_dir: String,
    pub bundle_id: [u8; 16],
    pub derived_keys: DerivedKeys,
    pub route_table: RouteTableView,
    pub cache: PageCache,
    pub fd_table: FdTable,
    pub overlay: OverlayIndex,
    pub real: RealFunctions,
}

// SAFETY: All interior mutable fields (FdTable, PageCache, OverlayIndex) use
// RwLock / Mutex / atomics internally. RealFunctions contains only function
// pointers which are inherently Send+Sync.
unsafe impl Send for ShimState {}
unsafe impl Sync for ShimState {}
