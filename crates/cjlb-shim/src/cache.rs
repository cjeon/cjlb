// cache.rs -- Sharded LRU page cache with zeroize-on-drop.
//
// Each decrypted page is up to PAGE_BODY_SIZE (1 MiB). The cache is sharded
// by page_id to reduce lock contention. Eviction is LRU based on a monotonic
// access counter.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use zeroize::Zeroize;

/// Default number of shards.
const DEFAULT_SHARD_COUNT: usize = 16;

/// A decrypted page. Zeroized on drop so plaintext doesn't linger in memory.
#[derive(Debug)]
pub struct DecryptedPage {
    pub data: Vec<u8>,
}

impl Drop for DecryptedPage {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

/// Sharded LRU page cache.
#[allow(missing_debug_implementations)] // contains Mutex internals
pub struct PageCache {
    shards: Vec<Mutex<LruShard>>,
    shard_count: usize,
    budget_per_shard: AtomicUsize,
    /// Monotonic counter for LRU ordering.
    tick: AtomicU64,
    /// Diagnostic counters.
    pub hits: AtomicU64,
    pub misses: AtomicU64,
}

struct LruShard {
    entries: Vec<CacheEntry>,
    used_bytes: usize,
}

struct CacheEntry {
    page_id: u32,
    data: Arc<DecryptedPage>,
    last_access: u64,
}

#[allow(clippy::significant_drop_tightening)] // lock must be held during eviction loop
impl PageCache {
    /// Create a new page cache with the given total memory budget (bytes).
    pub fn new(total_budget: usize) -> Self {
        let shard_count = DEFAULT_SHARD_COUNT;
        let budget_per_shard = total_budget / shard_count;
        let shards = (0..shard_count)
            .map(|_| {
                Mutex::new(LruShard {
                    entries: Vec::new(),
                    used_bytes: 0,
                })
            })
            .collect();
        Self {
            shards,
            shard_count,
            budget_per_shard: AtomicUsize::new(budget_per_shard),
            tick: AtomicU64::new(0),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// Update the total cache budget at runtime. If the new budget is smaller,
    /// pages are evicted immediately from each shard to fit.
    pub fn set_budget(&self, total_budget: usize) {
        let new_per_shard = total_budget / self.shard_count;
        self.budget_per_shard
            .store(new_per_shard, Ordering::Relaxed);

        // Evict from each shard until it fits the new budget.
        for shard_mutex in &self.shards {
            let mut shard = shard_mutex.lock().unwrap();
            while shard.used_bytes > new_per_shard && !shard.entries.is_empty() {
                let lru_idx = shard
                    .entries
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, e)| e.last_access)
                    .map(|(i, _)| i)
                    .unwrap();
                let evicted = shard.entries.swap_remove(lru_idx);
                shard.used_bytes -= evicted.data.data.len();
            }
        }
    }

    /// Return the current total budget in bytes.
    pub fn budget(&self) -> usize {
        self.budget_per_shard.load(Ordering::Relaxed) * self.shard_count
    }

    const fn shard_idx(&self, page_id: u32) -> usize {
        page_id as usize % self.shard_count
    }

    fn next_tick(&self) -> u64 {
        self.tick.fetch_add(1, Ordering::Relaxed)
    }

    /// Look up a page in the cache. Returns a shared reference if present.
    pub fn get(&self, page_id: u32) -> Option<Arc<DecryptedPage>> {
        let idx = self.shard_idx(page_id);
        let mut shard = self.shards[idx].lock().unwrap();
        for entry in &mut shard.entries {
            if entry.page_id == page_id {
                entry.last_access = self.next_tick();
                self.hits.fetch_add(1, Ordering::Relaxed);
                return Some(Arc::clone(&entry.data));
            }
        }
        self.misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// Insert a decrypted page into the cache, evicting LRU entries if needed.
    /// Returns a shared reference to the inserted (or existing) page.
    pub fn insert(&self, page_id: u32, data: Vec<u8>) -> Arc<DecryptedPage> {
        let idx = self.shard_idx(page_id);
        let mut shard = self.shards[idx].lock().unwrap();

        // Check if already present (concurrent insert race).
        for entry in &mut shard.entries {
            if entry.page_id == page_id {
                entry.last_access = self.next_tick();
                return Arc::clone(&entry.data);
            }
        }

        let data_len = data.len();
        let page = Arc::new(DecryptedPage { data });

        // Evict until we have room.
        let budget = self.budget_per_shard.load(Ordering::Relaxed);
        while shard.used_bytes + data_len > budget && !shard.entries.is_empty() {
            // Find LRU entry (lowest last_access).
            let lru_idx = shard
                .entries
                .iter()
                .enumerate()
                .min_by_key(|(_, e)| e.last_access)
                .map(|(i, _)| i)
                .unwrap();
            let evicted = shard.entries.swap_remove(lru_idx);
            shard.used_bytes -= evicted.data.data.len();
        }

        let tick = self.next_tick();
        shard.entries.push(CacheEntry {
            page_id,
            data: Arc::clone(&page),
            last_access: tick,
        });
        shard.used_bytes += data_len;

        page
    }
}
