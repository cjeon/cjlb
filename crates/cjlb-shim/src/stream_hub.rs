// stream_hub.rs — Pub/sub hub for streaming file writes to IPC clients.
//
// The write hook publishes pre-encryption plaintext to subscribers.
// Socket handler threads subscribe to receive real-time write data.

use std::collections::HashMap;
use std::fmt;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, OnceLock, RwLock};

/// Global singleton hub. Initialised once; available to the write hook and IPC
/// socket handlers without additional locking overhead.
pub static STREAM_HUB: OnceLock<StreamHub> = OnceLock::new();

/// Bounded channel capacity per subscriber. `try_send` drops frames when a
/// subscriber falls behind, so the write hook is never blocked.
#[allow(dead_code)] // used once IPC socket server consumes subscribe()
const CHANNEL_CAPACITY: usize = 64;

/// Per-path list of subscriber senders.
type SubscriberMap = HashMap<String, Vec<SyncSender<Arc<Vec<u8>>>>>;

/// Fan-out hub that routes write data to per-path subscriber channels.
///
/// Publishers call [`StreamHub::publish`] on the hot path (inside the write
/// hook). The fast path — no subscribers for the given path — is a single
/// `RwLock` read + `HashMap` lookup that returns immediately.
pub struct StreamHub {
    inner: RwLock<SubscriberMap>,
}

impl StreamHub {
    /// Create an empty hub with no subscribers.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    /// Subscribe to writes targeting `path`.
    ///
    /// Returns a bounded receiver. If the subscriber cannot keep up, the
    /// publisher silently drops frames rather than stalling the write hook.
    #[allow(dead_code)] // used once IPC socket server is wired up
    pub fn subscribe(&self, path: &str) -> Receiver<Arc<Vec<u8>>> {
        let (tx, rx) = sync_channel(CHANNEL_CAPACITY);
        let mut map = self
            .inner
            .write()
            .expect("stream_hub: write lock poisoned");
        map.entry(path.to_owned()).or_default().push(tx);
        rx
    }

    /// Publish `data` to every subscriber watching `path`.
    ///
    /// Uses `try_send` so a slow/disconnected subscriber never stalls the
    /// caller. Disconnected senders are garbage-collected lazily: on the first
    /// failed send we upgrade to a write lock and remove dead entries.
    pub fn publish(&self, path: &str, data: &[u8]) {
        let has_disconnected = {
            let map = self
                .inner
                .read()
                .expect("stream_hub: read lock poisoned");
            let senders = match map.get(path) {
                Some(s) => s,
                None => return, // fast path — no subscribers
            };
            if senders.is_empty() {
                return;
            }
            let chunk = Arc::new(data.to_vec());
            let mut any_disconnected = false;
            for tx in senders {
                if tx.try_send(Arc::clone(&chunk)).is_err() {
                    // Channel full or disconnected — mark for cleanup.
                    // We cannot distinguish "full" from "disconnected" with
                    // try_send alone, but a disconnected sender will fail
                    // forever, so it will be retried and removed on the next
                    // publish.  For now, only flag true if the receiver is
                    // actually gone.
                    //
                    // SyncSender::try_send returns TrySendError::Disconnected
                    // when the receiver is dropped.  We only GC on that case.
                    // Re-check after the fact is fine — worst case we skip one
                    // cleanup round.
                    any_disconnected = true;
                }
            }
            any_disconnected
        };

        if has_disconnected {
            self.gc_disconnected(path);
        }
    }

    /// Remove disconnected senders for `path` under a write lock.
    fn gc_disconnected(&self, path: &str) {
        let mut map = self
            .inner
            .write()
            .expect("stream_hub: write lock poisoned");
        if let Some(senders) = map.get_mut(path) {
            // A sender is disconnected iff a zero-byte probe fails with
            // Disconnected. We send a zero-length sentinel that receivers
            // should tolerate (or we could try a different approach).
            // Instead, retain only senders that are NOT disconnected.
            // `try_send` of an empty Arc is cheap if the channel has room.
            senders.retain(|tx| {
                // Attempt a zero-cost probe: a zero-length vec.
                // If the receiver is gone, try_send returns Disconnected.
                match tx.try_send(Arc::new(Vec::new())) {
                    Ok(()) | Err(std::sync::mpsc::TrySendError::Full(_)) => true,
                    Err(std::sync::mpsc::TrySendError::Disconnected(_)) => false,
                }
            });
            if senders.is_empty() {
                map.remove(path);
            }
        }
    }
}

impl Default for StreamHub {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for StreamHub {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamHub")
            .field("paths", &"<opaque>")
            .finish()
    }
}
