//! Bounded TTL+capacity map.
//!
//! Eviction policy: combination of (a) hard size cap with FIFO drop on
//! insert when at capacity, and (b) idle-TTL — entries unused for longer
//! than `ttl` are pruned on the next `sweep()`.
//!
//! Used for:
//!   - the node tunnel's per-peer state (idle-TTL prevents UDP-source
//!     spoof from filling memory)
//!   - the control plane's per-session state (cap caps active sessions
//!     a node will track; TTL drops abandoned sessions)
//!   - the mock RPC's tx history (cap keeps the test process bounded)

use std::{
    collections::{HashMap, VecDeque},
    hash::Hash,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use parking_lot::Mutex;

#[derive(Debug)]
struct Entry<V> {
    value: V,
    inserted_at: Instant,
    last_touch_us: AtomicU64,
}

/// Bounded TTL map. Cheap reads/writes; periodic `sweep()` evicts stale.
pub struct BoundedMap<K: Hash + Eq + Clone, V: Clone> {
    inner: Mutex<Inner<K, V>>,
    capacity: usize,
    ttl: Duration,
}

struct Inner<K: Hash + Eq + Clone, V: Clone> {
    map: HashMap<K, Entry<V>>,
    order: VecDeque<K>,
}

impl<K: Hash + Eq + Clone, V: Clone> BoundedMap<K, V> {
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(Inner {
                map: HashMap::with_capacity(capacity.min(1024)),
                order: VecDeque::with_capacity(capacity.min(1024)),
            }),
            capacity,
            ttl,
        }
    }

    /// Insert a new key. If the map is at capacity, the oldest entry by
    /// insertion order is evicted. Returns true on insert, false if the
    /// key already existed (in which case the value is replaced).
    pub fn insert(&self, key: K, value: V) -> bool {
        let mut g = self.inner.lock();
        let now_us = mono_us();
        let new_entry = Entry {
            value,
            inserted_at: Instant::now(),
            last_touch_us: AtomicU64::new(now_us),
        };
        let was_present = g.map.contains_key(&key);
        if was_present {
            g.map.insert(key, new_entry);
            return false;
        }
        if g.map.len() >= self.capacity {
            if let Some(victim) = g.order.pop_front() {
                g.map.remove(&victim);
            }
        }
        g.order.push_back(key.clone());
        g.map.insert(key, new_entry);
        true
    }

    /// Get a clone of the value and refresh the entry's last-touch time.
    pub fn get(&self, key: &K) -> Option<V> {
        let g = self.inner.lock();
        let entry = g.map.get(key)?;
        entry.last_touch_us.store(mono_us(), Ordering::Relaxed);
        Some(entry.value.clone())
    }

    /// Modify the entry in place via a closure. Refreshes last-touch.
    /// Returns whatever the closure returns, or None if the key is missing.
    pub fn modify<R>(&self, key: &K, f: impl FnOnce(&mut V) -> R) -> Option<R> {
        let mut g = self.inner.lock();
        let entry = g.map.get_mut(key)?;
        entry.last_touch_us.store(mono_us(), Ordering::Relaxed);
        Some(f(&mut entry.value))
    }

    /// Remove a key.
    pub fn remove(&self, key: &K) -> Option<V> {
        let mut g = self.inner.lock();
        g.order.retain(|k| k != key);
        g.map.remove(key).map(|e| e.value)
    }

    /// Evict entries idle longer than `ttl`. Returns the number evicted.
    /// Intended to be called periodically from a background task.
    pub fn sweep(&self) -> usize {
        let mut g = self.inner.lock();
        let now_us = mono_us();
        let ttl_us = self.ttl.as_micros() as u64;
        let to_evict: Vec<K> = g
            .map
            .iter()
            .filter_map(|(k, e)| {
                let last = e.last_touch_us.load(Ordering::Relaxed);
                if now_us.saturating_sub(last) > ttl_us {
                    Some(k.clone())
                } else {
                    None
                }
            })
            .collect();
        let n = to_evict.len();
        for k in &to_evict {
            g.map.remove(k);
        }
        // Rebuild order to drop evicted keys; small map sizes make this
        // cheaper than a per-insert linked-list bookkeeping.
        g.order = g.map.keys().cloned().collect();
        n
    }

    pub fn len(&self) -> usize {
        self.inner.lock().map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn contains_key(&self, key: &K) -> bool {
        self.inner.lock().map.contains_key(key)
    }

    /// Visit each key with the value (snapshot). Safe to call concurrently
    /// with other ops; callers see a consistent snapshot at the moment of
    /// the call.
    pub fn snapshot(&self) -> Vec<(K, V)> {
        let g = self.inner.lock();
        g.map
            .iter()
            .map(|(k, e)| (k.clone(), e.value.clone()))
            .collect()
    }

    /// Snapshot just the keys — clones the keys but **not** the values.
    /// For callers that only need to enumerate keys (e.g. trial-matching
    /// an incoming handshake against allowed pubkeys), this avoids
    /// cloning every (potentially large) `V` the way [`Self::snapshot`]
    /// does. The released lock lets the caller `.await` per key.
    pub fn keys(&self) -> Vec<K> {
        self.inner.lock().map.keys().cloned().collect()
    }

    /// Number of entries inserted since `epoch`. Crude metric for tests
    /// and dashboards.
    pub fn elapsed_since_oldest(&self) -> Option<Duration> {
        let g = self.inner.lock();
        g.order
            .front()
            .and_then(|k| g.map.get(k))
            .map(|e| e.inserted_at.elapsed())
    }
}

/// Microseconds since a fixed process-start baseline, read off the
/// **monotonic** clock. The value is only ever used for idle-TTL delta
/// math (`now - last_touch`), so wall-clock is both unnecessary and
/// wrong: a backward `SystemTime` jump (NTP step, `settimeofday`) could
/// make a live entry look arbitrarily stale and evict it mid-session.
/// `Instant` can't jump, and on macOS skips the pricier `gettimeofday`
/// the wall-clock path took on every per-packet `get`/`modify`.
fn mono_us() -> u64 {
    use std::sync::OnceLock;
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    EPOCH.get_or_init(Instant::now).elapsed().as_micros() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacity_evicts_oldest() {
        let m: BoundedMap<u32, u32> = BoundedMap::new(2, Duration::from_secs(60));
        m.insert(1, 11);
        m.insert(2, 22);
        m.insert(3, 33);
        assert!(!m.contains_key(&1));
        assert_eq!(m.get(&2), Some(22));
        assert_eq!(m.get(&3), Some(33));
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn ttl_sweeps_idle() {
        let m: BoundedMap<u32, u32> = BoundedMap::new(10, Duration::from_millis(20));
        m.insert(1, 11);
        std::thread::sleep(Duration::from_millis(40));
        assert_eq!(m.sweep(), 1);
        assert!(!m.contains_key(&1));
    }

    #[test]
    fn get_refreshes_touch() {
        let m: BoundedMap<u32, u32> = BoundedMap::new(10, Duration::from_millis(50));
        m.insert(1, 11);
        std::thread::sleep(Duration::from_millis(30));
        let _ = m.get(&1);
        std::thread::sleep(Duration::from_millis(30));
        // Total elapsed = 60ms but get() refreshed at +30ms; ttl is 50ms
        // so age since touch is 30ms < 50ms. Should NOT evict.
        assert_eq!(m.sweep(), 0);
        assert!(m.contains_key(&1));
    }

    #[test]
    fn modify_in_place() {
        let m: BoundedMap<u32, u32> = BoundedMap::new(10, Duration::from_secs(60));
        m.insert(1, 11);
        m.modify(&1, |v| *v += 1);
        assert_eq!(m.get(&1), Some(12));
    }
}
