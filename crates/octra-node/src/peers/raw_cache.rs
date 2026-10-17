//! Native raw-bundle entry cap and insertion-order eviction. The native byte
//! estimate is diagnostic only: this cache has no independent byte limit.
use super::{Error, RawBundle};
use std::collections::{BTreeMap, VecDeque};

pub(super) struct RawCache {
    capacity: usize,
    entries: BTreeMap<[u8; 32], (i64, RawBundle)>,
    fifo: VecDeque<[u8; 32]>,
}
impl RawCache {
    pub(super) fn from_inputs(value: Option<&[u8]>) -> Self {
        Self::new(octra_node_runtime::consensus_preverify_cache::configured_capacity(value))
    }
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: BTreeMap::new(),
            fifo: VecDeque::new(),
        }
    }
    pub(super) fn store(
        &mut self,
        epoch: i64,
        id: [u8; 32],
        bundle: RawBundle,
    ) -> Result<(), Error> {
        // Preserve the host's existing immutable commitment guard. An exact
        // retry, like a native replacement, does not refresh insertion age.
        if let Some((prior, raw)) = self.entries.get(&id) {
            if *prior != epoch || raw != &bundle {
                return Err("proposal cache commitment conflict".into());
            }
            return Ok(());
        }
        self.entries.insert(id, (epoch, bundle));
        self.fifo.push_back(id);
        while self.entries.len() > self.capacity {
            let Some(old) = self.fifo.pop_front() else {
                break;
            };
            self.entries.remove(&old);
        }
        Ok(())
    }
    pub(super) fn lookup(&self, id: &[u8; 32]) -> Option<RawBundle> {
        self.entries.get(id).map(|(_, raw)| raw.clone())
    }
    pub(super) fn prune(&mut self, committed: i64) {
        self.entries.retain(|_, (epoch, _)| *epoch > committed);
        // Unlike native's separate frozen table, this host also releases old
        // raw epochs. Remove their queue records so reinserting an ID cannot
        // evict its new value through a stale insertion record.
        self.fifo.retain(|id| self.entries.contains_key(id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle(value: u8) -> RawBundle {
        RawBundle {
            tx_hashes: vec![vec![value]],
            txs_json: vec![vec![value; 2]],
            receipts_json: vec![vec![value; 3]],
        }
    }
    fn store(cache: &mut RawCache, epoch: i64, id: u8) {
        cache.store(epoch, [id; 32], bundle(id)).unwrap();
        assert!(cache.entries.len() <= cache.capacity);
        assert_eq!(cache.entries.len(), cache.fifo.len());
        let mut ordered = cache.fifo.iter().copied().collect::<Vec<_>>();
        ordered.sort_unstable();
        assert_eq!(ordered, cache.entries.keys().copied().collect::<Vec<_>>());
    }

    #[test]
    fn captured_setting_caps_raw_cache_without_process_environment() {
        use octra_node_protocol::consensus::profile::Settings;
        let settings = Settings::from_values(BTreeMap::from([(
            "OCTRA_BUNDLE_CACHE_CAP".into(),
            b"64".to_vec(),
        )]))
        .unwrap();
        let mut cache = RawCache::from_inputs(settings.get("OCTRA_BUNDLE_CACHE_CAP"));
        for id in 0..65 {
            store(&mut cache, 7, id);
        }
        assert_eq!(cache.entries.len(), 64);
        assert!(cache.lookup(&[0; 32]).is_none());
        assert_eq!(cache.lookup(&[64; 32]), Some(bundle(64)));
        let absent = Settings::from_values(BTreeMap::new()).unwrap();
        assert_eq!(
            RawCache::from_inputs(absent.get("OCTRA_BUNDLE_CACHE_CAP")).capacity,
            4096
        );
    }

    #[test]
    fn hits_and_identical_replacements_do_not_refresh_native_fifo() {
        let mut cache = RawCache::new(2);
        store(&mut cache, 7, 1);
        store(&mut cache, 7, 2);
        assert_eq!(cache.lookup(&[1; 32]), Some(bundle(1)));
        assert!(cache.lookup(&[9; 32]).is_none());
        store(&mut cache, 7, 1);
        store(&mut cache, 7, 3);
        assert!(cache.lookup(&[1; 32]).is_none());
        assert_eq!(cache.lookup(&[2; 32]), Some(bundle(2)));
        assert_eq!(cache.lookup(&[3; 32]), Some(bundle(3)));
        assert_eq!(cache.fifo, VecDeque::from([[2; 32], [3; 32]]));
    }

    #[test]
    fn conflicting_replacements_preserve_contents_and_eviction_order() {
        let mut cache = RawCache::new(2);
        store(&mut cache, 7, 1);
        store(&mut cache, 8, 2);
        assert!(cache.store(7, [1; 32], bundle(9)).is_err());
        assert!(cache.store(8, [1; 32], bundle(1)).is_err());
        assert_eq!(cache.lookup(&[1; 32]), Some(bundle(1)));
        assert_eq!(cache.fifo, VecDeque::from([[1; 32], [2; 32]]));
        store(&mut cache, 9, 3);
        assert!(cache.lookup(&[1; 32]).is_none());
        assert_eq!(cache.lookup(&[2; 32]), Some(bundle(2)));
    }

    #[test]
    fn pruning_and_reinsertion_have_no_stale_fifo_tickets() {
        let mut cache = RawCache::new(2);
        store(&mut cache, 1, 1);
        store(&mut cache, 2, 2);
        cache.prune(1);
        assert!(cache.lookup(&[1; 32]).is_none());
        assert_eq!(cache.fifo, VecDeque::from([[2; 32]]));
        store(&mut cache, 3, 1);
        store(&mut cache, 3, 3);
        assert!(cache.lookup(&[2; 32]).is_none());
        assert_eq!(cache.lookup(&[1; 32]), Some(bundle(1)));
        assert_eq!(cache.fifo, VecDeque::from([[1; 32], [3; 32]]));
        cache.prune(3);
        assert!(cache.entries.is_empty());
        assert!(cache.fifo.is_empty());
        for epoch in 4..100 {
            store(&mut cache, epoch, 1);
            cache.prune(epoch);
            assert!(cache.fifo.is_empty());
        }
    }

    #[test]
    fn entry_cap_includes_empty_and_large_bundles_and_zero_disables_retention() {
        let mut cache = RawCache::new(1);
        let empty = RawBundle {
            tx_hashes: vec![],
            txs_json: vec![],
            receipts_json: vec![],
        };
        cache.store(1, [1; 32], empty.clone()).unwrap();
        assert_eq!(cache.lookup(&[1; 32]), Some(empty));
        let mut large = bundle(2);
        large.receipts_json = vec![vec![2; 1 << 20]];
        cache.store(1, [2; 32], large.clone()).unwrap();
        assert!(cache.lookup(&[1; 32]).is_none());
        assert_eq!(cache.lookup(&[2; 32]), Some(large));
        let mut disabled = RawCache::new(0);
        store(&mut disabled, 1, 1);
        assert!(disabled.entries.is_empty());
        assert!(disabled.fifo.is_empty());
    }

    #[test]
    fn captured_capacity_parser_matches_native_startup_bounds() {
        use octra_node_runtime::consensus_preverify_cache::configured_capacity as capacity;
        assert_eq!(capacity(None), 4096);
        for invalid in [b"63".as_slice(), b"65537", b"-1", b"invalid"] {
            assert_eq!(capacity(Some(invalid)), 4096);
        }
        assert_eq!(capacity(Some(b"64")), 64);
        assert_eq!(capacity(Some(b"65536")), 65_536);
        assert_eq!(capacity(Some(b"0x10000")), 65_536);
        let mut cache = RawCache::new(capacity(Some(b"64")));
        for id in 0..65 {
            store(&mut cache, 1, id);
        }
        assert!(cache.lookup(&[0; 32]).is_none());
        assert_eq!(cache.entries.len(), 64);
    }
}
