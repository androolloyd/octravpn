//! Bounded immutable capabilities. Time is explicit for deterministic expiry tests.
use anyhow::{ensure, Result};
use octra_browser::{Provenance, SnapshotIdentity};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

struct Entry<T> {
    identity: SnapshotIdentity,
    value: T,
    expires: Instant,
}
pub(super) struct Cache<T> {
    entries: BTreeMap<String, Entry<T>>,
    capacity: usize,
    ttl: Duration,
}
impl<T> Default for Cache<T> {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
            capacity: 32,
            ttl: Duration::from_secs(120),
        }
    }
}

impl<T: Clone> Cache<T> {
    pub(super) fn remember(
        &mut self,
        identity: SnapshotIdentity,
        value: T,
        now: Instant,
    ) -> Result<()> {
        self.entries.retain(|_, e| e.expires > now);
        let scope = Provenance::Canonical(identity.clone()).id();
        if let Some(old) = self.entries.get(&scope) {
            ensure!(old.identity == identity, "gateway scope identity differs");
            return Ok(());
        }
        if self.entries.len() >= self.capacity {
            if let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.expires)
                .map(|(k, _)| k.clone())
            {
                self.entries.remove(&oldest);
            }
        }
        self.entries.insert(
            scope,
            Entry {
                identity,
                value,
                expires: now + self.ttl,
            },
        );
        Ok(())
    }
    pub(super) fn get(&mut self, scope: &str, now: Instant) -> Option<(SnapshotIdentity, T)> {
        self.entries.retain(|_, e| e.expires > now);
        let entry = self.entries.get(scope)?;
        if Provenance::Canonical(entry.identity.clone()).id() != scope {
            return None;
        }
        Some((entry.identity.clone(), entry.value.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn identity(epoch: u64) -> SnapshotIdentity {
        SnapshotIdentity {
            chain_id: "gateway-cache-fixture".into(),
            origin: octra_browser::ChainOrigin::Genesis {
                state_root: octra_browser::StateRoot([7; 32]),
            },
            epoch,
            state_root: format!("{epoch:064x}"),
            ledger_root: "11".repeat(64),
            irmin_commit: "22".repeat(64),
        }
    }
    #[test]
    fn retained_gateway_cache_has_exact_identity_fixed_ttl_and_count_bounds() {
        let now = Instant::now();
        let mut cache = Cache::<u64>::default();
        let first = identity(0);
        let scope = Provenance::Canonical(first.clone()).id();
        cache.remember(first.clone(), 0, now).unwrap();
        cache
            .remember(first, 9, now + Duration::from_secs(119))
            .unwrap();
        assert_eq!(
            cache.get(&scope, now + Duration::from_secs(119)).unwrap().1,
            0
        );
        assert!(cache.get(&scope, now + Duration::from_secs(120)).is_none());
        for epoch in 0..33 {
            cache
                .remember(identity(epoch), epoch, now + Duration::from_millis(epoch))
                .unwrap();
        }
        assert_eq!(cache.entries.len(), 32);
        assert!(cache.get(&scope, now + Duration::from_secs(1)).is_none());
        let scope = Provenance::Canonical(identity(32)).id();
        cache.entries.get_mut(&scope).unwrap().identity.chain_id = "foreign".into();
        assert!(cache.get(&scope, now + Duration::from_secs(1)).is_none());
        assert!(cache
            .remember(identity(32), 32, now + Duration::from_secs(1))
            .is_err());
    }
}
