//! Offline setup reads only this node's audited retained state. It cannot
//! publish a serving lease, synchronize the index or authorize spending.
use super::{seed, Index, Limits, Pool, Seed};
use anyhow::{ensure, Result};
use octravpn_core::sealed::Key;
use std::{path::Path, sync::Arc};

impl Index {
    pub(crate) async fn initialize<A: crate::Host>(
        path: &Path,
        key: Key,
        source: Arc<Pool>,
        limits: Limits,
        seed: Option<&Seed>,
        node: &crate::Node<A>,
    ) -> Result<Self> {
        limits.check()?;
        let shared = source.directory.shared.clone();
        ensure!(
            Arc::ptr_eq(&shared, &node.shared),
            "offline index belongs to another node"
        );
        let _operation = node.operations.lock().await;
        let ticket = shared.root_quarantine_ticket();
        shared.with_root_ticket(&ticket, || Ok(()))?;
        let committed = node.retained_view().await?;
        source.directory.check_value_effects(&committed).await?;
        source.directory.canonical_time(&committed).await?;
        source.state(committed.state())?;
        let index = if let Some(seed) = seed {
            let (head, index) = seed::authenticate_at(&source, seed, limits, &committed).await?;
            Self::create_seeded(path, key, source, seed, limits, head, index).await?
        } else {
            let base = Self::baseline_at(&source, committed.head()).await?;
            Self::create_empty(path, key, source, limits, base).await?
        };
        ensure!(
            node.head().await? == *committed.head(),
            "offline index retained head changed"
        );
        shared.with_root_ticket(&ticket, || Ok(()))?;
        Ok(index)
    }
}
