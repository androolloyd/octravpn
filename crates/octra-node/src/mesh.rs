//! Mesh availability follows the canonical service publication. This gate
//! grants neither a payment plan nor access beyond the operator's mesh policy.
use crate::Shared;
use std::sync::Arc;

pub(crate) fn admission(shared: Arc<Shared>) -> Arc<dyn Fn() -> bool + Send + Sync> {
    Arc::new(move || {
        shared
            .current()
            .is_ok_and(|serving| !serving.revocation.is_revoked())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Host, Node, RootEvidence};
    use octra_browser::application::UnavailableHost;
    use octra_exex::{sqlite::SqliteCheckpoints, ChainIdentity, StateRoot};
    use octra_node_protocol::epoch_index;
    use octra_node_runtime::{
        canonical::{CanonicalStore, Head, ReliefSource},
        circle::{CircleRuntime, Error, HfheBackend},
        finality::{EpochRules, ValidatorHistory},
        state_batch::StateBatch,
    };
    use serde_json::Value;

    struct GenesisHost;
    #[async_trait::async_trait]
    impl ValidatorHistory for GenesisHost {
        async fn resolve(&self, _: &Head, _: u64, _: ReliefSource) -> Result<EpochRules, String> {
            Err("genesis-only mesh fixture has no successor authority".into())
        }
    }
    impl Host for GenesisHost {}

    struct NoHfhe;
    impl HfheBackend for NoHfhe {
        fn call(&self, _: &Value) -> Result<Value, Error> {
            panic!("mesh admission must not invoke HFHE")
        }
    }

    async fn node(directory: &std::path::Path) -> Node<GenesisHost> {
        let mut state = StateBatch::default();
        state.begin().unwrap();
        state.set(&[b"meta", b"last_epoch"], b"0".to_vec()).unwrap();
        state.acknowledge_commit().unwrap();
        let (_, index) =
            epoch_index::next_root(hex::encode(epoch_index::genesis_root()).as_bytes(), 0, &[])
                .unwrap();
        let root = epoch_index::folded_state_root(
            hex::encode(state.root().unwrap()).as_bytes(),
            hex::encode(index).as_bytes(),
        )
        .unwrap();
        let store = CanonicalStore::create(
            &directory.join("canonical.db"),
            ChainIdentity::genesis("mesh-serving-gate", StateRoot(root)),
            state.snapshot(),
            0,
        )
        .await
        .unwrap();
        let checkpoints = SqliteCheckpoints::open(&directory.join("exex.db"))
            .await
            .unwrap();
        Node::open(
            store,
            GenesisHost,
            CircleRuntime::new(Arc::new(NoHfhe)),
            Arc::new(UnavailableHost),
            Arc::new(checkpoints),
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn retained_mesh_callback_tracks_node_publication_and_root_recovery() {
        let directory = tempfile::tempdir().unwrap();
        let node = node(directory.path()).await;
        let guard = admission(node.shared.clone());
        let head = node.head().await.unwrap();
        assert!(!guard(), "retained history alone cannot admit mesh clients");

        assert!(node.resume().await.unwrap());
        assert!(guard());
        let previous = node.shared.current().unwrap();
        node.suspend(crate::published::PUBLICATION_REASON);
        assert!(previous.revocation.is_revoked());
        assert!(node.shared.gateway_view().is_ok());
        assert!(!guard(), "gateway read grace must not grant mesh admission");

        assert!(node.resume_at(&head).await.unwrap());
        assert!(
            guard(),
            "the original callback must follow the new publication"
        );
        assert!(node
            .quarantine_root_at(&head, "peer_root_mismatch_at_head 0")
            .await
            .unwrap());
        assert!(!guard());
        assert!(!node.resume_at(&head).await.unwrap());
        assert!(!guard());
        let ticket = node.root_quarantine_ticket();
        assert!(node
            .clear_root_quarantine_at(&head, &ticket, RootEvidence::InSync, true)
            .await
            .unwrap());
        assert!(!guard(), "clearing quarantine is not a service publication");
        assert!(node.resume_at(&head).await.unwrap());
        assert!(guard());
        assert_eq!(node.head().await.unwrap(), head);

        node.shared.current().unwrap().revocation.revoke();
        assert!(!guard(), "a revoked publication cannot admit mesh clients");
    }
}
