//! Real actor thread propagation, independent of the caller's crypto TLS scope.
#[path = "common/crypto_worker.rs"]
mod crypto_worker;
use octra_node_protocol::transaction::RuleMode;
use octra_node_runtime::{
    crypto_worker::{Limits, Pool},
    private_account_rpc::{migration_status, MigrationRules},
    pvac_status_actor::{Error, Query, Service},
};
use std::sync::Arc;

fn query(scope: &[u8]) -> Query {
    Query {
        scope: scope.to_vec(),
        address: b"viewer".to_vec(),
        key_hash: None,
        cipher: Arc::from(b"hfhe_v1|eA==".as_slice()),
    }
}
fn rules() -> MigrationRules {
    MigrationRules {
        epoch: 1,
        owner: RuleMode::Prior,
        cipher: RuleMode::Prior,
        proof: RuleMode::Prior,
        math: false,
    }
}
#[tokio::test]
async fn isolated_actor_preserves_classification_and_authenticated_cache_scope() {
    let local = Service::default();
    let isolated = Service::isolated(crypto_worker::pool());
    let mut outputs = vec![];
    for service in [&local, &isolated] {
        let mut rows = vec![];
        for scope in [b"first".as_slice(), b"first", b"next"] {
            let result = service
                .query(query(scope), Box::new(|| Ok(Some(b"invalid-key".to_vec()))))
                .await
                .unwrap();
            rows.push(migration_status(b"viewer", b"hfhe_v1|eA==", result, rules(), None).unwrap());
        }
        assert_eq!(service.stats().await.cache_entries, 4);
        outputs.push(rows);
        service.shutdown().await;
        assert!(matches!(
            service.query(query(b"first"), Box::new(|| Ok(None))).await,
            Err(Error::Busy)
        ));
    }
    assert_eq!(outputs[0], outputs[1]);
}
#[tokio::test]
async fn configured_actor_cannot_fall_back_to_parent_crypto() {
    let file = tempfile::NamedTempFile::new().unwrap();
    // A regular file accepted as an explicit capability, but never executable.
    // Local classification would succeed with Malformed, concealing this error.
    let pool = Pool::open(
        file.path(),
        Limits {
            capacity: 1,
            timeout_seconds: 1.,
            rss_mb: 64,
        },
    )
    .unwrap();
    let service = Service::isolated(pool);
    assert!(matches!(
        service
            .query(
                query(b"source"),
                Box::new(|| Ok(Some(b"invalid-key".to_vec())))
            )
            .await,
        Err(Error::ReadFailed)
    ));
    assert_eq!(service.stats().await.cache_entries, 0);
    service.shutdown().await;
}
