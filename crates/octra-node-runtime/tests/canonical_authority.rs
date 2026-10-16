//! Signed publication using canonical membership. Epoch state changes are
//! explicit fixtures; transaction execution and live consensus have other tests.
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use octra_exex::{ChainIdentity, CommittedEpochSource, Sequence, StateRoot};
use octra_node_protocol::{
    consensus::{
        codec::Wire, engine, hash, journal::JournalOwner, reward_attribution, EpochHeader,
        Finalize, Validator, ValidatorSet, Vote, VoteType,
    },
    control_payload::ValidatorUpdate,
    epoch_index,
    transaction::address_from_public_key,
    transaction_policy::Profile,
    validator::{admission::Member, update},
};
use octra_node_runtime::{
    canonical::{CanonicalStore, Head, ReliefSource},
    finality::{ExecutedEpoch, Publisher, ValidatorHistory},
    state_batch::StateBatch,
    validator_history::{Authority, Environment, ReceiptPolicy},
};
use std::sync::Arc;
fn root(base: Option<&Head>, state: &StateBatch) -> [u8; 32] {
    let prior = base.map_or_else(
        || hex::encode(epoch_index::genesis_root()),
        |b| b.index_root.clone(),
    );
    let (_, index) = epoch_index::next_root(
        prior.as_bytes(),
        base.map_or(0, |b| b.cursor.epoch.0 as i64 + 1),
        &[],
    )
    .unwrap();
    epoch_index::folded_state_root(
        hex::encode(state.root().unwrap()).as_bytes(),
        hex::encode(index).as_bytes(),
    )
    .unwrap()
}

fn key(id: u8) -> SigningKey {
    SigningKey::from_bytes(&[id; 32])
}
fn member(id: u8) -> Validator {
    let pubkey = key(id).verifying_key().to_bytes().to_vec();
    Validator {
        address: address_from_public_key(STANDARD.encode(&pubkey).as_bytes()),
        pubkey,
    }
}
fn environment() -> Environment {
    Environment {
        current: Some(
            (1..=4)
                .map(|id| {
                    let v = member(id);
                    [
                        v.address.as_slice(),
                        b":",
                        STANDARD.encode(v.pubkey).as_bytes(),
                    ]
                    .concat()
                })
                .collect::<Vec<_>>()
                .join(&b','),
        ),
        ..Environment::default()
    }
}
fn authority(store: &CanonicalStore, journal: &JournalOwner) -> Authority {
    Authority::new(
        store.reader(),
        environment(),
        ReceiptPolicy::new(
            Some(b"5"),
            &Profile::from_values(Some(b"devnet_private_v1"), None, None),
            Some(b"6000"),
        ),
        journal.clone(),
    )
}
fn certificate(
    base: &Head,
    state: &StateBatch,
    chain: &str,
    ids: std::ops::RangeInclusive<u8>,
) -> (Finalize, ExecutedEpoch) {
    let members = ids.clone().map(member).collect::<Vec<_>>();
    let proposer = members[0].address.clone();
    let keys = members
        .iter()
        .map(|v| (v.address.clone(), STANDARD.encode(&v.pubkey).into_bytes()))
        .collect::<Vec<_>>();
    let executed = ExecutedEpoch {
        epoch_observation: None,
        metrics: octra_node_protocol::metrics::Epoch::default(),
        vm_receipts: std::collections::BTreeMap::default(),
        state: state.snapshot(),
        transactions: vec![],
        consensus_receipts: vec![],
        reward_source: reward_attribution::to_source(&reward_attribution::full_set(
            &proposer, &keys,
        ))
        .unwrap(),
        date: base.cursor.epoch.0 as i64 + 1,
        message: b"authority fixture".to_vec(),
    };
    let epoch = base.cursor.epoch.0 + 1;
    let mut f = Finalize {
        chain_id: chain.as_bytes().to_vec(),
        epoch_id: epoch as i64,
        commit_round: 0,
        header: EpochHeader {
            proto_version: 4,
            chain_id: chain.as_bytes().to_vec(),
            epoch_id: epoch as i64,
            prev_state_root: base.cursor.state_root.0.to_vec(),
            proposed_state_root: root(Some(base), state).to_vec(),
            tx_list_hash: engine::tx_list_hash_for_header(&[]).to_vec(),
            receipt_root: hash::receipt_root(&[]).unwrap().to_vec(),
            parent_commit_hash: vec![0; 32],
            creator_addr: proposer,
            txid_hi: base.txid_hi,
            ts: f64::from(u32::try_from(epoch).unwrap()) * 10.,
        },
        proposal_id: vec![],
        precommits: vec![],
        parent_commit: None,
    };
    f.proposal_id = hash::proposal_id(&f.header).unwrap().to_vec();
    f.precommits = ids
        .map(|id| {
            let mut v = Vote {
                chain_id: f.chain_id.clone(),
                epoch_id: f.epoch_id,
                round: 0,
                vote_type: VoteType::Precommit,
                proposal_id: f.proposal_id.clone(),
                validator: member(id).address,
                signature: vec![],
            };
            v.signature = key(id)
                .sign(&hash::vote_sign_bytes(&v).unwrap())
                .to_bytes()
                .to_vec();
            v
        })
        .collect();
    (f, executed)
}

#[tokio::test]
async fn canonical_authority_activates_and_reaudits_signed_history_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.db");
    let journal = JournalOwner::open(dir.path()).unwrap();
    let pending = ValidatorUpdate::make_weighted(
        0,
        64,
        &(2..=5)
            .map(|id| {
                let v = member(id);
                Member {
                    address: v.address,
                    pubkey: v.pubkey,
                    weight: 1.into(),
                }
            })
            .collect::<Vec<_>>(),
    )
    .unwrap()
    .to_bytes();
    let mut state = StateBatch::default();
    state.begin().unwrap();
    state
        .set(&[b"meta", update::PENDING_KEY], pending.clone())
        .unwrap();
    state.acknowledge_commit().unwrap();
    let chain =
        ChainIdentity::genesis("canonical-authority-fixture", StateRoot(root(None, &state)));
    let mut store = Arc::new(
        CanonicalStore::create(&path, chain.clone(), state.snapshot(), 0)
            .await
            .unwrap(),
    );
    let mut publisher = Publisher::open(store.clone(), authority(&store, &journal))
        .await
        .unwrap();
    for epoch in 1..=66 {
        let (base, mut next) = store.snapshot().await.unwrap();
        next.begin().unwrap();
        let rules = authority(&store, &journal)
            .resolve(&base, epoch, ReliefSource::Journal)
            .await
            .unwrap();
        assert_eq!(rules.validators.weighted, epoch >= 64);
        assert_eq!(rules.receipts.required, epoch >= 5);
        assert!(rules.receipts.crypto_active);
        assert_eq!(rules.receipts.stealth_minimum, 6000.into());
        if epoch == 64 {
            next.set(&[b"meta", update::ACTIVE_KEY], pending.clone())
                .unwrap();
            next.remove(&[b"meta", update::PENDING_KEY]).unwrap();
        }
        let ids = if epoch < 64 { 1..=4 } else { 2..=5 };
        let (cert, executed) = certificate(&base, &next, &chain.chain_id, ids);
        if epoch == 64 {
            let (stale, _) = certificate(&base, &next, &chain.chain_id, 1..=4);
            assert!(publisher
                .verify_certificate(&base, &stale.encode().unwrap())
                .await
                .is_err());
        }
        if matches!(epoch, 1 | 64) {
            drop(
                publisher
                    .prepare(&base, &cert.encode().unwrap(), executed.clone())
                    .await
                    .unwrap(),
            );
            assert_eq!(store.head().await.unwrap(), base);
            assert!(store
                .source()
                .load(Sequence(epoch))
                .await
                .unwrap()
                .is_none());
            assert!(matches!(
                store.reader().relief_after(&base).await.unwrap(),
                ReliefSource::Journal
            ));
        }
        let committed = publisher
            .prepare(&base, &cert.encode().unwrap(), executed)
            .await
            .unwrap()
            .commit()
            .await
            .unwrap();
        assert_eq!(store.source().head().await.unwrap(), committed.cursor);
        assert!(matches!(
            store.reader().relief_after(&base).await.unwrap(),
            ReliefSource::Committed(None)
        ));
        if epoch == 1 {
            // Committed absence must not reconsult a changed/corrupt live log.
            let log = dir.path().join("relief_log");
            std::fs::create_dir_all(&log).unwrap();
            let mark = log.join(octra_node_protocol::consensus::relief_log::name(0));
            std::fs::write(&mark, b"corrupt journal").unwrap();
            publisher.audit().await.unwrap();
            let (head, state) = store.snapshot().await.unwrap();
            let (next, _) = certificate(&head, &state, &chain.chain_id, 1..=4);
            assert!(publisher
                .verify_certificate(&head, &next.encode().unwrap())
                .await
                .is_err());
            std::fs::remove_file(mark).unwrap();
        }
        if matches!(epoch, 1 | 63 | 64 | 66) {
            drop(publisher);
            drop(store);
            store = Arc::new(CanonicalStore::open(&path, &chain).await.unwrap());
            publisher = Publisher::open(store.clone(), authority(&store, &journal))
                .await
                .unwrap();
            assert_eq!(
                publisher
                    .record(Sequence(1))
                    .await
                    .unwrap()
                    .finality
                    .unwrap()
                    .validator_set,
                ValidatorSet::unweighted((1..=4).map(member).collect())
            );
        }
    }
    // A committed epoch without its archive entry cannot fall back to the log.
    let db = sqlx::SqlitePool::connect(&format!("sqlite:{}", path.display()))
        .await
        .unwrap();
    sqlx::query("DELETE FROM node_epoch_relief WHERE sequence=1")
        .execute(&db)
        .await
        .unwrap();
    assert!(publisher.audit().await.is_err());
    assert!(Publisher::open(store.clone(), authority(&store, &journal))
        .await
        .is_err());
}
