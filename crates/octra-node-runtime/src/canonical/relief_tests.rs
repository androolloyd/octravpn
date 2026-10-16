//! Storage qualification with a native-height relief proof. The short raw
//! storage prefix is not a consensus history at the proof's activation height.
use super::*;
use ed25519_dalek::{Signer, SigningKey};
use octra_node_protocol::consensus::{
    hash,
    journal::JournalOwner,
    policy::DEVNET,
    relief::{Decision, Plan},
    relief_log, RoundStep, RoundSync, Validator, ValidatorSet,
};

fn member(id: u8) -> Validator {
    Validator {
        address: format!("validator-{id}").into_bytes(),
        pubkey: SigningKey::from_bytes(&[id; 32])
            .verifying_key()
            .to_bytes()
            .to_vec(),
    }
}
#[tokio::test]
async fn relief_archive_survives_pruning_and_reauthenticates_every_witness() {
    let directory = tempfile::tempdir().unwrap();
    let journal = JournalOwner::open(directory.path()).unwrap();
    let current =
        ValidatorSet::weighted((1..=7).map(|id| (member(id), 1.into())).collect()).unwrap();
    let target =
        ValidatorSet::weighted((1..=6).map(|id| (member(id), 1.into())).collect()).unwrap();
    let fingerprint = "ab".repeat(32);
    let plan = Plan {
        chain_id: DEVNET,
        height: 1_380_000,
        current: &current,
        activate_epoch: 1_380_032,
        target: &target,
        fingerprint: fingerprint.as_bytes(),
    };
    let proof = (1..=5)
        .map(|id| {
            let mut sync = RoundSync {
                chain_id: DEVNET.to_vec(),
                epoch_id: plan.height,
                round: 64,
                step: RoundStep::Precommit,
                request: false,
                validator: member(id).address,
                signature: vec![],
            };
            sync.signature = SigningKey::from_bytes(&[id; 32])
                .sign(&hash::round_sync_sign_bytes(&sync).unwrap())
                .to_bytes()
                .to_vec();
            sync
        })
        .collect::<Vec<_>>();
    let Decision::Apply(mark) = plan.decide(&proof).unwrap() else {
        panic!("valid native relief proof refused");
    };
    journal.keep_relief(mark.clone()).unwrap();
    let state = StateBatch::default().snapshot();
    let (_, index) =
        epoch_index::next_root(hex::encode(epoch_index::genesis_root()).as_bytes(), 0, &[])
            .unwrap();
    let chain = ChainIdentity::genesis(
        String::from_utf8(DEVNET.to_vec()).unwrap(),
        StateRoot(
            epoch_index::folded_state_root(
                hex::encode(state.root().unwrap()).as_bytes(),
                hex::encode(index).as_bytes(),
            )
            .unwrap(),
        ),
    );
    let path = directory.path().join("history.db");
    let store = CanonicalStore::create(&path, chain.clone(), state.clone(), 0)
        .await
        .unwrap();
    let base = store.head().await.unwrap();
    let applied = AppliedEpoch {
        epoch: 1,
        expected_root: execution_root(&base, 1, &state, &[]).unwrap(),
        state,
        transactions: vec![],
        certificate: b"raw storage fixture".to_vec(),
        date: 1,
        message: vec![],
    };
    let mut dropped = store.prepare(&base, applied.clone()).await.unwrap();
    dropped.retain_relief(Some(&mark)).await.unwrap();
    drop(dropped);
    assert!(matches!(
        store.reader().relief_after(&base).await.unwrap(),
        ReliefSource::Journal
    ));
    let mut commit = store.prepare(&base, applied).await.unwrap();
    commit.retain_relief(Some(&mark)).await.unwrap();
    commit.commit().await.unwrap();
    let stored: Vec<u8> = sqlx::query_scalar("SELECT mark FROM node_epoch_relief WHERE sequence=1")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(stored, relief_log::encode(&mark).unwrap());
    journal
        .prune_finalized(plan.activate_epoch - 1)
        .unwrap()
        .relief
        .unwrap();
    assert!(journal.latest_relief(plan.height).unwrap().is_none());
    drop(store);
    let store = CanonicalStore::open(&path, &chain).await.unwrap();
    let ReliefSource::Committed(Some(mut recovered)) =
        store.reader().relief_after(&base).await.unwrap()
    else {
        panic!("archived relief lost");
    };
    assert_eq!(recovered, mark);
    assert_eq!(plan.restore(&recovered).unwrap(), Some(&target));
    recovered.proof[0].signature[0] ^= 1;
    assert!(plan
        .restore(&recovered)
        .unwrap_err()
        .to_string()
        .contains("signature"));
    sqlx::query("UPDATE node_epoch_relief SET mark=? WHERE sequence=1")
        .bind(b"corrupt".as_slice())
        .execute(&store.pool)
        .await
        .unwrap();
    assert!(store.reader().relief_after(&base).await.is_err());
    sqlx::query("UPDATE node_epoch_relief SET mark=zeroblob(?) WHERE sequence=1")
        .bind(relief_log::MAX_WIRE_BYTES as i64 + 1)
        .execute(&store.pool)
        .await
        .unwrap();
    assert!(store
        .reader()
        .relief_after(&base)
        .await
        .err()
        .unwrap()
        .to_string()
        .contains("native record limit"));
}
