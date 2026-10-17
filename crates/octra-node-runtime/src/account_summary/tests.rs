use super::{Cache, Root};
use crate::{account_store, state_batch::StateBatch};
use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::{account_pack, state::Account, transaction::RuleMode};
use std::sync::{Arc, Barrier};

fn state() -> StateBatch {
    let mut state = StateBatch::default();
    state.begin().unwrap();
    for (address, balance) in [(b"alice".as_slice(), 17), (b"bob", 0)] {
        account_store::set(
            &mut state,
            address,
            &Account {
                balance: balance.into(),
                ..Account::default()
            },
            RuleMode::Active,
        )
        .unwrap();
    }
    state
        .set(&[b"meta", b"total_supply"], b"20".to_vec())
        .unwrap();
    state
}

#[test]
fn exact_account_root_reuses_validated_summary_across_unrelated_publications() {
    let cache = Cache::default();
    let mut state = state();
    let before = state.snapshot();
    let first = cache.get(&before).unwrap();
    assert_eq!(first.accounts(), 2);
    assert_eq!(first.active_accounts(), 1);
    assert_eq!(first.total_supply(), &17.into());
    state
        .set(&[b"meta", b"total_supply"], b"30".to_vec())
        .unwrap();
    state
        .set(&[b"circles", b"app", b"counter"], b"1".to_vec())
        .unwrap();
    let after = state.snapshot();
    assert_ne!(before.root().unwrap(), after.root().unwrap());
    assert_eq!(
        before.hash_at(&[b"accounts"]).unwrap(),
        after.hash_at(&[b"accounts"]).unwrap()
    );
    assert!(Arc::ptr_eq(&first, &cache.get(&after).unwrap()));
    // Supply metadata remains owned by the exact caller snapshot, never by the
    // summary; a metadata-only cap violation must still reach the RPC checks.
    state
        .set(&[b"meta", b"total_supply"], b"1".to_vec())
        .unwrap();
    let invalid_supply = state.snapshot();
    assert!(Arc::ptr_eq(&first, &cache.get(&invalid_supply).unwrap()));
    assert_eq!(
        invalid_supply.get(&[b"meta", b"total_supply"]),
        Some(b"1".as_slice())
    );
    assert_eq!(
        before.get(&[b"meta", b"total_supply"]),
        Some(b"20".as_slice())
    );
}

#[test]
fn changed_accounts_and_foreign_same_height_snapshots_cannot_reuse_an_old_summary() {
    let cache = Cache::default();
    let mut original = state();
    let old = original.snapshot();
    let first = cache.get(&old).unwrap();
    account_store::set(
        &mut original,
        b"bob",
        &Account {
            balance: 9.into(),
            ..Account::default()
        },
        RuleMode::Active,
    )
    .unwrap();
    let updated = cache.get(&original.snapshot()).unwrap();
    assert!(!Arc::ptr_eq(&first, &updated));
    assert_eq!(updated.total_supply(), &26.into());
    assert_eq!(updated.active_accounts(), 2);
    assert_eq!(first.total_supply(), &17.into());
    // The cache is bounded to one completed root, not a retained history.
    let restored = cache.get(&old).unwrap();
    assert!(!Arc::ptr_eq(&first, &restored));
    assert_eq!(restored.total_supply(), first.total_supply());
    assert!(Root::Tree([1; 64]) != Root::Contents([1; 64]));
}

#[test]
fn packed_corruption_is_rejected_on_cold_load_and_after_a_valid_root_was_cached() {
    let cache = Cache::default();
    let mut state = state();
    let account = Account {
        balance: 4.into(),
        encrypted_balance: Some(
            format!("hfhe_v1|{}", STANDARD.encode(vec![7_u8; 9000])).into_bytes(),
        ),
        ..Account::default()
    };
    account_store::set(&mut state, b"sealed", &account, RuleMode::Active).unwrap();
    let good = state.snapshot();
    let validated = cache.get(&good).unwrap();
    assert_eq!(validated.total_supply(), &21.into());
    let meta = account_pack::meta(
        state
            .get(&[b"accounts", b"sealed", b"cipher", b"meta"])
            .unwrap(),
    )
    .unwrap();
    let part = &meta.parts[0];
    let mut altered = state
        .get(&[b"accounts", b"sealed", b"cipher", b"parts", part])
        .unwrap()
        .to_vec();
    altered[0] ^= 1;
    state
        .set(
            &[b"accounts", b"sealed", b"cipher", b"parts", part],
            altered,
        )
        .unwrap();
    let corrupt = state.snapshot();
    assert!(cache
        .get(&corrupt)
        .unwrap_err()
        .to_string()
        .contains("blob part id differs"));
    assert!(Cache::default().get(&corrupt).is_err());
    assert!(
        Arc::ptr_eq(&validated, &cache.get(&good).unwrap()),
        "refusal cannot install a mismatched summary"
    );
    state
        .remove(&[b"accounts", b"sealed", b"cipher", b"parts", part])
        .unwrap();
    assert!(cache
        .get(&state.snapshot())
        .unwrap_err()
        .to_string()
        .contains("account cipher part is missing"));
}

#[test]
fn account_and_ledger_cipher_validation_is_not_bypassed_by_statistics() {
    let cache = Cache::default();
    let mut state = state();
    account_store::set(
        &mut state,
        b"bad",
        &Account {
            encrypted_balance: Some(b"unsupported".to_vec()),
            ..Account::default()
        },
        RuleMode::Prior,
    )
    .unwrap();
    assert!(cache
        .get(&state.snapshot())
        .unwrap_err()
        .to_string()
        .contains("ledger cipher format unsupported"));
    state
        .set(&[b"accounts", b"bad", b"data"], b"invalid json".to_vec())
        .unwrap();
    assert!(cache.get(&state.snapshot()).is_err());
}

#[test]
fn concurrent_same_root_cold_reads_publish_one_shared_result() {
    let cache = Cache::default();
    let snapshot = state().snapshot();
    let barrier = Barrier::new(8);
    std::thread::scope(|threads| {
        let readers = (0..8)
            .map(|_| {
                threads.spawn(|| {
                    barrier.wait();
                    cache.get(&snapshot).unwrap()
                })
            })
            .collect::<Vec<_>>();
        let results = readers
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>();
        assert!(results
            .iter()
            .all(|summary| Arc::ptr_eq(summary, &results[0])));
    });
}
