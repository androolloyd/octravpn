use super::account_value;
use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::{
    account_pack,
    state::Account,
    transaction::{Nonce, RuleMode},
};
use octra_node_runtime::{account_store, state_batch::StateBatch};
use serde_json::json;

fn state() -> StateBatch {
    let mut state = StateBatch::default();
    state.begin().unwrap();
    account_store::set(
        &mut state,
        b"alice",
        &Account {
            balance: 12.into(),
            nonce: Nonce::new(3).unwrap(),
            encrypted_balance: Some(
                format!("hfhe_v1|{}", STANDARD.encode(vec![2_u8; 9000])).into_bytes(),
            ),
            ..Account::default()
        },
        RuleMode::Active,
    )
    .unwrap();
    state
}

#[test]
fn targeted_account_read_uses_its_captured_snapshot_without_folding_unrelated_accounts() {
    let mut state = state();
    let old = state.snapshot();
    // An unrelated account must not be hydrated to read Alice's balance.
    state
        .set(&[b"accounts", b"unrelated", b"data"], b"invalid".to_vec())
        .unwrap();
    assert_eq!(
        account_value(&state.snapshot(), "alice", 7).unwrap(),
        json!({"address":"alice","balance":"12","nonce":3,"epoch":7})
    );
    account_store::set(
        &mut state,
        b"alice",
        &Account {
            balance: 19.into(),
            ..Account::default()
        },
        RuleMode::Active,
    )
    .unwrap();
    assert_eq!(
        account_value(&old, "alice", 6).unwrap(),
        json!({"address":"alice","balance":"12","nonce":3,"epoch":6})
    );
    assert_eq!(
        account_value(&state.snapshot(), "alice", 7).unwrap(),
        json!({"address":"alice","balance":"19","nonce":0,"epoch":7})
    );
}

#[test]
fn requested_account_still_refuses_missing_or_corrupt_packed_and_legacy_data() {
    let mut state = state();
    assert!(account_value(&state.snapshot(), "missing", 0).is_err());
    let meta = account_pack::meta(
        state
            .get(&[b"accounts", b"alice", b"cipher", b"meta"])
            .unwrap(),
    )
    .unwrap();
    state
        .remove(&[b"accounts", b"alice", b"cipher", b"parts", &meta.parts[0]])
        .unwrap();
    assert!(account_value(&state.snapshot(), "alice", 0).is_err());
    account_store::set(
        &mut state,
        b"alice",
        &Account {
            encrypted_balance: Some(b"unsupported".to_vec()),
            ..Account::default()
        },
        RuleMode::Prior,
    )
    .unwrap();
    assert!(account_value(&state.snapshot(), "alice", 0).is_err());
    state
        .set(&[b"accounts", b"alice", b"data"], b"invalid".to_vec())
        .unwrap();
    assert!(account_value(&state.snapshot(), "alice", 0).is_err());
}
