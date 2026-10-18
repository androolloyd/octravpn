use super::SenderAccount;
use octra_node_protocol::{
    state::Account,
    transaction::{Nonce, RuleMode},
};
use octra_node_runtime::{account_store, private_balance::AccountView, state_batch::StateBatch};

fn state(cipher: Option<&[u8]>) -> (StateBatch, Account) {
    let account = Account {
        balance: 7.into(),
        nonce: Nonce::new(3).unwrap(),
        encrypted_balance: cipher.map(<[u8]>::to_vec),
        ..Account::default()
    };
    let mut state = StateBatch::default();
    state.begin().unwrap();
    account_store::set(&mut state, b"owner", &account, RuleMode::Prior).unwrap();
    (state, account)
}

#[test]
fn sender_account_view_ignores_unrelated_corruption_without_becoming_an_execution_ledger() {
    let (mut state, owner) = state(None);
    state
        .set(&[b"accounts", b"unrelated", b"data"], b"{".to_vec())
        .unwrap();
    let snapshot = state.snapshot();
    let captured = SenderAccount::load(&snapshot, b"owner").unwrap();
    assert_eq!(captured.account(b"owner"), Some(&owner));
    assert!(captured.account(b"unrelated").is_none());
    assert!(captured.account(b"missing").is_none());
    // The partial capability grants no execution/supply authority. The exact
    // same snapshot must still fail the authoritative full-ledger load.
    assert!(account_store::ledger(&StateBatch::from_snapshot(snapshot)).is_err());
}

#[test]
fn sender_account_view_normalizes_legacy_zero_without_mutating_its_captured_snapshot() {
    let (state, mut owner) = state(Some(b"0"));
    let snapshot = state.snapshot();
    let raw = snapshot
        .get(&[b"accounts", b"owner", b"data"])
        .unwrap()
        .to_vec();
    let captured = SenderAccount::load(&snapshot, b"owner").unwrap();
    owner.encrypted_balance = None;
    assert_eq!(captured.account(b"owner"), Some(&owner));
    let full = account_store::ledger(&StateBatch::from_snapshot(snapshot.clone())).unwrap();
    assert_eq!(full.account(b"owner"), captured.account(b"owner"));
    assert_eq!(
        snapshot.get(&[b"accounts", b"owner", b"data"]),
        Some(raw.as_slice())
    );
    assert_eq!(
        account_store::load(&state, b"owner")
            .unwrap()
            .unwrap()
            .encrypted_balance
            .as_deref(),
        Some(b"0".as_slice())
    );
}

#[test]
fn sender_account_view_refuses_the_requested_unsupported_cipher_prefix() {
    let (state, _) = state(Some(b"unsupported cipher"));
    let snapshot = state.snapshot();
    let error = SenderAccount::load(&snapshot, b"owner").err().unwrap();
    assert_eq!(error, account_store::ledger(&state).unwrap_err());
    assert_eq!(
        error.0,
        "ledger cipher format unsupported; run fhe_audit on a data copy"
    );
}
