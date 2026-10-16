use super::*;
use crate::{
    account_store,
    private_crypto::{self, ResultPolicy},
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use octra_hfhe::scalar::ScalarRule;
use octra_node_protocol::{
    state::{Account, Ledger},
    transaction::{Nonce, RuleMode},
};
use serde_json::{json, Value};
fn raw(value: &Value) -> Vec<u8> {
    STANDARD.decode(value.as_str().unwrap()).unwrap()
}
fn fixture() -> (
    Ledger,
    StateBatch,
    Transaction,
    private_balance::Profile,
    Vec<u8>,
    Vec<u8>,
) {
    let data: Value =
        serde_json::from_slice(include_bytes!("../../tests/fixtures/private-crypto.json")).unwrap();
    let cases = data["cases"].as_array().unwrap();
    let amount = cases
        .iter()
        .find(|c| {
            c["input"]["name"] == "genuine amount proof"
                && c["input"]["strict"] == true
                && c["input"]["math"] == true
        })
        .unwrap();
    let input = &amount["input"];
    let range = cases
        .iter()
        .find(|c| {
            c["input"]["name"] == "genuine remainder proof"
                && c["input"]["strict"] == true
                && c["input"]["math"] == true
                && c["expected"]["ok"] == true
        })
        .unwrap();
    let public = raw(&input["public"]);
    let other = raw(&cases
        .iter()
        .find(|c| c["input"]["name"] == "public mutation 2")
        .unwrap()["input"]["public"]);
    assert!(private_crypto::load_pubkey(&other).is_ok());
    let delta = raw(&input["delta"]);
    let pk = private_crypto::load_pubkey(&public).unwrap();
    let cipher = private_crypto::decode_cipher(&delta, false, true).unwrap();
    let commitment = STANDARD.encode(cipher.commitment(&pk));
    let proof = raw(&range["input"]["range"]);
    let account = Account {
        balance: 10000.into(),
        public_key: None,
        encrypted_balance: Some(raw(&input["current"])),
        ..Default::default()
    };
    let mut state = StateBatch::default();
    state.begin().unwrap();
    account_store::set(&mut state, b"alice", &account, RuleMode::Prior).unwrap();
    let ledger = Ledger::from_accounts([(b"alice".to_vec(), account)].into()).unwrap();
    let tx=Transaction{from:b"alice".to_vec(),to:b"stealth".to_vec(),amount:0.into(),nonce:Nonce::new(1).unwrap(),ou:2.into(),timestamp:1.,signature:b"fixture".to_vec(),public_key:None,message:None,op_type:OpType::Stealth,encrypted_data:Some(serde_json::to_vec(&json!({"version":5,"delta_cipher":std::str::from_utf8(&delta).unwrap(),"commitment":commitment,"range_proof_delta":std::str::from_utf8(&proof).unwrap(),"range_proof_balance":std::str::from_utf8(&proof).unwrap(),"eph_pub":"eph","stealth_tag":"tag","enc_amount":"encrypted","claim_pub":"ab".repeat(32),"amount_commitment":std::str::from_utf8(&raw(&input["commitment"])).unwrap(),"send_zero_proof":std::str::from_utf8(&raw(&input["proof"])).unwrap()})).unwrap())};
    (
        ledger,
        state,
        tx,
        private_balance::Profile {
            fields: RuleMode::Active,
            strict: true,
            math: ScalarRule::Wide,
            result: ResultPolicy::Recoverable,
        },
        public,
        other,
    )
}
#[test]
fn actual_range_cache_binds_every_profile_field_key_transaction_and_source() {
    let (ledger, _, tx, profile, key, other_key) = fixture();
    let binding = CacheBinding::preverify(&ledger, &tx, profile, &key).unwrap();
    let current = ledger
        .account(b"alice")
        .unwrap()
        .encrypted_balance
        .as_deref()
        .unwrap();
    // The proof is genuinely valid for remainder13, and genuinely false for
    // delta7. No synthetic Ready boolean can promote the false result.
    assert_eq!(
        binding.results(&tx, profile, current, &key),
        Some((false, true))
    );
    assert_eq!(binding.results(&tx, profile, current, &other_key), None);
    for changed in [
        private_balance::Profile {
            fields: RuleMode::Prior,
            ..profile
        },
        private_balance::Profile {
            result: ResultPolicy::Legacy,
            ..profile
        },
        private_balance::Profile {
            strict: false,
            ..profile
        },
        private_balance::Profile {
            math: ScalarRule::Prior,
            ..profile
        },
    ] {
        assert_eq!(binding.results(&tx, changed, current, &key), None);
    }
    let mut other = tx.clone();
    other.nonce = Nonce::new(2).unwrap();
    assert_eq!(binding.results(&other, profile, current, &key), None);
    assert_eq!(
        binding.results(&tx, profile, b"different source", &key),
        None
    );
}
#[test]
fn unverified_preparation_or_ready_status_never_overrides_a_false_range_proof() {
    let (mut ledger, mut state, tx, profile, key, _) = fixture();
    let before = state.root().unwrap();
    let account = ledger.account(b"alice").unwrap().to_json_bytes();
    let prepared =
        private_transfer::prepare_stealth(&ledger, &state, &tx, profile, || Ok(Some(key.clone())))
            .unwrap();
    assert_eq!(
        prepared.current_cipher(),
        ledger
            .account(b"alice")
            .unwrap()
            .encrypted_balance
            .as_deref()
            .unwrap()
    );
    let binding = CacheBinding::preverify(&ledger, &tx, profile, &key).unwrap();
    let hash = hex::encode(tx.hash().unwrap());
    let mut epoch = Epoch::new(
        Deferred::default(),
        [(hash.clone(), Preverify::Ready)].into(),
        32,
        32,
        3,
        false,
    );
    epoch.ready.insert(hash, binding);
    let effect = epoch
        .process(
            &tx,
            &mut ledger,
            &mut state,
            private_key::Policy {
                balance: profile,
                owner: RuleMode::Prior,
                cipher: RuleMode::Prior,
            },
            1,
            None,
            || Ok(Some(key)),
            |_, _| Ok(true),
            |_| Ok(()),
        )
        .unwrap();
    assert!(
        matches!(effect,Completion::Rejected(Rejection{ref tag,..})if tag=="bad_range_proof_delta")
    );
    assert_eq!(state.root().unwrap(), before);
    assert_eq!(ledger.account(b"alice").unwrap().to_json_bytes(), account);
}
