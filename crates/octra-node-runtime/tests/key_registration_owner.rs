//! Real keyed owner proof through the private key-registration verifier and
//! atomic application. Compact deterministic keys are local test material.
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signer as _, SigningKey};
use octra_hfhe::{
    encrypt,
    keys::{keygen_from_seed, Params, PublicKey},
    proof::zero::{make_bound_keyed, BoundProfile},
    scalar::{Scalar, ScalarRule},
};
use octra_node_protocol::{
    state::{Account, Ledger},
    transaction::{address_from_public_key, Nonce, OpType, RuleMode, Transaction},
};
use octra_node_runtime::{
    account_store, admission,
    private_balance::{Error, Profile},
    private_crypto::{encode_cipher, ResultPolicy},
    private_key::{self, Policy},
    state_batch::StateBatch,
};
use rand::{rngs::StdRng, SeedableRng as _};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};

fn policy(keyed: bool) -> Policy {
    Policy {
        balance: Profile {
            keyed,
            registered: true,
            fields: RuleMode::Active,
            strict: true,
            math: ScalarRule::Wide,
            result: ResultPolicy::Recoverable,
        },
        owner: RuleMode::Active,
        cipher: RuleMode::Active,
    }
}
fn transaction(key: &SigningKey, payload: &Value) -> Transaction {
    let public = STANDARD.encode(key.verifying_key().as_bytes()).into_bytes();
    let address = address_from_public_key(&public);
    let mut tx = Transaction {
        from: address.clone(),
        to: address,
        amount: 0.into(),
        nonce: Nonce::new(1).unwrap(),
        ou: 1.into(),
        timestamp: 1.,
        signature: vec![],
        public_key: Some(public),
        message: None,
        op_type: OpType::KeySwitch,
        encrypted_data: Some(serde_json::to_vec(payload).unwrap()),
    };
    tx.signature = STANDARD
        .encode(key.sign(&tx.signing_bytes().unwrap()).to_bytes())
        .into_bytes();
    admission::signature(&tx, tx.public_key.as_deref()).unwrap();
    tx
}
fn rejected_before_key_lookup(ledger: &Ledger, tx: &Transaction, prefix: &[u8]) {
    let result = private_key::verify::<Vec<u8>>(ledger, tx, policy(true), 1, None, || {
        panic!("invalid owner proof must fail before reading the previous account key")
    });
    match result {
        Err(Error::Rejected(failure)) => {
            assert_eq!(failure.tag, "key_switch_rejected");
            assert!(
                failure.reason.starts_with(prefix),
                "{}",
                String::from_utf8_lossy(&failure.reason)
            );
        }
        Err(error) => panic!("unexpected operational failure: {error}"),
        Ok(_) => panic!("invalid owner proof accepted"),
    }
}
#[test]
fn active_registration_binds_owner_to_sender_and_complete_key() {
    let params = Params {
        basis: 126,
        m_bits: 65,
        n_bits: 17,
        h_col_weight: 13,
        x_col_weight: 7,
        error_weight: 2,
        lpn_n: 65,
        lpn_t: 127,
        noise_entropy_bits: 0.,
        ..Params::default()
    };
    let (public, secret) = keygen_from_seed(params, &[0x31; 32]).unwrap();
    assert!(public.supports_alias_rejection() && public.powers_ok());
    let signer = SigningKey::from_bytes(&[1; 32]);
    let other = SigningKey::from_bytes(&[2; 32]);
    let sender = address_from_public_key(
        STANDARD
            .encode(signer.verifying_key().as_bytes())
            .as_bytes(),
    );
    let other_address =
        address_from_public_key(STANDARD.encode(other.verifying_key().as_bytes()).as_bytes());
    let blind: [u8; 32] =
        Sha256::digest([b"octra:pvac:key_owner\0".as_slice(), &sender].concat()).into();
    let cipher = encrypt::value_seeded(&public, &secret, 0, &[0x52; 32]).unwrap();
    assert!(cipher.is_wrapped_scalar());
    let proof = make_bound_keyed(
        &public,
        &secret,
        &cipher,
        0,
        Scalar::from_bytes_raw(&blind),
        BoundProfile::Standard,
        ScalarRule::Wide,
        true,
        &mut StdRng::seed_from_u64(42),
    )
    .unwrap();
    let key_bytes = public.to_bytes().unwrap();
    let payload = json!({
        "new_pubkey": STANDARD.encode(&key_bytes),
        "aes_kat": hex::encode(octra_hfhe::seeded_rng::aes_kat()),
        "owner_cipher": String::from_utf8(encode_cipher(&cipher).unwrap()).unwrap(),
        "owner_proof": format!("zkzp_v2|{}", STANDARD.encode(proof.to_raw_bytes().unwrap())),
    });
    let accounts = [sender.clone(), other_address]
        .into_iter()
        .map(|address| {
            (
                address,
                Account {
                    balance: 10.into(),
                    encrypted_balance: None,
                    ..Account::default()
                },
            )
        })
        .collect();
    let mut ledger = Ledger::from_accounts(accounts).unwrap();
    let before = ledger.accounts().clone();
    let tx = transaction(&signer, &payload);
    let verified =
        private_key::verify(&ledger, &tx, policy(true), 1, None, || Ok(None::<Vec<u8>>)).unwrap();
    assert_eq!(verified.current_cipher(), b"0");
    assert_eq!(verified.public_key(), key_bytes);
    assert_eq!(ledger.accounts(), &before);

    // The same key, cipher and valid proof cannot be registered by a different
    // correctly signed sender: its deterministic ownership commitment differs.
    rejected_before_key_lookup(
        &ledger,
        &transaction(&other, &payload),
        b"key ownership proof failed: ",
    );
    let mut missing = payload.clone();
    missing.as_object_mut().unwrap().remove("owner_proof");
    rejected_before_key_lookup(
        &ledger,
        &transaction(&signer, &missing),
        b"key ownership proof is required",
    );

    // Substitution of another well-formed, cyclic public key still fails the
    // bound owner proof; the rejection is not a malformed-key shortcut.
    let (substitute, _) = keygen_from_seed(params, &[0x32; 32]).unwrap();
    assert!(substitute.powers_ok());
    let mut changed = payload;
    changed["new_pubkey"] = json!(STANDARD.encode(substitute.to_bytes().unwrap()));
    rejected_before_key_lookup(
        &ledger,
        &transaction(&signer, &changed),
        b"key ownership proof failed: ",
    );
    let mut malformed = public.to_raw_bytes();
    let power = malformed.len() - 33 - params.basis as usize * 16;
    malformed[power..power + 16].copy_from_slice(&2u128.to_le_bytes());
    assert!(!PublicKey::from_bytes(&malformed).unwrap().powers_ok());
    changed["new_pubkey"] = json!(STANDARD.encode(malformed));
    rejected_before_key_lookup(
        &ledger,
        &transaction(&signer, &changed),
        b"pvac public key powers are not cyclic",
    );
    assert_eq!(ledger.accounts(), &before);

    // Historical registration neither requires nor interprets owner fields.
    missing.as_object_mut().unwrap().remove("owner_cipher");
    assert!(private_key::verify(
        &ledger,
        &transaction(&other, &missing),
        policy(false),
        1,
        None,
        || Ok(None::<Vec<u8>>)
    )
    .is_ok());

    let mut state = StateBatch::default();
    state.begin().unwrap();
    for (address, account) in ledger.accounts() {
        account_store::set(&mut state, address, account, RuleMode::Prior).unwrap();
    }
    let mut persisted = None;
    verified
        .apply(&mut ledger, &mut state, &tx, |bytes| {
            persisted = Some(bytes.to_vec());
            Ok(())
        })
        .unwrap();
    assert_eq!(persisted.as_deref(), Some(key_bytes.as_slice()));
    let digest = hex::encode(Sha256::digest(&key_bytes));
    assert_eq!(
        state.get(&[b"pvac_hashes", &sender]),
        Some(digest.as_bytes())
    );
    let account = ledger.account(&sender).unwrap();
    assert_eq!(account.balance, 9.into());
    assert_eq!(account.nonce, Nonce::new(1).unwrap());
    assert_eq!(account.encrypted_balance, None);
}
