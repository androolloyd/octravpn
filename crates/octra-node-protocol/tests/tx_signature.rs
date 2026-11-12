use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::SigningKey;
use octra_node_protocol::{
    oce1::Reader,
    transaction::{address_from_public_key, Nonce, OpType, Transaction},
    tx_signature::{self, Mode},
};
fn transaction(key: &SigningKey) -> Transaction {
    let public = STANDARD.encode(key.verifying_key().as_bytes()).into_bytes();
    Transaction {
        from: address_from_public_key(&public),
        to: b"oct11111111111111111111111111111111111111111111".to_vec(),
        amount: 1.into(),
        nonce: Nonce::new(1).unwrap(),
        ou: 100_000.into(),
        timestamp: 10.,
        signature: vec![],
        public_key: Some(public),
        message: None,
        op_type: OpType::Standard,
        encrypted_data: None,
    }
}
#[test]
fn network_domain_is_exact_and_prevents_cross_network_replay() {
    let key = SigningKey::from_bytes(&[9; 32]);
    let tx = transaction(&key);
    let mode = Mode::Network(b"devnet".to_vec());
    let bytes = mode.bytes(&tx).unwrap();
    let mut reader = Reader::new(&bytes);
    assert_eq!(reader.get_bytes().unwrap(), b"octra:transaction:network");
    assert_eq!(reader.get_bytes().unwrap(), b"devnet");
    assert_eq!(reader.get_bytes().unwrap(), tx.signing_bytes().unwrap());
    reader.finish().unwrap();
    let signed = mode.sign(&tx, &key).unwrap();
    mode.check(&signed).unwrap();
    assert!(Mode::Network(b"mainnet".to_vec()).check(&signed).is_err());
    assert!(!signed.verify(signed.public_key.as_ref().unwrap()));
    let old = Mode::Historical.sign(&tx, &key).unwrap();
    assert!(old.verify(old.public_key.as_ref().unwrap()));
    assert!(mode.check(&old).is_err());
    assert_eq!(
        tx_signature::at_plan(b"devnet", Some(10), 9),
        Mode::Historical
    );
    assert_eq!(tx_signature::at_plan(b"devnet", Some(10), 10), mode);
    for chain in [b"devnet".as_slice(), b"mainnet", b"local"] {
        assert_eq!(tx_signature::at(chain, i64::MAX), Mode::Historical);
    }
    assert!(Mode::Network(vec![]).bytes(&tx).is_err());
}
