use octra_pvac::{keygen, Cipher, Math, PublicKey, SecretKey};

#[test]
fn imported_keys_and_ciphertexts_preserve_arithmetic_and_commitments() {
    let (public, secret) = keygen(&[17; 32]).unwrap();
    let pk = PublicKey::from_bytes(&public.to_bytes().unwrap()).unwrap();
    let sk = SecretKey::from_bytes(&secret.to_bytes().unwrap()).unwrap();
    let a = public.encrypt(&secret, 123, &[29; 32]).unwrap();
    let b = pk.encrypt(&sk, 456, &[31; 32]).unwrap();
    let a_imported = Cipher::from_bytes(&a.to_bytes().unwrap(), true).unwrap();
    assert_eq!(
        public.commitment(&a).unwrap(),
        pk.commitment(&a_imported).unwrap()
    );
    assert_eq!(
        pk.decrypt(&sk, &pk.add(&a_imported, &b).unwrap()).unwrap(),
        579
    );
    assert_eq!(
        pk.decrypt(&sk, &pk.sub(&b, &a_imported).unwrap()).unwrap(),
        333
    );
    assert_eq!(
        pk.decrypt(&sk, &pk.scale(&a_imported, -2, Math::Active).unwrap())
            .unwrap(),
        -246
    );
    assert_eq!(
        pk.decrypt(
            &sk,
            &pk.add_const(&a_imported, 1000, 0, Math::Active).unwrap()
        )
        .unwrap(),
        1123
    );
    assert!(PublicKey::from_bytes(b"bad").is_err());
    assert!(SecretKey::from_bytes(b"bad").is_err());
    assert!(Cipher::from_bytes(b"bad", true).is_err());
}

#[test]
fn proof_key_binding_and_power_checks_match_rust_on_valid_and_mutated_keys() {
    let (native, _) = keygen(&[23; 32]).unwrap();
    let rust = octra_hfhe::keys::PublicKey::from_bytes(&native.to_bytes().unwrap()).unwrap();
    assert_eq!(
        native.proof_key_digest().unwrap(),
        octra_hfhe::proof::key::digest(&rust)
    );
    assert!(native.powers_ok().unwrap() && rust.powers_ok());
    let mut raw = rust.to_raw_bytes();
    // v5 ends in 337 field powers followed by commitment(32) and profile(1).
    let first_power = raw.len() - 33 - 337 * 16;
    raw[first_power] = 2;
    let changed_rust = octra_hfhe::keys::PublicKey::from_bytes(&raw).unwrap();
    // The bridge caps transport bytes; a default key's expanded raw image is
    // larger. Feed it the same compressed wire format as the valid control.
    let changed_native = PublicKey::from_bytes(&changed_rust.to_bytes().unwrap()).unwrap();
    assert!(!changed_native.powers_ok().unwrap() && !changed_rust.powers_ok());
    assert_eq!(
        changed_native.proof_key_digest().unwrap(),
        octra_hfhe::proof::key::digest(&changed_rust)
    );
    assert_ne!(
        changed_native.proof_key_digest().unwrap(),
        native.proof_key_digest().unwrap()
    );
}
