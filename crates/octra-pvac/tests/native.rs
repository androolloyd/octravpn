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
