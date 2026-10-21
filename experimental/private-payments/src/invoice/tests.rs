use super::*;

fn fixture() -> (SigningKey, Invoice, Consent) {
    let operator = SigningKey::from_bytes(&[7; 32]);
    let invoice = Invoice {
        chain_origin: [1; 32],
        directory_circle: *b"oct1JBUrYbeTQazQ39LQn4ZjnPLHfDpLGXouqon1jZhJfYP",
        operator_key: operator.verifying_key().to_bytes(),
        bond_generation: 2,
        offer: 3,
        tariff_hash: [4; 32],
        receipt_key: SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes(),
        recipient_key: SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes(),
        settlement: Settlement::NativeClaim,
        nonce: [10; 32],
        traffic_class: 1,
        bytes: 2_097_153,
        rate_ou_per_mib: 1_000,
        valid_from_ms: 1_000,
        expires_ms: 60_000,
    };
    let consent = Consent {
        chain_origin: invoice.chain_origin,
        directory_circle: invoice.directory_circle,
        operator_key: invoice.operator_key,
        bond_generation: 2,
        offer: 3,
        tariff_hash: invoice.tariff_hash,
        receipt_key: invoice.receipt_key,
        settlement: invoice.settlement.clone(),
        traffic_class: 1,
        rate_ou_per_mib: 1_000,
        max_bytes: 3_000_000,
        max_cost_ou: 3_000,
        canonical_ms: 2_000,
        active_from_ms: 1_000,
        purchase_deadline_ms: None,
    };
    (operator, invoice, consent)
}

fn sign_quote(invoice: Invoice, operator: &SigningKey) -> Result<SignedInvoice> {
    SignedInvoice::sign(invoice, operator, &SigningKey::from_bytes(&[9; 32]))
}

#[test]
fn signed_quote_binds_finite_rounded_price_and_one_time_native_recipient() {
    let (operator, q, consent) = fixture();
    assert_eq!(q.amount_ou().unwrap(), 2001);
    let signed = sign_quote(q, &operator).unwrap();
    let id = signed.verify(&consent).unwrap();
    assert_eq!(id, signed.verify(&consent).unwrap());
    let mut replacement = signed.invoice.clone();
    replacement.nonce[0] ^= 1;
    assert_ne!(
        id,
        sign_quote(replacement, &operator)
            .unwrap()
            .verify(&consent)
            .unwrap()
    );
    let seed = [9; 32];
    let secret = crate::native_stealth::view_secret(&seed);
    assert_eq!(
        signed.invoice.recipient_view_public().unwrap(),
        crate::native_stealth::view_public(&secret)
    );
}

#[test]
fn quote_address_and_view_match_actual_native_wallet_vectors() {
    let f: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/native-stealth.json")).unwrap();
    let (_, mut q, _) = fixture();
    q.recipient_key = hex::decode(f["ed_public"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(
        q.recipient_address().unwrap().as_slice(),
        f["address"].as_str().unwrap().as_bytes()
    );
    assert_eq!(
        q.recipient_view_public().unwrap().as_slice(),
        hex::decode(f["view_public"].as_str().unwrap()).unwrap()
    );
}

#[test]
fn changed_terms_cannot_reuse_operator_signature_or_cross_domains() {
    let (operator, q, consent) = fixture();
    let signed = sign_quote(q, &operator).unwrap();
    let mutations: [fn(&mut Invoice); 13] = [
        |q| q.chain_origin[0] ^= 1,
        |q| q.directory_circle[5] = b'A',
        |q| q.bond_generation += 1,
        |q| q.offer += 1,
        |q| q.tariff_hash[0] ^= 1,
        |q| q.receipt_key = SigningKey::from_bytes(&[11; 32]).verifying_key().to_bytes(),
        |q| q.recipient_key = SigningKey::from_bytes(&[12; 32]).verifying_key().to_bytes(),
        |q| q.nonce[0] ^= 1,
        |q| q.traffic_class += 1,
        |q| q.bytes += 1,
        |q| q.rate_ou_per_mib += 1,
        |q| q.valid_from_ms += 1,
        |q| q.expires_ms -= 1,
    ];
    for mutation in mutations {
        let mut q = signed.invoice.clone();
        mutation(&mut q);
        assert!(SignedInvoice {
            invoice: q,
            signature: signed.signature,
            claimant_signature: signed.claimant_signature
        }
        .verify(&consent)
        .is_err());
    }
    assert!(sign_quote(signed.invoice.clone(), &SigningKey::from_bytes(&[13; 32])).is_err());
}

#[test]
fn caps_expiry_activation_and_rate_notice_are_enforced_at_chain_time() {
    let (operator, q, mut c) = fixture();
    let signed = sign_quote(q, &operator).unwrap();
    c.max_cost_ou = 2000;
    assert!(signed.verify(&c).is_err());
    c.max_cost_ou = 3000;
    c.max_bytes = 2_097_152;
    assert!(signed.verify(&c).is_err());
    c.max_bytes = 3_000_000;
    c.canonical_ms = 999;
    assert!(signed.verify(&c).is_err());
    c.canonical_ms = 60_000;
    assert!(signed.verify(&c).is_err());
    c.canonical_ms = 2000;
    c.active_from_ms = 1001;
    assert!(signed.verify(&c).is_err());
    c.active_from_ms = 1000;
    c.purchase_deadline_ms = Some(59_999);
    assert!(signed.verify(&c).is_err());
    c.purchase_deadline_ms = Some(60_000);
    assert!(signed.verify(&c).is_ok());
}

#[test]
fn only_authenticated_future_quotes_can_wait_for_canonical_time() {
    let (operator, quote, mut consent) = fixture();
    let mut signed = sign_quote(quote, &operator).unwrap();
    consent.canonical_ms = signed.invoice.valid_from_ms - 1;
    assert!(signed.verify(&consent).unwrap_err().is::<NotYetValid>());
    let original_id = signed.id().unwrap();
    consent.canonical_ms = signed.invoice.valid_from_ms;
    assert_eq!(signed.verify(&consent).unwrap(), original_id);
    consent.canonical_ms = signed.invoice.expires_ms;
    assert!(!signed.verify(&consent).unwrap_err().is::<NotYetValid>());
    consent.canonical_ms = signed.invoice.valid_from_ms - 1;
    consent.max_cost_ou = 1;
    assert!(!signed.verify(&consent).unwrap_err().is::<NotYetValid>());
    consent.max_cost_ou = 3000;
    consent.active_from_ms = signed.invoice.valid_from_ms + 1;
    assert!(!signed.verify(&consent).unwrap_err().is::<NotYetValid>());
    consent.active_from_ms = signed.invoice.valid_from_ms;
    consent.purchase_deadline_ms = Some(signed.invoice.expires_ms - 1);
    assert!(!signed.verify(&consent).unwrap_err().is::<NotYetValid>());
    consent.purchase_deadline_ms = None;
    signed.claimant_signature[0] ^= 1;
    assert!(!signed.verify(&consent).unwrap_err().is::<NotYetValid>());
    signed.claimant_signature[0] ^= 1;
    signed.signature[0] ^= 1;
    assert!(!signed.verify(&consent).unwrap_err().is::<NotYetValid>());
}

#[test]
fn invalid_quantities_keys_and_uninitialized_quotes_fail_before_signing() {
    let (operator, q, _) = fixture();
    let mut changed = q.clone();
    changed.bytes = 0;
    assert!(sign_quote(changed, &operator).is_err());
    let mut changed = q.clone();
    changed.bytes = i64::MAX as u64;
    changed.rate_ou_per_mib = i64::MAX as u64;
    assert!(changed.amount_ou().is_err());
    let mut changed = q.clone();
    changed.recipient_key = changed.operator_key;
    assert!(sign_quote(changed, &operator).is_err());
    let mut changed = q.clone();
    changed.recipient_key = [0; 32];
    assert!(sign_quote(changed, &operator).is_err());
    let mut changed = q.clone();
    changed.nonce = [0; 32];
    assert!(sign_quote(changed, &operator).is_err());
    let mut changed = q;
    changed.expires_ms = changed.valid_from_ms + DAY_MS + 1;
    assert!(sign_quote(changed, &operator).is_err());
}

#[test]
fn claimant_must_prove_control_before_a_quote_is_accepted() {
    let (operator, q, consent) = fixture();
    assert!(SignedInvoice::sign(q.clone(), &operator, &SigningKey::from_bytes(&[14; 32])).is_err());
    let mut invoice = sign_quote(q, &operator).unwrap();
    invoice.claimant_signature[0] ^= 1;
    assert!(invoice.verify(&consent).is_err());
}

#[test]
fn shielded_quotes_bind_pool_and_note_owner_and_cannot_be_native_transfers() {
    use crate::pool::{self, Domain, SpendKey};
    let (operator, mut q, mut consent) = fixture();
    let circle = *b"oct1JBUrYbeTQazQ39LQn4ZjnPLHfDpLGXouqon1jZhJfYP";
    let domain = Domain::new(&q.chain_origin, &circle).unwrap();
    let spend = SpendKey::random();
    q.settlement = Settlement::ShieldedPool {
        circle,
        note_owner: pool::encode_field(spend.owner(domain)),
    };
    consent.settlement = q.settlement.clone();
    let signed = sign_quote(q, &operator).unwrap();
    let purchase = pool::purchase::prepare(&signed, &consent).unwrap();
    assert_eq!(purchase.quote, signed.verify(&consent).unwrap());
    assert_eq!(purchase.circle, circle);
    let note = purchase.output.bind(&[91; 32]);
    let opened = pool::envelope::open(
        domain,
        spend.owner(domain),
        &crate::native_stealth::view_secret(&[9; 32]),
        &purchase.output.ciphertext,
        &[91; 32],
        note.commitment(domain),
    )
    .unwrap();
    assert_eq!(opened.value(), 2001);
    assert!(crate::proposal::prepare(
        &signed,
        &consent,
        &crate::native_stealth::Amount::new(2001, [3; 32])
    )
    .is_err());
    let mut changed = signed.invoice.clone();
    if let Settlement::ShieldedPool { note_owner, .. } = &mut changed.settlement {
        *note_owner = pool::encode_field(SpendKey::random().owner(domain));
    }
    // Even accepting new external facts cannot repair a reused signature.
    consent.settlement = changed.settlement.clone();
    assert!(SignedInvoice {
        invoice: changed,
        signature: signed.signature,
        claimant_signature: signed.claimant_signature
    }
    .verify(&consent)
    .is_err());
    consent.settlement = Settlement::NativeClaim;
    assert!(signed.verify(&consent).is_err());
    let (operator, q, consent) = fixture();
    assert!(pool::purchase::prepare(&sign_quote(q, &operator).unwrap(), &consent).is_err());
}

#[test]
fn private_wire_codec_authenticates_every_byte_and_rejects_noncanonical_frames() {
    let (operator, base, mut consent) = fixture();
    let pool = Settlement::ShieldedPool {
        circle: base.directory_circle,
        note_owner: crate::pool::encode_field(ark_bn254::Fr::from(19_u64)),
    };
    for settlement in [Settlement::NativeClaim, pool] {
        let mut invoice = base.clone();
        invoice.settlement = settlement.clone();
        consent.settlement = settlement;
        let signed = sign_quote(invoice, &operator).unwrap();
        let wire = signed.encode_private().unwrap();
        let decoded = SignedInvoice::decode_private(&wire).unwrap();
        assert_eq!(decoded.verify(&consent).unwrap(), signed.id().unwrap());
        assert_eq!(*decoded.encode_private().unwrap(), *wire);
        for length in 0..wire.len() {
            assert!(SignedInvoice::decode_private(&wire[..length]).is_err());
        }
        for offset in 0..wire.len() {
            let mut changed = wire.to_vec();
            changed[offset] ^= 1;
            assert!(
                SignedInvoice::decode_private(&changed).is_err(),
                "offset {offset}"
            );
        }
        let mut trailing = wire.to_vec();
        trailing.push(0);
        assert!(SignedInvoice::decode_private(&trailing).is_err());
        assert!(SignedInvoice::decode_private(&vec![0; 2049]).is_err());
    }
}
