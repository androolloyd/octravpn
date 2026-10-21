use super::*;
use crate::invoice::Invoice;
use ed25519_dalek::SigningKey;

fn fixture() -> (SignedInvoice, Consent) {
    let operator = SigningKey::from_bytes(&[7; 32]);
    let claimant = SigningKey::from_bytes(&[9; 32]);
    let q = Invoice {
        chain_origin: [1; 32],
        directory_circle: *b"oct1JBUrYbeTQazQ39LQn4ZjnPLHfDpLGXouqon1jZhJfYP",
        operator_key: operator.verifying_key().to_bytes(),
        bond_generation: 1,
        offer: 2,
        tariff_hash: [3; 32],
        receipt_key: SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes(),
        recipient_key: claimant.verifying_key().to_bytes(),
        settlement: crate::invoice::Settlement::NativeClaim,
        nonce: [4; 32],
        traffic_class: 0,
        bytes: 1_048_576,
        rate_ou_per_mib: 1000,
        valid_from_ms: 1000,
        expires_ms: 60000,
    };
    let consent = Consent {
        chain_origin: q.chain_origin,
        directory_circle: q.directory_circle,
        operator_key: q.operator_key,
        bond_generation: q.bond_generation,
        offer: q.offer,
        tariff_hash: q.tariff_hash,
        receipt_key: q.receipt_key,
        settlement: q.settlement.clone(),
        traffic_class: q.traffic_class,
        rate_ou_per_mib: q.rate_ou_per_mib,
        max_bytes: q.bytes,
        max_cost_ou: 1000,
        canonical_ms: 2000,
        active_from_ms: 1000,
        purchase_deadline_ms: None,
    };
    (
        SignedInvoice::sign(q, &operator, &claimant).unwrap(),
        consent,
    )
}

#[test]
fn privately_proposed_native_output_matches_exact_signed_price() {
    let (invoice, c) = fixture();
    let amount = Amount::new(1000, [41; 32]);
    let proposal = prepare(&invoice, &c, &amount).unwrap();
    let key = native_stealth::view_secret(&[9; 32]);
    let opened = open(&invoice, &c, &proposal, &key).unwrap();
    assert_eq!(opened.value(), amount.value());
    assert_eq!(opened.blinding(), amount.blinding());
    let second = prepare(&invoice, &c, &amount).unwrap();
    assert_ne!(
        proposal.output.ephemeral_public,
        second.output.ephemeral_public
    );
    assert_ne!(proposal.output.tag, second.output.tag);
    assert_ne!(
        proposal.output.encrypted_amount,
        second.output.encrypted_amount
    );
    assert_eq!(proposal.invoice_id, second.invoice_id);
}

#[test]
fn no_proposal_can_silently_change_price_or_exceed_consent() {
    let (invoice, mut c) = fixture();
    assert!(prepare(&invoice, &c, &Amount::new(999, [41; 32])).is_err());
    assert!(prepare(&invoice, &c, &Amount::new(1001, [41; 32])).is_err());
    c.max_cost_ou = 999;
    assert!(prepare(&invoice, &c, &Amount::new(1000, [41; 32])).is_err());
}

#[test]
fn wrong_wallet_invoice_tag_claim_or_ciphertext_is_rejected() {
    let (invoice, c) = fixture();
    let amount = Amount::new(1000, [41; 32]);
    let key = native_stealth::view_secret(&[9; 32]);
    let p = prepare(&invoice, &c, &amount).unwrap();
    assert!(open(&invoice, &c, &p, &native_stealth::view_secret(&[10; 32])).is_err());
    let mut p = prepare(&invoice, &c, &amount).unwrap();
    p.invoice_id[0] ^= 1;
    assert!(open(&invoice, &c, &p, &key).is_err());
    let mut p = prepare(&invoice, &c, &amount).unwrap();
    p.output.tag[0] ^= 1;
    assert!(open(&invoice, &c, &p, &key).is_err());
    let mut p = prepare(&invoice, &c, &amount).unwrap();
    p.output.claim_public[0] ^= 1;
    assert!(open(&invoice, &c, &p, &key).is_err());
    let mut p = prepare(&invoice, &c, &amount).unwrap();
    p.output.ephemeral_public = [0; 32];
    assert!(open(&invoice, &c, &p, &key).is_err());
    let mut p = prepare(&invoice, &c, &amount).unwrap();
    p.output.encrypted_amount = "A".repeat(92);
    assert!(open(&invoice, &c, &p, &key).is_err());
}
