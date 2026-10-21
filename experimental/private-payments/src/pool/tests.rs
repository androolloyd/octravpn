use super::*;
use crate::native_stealth;
use ark_ff::{BigInt, Field};
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, R1CSVar};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use light_poseidon::{Poseidon, PoseidonBytesHasher, PoseidonHasher};

fn domain() -> Domain {
    Domain::new(
        &[3; 32],
        format!("oct{}", "2".repeat(44))
            .as_bytes()
            .try_into()
            .unwrap(),
    )
    .unwrap()
}
fn satisfied(circuit: PoolCircuit) -> bool {
    let cs = ConstraintSystem::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    cs.is_satisfied().unwrap()
}
fn deposit() -> (PoolCircuit, PoolIndex, Note, SpendKey) {
    let key = SpendKey::random();
    let note = Note::new(key.owner(domain()), 100, &[4; 32]).unwrap();
    let (circuit, index) = PoolIndex::default()
        .prepare(domain(), &[], std::slice::from_ref(&note), 100, 0, [4; 32])
        .unwrap();
    (circuit, index, note, key)
}

#[test]
fn public_leaf_round_trip_reconstructs_membership_and_spends() {
    let (_, index, note, key) = deposit();
    let change = Note::new(key.owner(domain()), 60, &[6; 32]).unwrap();
    let (_, after) = index
        .prepare(
            domain(),
            &[Spend {
                note: &note,
                key: &key,
                index: 0,
            }],
            &[change],
            0,
            40,
            [6; 32],
        )
        .unwrap();
    let PublicLeaves { notes, nullifiers } = after.public_leaves().unwrap();
    assert_eq!(notes.len(), 2);
    assert_eq!(nullifiers.len(), 1);
    let restored = PoolIndex::rebuild(&notes, &nullifiers).unwrap();
    assert_eq!(restored.roots(), after.roots());
    for position in 0..2 {
        assert_eq!(
            restored.membership(position).unwrap().siblings,
            after.membership(position).unwrap().siblings
        );
    }
    assert!(restored
        .spent(&encode_field(note.nullifier(domain(), &key).unwrap()))
        .unwrap());
    assert!(PoolIndex::rebuild(&[[0; 32]], &[]).is_err());
    assert!(PoolIndex::rebuild(&notes, &[[0; 32]]).is_err());
    assert!(PoolIndex::rebuild(&notes, &[nullifiers[0], nullifiers[0]]).is_err());
}

#[test]
fn poseidon_matches_pinned_independent_reference_and_its_published_vector() {
    let vector = Poseidon::<Fr>::new_circom(2)
        .unwrap()
        .hash_bytes_be(&[&[1; 32], &[2; 32]])
        .unwrap();
    assert_eq!(
        vector,
        [
            13, 84, 225, 147, 143, 138, 140, 28, 125, 235, 94, 3, 85, 242, 99, 25, 32, 123, 132,
            254, 156, 162, 206, 27, 38, 231, 53, 200, 41, 130, 25, 144
        ]
    );
    for tag in [
        0,
        hash::OWNER,
        hash::NOTE,
        hash::NULLIFIER,
        hash::CONTEXT,
        hash::AUTH,
        hash::NOTE_TREE,
        hash::NOTE_TREE + 31,
        hash::SPENT_TREE,
        hash::SPENT_TREE + 253,
    ] {
        let left = Fr::from(42);
        let right = -Fr::from(19);
        let expected = Poseidon::<Fr>::with_domain_tag_circom(2, Fr::from(tag))
            .unwrap()
            .hash(&[left, right])
            .unwrap();
        assert_eq!(hash::pair(tag, left, right), expected);
        let cs = ConstraintSystem::new_ref();
        let a = FpVar::new_witness(cs.clone(), || Ok(left)).unwrap();
        let b = FpVar::new_witness(cs.clone(), || Ok(right)).unwrap();
        assert_eq!(
            circuit::pair_gadget(tag, a, b).unwrap().value().unwrap(),
            expected
        );
        assert!(cs.is_satisfied().unwrap());
    }
}

#[test]
fn fields_and_envelopes_reject_aliases_tampering_wrong_owner_and_malformed_utf8_boundaries() {
    let modulus: [u8; 32] = Fr::MODULUS.to_bytes_be().try_into().unwrap();
    assert!(decode_field(&modulus).is_err());
    assert!(SpendKey::from_bytes(&[0; 32]).is_err());
    let key = SpendKey::random();
    let view = native_stealth::view_secret(&[8; 32]);
    let draft = envelope::Draft::new(
        key.owner(domain()),
        999,
        &native_stealth::view_public(&view),
    )
    .unwrap();
    let note = draft.bind(&[7; 32]);
    let commitment = note.commitment(domain());
    let opened = envelope::open(
        domain(),
        key.owner(domain()),
        &view,
        &draft.ciphertext,
        &[7; 32],
        commitment,
    )
    .unwrap();
    assert_eq!(opened.value(), 999);
    assert!(envelope::open(
        domain(),
        key.owner(domain()),
        &view,
        &draft.ciphertext,
        &[9; 32],
        commitment
    )
    .is_err());
    assert!(envelope::open(
        domain(),
        key.owner(domain()) + Fr::from(1),
        &view,
        &draft.ciphertext,
        &[7; 32],
        commitment
    )
    .is_err());
    let mut corrupted = draft.ciphertext.into_bytes();
    corrupted[46] = if corrupted[46] == b'A' { b'B' } else { b'A' };
    assert!(envelope::open(
        domain(),
        key.owner(domain()),
        &view,
        std::str::from_utf8(&corrupted).unwrap(),
        &[7; 32],
        commitment
    )
    .is_err());
    let mut non_ascii = "a".repeat(43);
    non_ascii.push('é');
    non_ascii.push_str(&"x".repeat(92));
    assert_eq!(non_ascii.len(), envelope::BOX_LEN);
    assert!(envelope::validate(&non_ascii).is_err());
}

#[test]
fn production_depth_conservation_membership_authorization_and_every_public_input_are_constrained() {
    let (funding, index, note, key) = deposit();
    assert!(satisfied(funding));
    let exit_key = SpendKey::random();
    let output = Note::new(exit_key.owner(domain()), 25, &[6; 32]).unwrap();
    let change = Note::new(key.owner(domain()), 75, &[6; 32]).unwrap();
    let (payment, next) = index
        .prepare(
            domain(),
            &[Spend {
                note: &note,
                key: &key,
                index: 0,
            }],
            &[output.clone(), change],
            0,
            0,
            [6; 32],
        )
        .unwrap();
    let cs = ConstraintSystem::new_ref();
    payment.clone().generate_constraints(cs.clone()).unwrap();
    assert!(cs.is_satisfied().unwrap());
    assert_eq!(cs.num_instance_variables(), INPUTS + 1);
    // Mutate every public scalar against the exact valid witness. Separate
    // recomputed-witness attacks below check more than this binding test.
    for slot in 1..=INPUTS {
        let original = cs.borrow().unwrap().instance_assignment[slot];
        cs.borrow_mut().unwrap().instance_assignment[slot] += Fr::from(1);
        assert!(!cs.is_satisfied().unwrap(), "unbound public input {slot}");
        cs.borrow_mut().unwrap().instance_assignment[slot] = original;
    }
    assert!(next
        .prepare(
            domain(),
            &[Spend {
                note: &note,
                key: &key,
                index: 0
            }],
            &[],
            0,
            100,
            [9; 32]
        )
        .is_err());
    assert!(index
        .prepare(
            domain(),
            &[Spend {
                note: &note,
                key: &exit_key,
                index: 0
            }],
            &[],
            0,
            100,
            [9; 32]
        )
        .is_err());
    let mut forged = payment.clone();
    forged.outputs[0].value += 1;
    forged.statement.outputs[0] = forged.outputs[0].commitment(domain());
    assert!(!satisfied(forged));
    let mut wrong_key = payment.clone();
    wrong_key.inputs[0].key = SpendKey::random();
    wrong_key.auth_key = wrong_key.inputs[0].key.clone();
    assert!(!satisfied(wrong_key));
    let mut zero_rho = payment.clone();
    zero_rho.outputs[0].rho = Fr::zero();
    zero_rho.statement.outputs[0] = zero_rho.outputs[0].commitment(domain());
    assert!(!satisfied(zero_rho));
    let mut path = payment;
    path.inputs[0].spent_path[253] += Fr::from(1);
    assert!(!satisfied(path));
    assert_ne!(index.roots().1, next.roots().1);
    let (spend_earnings, _) = next
        .prepare(
            domain(),
            &[Spend {
                note: &output,
                key: &exit_key,
                index: 1,
            }],
            &[],
            0,
            25,
            [9; 32],
        )
        .unwrap();
    assert!(satisfied(spend_earnings));
}

#[test]
fn two_inputs_and_zero_output_full_exit_remain_legal_when_note_tree_is_full() {
    let key = SpendKey::random();
    let first = Note::new(key.owner(domain()), 17, &[4; 32]).unwrap();
    let second = Note::new(key.owner(domain()), 23, &[4; 32]).unwrap();
    let (_, mut index) = PoolIndex::default()
        .prepare(
            domain(),
            &[],
            &[first.clone(), second.clone()],
            40,
            0,
            [4; 32],
        )
        .unwrap();
    // Boundary fixture: do not materialize 2^32 leaves. It tests the circuit's
    // capacity branch, not an actual history that filled the entire tree.
    index.count = CAPACITY;
    let (withdraw, _) = index
        .prepare(
            domain(),
            &[
                Spend {
                    note: &first,
                    key: &key,
                    index: 0,
                },
                Spend {
                    note: &second,
                    key: &key,
                    index: 1,
                },
            ],
            &[],
            0,
            40,
            [7; 32],
        )
        .unwrap();
    assert!(satisfied(withdraw));
    let output = Note::new(key.owner(domain()), 40, &[7; 32]).unwrap();
    assert!(index
        .prepare(
            domain(),
            &[
                Spend {
                    note: &first,
                    key: &key,
                    index: 0
                },
                Spend {
                    note: &second,
                    key: &key,
                    index: 1
                }
            ],
            &[output],
            0,
            0,
            [7; 32]
        )
        .is_err());
}

#[test]
fn sparse_tree_handles_field_endpoints_and_rejects_duplicate_insertion() {
    let mut tree = tree::Tree::new(SPENT_DEPTH, hash::SPENT_TREE);
    let key = (-Fr::from(1)).into_bigint();
    assert_eq!(tree.path(key).unwrap().len(), SPENT_DEPTH);
    tree.insert(key, Fr::from(1)).unwrap();
    assert!(tree.insert(key, Fr::from(1)).is_err());
    assert_eq!(tree.leaf(key), Fr::from(1));
    assert!(tree.path(BigInt::<4>::new([0, 0, 0, 1_u64 << 63])).is_err());
    assert_ne!(Fr::from(1).square(), Fr::from(2));
}

#[test]
fn canonical_membership_binds_position_root_and_count() {
    let (_, index, note, _) = deposit();
    let path = index.membership(0).unwrap();
    let (root, _, count) = index.roots();
    path.verify(root, count, note.commitment(domain())).unwrap();
    assert!(path.verify(root, 0, note.commitment(domain())).is_err());
    assert!(path
        .verify(root, CAPACITY + 1, note.commitment(domain()))
        .is_err());
    assert!(path.verify(root, count, Fr::zero()).is_err());
    assert!(index.membership(1).is_err());
    let mut wrong = path.clone();
    wrong.index = 1;
    assert!(wrong.verify(root, 2, note.commitment(domain())).is_err());
    wrong = path;
    wrong.siblings[31] += Fr::from(1);
    assert!(wrong
        .verify(root, count, note.commitment(domain()))
        .is_err());
}

#[test]
fn a_public_deposit_note_cannot_be_opened_as_a_shielded_internal_payment() {
    let key = SpendKey::random();
    let view = native_stealth::view_secret(&[87; 32]);
    let draft =
        envelope::Draft::new(key.owner(domain()), 10, &native_stealth::view_public(&view)).unwrap();
    let mut call = call::Call {
        quote: [9; 32],
        valid_from_ms: 10,
        expires_ms: 20,
        payout: *b"oct1JBUrYbeTQazQ39LQn4ZjnPLHfDpLGXouqon1jZhJfYP",
        deposit_ou: 10,
        withdraw_ou: 0,
        boxes: [draft.ciphertext.clone(), String::new()],
    };
    let circle = *b"oct1JBUrYbeTQazQ39LQn4ZjnPLHfDpLGXouqon1jZhJfYP";
    let context = call.context(&[3; 32], &circle, &circle).unwrap();
    let note = draft.bind(&context);
    call.deposit_ou = 0;
    let internal = call.context(&[3; 32], &circle, &circle).unwrap();
    assert_ne!(context, internal);
    assert!(envelope::open(
        domain(),
        key.owner(domain()),
        &view,
        &draft.ciphertext,
        &internal,
        note.commitment(domain())
    )
    .is_err());
}
