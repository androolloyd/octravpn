//! Fixed, versioned BN254 x^5/t=3 Poseidon parameters from light-poseidon 0.4.0.
//! Domain tags are capacity elements, not extra unconstrained message fields.
use ark_bn254::Fr;
use ark_ff::{Field, Zero};
use light_poseidon::{parameters::bn254_x5, PoseidonParameters};
use std::sync::OnceLock;

pub(super) const OWNER: u64 = 1;
pub(super) const NOTE: u64 = 2;
pub(super) const NULLIFIER: u64 = 3;
pub(super) const CONTEXT: u64 = 4;
pub(super) const AUTH: u64 = 5;
pub(super) const NOTE_TREE: u64 = 256;
pub(super) const SPENT_TREE: u64 = 512;

pub(super) fn parameters() -> &'static PoseidonParameters<Fr> {
    static PARAMS: OnceLock<PoseidonParameters<Fr>> = OnceLock::new();
    PARAMS.get_or_init(|| {
        let p = bn254_x5::get_poseidon_parameters(3).expect("fixed published Poseidon parameters");
        assert_eq!(
            (p.width, p.alpha, p.full_rounds, p.partial_rounds),
            (3, 5, 8, 57)
        );
        p
    })
}

pub(super) fn pair(tag: u64, left: Fr, right: Fr) -> Fr {
    let p = parameters();
    let mut state = [Fr::from(tag), left, right];
    for round in 0..p.full_rounds + p.partial_rounds {
        for (i, element) in state.iter_mut().enumerate() {
            *element += p.ark[round * 3 + i];
            if !(4..61).contains(&round) || i == 0 {
                *element = element.pow([5]);
            }
        }
        state =
            std::array::from_fn(|i| (0..3).fold(Fr::zero(), |acc, j| acc + state[j] * p.mds[i][j]));
    }
    state[0]
}

pub(super) fn fold(tag: u64, fields: &[Fr]) -> Fr {
    fields
        .iter()
        .fold(Fr::from(fields.len() as u64), |acc, x| pair(tag, acc, *x))
}
