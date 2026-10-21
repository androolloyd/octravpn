use super::{hash, Note, SpendKey, Statement, CAPACITY, NOTE_DEPTH, SPENT_DEPTH};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField, Zero};
use ark_r1cs_std::{
    alloc::AllocVar,
    boolean::Boolean,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    prelude::ToBitsGadget,
    R1CSVar,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use zeroize::{Zeroize, ZeroizeOnDrop};

type Var = FpVar<Fr>;
type Bits = Vec<Boolean<Fr>>;
type Error = SynthesisError;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub(super) struct Input {
    pub note: Note,
    pub key: SpendKey,
    pub index: u32,
    pub note_path: Vec<Fr>,
    pub spent_path: Vec<Fr>,
}

/// Fixed two-input/two-output circuit, including zero-output full withdrawals.
/// Paths use production depths even in tests. No witness serialization or Debug.
#[derive(Clone)]
pub struct PoolCircuit {
    pub statement: Statement,
    pub(super) inputs: Vec<Input>,
    pub(super) outputs: Vec<Note>,
    pub(super) output_paths: Vec<Vec<Fr>>,
    pub(super) auth_key: SpendKey,
}

fn pair(tag: u64, left: Var, right: Var) -> Result<Var, Error> {
    let p = hash::parameters();
    let mut state = [Var::Constant(Fr::from(tag)), left, right];
    for round in 0..p.full_rounds + p.partial_rounds {
        for (i, element) in state.iter_mut().enumerate() {
            *element += p.ark[round * 3 + i];
            if !(4..61).contains(&round) || i == 0 {
                let square = element.square()?;
                *element = square.square()? * &*element;
            }
        }
        state = std::array::from_fn(|i| {
            (0..3).fold(Var::zero(), |acc, j| acc + &state[j] * p.mds[i][j])
        });
    }
    Ok(state[0].clone())
}

fn fold(tag: u64, values: &[Var]) -> Result<Var, Error> {
    values.iter().try_fold(
        Var::Constant(Fr::from(values.len() as u64)),
        |acc, value| pair(tag, acc, value.clone()),
    )
}

fn witness(cs: &ConstraintSystemRef<Fr>, value: Fr) -> Result<Var, Error> {
    Var::new_witness(cs.clone(), || Ok(value))
}

fn range(value: &Var, width: usize) -> Result<Bits, Error> {
    let bits = (0..width)
        .map(|i| Boolean::new_witness(value.cs(), || Ok(value.value()?.into_bigint().get_bit(i))))
        .collect::<Result<Bits, _>>()?;
    Boolean::le_bits_to_fp(&bits)?.enforce_equal(value)?;
    Ok(bits)
}

fn count_bits(value: &Var) -> Result<Bits, Error> {
    let bits = range(value, NOTE_DEPTH + 1)?;
    // Counts include the full-tree sentinel 2^32, but never exceed it.
    for bit in &bits[..NOTE_DEPTH] {
        bit.conditional_enforce_equal(&Boolean::FALSE, &bits[NOTE_DEPTH])?;
    }
    Ok(bits)
}

fn path_root(
    cs: &ConstraintSystemRef<Fr>,
    mut leaf: Var,
    bits: &[Boolean<Fr>],
    siblings: &[Fr],
    tag: u64,
) -> Result<Var, Error> {
    if bits.len() != siblings.len() {
        return Err(Error::Unsatisfiable);
    }
    for (height, (bit, sibling)) in bits.iter().zip(siblings).enumerate() {
        let sibling = witness(cs, *sibling)?;
        let left = bit.select(&sibling, &leaf)?;
        let right = bit.select(&leaf, &sibling)?;
        leaf = pair(tag + height as u64, left, right)?;
    }
    Ok(leaf)
}

fn note_vars(
    cs: &ConstraintSystemRef<Fr>,
    note: &Note,
    domain: &[Var],
    enabled: &Boolean<Fr>,
) -> Result<(Var, Var, Var, Var), Error> {
    let owner = witness(cs, note.owner)?;
    let rho = witness(cs, note.rho)?;
    owner
        .is_eq(&Var::zero())?
        .conditional_enforce_equal(&Boolean::FALSE, enabled)?;
    rho.is_eq(&Var::zero())?
        .conditional_enforce_equal(&Boolean::FALSE, enabled)?;
    let value = witness(cs, Fr::from(note.value))?;
    range(&value, 63)?;
    value.conditional_enforce_equal(&Var::zero(), &!enabled)?;
    value
        .is_eq(&Var::zero())?
        .conditional_enforce_equal(&Boolean::FALSE, enabled)?;
    let context = witness(cs, note.context)?;
    let commitment = fold(
        hash::NOTE,
        &[
            domain[0].clone(),
            domain[1].clone(),
            owner.clone(),
            rho,
            value.clone(),
            context.clone(),
        ],
    )?;
    Ok((owner, value, context, commitment))
}

impl ConstraintSynthesizer<Fr> for PoolCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), Error> {
        if self.inputs.len() > 2
            || self.outputs.len() > 2
            || self.outputs.len() != self.output_paths.len()
        {
            return Err(Error::Unsatisfiable);
        }
        let public = self
            .statement
            .fields()
            .into_iter()
            .map(|x| Var::new_input(cs.clone(), || Ok(x)))
            .collect::<Result<Vec<_>, _>>()?;
        let domain = &public[..2];
        for i in [0, 1, 10, 11] {
            range(&public[i], 128)?;
        }
        range(&public[8], 63)?;
        range(&public[9], 63)?;
        let mut count = public[6].clone();
        count_bits(&count)?;
        count_bits(&public[7])?;
        let mut notes = public[2].clone();
        let mut spent = public[4].clone();
        let zero = Var::zero();
        let one = Var::one();
        let auth = witness(&cs, self.auth_key.0)?;
        auth.is_eq(&zero)?.enforce_equal(&Boolean::FALSE)?;
        let auth_hash = fold(
            hash::AUTH,
            &[
                domain[0].clone(),
                domain[1].clone(),
                auth.clone(),
                public[10].clone(),
                public[11].clone(),
            ],
        )?;
        auth_hash.enforce_equal(&public[12])?;
        let current_context = pair(hash::CONTEXT, public[10].clone(), public[11].clone())?;
        let input_enabled = [!public[13].is_eq(&zero)?, !public[14].is_eq(&zero)?];
        let output_enabled = [!public[15].is_eq(&zero)?, !public[16].is_eq(&zero)?];
        input_enabled[1].conditional_enforce_equal(&Boolean::FALSE, &!&input_enabled[0])?;
        output_enabled[1].conditional_enforce_equal(&Boolean::FALSE, &!&output_enabled[0])?;
        (&input_enabled[0] | &output_enabled[0]).enforce_equal(&Boolean::TRUE)?;
        let empty = Note {
            owner: Fr::zero(),
            rho: Fr::zero(),
            value: 0,
            context: Fr::zero(),
        };
        let mut total_in = public[8].clone();
        let mut total_out = public[9].clone();
        for (slot, enabled) in input_enabled.iter().enumerate() {
            let input = self.inputs.get(slot);
            let note = input.map(|i| &i.note).unwrap_or(&empty);
            let (owner, value, _, commitment) = note_vars(&cs, note, domain, enabled)?;
            total_in += value;
            let key = witness(&cs, input.map(|i| i.key.0).unwrap_or_default())?;
            key.is_eq(&zero)?
                .conditional_enforce_equal(&Boolean::FALSE, enabled)?;
            if slot == 0 {
                key.conditional_enforce_equal(&auth, enabled)?;
            }
            let owner_hash = fold(
                hash::OWNER,
                &[domain[0].clone(), domain[1].clone(), key.clone()],
            )?;
            owner_hash.conditional_enforce_equal(&owner, enabled)?;
            let index = witness(&cs, Fr::from(input.map(|i| i.index).unwrap_or_default()))?;
            let index_bits = range(&index, NOTE_DEPTH)?;
            // Membership of a nonzero note in the append root also prevents
            // reading future indices; this bound makes that condition explicit.
            let below_count = index.is_cmp(&public[6], std::cmp::Ordering::Less, false)?;
            below_count.conditional_enforce_equal(&Boolean::TRUE, enabled)?;
            let note_path = input
                .map(|i| i.note_path.clone())
                .unwrap_or(vec![Fr::zero(); NOTE_DEPTH]);
            let root = path_root(
                &cs,
                commitment.clone(),
                &index_bits,
                &note_path,
                hash::NOTE_TREE,
            )?;
            root.conditional_enforce_equal(&public[2], enabled)?;
            let nullifier = fold(
                hash::NULLIFIER,
                &[domain[0].clone(), domain[1].clone(), key, commitment],
            )?;
            nullifier.conditional_enforce_equal(&public[13 + slot], enabled)?;
            // Canonical 254-bit field decomposition, not truncated/modular bits.
            let nf_bits = public[13 + slot].to_bits_le()?;
            if nf_bits.len() != SPENT_DEPTH {
                return Err(Error::Unsatisfiable);
            }
            let spent_path = input
                .map(|i| i.spent_path.clone())
                .unwrap_or(vec![Fr::zero(); SPENT_DEPTH]);
            let old = path_root(&cs, zero.clone(), &nf_bits, &spent_path, hash::SPENT_TREE)?;
            old.conditional_enforce_equal(&spent, enabled)?;
            let new = path_root(&cs, one.clone(), &nf_bits, &spent_path, hash::SPENT_TREE)?;
            spent = enabled.select(&new, &spent)?;
        }
        for (slot, enabled) in output_enabled.iter().enumerate() {
            let output = self.outputs.get(slot).unwrap_or(&empty);
            let (_, value, context, commitment) = note_vars(&cs, output, domain, enabled)?;
            total_out += value;
            context.conditional_enforce_equal(&current_context, enabled)?;
            commitment.conditional_enforce_equal(&public[15 + slot], enabled)?;
            let count_bits = count_bits(&count)?;
            count_bits[NOTE_DEPTH].conditional_enforce_equal(&Boolean::FALSE, enabled)?;
            let path = self
                .output_paths
                .get(slot)
                .cloned()
                .unwrap_or(vec![Fr::zero(); NOTE_DEPTH]);
            let old = path_root(
                &cs,
                zero.clone(),
                &count_bits[..NOTE_DEPTH],
                &path,
                hash::NOTE_TREE,
            )?;
            old.conditional_enforce_equal(&notes, enabled)?;
            let new = path_root(
                &cs,
                commitment,
                &count_bits[..NOTE_DEPTH],
                &path,
                hash::NOTE_TREE,
            )?;
            notes = enabled.select(&new, &notes)?;
            count += Var::from(enabled.clone());
        }
        total_in.enforce_equal(&total_out)?;
        notes.enforce_equal(&public[3])?;
        spent.enforce_equal(&public[5])?;
        count.enforce_equal(&public[7])?;
        // 0-output withdrawals remain legal at CAPACITY, so filling the append
        // tree cannot lock users' remaining notes in custody.
        debug_assert_eq!(CAPACITY, 4_294_967_296);
        Ok(())
    }
}

#[cfg(test)]
pub(super) fn pair_gadget(tag: u64, left: Var, right: Var) -> Result<Var, Error> {
    pair(tag, left, right)
}
