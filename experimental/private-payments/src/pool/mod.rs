//! Experimental shielded OCT note pool. Proofs conserve value and atomically
//! update note/nullifier roots. No release forwarding or deployment is enabled.
pub mod app;
pub mod call;
mod circuit;
pub mod envelope;
mod hash;
pub mod purchase;
pub mod transaction;
mod tree;
pub mod wire;

use anyhow::{ensure, Result};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField, UniformRand, Zero};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub use circuit::PoolCircuit;

pub const NOTE_DEPTH: usize = 32;
pub const SPENT_DEPTH: usize = 254;
pub const INPUTS: usize = 17;
pub const CIRCUIT: &str = "octranet-shielded-pool-poseidon3-sparse254-v1";
const CAPACITY: u64 = 1_u64 << NOTE_DEPTH;

/// Whole-chain origin and immutable custody Circle identity. Public code/VK
/// pins and activated native value effects must also be verified by the caller.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Domain([Fr; 2]);

impl Domain {
    pub fn new(chain: &[u8; 32], circle: &[u8; 47]) -> Result<Self> {
        ensure!(
            *chain != [0; 32]
                && circle.starts_with(b"oct")
                && circle[3..].iter().all(|c| {
                    b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(c)
                }),
            "invalid pool domain"
        );
        let mut hash = Sha256::new();
        hash.update(b"Octranet shielded pool v1|");
        for byte in chain {
            hash.update(format!("{byte:02x}"));
        }
        hash.update(b"|");
        hash.update(circle);
        Ok(Self(halves(&hash.finalize().into())))
    }

    pub fn fields(self) -> [Fr; 2] {
        self.0
    }

    pub fn digest(self) -> [u8; 32] {
        let mut digest = [0; 32];
        digest[..16].copy_from_slice(&encode_field(self.0[0])[16..]);
        digest[16..].copy_from_slice(&encode_field(self.0[1])[16..]);
        digest
    }
}

/// Secret-bearing types intentionally have no Debug or generic serialization.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SpendKey(Fr);

impl SpendKey {
    pub fn random() -> Self {
        loop {
            let key = Fr::rand(&mut OsRng);
            if !key.is_zero() {
                return Self(key);
            }
        }
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let value = decode_field(bytes)?;
        ensure!(!value.is_zero(), "zero pool spend key");
        Ok(Self(value))
    }

    pub fn owner(&self, domain: Domain) -> Fr {
        hash::fold(hash::OWNER, &[domain.0[0], domain.0[1], self.0])
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Note {
    owner: Fr,
    rho: Fr,
    value: u64,
    context: Fr,
}

impl Note {
    pub fn new(owner: Fr, value: u64, context: &[u8; 32]) -> Result<Self> {
        ensure!(
            !owner.is_zero() && value > 0 && value <= i64::MAX as u64,
            "invalid private note"
        );
        let rho = SpendKey::random().0;
        Ok(Self {
            owner,
            rho,
            value,
            context: context_field(context),
        })
    }

    pub fn value(&self) -> u64 {
        self.value
    }
    pub fn owner(&self) -> Fr {
        self.owner
    }

    pub fn commitment(&self, domain: Domain) -> Fr {
        hash::fold(
            hash::NOTE,
            &[
                domain.0[0],
                domain.0[1],
                self.owner,
                self.rho,
                Fr::from(self.value),
                self.context,
            ],
        )
    }

    pub fn nullifier(&self, domain: Domain, key: &SpendKey) -> Result<Fr> {
        ensure!(
            self.owner == key.owner(domain),
            "private note belongs to another key"
        );
        let nf = hash::fold(
            hash::NULLIFIER,
            &[domain.0[0], domain.0[1], key.0, self.commitment(domain)],
        );
        ensure!(!nf.is_zero(), "zero nullifier");
        Ok(nf)
    }
}

pub struct Spend<'a> {
    pub note: &'a Note,
    pub key: &'a SpendKey,
    pub index: u32,
}

/// Untrusted path material. Only verification against an independently
/// authenticated canonical root/count proves membership, never this type alone.
#[derive(Clone)]
pub struct Membership {
    pub index: u32,
    pub siblings: [Fr; NOTE_DEPTH],
}
impl Membership {
    pub fn verify(&self, root: Fr, count: u64, commitment: Fr) -> Result<()> {
        ensure!(
            count <= CAPACITY && u64::from(self.index) < count && !commitment.is_zero(),
            "private note membership is outside the append tree"
        );
        let mut node = commitment;
        for (height, sibling) in self.siblings.iter().enumerate() {
            node = if self.index & (1_u32 << height) == 0 {
                hash::pair(hash::NOTE_TREE + height as u64, node, *sibling)
            } else {
                hash::pair(hash::NOTE_TREE + height as u64, *sibling, node)
            };
        }
        ensure!(node == root, "private note membership root differs");
        Ok(())
    }
}

/// Public transition. Nullifiers and commitments are unlinkable hash outputs;
/// values, owners, note positions consumed and Merkle paths stay in the proof.
/// Native deposits/withdrawals and transaction timing remain public.
#[derive(Clone)]
pub struct Statement {
    pub domain: Domain,
    pub old_notes: Fr,
    pub new_notes: Fr,
    pub old_spent: Fr,
    pub new_spent: Fr,
    pub old_count: u64,
    pub new_count: u64,
    pub deposit: u64,
    pub withdraw: u64,
    /// SHA256 of typed external call data, constructed again by the Circle.
    pub context: [u8; 32],
    pub authorization: Fr,
    pub nullifiers: [Fr; 2],
    pub outputs: [Fr; 2],
}

impl Statement {
    /// This order is versioned and must match the immutable Circle's packing.
    pub fn fields(&self) -> [Fr; INPUTS] {
        let context = halves(&self.context);
        [
            self.domain.0[0],
            self.domain.0[1],
            self.old_notes,
            self.new_notes,
            self.old_spent,
            self.new_spent,
            Fr::from(self.old_count),
            Fr::from(self.new_count),
            Fr::from(self.deposit),
            Fr::from(self.withdraw),
            context[0],
            context[1],
            self.authorization,
            self.nullifiers[0],
            self.nullifiers[1],
            self.outputs[0],
            self.outputs[1],
        ]
    }
}

/// Reconstructible public index. Updating this alone proves no payment and
/// mints no entitlement. Publish only after the actual Circle call finalizes.
#[derive(Clone)]
pub struct PoolIndex {
    notes: tree::Tree,
    spent: tree::Tree,
    count: u64,
}

pub struct PublicLeaves {
    pub notes: Vec<[u8; 32]>,
    pub nullifiers: Vec<[u8; 32]>,
}

impl Default for PoolIndex {
    fn default() -> Self {
        Self {
            notes: tree::Tree::new(NOTE_DEPTH, hash::NOTE_TREE),
            spent: tree::Tree::new(SPENT_DEPTH, hash::SPENT_TREE),
            count: 0,
        }
    }
}

impl PoolIndex {
    /// Public leaves only: no values, owners, witnesses or spend keys. The
    /// receiver must authenticate reconstructed roots against canonical state.
    pub fn public_leaves(&self) -> Result<PublicLeaves> {
        let notes = (0..self.count)
            .map(|i| {
                let value = self.notes.leaf(tree::Index::from(i));
                ensure!(!value.is_zero(), "public note tree has a hole");
                Ok(encode_field(value))
            })
            .collect::<Result<Vec<_>>>()?;
        let nullifiers = self
            .spent
            .leaves()
            .map(|(index, value)| {
                ensure!(value == Fr::from(1_u64), "public spent leaf differs");
                Ok(encode_field(Fr::from_bigint(index).ok_or_else(|| {
                    anyhow::anyhow!("public nullifier is not canonical")
                })?))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(PublicLeaves { notes, nullifiers })
    }
    pub fn rebuild(notes: &[[u8; 32]], nullifiers: &[[u8; 32]]) -> Result<Self> {
        ensure!(
            u64::try_from(notes.len())? <= CAPACITY,
            "public note seed exceeds tree capacity"
        );
        let mut result = Self::default();
        for raw in notes {
            let value = decode_field(raw)?;
            ensure!(!value.is_zero(), "zero public note leaf");
            result
                .notes
                .insert(tree::Index::from(result.count), value)?;
            result.count += 1;
        }
        for raw in nullifiers {
            let value = decode_field(raw)?;
            ensure!(!value.is_zero(), "zero public nullifier");
            result.spent.insert(value.into_bigint(), Fr::from(1_u64))?;
        }
        Ok(result)
    }
    /// Public index information only. Authenticate all three roots/count
    /// against the canonical node before relying on this for wallet recovery.
    pub fn spent(&self, nullifier: &[u8; 32]) -> Result<bool> {
        let nullifier = decode_field(nullifier)?;
        ensure!(!nullifier.is_zero(), "zero pool nullifier");
        Ok(!self.spent.leaf(nullifier.into_bigint()).is_zero())
    }
    pub fn roots(&self) -> (Fr, Fr, u64) {
        (self.notes.root(), self.spent.root(), self.count)
    }

    pub fn membership(&self, index: u32) -> Result<Membership> {
        let position = tree::Index::from(u64::from(index));
        ensure!(
            u64::from(index) < self.count && !self.notes.leaf(position).is_zero(),
            "private note index is absent"
        );
        Ok(Membership {
            index,
            siblings: self
                .notes
                .path(position)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("private note path depth differs"))?,
        })
    }
    /// Reconstruct a historical append prefix from the current public index.
    /// The caller must verify this witness against the actual historical root.
    pub fn membership_at(&self, index: u32, count: u64) -> Result<Membership> {
        ensure!(
            count <= self.count
                && !self
                    .notes
                    .leaf(tree::Index::from(u64::from(index)))
                    .is_zero(),
            "historical note prefix is unavailable"
        );
        Ok(Membership {
            index,
            siblings: self
                .notes
                .prefix_path(index, count)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("historical note path depth differs"))?,
        })
    }

    /// Rebuild the public index from a previously verified canonical event.
    /// This checks its root transition; it is not a substitute for verifying
    /// the proof, native finality, code/VK pins or the call's quote deadline.
    pub fn observe(&self, statement: &Statement) -> Result<Self> {
        ensure!(
            self.roots()
                == (
                    statement.old_notes,
                    statement.old_spent,
                    statement.old_count
                ),
            "pool event does not extend this index"
        );
        self.apply(
            statement.nullifiers,
            statement.outputs,
            (
                statement.new_notes,
                statement.new_spent,
                statement.new_count,
            ),
        )
    }

    /// Reconstruct public trees from untrusted hints. The result proves no
    /// execution, payment, deadline or finality; bind its roots/count to the
    /// canonical node before exposing it as a usable wallet index.
    pub fn apply(
        &self,
        nullifiers: [Fr; 2],
        outputs: [Fr; 2],
        roots: (Fr, Fr, u64),
    ) -> Result<Self> {
        let mut next = self.clone();
        let mut ended = false;
        for nf in nullifiers {
            if nf.is_zero() {
                ended = true;
                continue;
            }
            ensure!(!ended, "non-prefix pool nullifiers");
            next.spent.insert(nf.into_bigint(), Fr::from(1))?;
        }
        ended = false;
        for output in outputs {
            if output.is_zero() {
                ended = true;
                continue;
            }
            ensure!(!ended && next.count < CAPACITY, "invalid pool append");
            next.notes.insert(tree::Index::from(next.count), output)?;
            next.count += 1;
        }
        ensure!(next.roots() == roots, "pool event roots differ");
        Ok(next)
    }

    /// Build a private witness against one exact root pair. The returned index
    /// is a candidate only; stale roots must cause an atomic on-chain rejection.
    pub fn prepare(
        &self,
        domain: Domain,
        spends: &[Spend<'_>],
        outputs: &[Note],
        deposit: u64,
        withdraw: u64,
        context: [u8; 32],
    ) -> Result<(PoolCircuit, Self)> {
        ensure!(
            spends.len() <= 2 && outputs.len() <= 2 && (!spends.is_empty() || !outputs.is_empty()),
            "pool transition needs one or two inputs or outputs"
        );
        ensure!(
            deposit <= i64::MAX as u64 && withdraw <= i64::MAX as u64,
            "native value exceeds int64"
        );
        ensure!(
            spends
                .iter()
                .map(|s| u128::from(s.note.value))
                .sum::<u128>()
                + u128::from(deposit)
                == outputs.iter().map(|n| u128::from(n.value)).sum::<u128>() + u128::from(withdraw),
            "private transition does not conserve value"
        );
        let mut next = self.clone();
        let mut inputs = Vec::new();
        let mut nullifiers = [Fr::zero(); 2];
        for (slot, spend) in spends.iter().enumerate() {
            let index = tree::Index::from(u64::from(spend.index));
            ensure!(
                u64::from(spend.index) < self.count
                    && self.notes.leaf(index) == spend.note.commitment(domain),
                "input note is absent"
            );
            let nf = spend.note.nullifier(domain, spend.key)?;
            inputs.push(circuit::Input {
                note: spend.note.clone(),
                key: spend.key.clone(),
                index: spend.index,
                note_path: self.notes.path(index)?,
                spent_path: next.spent.path(nf.into_bigint())?,
            });
            next.spent.insert(nf.into_bigint(), Fr::from(1))?;
            nullifiers[slot] = nf;
        }
        let mut output_paths = Vec::new();
        let mut commitments = [Fr::zero(); 2];
        for (slot, note) in outputs.iter().enumerate() {
            ensure!(
                next.count < CAPACITY
                    && note.value > 0
                    && note.value <= i64::MAX as u64
                    && note.context == context_field(&context),
                "invalid output or note tree full"
            );
            let commitment = note.commitment(domain);
            ensure!(!commitment.is_zero(), "zero output commitment");
            let index = tree::Index::from(next.count);
            output_paths.push(next.notes.path(index)?);
            next.notes.insert(index, commitment)?;
            next.count += 1;
            commitments[slot] = commitment;
        }
        let auth_key = spends
            .first()
            .map(|s| s.key.clone())
            .unwrap_or_else(SpendKey::random);
        let halves = halves(&context);
        let authorization = hash::fold(
            hash::AUTH,
            &[domain.0[0], domain.0[1], auth_key.0, halves[0], halves[1]],
        );
        let statement = Statement {
            domain,
            old_notes: self.notes.root(),
            new_notes: next.notes.root(),
            old_spent: self.spent.root(),
            new_spent: next.spent.root(),
            old_count: self.count,
            new_count: next.count,
            deposit,
            withdraw,
            context,
            authorization,
            nullifiers,
            outputs: commitments,
        };
        Ok((
            PoolCircuit {
                statement,
                inputs,
                outputs: outputs.to_vec(),
                output_paths,
                auth_key,
            },
            next,
        ))
    }
}

pub fn encode_field(value: Fr) -> [u8; 32] {
    value
        .into_bigint()
        .to_bytes_be()
        .try_into()
        .expect("BN254 scalar width")
}

pub fn decode_field(bytes: &[u8; 32]) -> Result<Fr> {
    let value = Fr::from_be_bytes_mod_order(bytes);
    ensure!(encode_field(value) == *bytes, "noncanonical BN254 scalar");
    Ok(value)
}

fn halves(bytes: &[u8; 32]) -> [Fr; 2] {
    [
        Fr::from_be_bytes_mod_order(&bytes[..16]),
        Fr::from_be_bytes_mod_order(&bytes[16..]),
    ]
}

fn context_field(context: &[u8; 32]) -> Fr {
    let halves = halves(context);
    hash::pair(hash::CONTEXT, halves[0], halves[1])
}

#[cfg(test)]
mod tests;
