//! Bounded, authenticated round proofs and proposal recovery records.
use super::{io, Bytes, Error, Vote, VoteLog, VoteType, MAX_WIRE_BYTES};
use crate::consensus::{
    codec::{self, Wire},
    hash,
    policy::QuorumPolicy,
    ValidatorSet, NIL,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::{collections::BTreeSet, fs};
const PROOF_SIZE: u64 = codec::MAX_VALIDATORS as u64 * MAX_WIRE_BYTES * 6;
const VALUE_SIZE: u64 = 8 * 1024 * 1024;

pub fn check_proof(
    policy: QuorumPolicy,
    chain: &[u8],
    epoch: i64,
    set: &ValidatorSet,
    votes: &[Vote],
) -> Result<(), Error> {
    let first = votes.first().ok_or("vote proof is empty")?;
    let unique: BTreeSet<_> = votes.iter().map(|v| &v.validator).collect();
    if first.round < 0
        || first.round >= codec::MAX_ROUND
        || first.proposal_id == NIL
        || unique.len() != votes.len()
        || votes.iter().any(|v| {
            v.chain_id != chain
                || v.epoch_id != epoch
                || v.vote_type != VoteType::Prevote
                || v.round != first.round
                || v.proposal_id != first.proposal_id
        })
    {
        return Err("vote proof statement differs".into());
    }
    let valid = |set: &ValidatorSet| -> bool {
        set.has_quorum_for_policy(
            policy,
            epoch,
            &votes
                .iter()
                .map(|v| v.validator.clone())
                .collect::<Vec<_>>(),
        )
        .unwrap_or(false)
            && votes.iter().all(|v| {
                set.public_key(&v.validator)
                    .is_some_and(|key| hash::verify_vote(key, v).unwrap_or(false))
            })
    };
    if valid(set)
        || set
            .source_set(chain, epoch)
            .is_some_and(|source| valid(&source))
    {
        Ok(())
    } else {
        Err("vote proof quorum or signature is invalid".into())
    }
}
pub fn proof_ready(
    policy: QuorumPolicy,
    chain: &[u8],
    epoch: i64,
    set: &ValidatorSet,
    votes: &[Vote],
) -> bool {
    let addrs = votes
        .iter()
        .map(|v| v.validator.clone())
        .collect::<Vec<_>>();
    let enough = |set: &ValidatorSet| {
        set.has_quorum_for_policy(policy, epoch, &addrs)
            .unwrap_or(false)
    };
    enough(set) || set.source_set(chain, epoch).is_some_and(|set| enough(&set))
}
impl VoteLog {
    fn read_proofs(&self) -> Result<Vec<Vec<Vote>>, Error> {
        let path = match self {
            Self::Memory { proofs, .. } => return Ok(proofs.clone()),
            Self::Disk(path) => path.join("polc"),
        };
        if !path.exists() {
            return Ok(Vec::new());
        }
        let bytes = io::regular(&path, PROOF_SIZE, "vote proof")?;
        let encoded: Vec<Vec<String>> = serde_json::from_slice(&bytes)
            .map_err(|_| Error::from("vote proof list is invalid"))?;
        if encoded.len() > 3 {
            return Err("vote proof list is invalid".into());
        }
        let mut rounds = BTreeSet::new();
        let mut proofs = Vec::new();
        for entries in encoded {
            if entries.is_empty() || entries.len() > codec::MAX_VALIDATORS {
                return Err("vote proof list is invalid".into());
            }
            let votes = entries
                .into_iter()
                .map(|v| {
                    let wire = STANDARD
                        .decode(v)
                        .map_err(|_| Error::from("vote proof entry is invalid"))?;
                    if wire.len() > MAX_WIRE_BYTES as usize {
                        return Err("vote proof entry is invalid".into());
                    }
                    let vote = Vote::decode(&wire)?;
                    if vote.encode()? != wire {
                        return Err("vote log wire is not exact".into());
                    }
                    Ok(vote)
                })
                .collect::<Result<Vec<_>, Error>>()?;
            let first = &votes[0];
            if !rounds.insert((first.chain_id.clone(), first.epoch_id, first.round)) {
                return Err("vote proof round repeats".into());
            }
            proofs.push(votes);
        }
        Ok(proofs)
    }
    pub fn load_proofs(
        &self,
        policy: QuorumPolicy,
        chain: &[u8],
        epoch: i64,
        set: &ValidatorSet,
    ) -> Result<Vec<Vote>, Error> {
        let mut out = Vec::new();
        for proof in self.read_proofs()? {
            if proof[0].epoch_id < epoch {
                continue;
            }
            check_proof(policy, chain, epoch, set, &proof)?;
            out.extend(proof);
        }
        Ok(out)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn save_proof(
        &mut self,
        policy: QuorumPolicy,
        chain: &[u8],
        epoch: i64,
        set: &ValidatorSet,
        locked_round: i64,
        keep_rounds: &[i64],
        votes: &[Vote],
    ) -> Result<(), Error> {
        check_proof(policy, chain, epoch, set, votes)?;
        let first = &votes[0];
        let original = self.read_proofs()?;
        let mut proofs = vec![votes.to_vec()];
        for proof in &original {
            let old = &proof[0];
            if old.chain_id != chain || old.epoch_id > epoch {
                return Err("vote proof stored height or chain differs".into());
            }
            if old.epoch_id < epoch {
                continue;
            }
            if old.round == first.round {
                if old.proposal_id != first.proposal_id {
                    return Err("vote proof conflicts with stored proof".into());
                }
            } else {
                proofs.push(proof.clone());
            }
        }
        proofs.sort_by_key(|proof| std::cmp::Reverse(proof[0].round));
        let newest = proofs[0][0].round;
        proofs.retain(|proof| {
            let round = proof[0].round;
            round == newest
                || round == locked_round
                || round == first.round
                || keep_rounds.contains(&round)
        });
        if proofs.len() > 3 {
            return Err("vote proof retention is full".into());
        }
        for proof in &proofs {
            check_proof(policy, chain, epoch, set, proof)?;
        }
        match self {
            Self::Memory { proofs: saved, .. } => *saved = proofs,
            Self::Disk(path) => {
                io::directory(path, "vote log")?;
                if proofs == original {
                    io::sync_directory(path)?;
                } else {
                    let encoded = proofs
                        .iter()
                        .map(|proof| {
                            proof
                                .iter()
                                .map(|v| v.encode().map(|wire| STANDARD.encode(wire)))
                                .collect::<Result<Vec<_>, Error>>()
                        })
                        .collect::<Result<Vec<_>, Error>>()?;
                    let wire =
                        serde_json::to_vec(&encoded).map_err(|e| Error::from(e.to_string()))?;
                    if wire.len() as u64 > PROOF_SIZE {
                        return Err("vote proof size is invalid".into());
                    }
                    io::publish(path, &path.join("polc"), &wire, false)?;
                }
            }
        }
        Ok(())
    }
    pub fn value_read(&self) -> Result<Option<Bytes>, Error> {
        match self {
            Self::Memory { value, .. } => Ok(value.clone()),
            Self::Disk(path) => {
                let path = path.join("proposal");
                if !path.exists() {
                    return Ok(None);
                }
                let wire = io::regular(&path, VALUE_SIZE, "stored proposal")?;
                if wire.is_empty() {
                    return Err("stored proposal size is invalid".into());
                }
                Ok(Some(wire))
            }
        }
    }
    pub fn value_write(&mut self, wire: Bytes) -> Result<(), Error> {
        if wire.is_empty() || wire.len() as u64 > VALUE_SIZE {
            return Err("stored proposal size is invalid".into());
        }
        match self {
            Self::Memory { value, .. } => *value = Some(wire),
            Self::Disk(path) => {
                io::directory(path, "vote log")?;
                io::publish(path, &path.join("proposal"), &wire, false)?;
            }
        }
        Ok(())
    }
    pub(super) fn prune_proofs(&mut self, through: i64) -> Result<(), Error> {
        let proof_old = self
            .read_proofs()?
            .first()
            .and_then(|p| p.first())
            .is_some_and(|v| v.epoch_id <= through);
        let value_old = match self.value_read() {
            Ok(None) => false,
            Err(_) => true,
            Ok(Some(wire)) => crate::consensus::value_log::decode(&wire)
                .map_or(true, |record| record.proposal.epoch_id <= through),
        };
        match self {
            Self::Memory { proofs, value, .. } => {
                if proof_old {
                    proofs.clear();
                }
                if value_old {
                    *value = None;
                }
            }
            Self::Disk(path) => {
                let mut changed = false;
                for (remove, name) in [(proof_old, "polc"), (value_old, "proposal")] {
                    if remove {
                        match fs::remove_file(path.join(name)) {
                            Ok(()) => changed = true,
                            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                            Err(e) => return Err(io::io_error(e)),
                        }
                    }
                }
                if changed {
                    io::sync_directory(path)?;
                }
            }
        }
        Ok(())
    }
}
