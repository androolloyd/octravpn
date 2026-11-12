//! Compact historical precommit evidence. Every claim is authenticated before
//! mutating participation, so one invalid claim cannot partially credit a voter.
use super::{limit, table, CapMode, Config, Error, Final, Member, State};
use crate::{
    consensus::{hash, ValidatorSet, Vote, VoteType},
    duty,
    native_json::{Document, Value},
};
use base64::{engine::general_purpose::STANDARD, Engine};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MarkClaim {
    pub epoch: i64,
    pub signature: Vec<u8>,
}
pub type MarkSet = (i64, Vec<u8>, ValidatorSet);
#[derive(Clone, Debug)]
pub enum Evidence {
    Pulse,
    Commit(Box<duty::Proof>),
    Marks(Vec<MarkClaim>),
}

pub fn encode_marks(claims: &[MarkClaim]) -> Result<Vec<u8>, Error> {
    let mut raw = Vec::with_capacity(claims.len() * 72);
    for claim in claims {
        if claim.signature.len() != 64 {
            return Err("validator duty mark signature size".into());
        }
        raw.extend_from_slice(&(claim.epoch as u64).to_be_bytes());
        raw.extend_from_slice(&claim.signature);
    }
    Ok(STANDARD.encode(raw).into_bytes())
}
pub fn decode_marks(cfg: &Config, encoded: &[u8]) -> Result<Vec<MarkClaim>, Error> {
    let max_size = usize::try_from(cfg.challenge.saturating_sub(1))
        .unwrap_or(0)
        .saturating_mul(72);
    if encoded.len() > 4 * max_size.div_ceil(3) {
        return Err("validator duty mark count is invalid".into());
    }
    let raw = crate::native_base64::decode(encoded)
        .map_err(|_| Error::from("validator duty marks encoding is invalid"))?;
    if raw.is_empty()
        || raw.len() % 72 != 0
        || raw.len() > max_size
        || STANDARD.encode(&raw).as_bytes() != encoded
    {
        return Err("validator duty marks encoding is invalid".into());
    }
    Ok(raw
        .chunks_exact(72)
        .map(|chunk| MarkClaim {
            epoch: u64::from_be_bytes(chunk[..8].try_into().expect("claim epoch")) as i64,
            signature: chunk[8..].to_vec(),
        })
        .collect())
}
pub fn evidence_of_message(
    marks: bool,
    cfg: &Config,
    message: Option<&[u8]>,
) -> Result<Evidence, Error> {
    let legacy = || {
        duty::proof_of_message(message)
            .map(|proof| proof.map_or(Evidence::Pulse, |proof| Evidence::Commit(Box::new(proof))))
            .map_err(|error| Error(error.to_string()))
    };
    if !marks {
        return legacy();
    }
    let raw = message.ok_or("validator duty message is missing")?;
    let doc = Document::parse(raw)
        .map_err(|_| Error::from("validator duty message encoding is invalid"))?;
    let Value::Object(fields) = doc.root() else {
        return Err("validator duty message has wrong type".into());
    };
    let mut names = std::collections::BTreeSet::new();
    for (name, _) in fields {
        if !names.insert(name) {
            return Err(format!(
                "validator duty field is duplicated: {}",
                String::from_utf8_lossy(name)
            )
            .into());
        }
    }
    let Some(value) = doc.field(doc.root(), b"duty_marks") else {
        return legacy();
    };
    if doc.field(doc.root(), b"duty_vote").is_some()
        || doc.field(doc.root(), b"duty_commit").is_some()
    {
        return Err("validator duty proof formats overlap".into());
    }
    let Value::String(encoded) = value else {
        return Err("validator duty marks have wrong type".into());
    };
    decode_marks(cfg, encoded).map(Evidence::Marks)
}
impl State {
    fn check_mark_claim(
        &self,
        cfg: &Config,
        epoch: i64,
        claim: &MarkClaim,
    ) -> Result<&Final, Error> {
        if claim.epoch < 0 || epoch < claim.epoch || epoch - claim.epoch < 2 {
            return Err("validator duty mark epoch is not final".into());
        }
        if epoch - claim.epoch > cfg.challenge {
            return Err("validator duty mark challenge expired".into());
        }
        let finality = self
            .find_final(claim.epoch)
            .ok_or("validator duty finalized reference is missing")?;
        if finality.round.is_none() {
            return Err("validator duty mark round is missing".into());
        }
        Ok(finality)
    }
    pub fn check_mark_claims(
        &self,
        cfg: &Config,
        epoch: i64,
        claims: &[MarkClaim],
    ) -> Result<(), Error> {
        if claims.is_empty() || claims.len() as i64 >= cfg.challenge {
            return Err("validator duty mark count is invalid".into());
        }
        let mut previous = -1;
        for claim in claims {
            if claim.epoch <= previous {
                return Err("validator duty marks are not ordered".into());
            }
            self.check_mark_claim(cfg, epoch, claim)?;
            previous = claim.epoch;
        }
        Ok(())
    }
    pub fn verify_mark_claim(
        &self,
        cfg: &Config,
        chain: &[u8],
        epoch: i64,
        address: &[u8],
        sets: &[MarkSet],
        claim: &MarkClaim,
    ) -> Result<(), Error> {
        let finality = self.check_mark_claim(cfg, epoch, claim)?;
        let mut matches = sets.iter().filter(|(at, _, _)| *at == claim.epoch);
        let (_, saved_chain, validators) =
            matches.next().ok_or("validator duty mark set mismatch")?;
        if matches.next().is_some()
            || saved_chain != chain
            || hash::validator_set_hash(validators)
                .map_err(|e| Error(e.to_string()))?
                .as_slice()
                != finality.set_hash
        {
            return Err("validator duty mark set mismatch".into());
        }
        let public = validators
            .public_key(address)
            .ok_or("validator duty mark signer is not in set")?;
        let vote = Vote {
            chain_id: chain.to_vec(),
            epoch_id: claim.epoch,
            round: finality.round.expect("checked round"),
            vote_type: VoteType::Precommit,
            proposal_id: finality.proposal_id.clone(),
            validator: address.to_vec(),
            signature: claim.signature.clone(),
        };
        if !hash::verify_vote(public, &vote).unwrap_or(false) {
            return Err("validator duty mark signature is invalid".into());
        }
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    pub fn apply_mark_claims(
        &self,
        cfg: &Config,
        cap: CapMode,
        chain: &[u8],
        epoch: i64,
        active: bool,
        address: &[u8],
        sets: &[MarkSet],
        claims: &[MarkClaim],
    ) -> Result<Self, Error> {
        if claims.is_empty() || claims.len() as i64 >= cfg.challenge {
            return Err("validator duty mark count is invalid".into());
        }
        let mut previous = -1;
        for claim in claims {
            if claim.epoch <= previous {
                return Err("validator duty marks are not ordered".into());
            }
            self.verify_mark_claim(cfg, chain, epoch, address, sets, claim)?;
            previous = claim.epoch;
        }
        let mut members = table(&self.members);
        let member = members.entry(address.to_vec()).or_insert_with(|| {
            if active {
                Member::live(claims[0].epoch, address.to_vec())
            } else {
                Member::shadow(address.to_vec())
            }
        });
        for claim in claims {
            member.marks.add(cfg, claim.epoch);
        }
        Ok(Self {
            members: limit(cfg, cap, epoch, members)?.into_values().collect(),
            ..self.clone()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::Validator;
    use ed25519_dalek::{Signer, SigningKey};
    fn fixture() -> (State, ValidatorSet, Vec<MarkClaim>) {
        let key = SigningKey::from_bytes(&[19; 32]);
        let set = ValidatorSet::unweighted(vec![Validator {
            address: b"member".to_vec(),
            pubkey: key.verifying_key().to_bytes().to_vec(),
        }]);
        let mut state = State::default();
        let mut claims = Vec::new();
        for epoch in [84, 98] {
            let finality = Final {
                epoch,
                round: Some(7),
                proposal_id: vec![epoch as u8; 32],
                set_hash: hash::validator_set_hash(&set).unwrap().to_vec(),
            };
            let vote = Vote {
                chain_id: b"marks-test".to_vec(),
                epoch_id: epoch,
                round: 7,
                vote_type: VoteType::Precommit,
                proposal_id: finality.proposal_id.clone(),
                validator: b"member".to_vec(),
                signature: vec![],
            };
            claims.push(MarkClaim {
                epoch,
                signature: key
                    .sign(&hash::vote_sign_bytes(&vote).unwrap())
                    .to_bytes()
                    .to_vec(),
            });
            state.finals.push(finality);
        }
        (state, set, claims)
    }
    #[test]
    fn age_boundaries_historical_set_and_atomic_multi_claim_authentication() {
        let cfg = Config::participating();
        let (state, set, claims) = fixture();
        let sets: Vec<_> = claims
            .iter()
            .map(|claim| (claim.epoch, b"marks-test".to_vec(), set.clone()))
            .collect();
        let accepted = state
            .apply_mark_claims(
                &cfg,
                CapMode::Reject,
                b"marks-test",
                100,
                true,
                b"member",
                &sets,
                &claims,
            )
            .unwrap();
        assert_eq!(
            accepted.members[0]
                .marks
                .epochs
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            vec![84, 98]
        );
        assert!(state.members.is_empty());
        assert_eq!(
            state
                .check_mark_claims(&cfg, 101, &claims)
                .unwrap_err()
                .to_string(),
            "validator duty mark challenge expired"
        );
        assert_eq!(
            state
                .check_mark_claims(&cfg, 99, &claims)
                .unwrap_err()
                .to_string(),
            "validator duty mark epoch is not final"
        );
        let mut damaged = claims.clone();
        damaged[1].signature[0] ^= 1;
        assert!(state
            .apply_mark_claims(
                &cfg,
                CapMode::Reject,
                b"marks-test",
                100,
                true,
                b"member",
                &sets,
                &damaged
            )
            .is_err());
        assert!(state.members.is_empty());
        let mut duplicate_set = sets.clone();
        duplicate_set.push(sets[0].clone());
        assert_eq!(
            state
                .apply_mark_claims(
                    &cfg,
                    CapMode::Reject,
                    b"marks-test",
                    100,
                    true,
                    b"member",
                    &duplicate_set,
                    &claims
                )
                .unwrap_err()
                .to_string(),
            "validator duty mark set mismatch"
        );
        assert!(state
            .apply_mark_claims(
                &cfg,
                CapMode::Reject,
                b"other",
                100,
                true,
                b"member",
                &sets,
                &claims
            )
            .is_err());
        let mut wrong_round = state.clone();
        wrong_round.finals[0].round = Some(8);
        assert!(wrong_round
            .apply_mark_claims(
                &cfg,
                CapMode::Reject,
                b"marks-test",
                100,
                true,
                b"member",
                &sets,
                &claims
            )
            .is_err());
        assert_eq!(State::from_bytes(&state.to_bytes()).unwrap(), state);
    }
    #[test]
    fn compact_wire_is_exact_ordered_and_cannot_overlap_legacy_proofs() {
        let cfg = Config::participating();
        let (state, _, claims) = fixture();
        let encoded = encode_marks(&claims).unwrap();
        assert_eq!(STANDARD.decode(&encoded).unwrap().len(), 2 * 72);
        assert_eq!(decode_marks(&cfg, &encoded).unwrap(), claims);
        assert!(decode_marks(&cfg, &[]).is_err());
        assert!(decode_marks(&cfg, &encode_marks(&vec![claims[0].clone(); 16]).unwrap()).is_err());
        assert!(state
            .check_mark_claims(&cfg, 100, &[claims[1].clone(), claims[0].clone()])
            .is_err());
        assert!(state
            .check_mark_claims(&cfg, 100, &[claims[0].clone(), claims[0].clone()])
            .is_err());
        let message = format!(
            "{{\"duty_marks\":\"{}\"}}",
            String::from_utf8(encoded.clone()).unwrap()
        );
        assert!(matches!(
            evidence_of_message(true, &cfg, Some(message.as_bytes())).unwrap(),
            Evidence::Marks(_)
        ));
        assert!(matches!(
            evidence_of_message(false, &cfg, Some(message.as_bytes())).unwrap(),
            Evidence::Pulse
        ));
        let overlap = format!(
            "{{\"duty_vote\":\"\",\"duty_marks\":\"{}\"}}",
            String::from_utf8(encoded).unwrap()
        );
        assert_eq!(
            evidence_of_message(true, &cfg, Some(overlap.as_bytes()))
                .unwrap_err()
                .to_string(),
            "validator duty proof formats overlap"
        );
    }
}
