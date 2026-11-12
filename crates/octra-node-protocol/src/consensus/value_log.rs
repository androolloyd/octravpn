//! Native authenticated proposal-plus-prevotes recovery record.
use super::{
    codec::{self, Wire},
    engine::proof_proposal_valid,
    hash,
    policy::{Protocol, QuorumPolicy},
    vote_log::{check_proof, VoteLog},
    Error, Proposal, ValidatorSet, Vote,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
#[derive(Clone, Debug, PartialEq)]
pub struct Record {
    pub proposal: Proposal,
    pub votes: Vec<Vote>,
}
impl Record {
    pub fn check(
        &self,
        policy: QuorumPolicy,
        protocol: Protocol,
        chain: &[u8],
        epoch: i64,
        set: &ValidatorSet,
    ) -> Result<(), Error> {
        let pid = hash::proposal_id(&self.proposal.header)?;
        if self.proposal.epoch_id != epoch
            || !proof_proposal_valid(chain, set, protocol, &self.proposal)?
            || self
                .votes
                .iter()
                .any(|vote| vote.round != self.proposal.round || vote.proposal_id != pid)
        {
            return Err("stored proposal statement differs".into());
        }
        check_proof(policy, chain, epoch, set, &self.votes)
    }
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let votes = self
            .votes
            .iter()
            .map(|v| v.encode().map(|wire| STANDARD.encode(wire)))
            .collect::<Result<Vec<_>, Error>>()?;
        serde_json::to_vec(&(STANDARD.encode(self.proposal.encode()?), votes))
            .map_err(|e| Error::from(e.to_string()))
    }
    pub fn save(
        &self,
        log: &mut VoteLog,
        policy: QuorumPolicy,
        protocol: Protocol,
        chain: &[u8],
        epoch: i64,
        set: &ValidatorSet,
    ) -> Result<(), Error> {
        self.check(policy, protocol, chain, epoch, set)?;
        log.value_write(self.encode()?)
    }
}
pub fn decode(wire: &[u8]) -> Result<Record, Error> {
    let (proposal, votes): (String, Vec<String>) = serde_json::from_slice(wire)
        .map_err(|_| Error::from("stored proposal record is invalid"))?;
    if votes.len() > codec::MAX_VALIDATORS {
        return Err("stored proposal record is invalid".into());
    }
    let decode64 = |s: &str| {
        STANDARD
            .decode(s)
            .map_err(|_| Error::from("stored proposal record is invalid"))
    };
    Ok(Record {
        proposal: Proposal::decode(&decode64(&proposal)?)?,
        votes: votes
            .iter()
            .map(|v| Vote::decode(&decode64(v)?))
            .collect::<Result<_, Error>>()?,
    })
}
pub fn load(
    log: &VoteLog,
    policy: QuorumPolicy,
    protocol: Protocol,
    chain: &[u8],
    epoch: i64,
    set: &ValidatorSet,
) -> Result<Option<Record>, Error> {
    let Some(wire) = log.value_read()? else {
        return Ok(None);
    };
    let record = decode(&wire)?;
    if record.proposal.epoch_id < epoch {
        return Ok(None);
    }
    record.check(policy, protocol, chain, epoch, set)?;
    Ok(Some(record))
}
