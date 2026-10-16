use crate::{
    consensus::{RoundStep, ValidatorSet, Vote, VoteType},
    light_rpc::json::{self, array, boolean, number, object, optional, string},
    oce1::Error,
};
use num_bigint::BigInt;
use num_traits::Zero;
use std::collections::BTreeMap;
#[derive(Clone, Debug)]
pub struct Peer {
    pub responder_addr: Vec<u8>,
    pub head_epoch: i64,
    pub checked_epoch: i64,
    pub state_root: Option<Vec<u8>>,
    pub last_seen: f64,
    pub source: Vec<u8>,
}
#[derive(Clone, Debug)]
pub struct Round {
    pub epoch_id: i64,
    pub round: i64,
    pub step: RoundStep,
}
#[derive(Clone, Debug)]
pub struct RoundPeer {
    pub validator_addr: Vec<u8>,
    pub state: Round,
    pub last_seen: f64,
}
#[derive(Clone, Debug)]
pub struct Tally {
    pub proposal_id: Vec<u8>,
    pub voters: i64,
    pub weight: BigInt,
}
#[derive(Clone, Debug)]
pub struct Votes {
    pub prevotes: Vec<Tally>,
    pub precommits: Vec<Tally>,
    pub quorum: i64,
    pub quorum_weight: BigInt,
}
#[derive(Clone, Debug)]
pub struct Witness {
    pub wire: Vec<u8>,
    pub seen_at: f64,
}
fn float(value: f64) -> Result<Vec<u8>, Error> {
    crate::transaction::native_float(value)
        .map(String::into_bytes)
        .map_err(|e| e.to_string().into())
}
fn step(step: RoundStep) -> &'static [u8] {
    match step {
        RoundStep::Propose => b"propose",
        RoundStep::Prevote => b"prevote",
        RoundStep::Precommit => b"precommit",
    }
}
impl Round {
    pub fn to_json(&self) -> Vec<u8> {
        object(&[
            ("epoch_id", string(self.epoch_id.to_string())),
            ("round", number(self.round)),
            ("step", string(step(self.step))),
        ])
    }
}
impl Peer {
    pub fn to_json(&self, now: f64) -> Result<Vec<u8>, Error> {
        Ok(object(&[
            ("responder_addr", string(&self.responder_addr)),
            ("head_epoch", string(self.head_epoch.to_string())),
            ("checked_epoch", string(self.checked_epoch.to_string())),
            (
                "state_root",
                self.state_root
                    .as_ref()
                    .map_or_else(json::null, |v| string(hex::encode(v))),
            ),
            ("source", string(&self.source)),
            ("age_sec", float((now - self.last_seen).max(0.))?),
        ]))
    }
}
impl RoundPeer {
    pub fn to_json(&self, now: f64) -> Result<Vec<u8>, Error> {
        Ok(object(&[
            ("validator_addr", string(&self.validator_addr)),
            ("epoch_id", string(self.state.epoch_id.to_string())),
            ("round", number(self.state.round)),
            ("step", string(step(self.state.step))),
            ("age_sec", float((now - self.last_seen).max(0.))?),
        ]))
    }
}
impl Votes {
    pub fn of_votes(set: &ValidatorSet, votes: &[Vote]) -> Self {
        let tally = |kind| {
            let mut rows: BTreeMap<Vec<u8>, (i64, BigInt)> = BTreeMap::new();
            for vote in votes.iter().filter(|v| v.vote_type == kind) {
                let row = rows
                    .entry(vote.proposal_id.clone())
                    .or_insert_with(|| (0, BigInt::zero()));
                row.0 += 1;
                if let Some(weight) = set.weight(&vote.validator) {
                    row.1 += weight;
                }
            }
            let mut rows = rows
                .into_iter()
                .map(|(proposal_id, (voters, weight))| Tally {
                    proposal_id,
                    voters,
                    weight,
                })
                .collect::<Vec<_>>();
            rows.sort_by(|a, b| {
                b.weight
                    .cmp(&a.weight)
                    .then_with(|| b.voters.cmp(&a.voters))
                    .then_with(|| a.proposal_id.cmp(&b.proposal_id))
            });
            rows
        };
        Self {
            prevotes: tally(VoteType::Prevote),
            precommits: tally(VoteType::Precommit),
            quorum: set.quorum,
            quorum_weight: set.quorum_weight.clone(),
        }
    }
    pub fn to_json(&self) -> Vec<u8> {
        let tallies = |values: &[Tally]| {
            array(values.iter().map(|v| {
                object(&[
                    ("proposal_id", string(hex::encode(&v.proposal_id))),
                    ("voters", number(v.voters)),
                    ("weight", string(v.weight.to_string())),
                ])
            }))
        };
        object(&[
            ("prevotes", tallies(&self.prevotes)),
            ("precommits", tallies(&self.precommits)),
            ("quorum", number(self.quorum)),
            ("quorum_weight", string(self.quorum_weight.to_string())),
        ])
    }
}
impl Witness {
    pub fn to_json(&self, validator: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(object(&[
            ("validator", string(validator)),
            ("seen_at", float(self.seen_at)?),
            ("round_sync", string(json::base64(&self.wire))),
        ]))
    }
}
pub struct View<'a> {
    pub enabled: bool,
    pub voting: bool,
    pub voting_reason: Option<&'a [u8]>,
    pub round_state: Option<&'a Round>,
    pub round_peers: &'a [RoundPeer],
    pub round_votes: Option<&'a Votes>,
    pub round_agreed: bool,
    pub peers: &'a [Peer],
    pub diagnostics: Option<&'a crate::network::peer_diag::Diagnostics>,
}
impl View<'_> {
    pub fn to_json(&self, now: f64) -> Result<Vec<u8>, Error> {
        Ok(object(&[
            ("enabled", boolean(self.enabled)),
            ("voting", boolean(self.voting)),
            ("voting_reason", optional(self.voting_reason)),
            (
                "round_state",
                self.round_state.map_or_else(json::null, Round::to_json),
            ),
            (
                "round_peers",
                array(
                    self.round_peers
                        .iter()
                        .map(|v| v.to_json(now))
                        .collect::<Result<Vec<_>, _>>()?,
                ),
            ),
            (
                "round_votes",
                self.round_votes.map_or_else(json::null, Votes::to_json),
            ),
            ("round_agreed", boolean(self.round_agreed)),
            (
                "peers",
                array(
                    self.peers
                        .iter()
                        .map(|v| v.to_json(now))
                        .collect::<Result<Vec<_>, _>>()?,
                ),
            ),
            (
                "scores",
                match self.diagnostics {
                    None => b"[]".to_vec(),
                    Some(v) => v.scores_json(now)?,
                },
            ),
            (
                "p2p_diagnostics",
                self.diagnostics.map_or_else(
                    json::null,
                    super::super::network::peer_diag::Diagnostics::to_json,
                ),
            ),
        ]))
    }
}
