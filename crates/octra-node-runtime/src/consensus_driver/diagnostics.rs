use super::{BTreeMap, Bytes, Driver, Error, Host, Publication, RoundSync, ValidatorSet, Wire};
use octra_node_protocol::status_rpc::consensus::{Round, RoundPeer, Votes, Witness};
#[derive(Clone, Debug)]
pub struct Diagnostics {
    pub chain: Bytes,
    pub address: Bytes,
    pub validators: ValidatorSet,
    pub voting: bool,
    pub issue: Option<String>,
    pub round: Round,
    pub round_peers: Vec<RoundPeer>,
    pub votes: Votes,
    pub witnesses: BTreeMap<Bytes, Witness>,
}
impl Diagnostics {
    pub fn agreed(&self, now: f64) -> Result<bool, Error> {
        let mut signers = self
            .round_peers
            .iter()
            .filter(|peer| {
                let age = now - peer.last_seen;
                peer.state.epoch_id == self.round.epoch_id
                    && peer.state.round.abs_diff(self.round.round) <= 2
                    && (0. ..=30.).contains(&age)
            })
            .map(|p| p.validator_addr.clone())
            .collect::<Vec<_>>();
        if self.voting && self.validators.is_validator(&self.address) {
            signers.push(self.address.clone());
        }
        self.validators
            .has_quorum_at(&self.chain, self.round.epoch_id, &signers)
    }
}
impl<H: Host, C: Publication> Driver<H, C> {
    pub(super) fn remember_round_peer(&mut self, sync: &RoundSync) {
        let now = Self::wall_time();
        let later = |p: &RoundPeer| {
            sync.epoch_id > p.state.epoch_id
                || sync.epoch_id == p.state.epoch_id
                    && (sync.round > p.state.round
                        || sync.round == p.state.round && (sync.step as u8) > (p.state.step as u8))
        };
        if self.round_peers.get(&sync.validator).is_none_or(later) {
            self.round_peers.insert(
                sync.validator.clone(),
                RoundPeer {
                    validator_addr: sync.validator.clone(),
                    state: Round {
                        epoch_id: sync.epoch_id,
                        round: sync.round,
                        step: sync.step,
                    },
                    last_seen: now,
                },
            );
        }
    }
    pub(super) fn diagnostics(
        &self,
        ready: bool,
        issue: Option<&str>,
    ) -> Result<Diagnostics, Error> {
        let state = self.engine.state();
        let validators = self.engine.validators();
        let mut witnesses = BTreeMap::new();
        for validator in &validators.validators {
            if let Some((sync, seen_at)) = self.round_pool.reply(state.height, &validator.address) {
                if !sync.request {
                    witnesses.insert(
                        validator.address.clone(),
                        Witness {
                            wire: sync.encode()?,
                            seen_at: *seen_at,
                        },
                    );
                }
            }
        }
        Ok(Diagnostics {
            chain: self.chain.clone(),
            address: self.address.clone(),
            validators: validators.clone(),
            voting: ready,
            issue: issue.map(str::to_owned),
            round: Round {
                epoch_id: state.height,
                round: state.round,
                step: state.step,
            },
            round_peers: self.round_peers.values().cloned().collect(),
            votes: Votes::of_votes(validators, &self.engine.current_votes()),
            witnesses,
        })
    }
}
