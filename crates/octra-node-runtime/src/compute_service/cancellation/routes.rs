// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Actor-owned bounded reverse routes and durable cancellation output quotas.
//! The caller records a route only after protocol admission and quota commit.
use super::{coordinator, session_key, CancelRound, Error, HistoryWorker, Jobs, Message, Result};
use std::collections::BTreeMap;

#[derive(Default)]
pub struct Routes {
    paths: BTreeMap<Vec<u8>, (Vec<u8>, i64)>,
}
pub enum Delivery {
    None,
    Relay { source: Vec<u8>, payload: Vec<u8> },
    Send { peer: Vec<u8>, payload: Vec<u8> },
}
#[derive(Clone, Debug)]
// Keep native owned command/result records inline without changing their API.
#[allow(clippy::large_enum_variant)]
pub enum RelayQuota {
    Bypass,
    Refuse,
    Relay,
    Transit,
    Send {
        local: bool,
    },
    Round {
        delivery: CancelRound,
        transit: bool,
    },
}
fn route(delivery: &CancelRound) -> Result<Vec<u8>> {
    let key = session_key(&delivery.cancel.caller, &delivery.cancel.session_id)?;
    Ok([delivery.origin.as_slice(), key.as_slice()].concat())
}
impl Routes {
    pub fn len(&self) -> usize {
        self.paths.len()
    }
    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }
    /// Missing finalized head discards routes, following native actor gating.
    pub fn prune(&mut self, epoch: Option<i64>) {
        let epoch = epoch.unwrap_or(i64::MAX);
        self.paths.retain(|_, (_, expires)| *expires >= epoch);
    }
    pub fn allowed(&self, rounds: bool, node: &[u8], message: &Message) -> Result<bool> {
        Ok(match message {
            Message::CancelRound(delivery) => {
                rounds && (self.paths.len() < 1024 || self.paths.contains_key(&route(delivery)?))
            }
            Message::CancelAck(ack) => {
                rounds
                    && (ack.delivery.origin == node
                        || self.paths.contains_key(&route(&ack.delivery)?))
            }
            _ => true,
        })
    }
    pub fn remember(
        &mut self,
        source: Option<&[u8]>,
        node: &[u8],
        message: &Message,
    ) -> Result<()> {
        if let (Some(peer), Message::CancelRound(delivery)) = (source, message) {
            if delivery.origin != node {
                // Admission checked this bound before executing the protocol
                // transition; do not evict a live path to admit a new origin.
                let key = route(delivery)?;
                if self.paths.len() >= 1024 && !self.paths.contains_key(&key) {
                    return Err(Error::rejected(b"compute cancel route capacity"));
                }
                self.paths.insert(key, (peer.to_vec(), delivery.expires));
            }
        }
        Ok(())
    }
    pub fn path(&self, node: &[u8], delivery: &CancelRound) -> Result<Option<Vec<u8>>> {
        if delivery.origin == node {
            return Ok(None);
        }
        Ok(self
            .paths
            .get(&route(delivery)?)
            .map(|(peer, _)| peer.clone()))
    }
    /// Received acknowledgements travel only toward their origin. A missing
    /// route never turns them into gossip. Reveal delivery has its own owner.
    pub fn delivery(
        &self,
        node: &[u8],
        source: &[u8],
        message: &Message,
        payload: Vec<u8>,
    ) -> Result<Delivery> {
        Ok(match message {
            Message::Reveal(_) => Delivery::None,
            Message::CancelAck(ack) => match self.path(node, &ack.delivery)? {
                Some(peer) => Delivery::Send { peer, payload },
                None => Delivery::None,
            },
            _ => Delivery::Relay {
                source: source.to_vec(),
                payload,
            },
        })
    }
}
impl RelayQuota {
    /// Evaluate after direct protocol admission: accepted cancellation may have
    /// just closed a session, changing which durable quota owns its relay.
    pub fn for_message(
        jobs: &Jobs,
        rounds: bool,
        node: &[u8],
        source: Option<&[u8]>,
        message: &Message,
    ) -> Result<Self> {
        Ok(match message {
            Message::Reveal(_) => Self::Bypass,
            Message::CancelRound(delivery) => Self::Round {
                transit: !jobs
                    .session_cancelled(&delivery.cancel.caller, &delivery.cancel.session_id)?,
                delivery: delivery.clone(),
            },
            Message::CancelAck(ack) if source.is_some() && ack.delivery.origin == node => {
                Self::Bypass
            }
            Message::Cancel(cancel)
                if rounds && !jobs.session_cancelled(&cancel.caller, &cancel.session_id)? =>
            {
                Self::Refuse
            }
            Message::CancelAck(ack) => {
                if jobs.session_cancelled(
                    &ack.delivery.cancel.caller,
                    &ack.delivery.cancel.session_id,
                )? {
                    Self::Relay
                } else {
                    Self::Transit
                }
            }
            Message::Cancel(cancel) => {
                if jobs.session_cancelled(&cancel.caller, &cancel.session_id)? {
                    Self::Relay
                } else {
                    Self::Transit
                }
            }
            _ => Self::Send {
                local: source.is_none(),
            },
        })
    }
    pub async fn claim(&self, history: &HistoryWorker, epoch: i64, now: i64) -> Result<bool> {
        match self {
            Self::Bypass => return Ok(true),
            Self::Refuse => return Ok(false),
            _ => {}
        }
        let quota = self.clone();
        history
            .run(move |history| {
                let allowed = match quota {
                    Self::Relay => history.claim_relay(now),
                    Self::Transit => history.claim_transit(now),
                    Self::Send { local } => history.claim_send(local, now),
                    Self::Round { delivery, transit } => {
                        let body = Message::Cancel(delivery.cancel.clone()).encode()?;
                        let id = coordinator::wire_id(&body);
                        history.relay_cancel(
                            epoch,
                            delivery.expires,
                            delivery.round,
                            &delivery.origin,
                            &id,
                            &delivery.cancel.caller,
                            &delivery.cancel.session_id,
                            None,
                            false,
                            Some(now),
                            transit,
                        )
                    }
                    Self::Bypass => Ok(true),
                    Self::Refuse => Ok(false),
                };
                allowed.map_err(|error| Error::Unavailable(error.0))
            })
            .await
    }
}
