// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Signed epoch-root queries over the authenticated swarm. Independent leases
//! prevent one cancelled caller from deleting another caller's responses.
use num_bigint::BigInt;
use octra_node_protocol::{
    consensus::{
        codec::Wire,
        driver_policy, hash, policy,
        root_query::{Lease, RootQueries},
        Bytes, EpochRootQuery, EpochRootResponse, Error, ValidatorSet,
    },
    network::{frame::Frame, session::Peer, swarm::Swarm, verify_ed25519},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::time::Instant;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub responder_addr: Bytes,
    pub responder_head_epoch: i64,
    pub state_root: Option<Bytes>,
}
#[derive(Clone, Copy)]
pub enum WaitFor {
    SourceAgreement,
    ConsensusQuorum,
}
/// Driver state is trusted local input, never extracted from a peer reply.
pub struct State {
    pub active: ValidatorSet,
    pub stake: ValidatorSet,
    pub height: i64,
    pub head: i64,
}
#[async_trait::async_trait]
pub trait Host: Send + Sync + 'static {
    async fn state(&self) -> Result<State, Error>;
    async fn root(&self, epoch: i64) -> Result<Option<Bytes>, Error>;
    fn sign(&self, bytes: &[u8]) -> Result<Bytes, Error>;
    fn remember(&self, epoch: i64, response: &Response);
    async fn request_missing_finalize(
        &self,
        epoch: i64,
        responses: &[Response],
    ) -> Result<(), Error>;
}
struct Inner<H> {
    chain: Bytes,
    address: Bytes,
    host: H,
    swarm: Swarm,
    queries: Mutex<RootQueries<Response>>,
}
pub struct EpochRoots<H>(Arc<Inner<H>>);
impl<H> Clone for EpochRoots<H> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
struct Reader<H> {
    inner: Arc<Inner<H>>,
    lease: Lease,
}
impl<H> Drop for Reader<H> {
    fn drop(&mut self) {
        self.inner
            .queries
            .lock()
            .expect("epoch root queries")
            .leave(self.lease);
    }
}
impl<H: Host> EpochRoots<H> {
    pub fn new(chain: Bytes, address: Bytes, host: H, swarm: Swarm) -> Self {
        Self(Arc::new(Inner {
            chain,
            address,
            host,
            swarm,
            queries: Mutex::new(RootQueries::default()),
        }))
    }
    /// The outer driver handles operational errors as native query diagnostics.
    /// False means the frame belongs to another consensus service.
    pub async fn handle(&self, peer: &Peer, frame: &Frame) -> Result<bool, Error> {
        match frame.message {
            0x34 => {
                let q = EpochRootQuery::decode(&frame.payload)?;
                if q.chain_id != self.0.chain {
                    return Ok(true);
                }
                let state = self.0.host.state().await?;
                if !state.active.is_validator(&self.0.address) {
                    return Ok(true);
                }
                let mut response = EpochRootResponse {
                    chain_id: self.0.chain.clone(),
                    epoch_id: q.epoch_id,
                    state_root: self.0.host.root(q.epoch_id).await?,
                    responder_addr: self.0.address.clone(),
                    responder_head_epoch: state.head,
                    signature: vec![],
                };
                response.signature = self
                    .0
                    .host
                    .sign(&hash::epoch_root_response_sign_bytes(&response)?)?;
                peer.enqueue_wait(Frame {
                    message: 0x35,
                    payload: response.encode()?,
                })
                .await;
                Ok(true)
            }
            0x35 => {
                let response = EpochRootResponse::decode(&frame.payload)?;
                if response.chain_id != self.0.chain
                    || !self
                        .0
                        .queries
                        .lock()
                        .expect("epoch root queries")
                        .listening(response.epoch_id)
                {
                    return Ok(true);
                }
                let state = self.0.host.state().await?;
                let Some(key) = state.active.public_key(&response.responder_addr) else {
                    return Ok(true);
                };
                if !verify_ed25519(
                    key,
                    &hash::epoch_root_response_sign_bytes(&response)?,
                    &response.signature,
                ) {
                    self.0.swarm.report_peer(peer, b"bad_signature_epoch_root");
                    return Ok(true);
                }
                let record = Response {
                    responder_addr: response.responder_addr,
                    responder_head_epoch: response.responder_head_epoch,
                    state_root: response.state_root,
                };
                self.0.host.remember(response.epoch_id, &record);
                self.0.queries.lock().expect("epoch root queries").add(
                    response.epoch_id,
                    record,
                    |a, b| a.responder_addr == b.responder_addr,
                );
                Ok(true)
            }
            _ => Ok(false),
        }
    }
    pub async fn query(
        &self,
        epoch: i64,
        timeout: f64,
        wait_for: WaitFor,
        request_next: bool,
    ) -> Result<Vec<Response>, Error> {
        let lease = self
            .0
            .queries
            .lock()
            .expect("epoch root queries")
            .join(epoch)?;
        let reader = Reader {
            inner: self.0.clone(),
            lease,
        };
        let payload = EpochRootQuery {
            chain_id: self.0.chain.clone(),
            epoch_id: epoch,
        }
        .encode()?;
        self.0
            .swarm
            .broadcast(
                Frame {
                    message: 0x34,
                    payload,
                },
                None,
                false,
            )
            .await
            .map_err(|e| Error::from(e.to_string()))?;
        let nanos = driver_policy::deadline_after(0, timeout);
        let deadline = Instant::now()
            + Duration::from_nanos(u64::try_from(nanos).expect("bounded native deadline"));
        let collected = loop {
            let records = self
                .0
                .queries
                .lock()
                .expect("epoch root queries")
                .read(reader.lease)
                .to_vec();
            if Instant::now() >= deadline
                || reached(
                    &self.0.chain,
                    epoch,
                    &self.0.host.state().await?.stake,
                    wait_for,
                    &records,
                )?
            {
                break records;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        let state = self.0.host.state().await?;
        if request_next && epoch == state.head && state.height.wrapping_sub(state.head) == 1 {
            self.0
                .host
                .request_missing_finalize(state.height, &collected)
                .await?;
        }
        Ok(collected)
    }
}
pub fn reached(
    chain: &[u8],
    epoch: i64,
    stake: &ValidatorSet,
    wait_for: WaitFor,
    records: &[Response],
) -> Result<bool, Error> {
    match wait_for {
        WaitFor::SourceAgreement => {
            let set = stake.for_epoch(chain, epoch)?;
            let mut counts: BTreeMap<&[u8], (BigInt, i64)> = BTreeMap::new();
            for r in records {
                if let Some(root) = &r.state_root {
                    let total = counts.entry(root).or_insert_with(|| (BigInt::from(0), 0));
                    total.0 += set.weight(&r.responder_addr).cloned().unwrap_or_default();
                    total.1 += 1;
                    if driver_policy::catchup_source_agreement_reached(
                        &set,
                        policy::quorum_active(chain, epoch),
                        total.1,
                        &total.0,
                    ) {
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        }
        WaitFor::ConsensusQuorum => {
            let roots: BTreeSet<_> = records
                .iter()
                .filter_map(|r| r.state_root.as_ref())
                .collect();
            for root in roots {
                let signers: BTreeSet<_> = records
                    .iter()
                    .filter(|r| r.state_root.as_ref() == Some(root))
                    .map(|r| r.responder_addr.clone())
                    .collect();
                if stake.has_quorum_at(chain, epoch, &signers.into_iter().collect::<Vec<_>>())? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
    }
}
