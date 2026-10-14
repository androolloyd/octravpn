// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Signed native finality acquisition over catch-up range messages. Delivery
//! queues a certificate for the driver; only authenticated execution can commit it.
use crate::epoch_roots::Response as RootResponse;
use octra_node_protocol::{
    consensus::{
        codec::Wire,
        driver_policy::{self, QueryWindow},
        finality_query::{self, Plan, Query, Route},
        hash, Bytes, CatchupEpochRecord, CatchupQuery, CatchupResponse, Error, Finalize,
        ValidatorSet,
    },
    network::{domain_hash, frame::Frame, handshake, session::Peer, swarm::Swarm, verify_ed25519},
};
use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::{broadcast, Mutex as AsyncMutex};

mod range;
pub use range::RangePlan;

pub enum Range {
    Found {
        records: Vec<CatchupEpochRecord>,
        next_epoch: Option<i64>,
    },
    NotFound,
    Internal(Bytes),
}
#[async_trait::async_trait]
pub trait Host: Send + Sync + 'static {
    fn active_validators(&self) -> Result<ValidatorSet, Error>;
    async fn validators(&self, epoch: i64) -> Result<ValidatorSet, Error>;
    async fn range_plan(&self) -> Result<RangePlan, Error>;
    async fn lookup(&self, from_epoch: i64, max_epochs: i64) -> Result<Range, Error>;
    fn sign(&self, bytes: &[u8]) -> Result<Bytes, Error>;
    fn remember(&self, checked_epoch: i64, response: RootResponse);
    /// Queue for the driver's ordinary finality admission. Do not await bundle
    /// fetching here: a connection handler must remain free to receive replies.
    fn finalized(&self, peer: &Peer, finalized: Finalize) -> Result<(), Error>;
}
#[derive(Default)]
struct Windows {
    retry: Query,
    missing: Option<(Bytes, i64)>,
    proof: Option<(Bytes, i64)>,
    proof_owner: Option<Arc<()>>,
    range: Option<range::Slot>,
}
impl Windows {
    fn epoch(&self, id: &[u8]) -> Option<i64> {
        [&self.missing, &self.proof]
            .into_iter()
            .flatten()
            .find(|(key, _)| key == id)
            .map(|(_, epoch)| *epoch)
    }
}
struct Inner<H> {
    chain: Bytes,
    address: Bytes,
    host: H,
    swarm: Swarm,
    clock: Arc<dyn Fn() -> i64 + Send + Sync>,
    windows: Mutex<Windows>,
    proofs: AsyncMutex<()>,
    ranges: AsyncMutex<()>,
    delivered: broadcast::Sender<(Bytes, Finalize)>,
}
struct ProofReader<H> {
    inner: Arc<Inner<H>>,
    owner: Arc<()>,
}
impl<H> ProofReader<H> {
    fn active(&self) -> bool {
        self.inner
            .windows
            .lock()
            .expect("finality windows")
            .proof_owner
            .as_ref()
            .is_some_and(|owner| Arc::ptr_eq(owner, &self.owner))
    }
}
impl<H> Drop for ProofReader<H> {
    fn drop(&mut self) {
        let mut windows = self.inner.windows.lock().expect("finality windows");
        if windows
            .proof_owner
            .as_ref()
            .is_some_and(|owner| Arc::ptr_eq(owner, &self.owner))
        {
            windows.proof = None;
            windows.proof_owner = None;
        }
    }
}
pub struct Finality<H>(Arc<Inner<H>>);
impl<H> Clone for Finality<H> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
/// Eligible root responders, with the native sorted/deduplicated node IDs.
pub fn peer_ids(set: &ValidatorSet, epoch: i64, roots: &[RootResponse], proof: bool) -> Vec<Bytes> {
    let peers: BTreeSet<_> = roots
        .iter()
        .filter(|r| r.responder_head_epoch >= epoch)
        .filter_map(|r| set.public_key(&r.responder_addr))
        .map(handshake::node_id)
        .collect();
    peers
        .into_iter()
        .take(if proof {
            usize::MAX
        } else {
            (set.f + 2).max(1) as usize
        })
        .collect()
}
fn request_id(address: &[u8], epoch: i64, now: i64, attempt: Option<i64>) -> Result<Bytes, Error> {
    let (domain, suffix): (&[u8], String) = match attempt {
        Some(attempt) => (
            b"octra:finality_query_request",
            format!(":{epoch}:{attempt}:{now}"),
        ),
        None => (b"octra:finality_proof_request", format!(":{epoch}:{now}")),
    };
    hash::mark_complete_catchup_request(&domain_hash(
        domain,
        &[address, suffix.as_bytes()].concat(),
    ))
}
impl<H: Host> Finality<H> {
    pub fn new(
        chain: Bytes,
        address: Bytes,
        host: H,
        swarm: Swarm,
        clock: Arc<dyn Fn() -> i64 + Send + Sync>,
    ) -> Self {
        Self(Arc::new(Inner {
            chain,
            address,
            host,
            swarm,
            clock,
            windows: Mutex::new(Windows::default()),
            proofs: AsyncMutex::new(()),
            ranges: AsyncMutex::new(()),
            delivered: broadcast::channel(64).0,
        }))
    }
    pub async fn request(
        &self,
        epoch: i64,
        roots: &[RootResponse],
    ) -> Result<Option<Bytes>, Error> {
        self.send(epoch, roots, false, None).await
    }
    pub async fn request_proof(
        &self,
        epoch: i64,
        roots: &[RootResponse],
    ) -> Result<Option<Bytes>, Error> {
        self.send(epoch, roots, true, None).await
    }
    /// Await a native explicit proof request without blocking peer handlers.
    /// The consumer checks its historical QC and parent in `accept`. Rejected
    /// candidates do not prevent a valid peer's later answer. Cancellation removes only this reader's
    /// proof window, preserving independent driver requests and retry state.
    pub async fn query_proof<F: std::future::Future<Output = Result<bool, Error>>>(
        &self,
        epoch: i64,
        roots: &[RootResponse],
        timeout: f64,
        mut accept: impl FnMut(Finalize) -> F,
    ) -> Result<Option<Finalize>, Error> {
        let duration = Duration::from_secs_f64(driver_policy::bounded_timeout(timeout));
        if duration.is_zero() {
            return Ok(None);
        }
        tokio::time::timeout(duration, async {
            let _serial = self.0.proofs.lock().await;
            let reader = ProofReader {
                inner: self.0.clone(),
                owner: Arc::new(()),
            };
            let mut delivered = self.0.delivered.subscribe();
            let Some(id) = self
                .send(epoch, roots, true, Some(reader.owner.clone()))
                .await?
            else {
                return Ok(None);
            };
            loop {
                let (request, finalized) = delivered
                    .recv()
                    .await
                    .map_err(|e| Error::from(format!("finality proof delivery: {e}")))?;
                if !reader.active() {
                    return Ok(None);
                }
                if request == id && finalized.epoch_id == epoch && accept(finalized.clone()).await?
                {
                    // Revocation may occur while historical storage or proof
                    // verification is pending. Never return a revoked result.
                    return Ok(reader.active().then_some(finalized));
                }
            }
        })
        .await
        .unwrap_or(Ok(None))
    }
    async fn send(
        &self,
        epoch: i64,
        roots: &[RootResponse],
        proof: bool,
        owner: Option<Arc<()>>,
    ) -> Result<Option<Bytes>, Error> {
        let set = self.0.host.validators(epoch).await?;
        let peers = peer_ids(&set, epoch, roots, proof);
        if peers.is_empty() {
            return Ok(None);
        }
        let now = (self.0.clock)();
        let id = {
            let mut windows = self.0.windows.lock().expect("finality windows");
            if proof {
                let id = request_id(&self.0.address, epoch, now, None)?;
                windows.proof = Some((id.clone(), epoch));
                windows.proof_owner = owner;
                id
            } else {
                let Plan::Send(next) = windows.retry.plan(now, epoch) else {
                    return Ok(None);
                };
                let attempts = match next {
                    Query::Sent { attempts, .. } => attempts,
                    Query::Idle => 0,
                };
                let id = request_id(&self.0.address, epoch, now, Some(attempts))?;
                windows.retry = next;
                windows.missing = Some((id.clone(), epoch));
                id
            }
        };
        let frame = Frame {
            message: 0x3a,
            payload: CatchupQuery {
                chain_id: self.0.chain.clone(),
                request_id: id.clone(),
                from_epoch: epoch,
                max_epochs: 1,
            }
            .encode()?,
        };
        futures::future::join_all(
            peers
                .iter()
                .map(|id| self.0.swarm.send_to(id, frame.clone())),
        )
        .await;
        Ok(Some(id))
    }
    pub fn close(&self) {
        let mut windows = self.0.windows.lock().expect("finality windows");
        windows.range = None;
        windows.missing = None;
        windows.proof = None;
        windows.proof_owner = None;
    }
    pub fn clear_proofs(&self) {
        let mut windows = self.0.windows.lock().expect("finality windows");
        windows.proof = None;
        windows.proof_owner = None;
    }
    /// Operational decode/lookup failures are logged by the enclosing driver.
    /// Unknown message types return false. Current windows bound reply admission.
    pub async fn handle(&self, peer: &Peer, frame: &Frame) -> Result<bool, Error> {
        match frame.message {
            0x38 | 0x3a => {
                let v2 = frame.message == 0x3a;
                let q = CatchupQuery::decode(&frame.payload)?;
                if q.chain_id != self.0.chain
                    || !self
                        .0
                        .host
                        .active_validators()?
                        .is_validator(&self.0.address)
                {
                    return Ok(true);
                }
                let (status, error_code, records, next_epoch) =
                    match self.0.host.lookup(q.from_epoch, q.max_epochs).await? {
                        Range::Found {
                            records,
                            next_epoch,
                        } => (b"ok".to_vec(), None, records, next_epoch),
                        Range::NotFound => (
                            b"not_found".to_vec(),
                            Some(b"no_data".to_vec()),
                            vec![],
                            None,
                        ),
                        Range::Internal(reason) => {
                            (b"internal_error".to_vec(), Some(reason), vec![], None)
                        }
                    };
                let mut response = CatchupResponse {
                    chain_id: self.0.chain.clone(),
                    request_id: q.request_id,
                    status,
                    error_code,
                    records,
                    next_epoch,
                    responder_addr: self.0.address.clone(),
                    signature: vec![],
                };
                let sign = if v2 && hash::catchup_request_is_complete(&response.request_id) {
                    hash::catchup_complete_sign_bytes(q.from_epoch, &response)?
                } else {
                    let root = if v2 {
                        hash::catchup_records_root(&response.records)?
                    } else {
                        hash::catchup_records_root_v1(&response.records)?
                    };
                    hash::catchup_response_sign_bytes(
                        &response.chain_id,
                        &response.request_id,
                        &response.responder_addr,
                        q.from_epoch,
                        &root,
                    )?
                };
                response.signature = self.0.host.sign(&sign)?;
                peer.enqueue_wait(Frame {
                    message: if v2 { 0x3b } else { 0x39 },
                    payload: response.encode(v2)?,
                })
                .await;
                Ok(true)
            }
            0x39 | 0x3b => {
                let v2 = frame.message == 0x3b;
                let response = CatchupResponse::decode(&frame.payload, v2)?;
                if response.chain_id != self.0.chain {
                    return Ok(true);
                }
                let request = {
                    let windows = self.0.windows.lock().expect("finality windows");
                    windows
                        .epoch(&response.request_id)
                        .map(|epoch| {
                            (
                                QueryWindow {
                                    from_epoch: epoch,
                                    max_epochs: 1,
                                },
                                None,
                            )
                        })
                        .or_else(|| {
                            windows
                                .range
                                .as_ref()
                                .filter(|slot| slot.id == response.request_id)
                                .map(|slot| (slot.window, Some(slot.owner.clone())))
                        })
                };
                let Some((window, owner)) = request else {
                    return Ok(true);
                };
                let epoch = window.from_epoch;
                if !window.contains_records(&response.records) {
                    return Ok(true);
                }
                let set = self
                    .0
                    .host
                    .validators(response.records.last().map_or(epoch, |r| r.epoch_id))
                    .await?;
                let Some(public) = set.public_key(&response.responder_addr) else {
                    return Ok(true);
                };
                let root = if v2 {
                    hash::catchup_records_root(&response.records)?
                } else {
                    hash::catchup_records_root_v1(&response.records)?
                };
                let legacy = hash::catchup_response_sign_bytes(
                    &response.chain_id,
                    &response.request_id,
                    &response.responder_addr,
                    epoch,
                    &root,
                )?;
                let complete = v2
                    && hash::catchup_request_is_complete(&response.request_id)
                    && verify_ed25519(
                        public,
                        &hash::catchup_complete_sign_bytes(epoch, &response)?,
                        &response.signature,
                    );
                let proof = finality_query::proof(
                    complete,
                    verify_ed25519(public, &legacy, &response.signature),
                    v2 && driver_policy::catchup_records_complete(&response.records),
                );
                let scope = finality_query::scope(
                    hash::catchup_request_is_complete(&response.request_id),
                    owner.is_none(),
                );
                let route = finality_query::route(scope, proof);
                match route {
                    Route::IgnoreLegacy => return Ok(true),
                    Route::Reject => {
                        self.0
                            .swarm
                            .report_peer(peer, b"bad_signature_catchup_range");
                        return Ok(true);
                    }
                    Route::Complete | Route::Finality => (),
                    Route::LegacyRange => {
                        if !driver_policy::response_source_matches(
                            &set,
                            &peer.hello().node_id,
                            &response.responder_addr,
                        ) {
                            self.0
                                .swarm
                                .report_peer(peer, b"relayed_legacy_catchup_range");
                            return Ok(true);
                        }
                    }
                }
                let response = Arc::new(if route == Route::LegacyRange {
                    let Some(normalized) =
                        driver_policy::normalize_legacy_range_response(&response)
                    else {
                        return Ok(true);
                    };
                    normalized
                } else {
                    response
                });
                // Host lookup can yield while this query is cancelled/replaced.
                // A stale response cannot enter a new reader's collection, even
                // when request IDs collide.
                {
                    let mut windows = self.0.windows.lock().expect("finality windows");
                    if let Some(owner) = &owner {
                        let Some(slot) = windows.range.as_mut().filter(|slot| {
                            slot.id == response.request_id && Arc::ptr_eq(&slot.owner, owner)
                        }) else {
                            return Ok(true);
                        };
                        if !slot
                            .responses
                            .iter()
                            .any(|prior| prior.responder_addr == response.responder_addr)
                        {
                            slot.responses.insert(0, response.clone());
                        }
                    } else if windows.epoch(&response.request_id) != Some(epoch) {
                        return Ok(true);
                    }
                }
                if matches!(route, Route::Complete | Route::LegacyRange) {
                    let checked = response.records.last().map_or(epoch, |r| r.epoch_id);
                    self.0.host.remember(
                        checked,
                        RootResponse {
                            responder_addr: response.responder_addr.clone(),
                            responder_head_epoch: response
                                .next_epoch
                                .map_or(checked, |next| next.wrapping_sub(1)),
                            state_root: response.records.last().map(|r| r.state_root.clone()),
                        },
                    );
                }
                if owner.is_some() {
                    return Ok(true);
                }
                if let [record] = response.records.as_slice() {
                    if record.epoch_id == epoch {
                        if let Some(proof) = &record.finality {
                            if proof.finalize.epoch_id == epoch {
                                self.0.host.finalized(peer, proof.finalize.clone())?;
                                let _ = self
                                    .0
                                    .delivered
                                    .send((response.request_id.clone(), proof.finalize.clone()));
                            }
                        }
                    }
                }
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use octra_node_protocol::consensus::Validator;
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};
    #[test]
    fn native_finality_peers_and_request_ids_match() {
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/fixtures/finality-query.json")).unwrap();
        let source: Value =
            serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
        assert_eq!(fixture["upstream_commit"], source["upstream_commit"]);
        assert_eq!(fixture["source_sha256"], source["files"]);
        assert_eq!(fixture["instrumentation"], json!({}));
        assert_eq!(
            fixture["oracle_sha256"],
            hex::encode(Sha256::digest(include_bytes!(
                "../../../scripts/node-port/finality-query-oracle.ml"
            )))
        );
        assert_eq!(
            fixture["runner_sha256"],
            hex::encode(Sha256::digest(include_bytes!(
                "../../../scripts/node-port/native-oracle.py"
            )))
        );
        for (index, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
            let input = &case["input"];
            let set = ValidatorSet::unweighted(
                (1..=input["validators"].as_u64().unwrap())
                    .map(|n| Validator {
                        address: format!("v{n}").into_bytes(),
                        pubkey: SigningKey::from_bytes(&[n as u8; 32])
                            .verifying_key()
                            .to_bytes()
                            .to_vec(),
                    })
                    .collect(),
            );
            let epoch = input["epoch"].as_str().unwrap().parse().unwrap();
            let now = input["now"].as_str().unwrap().parse().unwrap();
            let attempt = input["attempt"].as_i64().unwrap();
            let address = hex::decode(input["address"].as_str().unwrap()).unwrap();
            let records = input["records"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| RootResponse {
                    responder_addr: r["address"].as_str().unwrap().as_bytes().to_vec(),
                    responder_head_epoch: r["head"].as_str().unwrap().parse().unwrap(),
                    state_root: None,
                })
                .collect::<Vec<_>>();
            assert_eq!(
                json!({
                    "peers":peer_ids(&set,epoch,&records,false).iter().map(hex::encode).collect::<Vec<_>>(),
                    "proof_peers":peer_ids(&set,epoch,&records,true).iter().map(hex::encode).collect::<Vec<_>>(),
                    "request":hex::encode(request_id(&address,epoch,now,Some(attempt)).unwrap()),
                    "proof_request":hex::encode(request_id(&address,epoch,now,None).unwrap()),
                }),
                case["expected"],
                "native finality query {index}"
            );
        }
    }
}
