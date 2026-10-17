// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Signed native bundle fetching. Same-proposal callers are serialized so an
//! older query cannot erase a newer reader; cancellation always removes its slot.
use crate::{consensus_bundle::RawBundle, query_peers};
use octra_node_protocol::{
    consensus::{
        codec::Wire, driver_policy, hash, BundleQuery, BundleResponse, Bytes, Error, ValidatorSet,
    },
    network::{frame::Frame, session::Peer, swarm::Swarm, verify_ed25519},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex, Weak},
    time::Duration,
};
use tokio::{
    sync::{Mutex as AsyncMutex, OwnedMutexGuard},
    time::Instant,
};
type ProposalId = [u8; 32];
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub responder: Bytes,
    pub bundle: RawBundle,
}
#[async_trait::async_trait]
pub trait Host: Send + Sync + 'static {
    fn validators(&self) -> Result<ValidatorSet, Error>;
    async fn lookup(&self, proposal: &ProposalId) -> Result<Option<RawBundle>, Error>;
    fn sign(&self, bytes: &[u8]) -> Result<Bytes, Error>;
}
#[derive(Default)]
struct Slots {
    gates: BTreeMap<ProposalId, Weak<AsyncMutex<()>>>,
    replies: BTreeMap<ProposalId, Vec<Response>>,
}
struct Inner<H> {
    chain: Bytes,
    address: Bytes,
    host: H,
    swarm: Swarm,
    slots: Mutex<Slots>,
}
pub struct Bundles<H>(Arc<Inner<H>>);
impl<H> Clone for Bundles<H> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
struct Reader<H> {
    inner: Arc<Inner<H>>,
    proposal: ProposalId,
    _guard: OwnedMutexGuard<()>,
}
impl<H> Drop for Reader<H> {
    fn drop(&mut self) {
        self.inner
            .slots
            .lock()
            .expect("bundle queries")
            .replies
            .remove(&self.proposal);
    }
}
impl<H: Host> Bundles<H> {
    pub fn new(chain: Bytes, address: Bytes, host: H, swarm: Swarm) -> Self {
        Self(Arc::new(Inner {
            chain,
            address,
            host,
            swarm,
            slots: Mutex::new(Slots::default()),
        }))
    }
    /// Read a locally retained bundle without opening a remote query. This is
    /// acquisition only: callers must bind it to the expected header, epoch
    /// rules and local execution before accepting it.
    pub async fn local(&self, proposal: &ProposalId) -> Result<Option<RawBundle>, Error> {
        self.0.host.lookup(proposal).await
    }
    /// The driver logs operational errors without treating malformed query
    /// payloads as consensus votes. Unknown message types return false.
    pub async fn handle(&self, peer: &Peer, frame: &Frame) -> Result<bool, Error> {
        match frame.message {
            0x36 => {
                let query = BundleQuery::decode(&frame.payload)?;
                if query.chain_id != self.0.chain
                    || !self.0.host.validators()?.is_validator(&self.0.address)
                {
                    return Ok(true);
                }
                let id: ProposalId = query
                    .proposal_id
                    .as_slice()
                    .try_into()
                    .expect("decoded proposal id");
                let Some(bundle) = self.0.host.lookup(&id).await? else {
                    return Ok(true);
                };
                let mut response = BundleResponse {
                    chain_id: self.0.chain.clone(),
                    epoch_id: query.epoch_id,
                    proposal_id: query.proposal_id,
                    responder_addr: self.0.address.clone(),
                    tx_hashes: bundle.tx_hashes,
                    txs_json: bundle.txs_json,
                    receipts_json: bundle.receipts_json,
                    signature: vec![],
                };
                response.signature = self
                    .0
                    .host
                    .sign(&hash::bundle_response_sign_bytes(&response)?)?;
                peer.enqueue_wait(Frame {
                    message: 0x37,
                    payload: response.encode()?,
                })
                .await;
                Ok(true)
            }
            0x37 => {
                let response = BundleResponse::decode(&frame.payload)?;
                let id: ProposalId = response
                    .proposal_id
                    .as_slice()
                    .try_into()
                    .expect("decoded proposal id");
                if response.chain_id != self.0.chain
                    || !self
                        .0
                        .slots
                        .lock()
                        .expect("bundle queries")
                        .replies
                        .contains_key(&id)
                {
                    return Ok(true);
                }
                let validators = self.0.host.validators()?;
                let Some(public) = validators.public_key(&response.responder_addr) else {
                    return Ok(true);
                };
                if !verify_ed25519(
                    public,
                    &hash::bundle_response_sign_bytes(&response)?,
                    &response.signature,
                ) {
                    self.0.swarm.report_peer(peer, b"bad_signature_bundle");
                    return Ok(true);
                }
                if response.tx_hashes.len() != response.txs_json.len() {
                    return Ok(true);
                }
                let record = Response {
                    responder: response.responder_addr,
                    bundle: RawBundle {
                        tx_hashes: response.tx_hashes,
                        txs_json: response.txs_json,
                        receipts_json: response.receipts_json,
                    },
                };
                if let Some(replies) = self
                    .0
                    .slots
                    .lock()
                    .expect("bundle queries")
                    .replies
                    .get_mut(&id)
                {
                    if !replies
                        .iter()
                        .any(|prior| prior.responder == record.responder)
                    {
                        replies.insert(0, record);
                    }
                }
                Ok(true)
            }
            _ => Ok(false),
        }
    }
    async fn reader(&self, proposal: ProposalId) -> Reader<H> {
        let gate = {
            let mut slots = self.0.slots.lock().expect("bundle queries");
            slots.gates.retain(|_, gate| gate.strong_count() > 0);
            if let Some(gate) = slots.gates.get(&proposal).and_then(Weak::upgrade) {
                gate
            } else {
                let gate = Arc::new(AsyncMutex::new(()));
                slots.gates.insert(proposal, Arc::downgrade(&gate));
                gate
            }
        };
        let guard = gate.lock_owned().await;
        self.0
            .slots
            .lock()
            .expect("bundle queries")
            .replies
            .insert(proposal, vec![]);
        Reader {
            inner: self.0.clone(),
            proposal,
            _guard: guard,
        }
    }
    /// Validation binds the bundle to the expected header and execution rules.
    /// Return decoded data with acceptance to avoid parsing a large bundle twice.
    /// An operational failure stops the query; ordinary invalid bundles are None.
    pub async fn query<T>(
        &self,
        epoch: i64,
        proposal: ProposalId,
        timeout: f64,
        mut validate: impl FnMut(&Response) -> Result<Option<T>, Error>,
    ) -> Result<Option<(Response, T)>, Error> {
        let reader = self.reader(proposal).await;
        let frame = Frame {
            message: 0x36,
            payload: BundleQuery {
                chain_id: self.0.chain.clone(),
                epoch_id: epoch,
                proposal_id: proposal.to_vec(),
            }
            .encode()?,
        };
        let mut rejected = BTreeSet::new();
        let deadline = Instant::now() + duration(timeout);
        let connected = self
            .0
            .swarm
            .peers()
            .iter()
            .map(|p| p.hello().node_id.clone())
            .collect::<Vec<_>>();
        let waves = query_peers::bundle_waves(query_peers::ordered(
            &self.0.host.validators()?,
            &proposal,
            &connected,
        ));
        if waves.is_empty() {
            self.0.swarm.broadcast(frame, None, false).await?;
            return self
                .wait(&reader, deadline, &mut rejected, &mut validate)
                .await;
        }
        for (index, wave) in waves.iter().enumerate() {
            if Instant::now() >= deadline {
                return Ok(None);
            }
            futures::future::join_all(
                wave.iter()
                    .map(|id| self.0.swarm.send_to(id, frame.clone())),
            )
            .await;
            let until = if index + 1 == waves.len() {
                deadline
            } else {
                deadline.min(Instant::now() + Duration::from_millis(250))
            };
            if let Some(found) = self
                .wait(&reader, until, &mut rejected, &mut validate)
                .await?
            {
                return Ok(Some(found));
            }
        }
        Ok(None)
    }
    async fn wait<T>(
        &self,
        reader: &Reader<H>,
        deadline: Instant,
        rejected: &mut BTreeSet<Bytes>,
        validate: &mut impl FnMut(&Response) -> Result<Option<T>, Error>,
    ) -> Result<Option<(Response, T)>, Error> {
        while Instant::now() < deadline {
            let replies = self
                .0
                .slots
                .lock()
                .expect("bundle queries")
                .replies
                .get(&reader.proposal)
                .cloned()
                .unwrap_or_default();
            for response in replies {
                if rejected.insert(response.responder.clone()) {
                    if let Some(value) = validate(&response)? {
                        return Ok(Some((response, value)));
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Ok(None)
    }
}
fn duration(seconds: f64) -> Duration {
    Duration::from_nanos(
        u64::try_from(driver_policy::deadline_after(0, seconds)).expect("bounded native timeout"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use octra_node_protocol::network::{endpoint::Endpoint, session::Timeouts, swarm::Config};

    struct Empty;
    #[async_trait::async_trait]
    impl Host for Empty {
        fn validators(&self) -> Result<ValidatorSet, Error> {
            Ok(ValidatorSet::unweighted(vec![]))
        }
        async fn lookup(&self, _: &ProposalId) -> Result<Option<RawBundle>, Error> {
            Ok(None)
        }
        fn sign(&self, _: &[u8]) -> Result<Bytes, Error> {
            unreachable!()
        }
    }
    fn service() -> Bundles<Empty> {
        with_host(Empty)
    }
    fn with_host<H: Host>(host: H) -> Bundles<H> {
        let config = Config {
            chain_id: b"lifecycle-fixture".to_vec(),
            node_address: b"v1".to_vec(),
            config_hash: vec![1; 32],
            binary_hash: vec![2; 32],
            require_binary_hash: false,
            upgrade: None,
            profiles: vec![],
            allowed_public_keys: vec![],
            bootstrap: vec![],
            maximum_validators: 16,
            advertised: Endpoint {
                host: b"127.0.0.1".to_vec(),
                port: 1,
            },
            timeouts: Timeouts::default(),
            head: Arc::new(|| (0, [0; 32])),
        };
        Bundles::new(
            config.chain_id.clone(),
            config.node_address.clone(),
            host,
            Swarm::new(config, SigningKey::from_bytes(&[1; 32])).unwrap(),
        )
    }
    struct Local {
        calls: Arc<Mutex<Vec<ProposalId>>>,
        bundle: Option<RawBundle>,
        fail: bool,
    }
    #[async_trait::async_trait]
    impl Host for Local {
        fn validators(&self) -> Result<ValidatorSet, Error> {
            Ok(ValidatorSet::unweighted(vec![]))
        }
        async fn lookup(&self, id: &ProposalId) -> Result<Option<RawBundle>, Error> {
            self.calls.lock().unwrap().push(*id);
            if self.fail {
                Err("retained bundle unavailable".into())
            } else {
                Ok(self.bundle.clone())
            }
        }
        fn sign(&self, _: &[u8]) -> Result<Bytes, Error> {
            unreachable!()
        }
    }
    #[tokio::test]
    async fn local_lookup_is_explicit_and_never_creates_a_remote_reader() {
        let id = [7; 32];
        let raw = RawBundle {
            tx_hashes: vec![b"unvalidated local hash".to_vec()],
            txs_json: vec![b"unvalidated local body".to_vec()],
            receipts_json: vec![b"unvalidated local receipt".to_vec()],
        };
        for (bundle, fail) in [(Some(raw), false), (None, false), (None, true)] {
            let calls = Arc::new(Mutex::new(vec![]));
            let service = with_host(Local {
                calls: calls.clone(),
                bundle: bundle.clone(),
                fail,
            });
            let result = service.local(&id).await;
            if fail {
                assert_eq!(
                    result.unwrap_err().to_string(),
                    "retained bundle unavailable"
                );
            } else {
                assert_eq!(result.unwrap(), bundle);
            }
            assert_eq!(*calls.lock().unwrap(), vec![id]);
            assert!(service.0.slots.lock().unwrap().replies.is_empty());
            assert!(service.0.slots.lock().unwrap().gates.is_empty());
            assert!(service
                .query::<()>(1, id, 0., |_| panic!("no peer response"))
                .await
                .unwrap()
                .is_none());
            assert_eq!(
                *calls.lock().unwrap(),
                vec![id],
                "remote query must not silently trust local bytes"
            );
        }
    }
    async fn started(service: &Bundles<Empty>, id: ProposalId) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while !service.0.slots.lock().unwrap().replies.contains_key(&id) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn query_slots_are_owned_through_cancellation_error_and_panic() {
        let service = service();
        let id = [1; 32];
        for failure in ["cancel", "error", "panic"] {
            let reader = service.clone();
            let task = tokio::spawn(async move {
                reader
                    .query::<()>(1, id, 10., |_| match failure {
                        "error" => Err("fixture validate".into()),
                        "panic" => panic!("fixture panic"),
                        _ => Ok(None),
                    })
                    .await
            });
            started(&service, id).await;
            service
                .0
                .slots
                .lock()
                .unwrap()
                .replies
                .get_mut(&id)
                .unwrap()
                .push(Response {
                    responder: b"v2".to_vec(),
                    bundle: RawBundle {
                        tx_hashes: vec![],
                        txs_json: vec![],
                        receipts_json: vec![],
                    },
                });
            match failure {
                "cancel" => {
                    task.abort();
                    assert!(task.await.unwrap_err().is_cancelled());
                }
                "error" => assert_eq!(
                    task.await.unwrap().unwrap_err().to_string(),
                    "fixture validate"
                ),
                _ => assert!(task.await.unwrap_err().is_panic()),
            }
            assert!(
                service.0.slots.lock().unwrap().replies.is_empty(),
                "slot leaked after {failure}"
            );
        }
        // Poll both waiters into the gate queue, then cancel one. An unrelated
        // reader can start; releasing the owner admits the remaining waiter.
        let first = service.reader(id).await;
        let mut second = Box::pin(service.reader(id));
        let mut cancelled = Box::pin(service.reader(id));
        assert!(futures::poll!(&mut second).is_pending());
        assert!(futures::poll!(&mut cancelled).is_pending());
        drop(cancelled);
        let unrelated = service.reader([2; 32]).await;
        assert_eq!(service.0.slots.lock().unwrap().replies.len(), 2);
        drop(first);
        let second = second.await;
        assert_eq!(service.0.slots.lock().unwrap().replies.len(), 2);
        drop(second);
        drop(unrelated);
        assert!(service.0.slots.lock().unwrap().replies.is_empty());
    }
}
