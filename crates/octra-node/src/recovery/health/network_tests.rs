//! Signed TCP peer replies through EpochRoots and the health classifier. This
//! does not qualify the complete recovery Service::run orchestration.
use super::*;
use crate::published::Shared;
use ed25519_dalek::{Signer, SigningKey};
use octra_exex::{Cursor, EpochId, Sequence, StateRoot};
use octra_node_protocol::{
    consensus::{codec::Wire, hash, CatchupEpochRecord, EpochRootResponse, Validator},
    network::frame::Frame,
};
use std::sync::Mutex;

use super::super::test_peer as peer;

const CHAIN: &[u8] = b"connected-root-health-fixture";
const EPOCH: i64 = 10;
const LOCAL: [u8; 32] = [7; 32];
const OTHER: [u8; 32] = [8; 32];

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
fn member(seed: u8) -> Validator {
    Validator {
        address: format!("validator-{seed}").into_bytes(),
        pubkey: key(seed).verifying_key().to_bytes().to_vec(),
    }
}
// Only the root-query fixture reads these records; no certificate or finalized
// state is inferred from their other fields.
fn record(root: [u8; 32]) -> CatchupEpochRecord {
    CatchupEpochRecord {
        epoch_id: EPOCH,
        prev_state_root: vec![0; 32],
        state_root: root.to_vec(),
        tx_list_hash: vec![0; 32],
        tx_hashes: vec![],
        txs_json: vec![],
        receipt_root: vec![0; 32],
        receipts_json: vec![],
        epoch_ts: 100.,
        creator_addr: member(1).address,
        commit_round: 0,
        reward_source: None,
        finality: None,
    }
}
fn head() -> Head {
    Head {
        cursor: Cursor {
            sequence: Sequence(EPOCH as u64),
            epoch: EpochId(EPOCH as u64),
            state_root: StateRoot(LOCAL),
        },
        ledger_root: "0".repeat(64),
        irmin_commit: "0".repeat(128),
        parent_commit: None,
        index_root: "0".repeat(64),
        index_hash: None,
        txid_hi: -1,
        date: 0,
        message: vec![],
    }
}
struct Connected<'a> {
    reader: &'a peer::Node,
    authority: ValidatorSet,
    shared: Shared,
    responses: Mutex<Vec<Response>>,
}
#[async_trait::async_trait]
impl Source for Connected<'_> {
    fn chain(&self) -> &[u8] {
        CHAIN
    }
    fn ticket(&self) -> RootQuarantineTicket {
        self.shared.root_quarantine_ticket()
    }
    async fn head(&self) -> Result<Head> {
        Ok(head())
    }
    async fn authority(&self, observed: &Head, epoch: i64) -> Result<Members> {
        assert_eq!(*observed, head());
        assert_eq!(epoch, EPOCH + 1);
        Ok(Members {
            active: self.authority.clone(),
            stake: self.authority.clone(),
        })
    }
    async fn roots(&self, epoch: i64, wait_for: WaitFor) -> Result<Vec<Response>> {
        let responses = self.reader.roots.query(epoch, 2., wait_for, false).await?;
        *self.responses.lock().unwrap() = responses.clone();
        Ok(responses)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authenticated_connected_roots_quarantine_and_clear_only_fresh_matching_evidence() {
    let authority = ValidatorSet::unweighted((1..=4).map(member).collect());
    let reader = peer::node(CHAIN, member(1).address, key(1), authority.clone(), vec![]).await;
    let mut peers = vec![];
    for seed in 2..=4 {
        let node = peer::node(
            CHAIN,
            member(seed).address,
            key(seed),
            authority.clone(),
            vec![reader.endpoint.clone()],
        )
        .await;
        node.authority
            .ranges
            .lock()
            .unwrap()
            .insert(EPOCH, record(OTHER));
        peers.push(node);
    }
    peer::wait_for(|| {
        reader.swarm.peers().len() == 3 && peers.iter().all(|p| p.swarm.peers().len() == 3)
    })
    .await;
    let source = Connected {
        reader: &reader,
        authority,
        shared: Shared::new(),
        responses: Mutex::new(vec![]),
    };
    let conflict = query_source(&source).await.unwrap();
    assert_eq!(
        conflict.status,
        Status::Conflicting {
            root: OTHER,
            consensus: true
        }
    );
    assert_eq!(source.responses.lock().unwrap().len(), 3);
    source
        .shared
        .quarantine_root(&conflict.head, "signed peer conflict");
    assert!(source.shared.root_quarantined());
    assert!(!source.shared.clear_root_quarantine(&conflict.ticket));

    // One bad signature and one missing root leave only one usable signer.
    peers[0]
        .authority
        .corrupt
        .store(true, std::sync::atomic::Ordering::SeqCst);
    peers[1].authority.ranges.lock().unwrap().remove(&EPOCH);
    reader.authority.observations.lock().unwrap().clear();
    let missing_address = member(3).address;
    let remaining_address = member(4).address;
    let malformed = async {
        peer::wait_for(|| {
            let observations = reader.authority.observations.lock().unwrap();
            observations.iter().any(|(epoch, r)| {
                *epoch == EPOCH && r.responder_addr == missing_address && r.state_root.is_none()
            }) && observations
                .iter()
                .any(|(epoch, r)| *epoch == EPOCH && r.responder_addr == remaining_address)
        })
        .await;
        let mut response = EpochRootResponse {
            chain_id: CHAIN.to_vec(),
            epoch_id: EPOCH,
            state_root: Some(OTHER.to_vec()),
            responder_addr: member(3).address,
            responder_head_epoch: EPOCH,
            signature: vec![],
        };
        response.signature = key(3)
            .sign(&hash::epoch_root_response_sign_bytes(&response).unwrap())
            .to_bytes()
            .to_vec();
        let mut payload = response.encode().unwrap();
        payload.push(0); // Valid signature cannot authorize a malformed envelope.
        assert!(
            peers[1]
                .swarm
                .send_to(
                    reader.swarm.node_id(),
                    Frame {
                        message: 0x35,
                        payload
                    }
                )
                .await
        );
        peer::wait_for(|| {
            reader
                .swarm
                .peers()
                .iter()
                .all(|p| p.hello().node_id != peers[1].swarm.node_id())
        })
        .await;
    };
    let (unknown, ()) = tokio::join!(query_source(&source), malformed);
    assert_eq!(unknown.unwrap().status, Status::Unknown);
    let accepted = source.responses.lock().unwrap().clone();
    assert_eq!(accepted.len(), 2);
    assert!(accepted
        .iter()
        .all(|r| r.responder_addr != member(2).address));
    assert_eq!(
        accepted.iter().filter(|r| r.state_root.is_some()).count(),
        1
    );
    assert!(source.shared.root_quarantined());

    // Replace the deliberately malformed transport explicitly rather than
    // relying on the peer exchange retry interval for this positive control.
    drop(peers.remove(1));
    let replacement = peer::node(
        CHAIN,
        member(3).address,
        key(3),
        source.authority.clone(),
        vec![reader.endpoint.clone()],
    )
    .await;
    peers.push(replacement);
    for node in &peers {
        node.authority
            .corrupt
            .store(false, std::sync::atomic::Ordering::SeqCst);
        node.authority
            .ranges
            .lock()
            .unwrap()
            .insert(EPOCH, record(LOCAL));
    }
    peer::wait_for(|| {
        reader.swarm.peers().len() == 3 && peers.iter().all(|p| p.swarm.peers().len() == 3)
    })
    .await;
    let matching = query_source(&source).await.unwrap();
    assert_eq!(matching.status, Status::Attested { consensus: true });
    assert_eq!(matching.head, conflict.head);
    assert_eq!(source.responses.lock().unwrap().len(), 3);
    assert!(source.shared.clear_root_quarantine(&matching.ticket));
    assert!(!source.shared.root_quarantined());
}
