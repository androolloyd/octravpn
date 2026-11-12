//! Shared native query budget, retained until a reply is written or cancelled.
use octra_node_protocol::{
    consensus::{
        query_work::{self, QueryWork},
        ValidatorSet,
    },
    network::{
        frame::Frame,
        handshake,
        session::{Peer, ServicePermit},
    },
};
use std::sync::{Arc, Mutex, OnceLock};
use tokio::time::Instant;

pub(crate) fn now() -> i64 {
    static START: OnceLock<Instant> = OnceLock::new();
    i64::try_from(START.get_or_init(Instant::now).elapsed().as_nanos()).unwrap_or(i64::MAX)
}

#[derive(Clone)]
pub struct Service(Arc<Mutex<QueryWork>>);
impl Default for Service {
    fn default() -> Self {
        Self(Arc::new(Mutex::new(QueryWork::new(now()))))
    }
}
pub(crate) struct Permit {
    work: Service,
    id: u64,
    writer: Option<ServicePermit>,
}
impl Drop for Permit {
    fn drop(&mut self) {
        self.work.0.lock().expect("query work").finish(self.id);
    }
}
impl Service {
    pub(crate) fn validator(set: &ValidatorSet, peer: &Peer) -> bool {
        set.validators
            .iter()
            .any(|v| handshake::node_id(&v.pubkey) == peer.hello().node_id)
    }
    pub(crate) async fn start(&self, peer: &Peer, validator: bool, cost: i64) -> Option<Permit> {
        let writer = peer.service().await?;
        let network = peer
            .remote_addr()
            .map_or_else(|| b"unknown".to_vec(), query_work::network);
        let id = self.0.lock().expect("query work").start(
            now(),
            &peer.hello().node_id,
            &network,
            validator,
            cost,
        )?;
        Some(Permit {
            work: self.clone(),
            id,
            writer: Some(writer),
        })
    }
}
impl Permit {
    pub(crate) async fn send(mut self, frame: Frame, cost: i64) {
        let ready =
            self.work
                .0
                .lock()
                .expect("query work")
                .prepared(self.id, frame.payload.len(), cost);
        if ready {
            if let Some(writer) = self.writer.take() {
                writer.send_retained(frame, self).await;
            }
        }
    }
}

#[cfg(test)]
mod cancellation_tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use octra_node_protocol::network::session::{self, LocalNode, Timeouts};
    use rand::{rngs::StdRng, SeedableRng};
    use std::time::Duration;
    #[tokio::test]
    async fn queued_reply_retains_query_reservation_after_caller_cancellation() {
        let (left, right) = tokio::io::duplex(64);
        let local = LocalNode {
            chain_id: b"query-quota-test".to_vec(),
            node_address: b"node".to_vec(),
            config_hash: [1; 32],
            listen_port: 9000,
            best_epoch: 0,
            best_root: [0; 32],
        };
        let a = SigningKey::from_bytes(&[1; 32]);
        let b = SigningKey::from_bytes(&[2; 32]);
        let mut arng = StdRng::seed_from_u64(1);
        let mut brng = StdRng::seed_from_u64(2);
        let timeouts = Timeouts {
            handshake_read: Duration::from_secs(2),
            read_idle: Duration::from_secs(2),
            write_idle: Duration::from_secs(2),
        };
        let (left, right) = tokio::join!(
            session::dial(left, &local, &a, &[], &mut arng, timeouts),
            session::accept(right, &local, &b, &[], &mut brng, timeouts)
        );
        let (peer, driver) = left.unwrap().into_driver().unwrap();
        let mut remote = right.unwrap();
        let running = tokio::spawn(driver.run(|_, _| async { Ok(()) }));
        let work = Service::default();
        let permit = work.start(&peer, true, 1).await.unwrap();
        let writing = tokio::spawn(permit.send(
            Frame {
                message: 0x39,
                payload: vec![0; 4096],
            },
            1,
        ));
        tokio::task::yield_now().await;
        writing.abort();
        let _ = writing.await;
        assert!(work
            .0
            .lock()
            .unwrap()
            .start(now(), &peer.hello().node_id, b"unknown", true, 1)
            .is_none());
        assert_eq!(remote.receive().await.unwrap().payload.len(), 4096);
        tokio::task::yield_now().await;
        let next = work
            .0
            .lock()
            .unwrap()
            .start(now(), &peer.hello().node_id, b"unknown", true, 1)
            .expect("writer completion releases query quota");
        work.0.lock().unwrap().finish(next);
        peer.close();
        let _ = running.await;
    }
}
