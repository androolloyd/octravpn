use ed25519_dalek::SigningKey;
use octra_node_protocol::network::{
    frame::Frame,
    session::{self, Connection, Driver, LocalNode, Peer, Timeouts},
    Error,
};
use rand::{rngs::StdRng, SeedableRng};
use std::time::Duration;
use tokio::{io::DuplexStream, sync::mpsc};
const WAIT: Duration = Duration::from_secs(2);
async fn connections() -> (Connection<DuplexStream>, Connection<DuplexStream>) {
    let (a, b) = tokio::io::duplex(64);
    let local = LocalNode {
        chain_id: b"driver-test".to_vec(),
        node_address: b"node".to_vec(),
        config_hash: [1; 32],
        listen_port: 9000,
        best_epoch: 0,
        best_root: [0; 32],
    };
    let akey = SigningKey::from_bytes(&[1; 32]);
    let bkey = SigningKey::from_bytes(&[2; 32]);
    let mut arng = StdRng::seed_from_u64(1);
    let mut brng = StdRng::seed_from_u64(2);
    let timeouts = Timeouts {
        handshake_read: WAIT,
        read_idle: WAIT,
        write_idle: WAIT,
    };
    let (a, b) = tokio::join!(
        session::dial(a, &local, &akey, &[], &mut arng, timeouts),
        session::accept(b, &local, &bkey, &[], &mut brng, timeouts)
    );
    (a.unwrap(), b.unwrap())
}
async fn drivers() -> ((Peer, Driver<DuplexStream>), (Peer, Driver<DuplexStream>)) {
    let (a, b) = connections().await;
    (a.into_driver().unwrap(), b.into_driver().unwrap())
}
fn frame(byte: u8) -> Frame {
    Frame {
        message: 3,
        payload: vec![byte; 4096],
    }
}
#[tokio::test]
async fn fragmented_full_duplex_callback_can_enqueue_reply() {
    let ((a, ad), (b, bd)) = drivers().await;
    let (tx, mut rx) = mpsc::channel(1);
    let at = tokio::spawn(ad.run(move |_, frame| {
        let tx = tx.clone();
        async move {
            tx.send(frame)
                .await
                .map_err(|_| Error::from("consumer closed"))
        }
    }));
    let bt = tokio::spawn(bd.run(|peer, frame| async move {
        assert!(peer.enqueue(frame, WAIT).await);
        Ok(())
    }));
    for byte in 0..8 {
        let expected = frame(byte);
        assert!(a.enqueue(expected.clone(), WAIT).await);
        assert_eq!(
            tokio::time::timeout(WAIT, rx.recv())
                .await
                .unwrap()
                .unwrap(),
            expected
        );
    }
    assert_eq!(b.message_counts().0, 8);
    assert_eq!(a.message_counts().0, 8);
    a.close();
    b.close();
    at.await.unwrap().unwrap();
    bt.await.unwrap().unwrap();
    assert!(!a.is_connected());
    assert!(!b.is_connected());
}
#[tokio::test]
async fn cancelled_queue_wait_does_not_corrupt_accepted_frame() {
    let ((a, ad), (b, bd)) = drivers().await;
    assert!(a.enqueue(frame(1), WAIT).await);
    assert!(!a.enqueue(frame(2), Duration::from_millis(1)).await);
    assert!(a.is_connected());
    let (tx, mut rx) = mpsc::channel(1);
    let at = tokio::spawn(ad.run(|_, _| async { Ok(()) }));
    let bt = tokio::spawn(bd.run(move |_, f| {
        let tx = tx.clone();
        async move {
            tx.send(f).await.unwrap();
            Ok(())
        }
    }));
    assert_eq!(
        tokio::time::timeout(WAIT, rx.recv()).await.unwrap(),
        Some(frame(1))
    );
    assert!(a.enqueue(frame(3), WAIT).await);
    assert_eq!(
        tokio::time::timeout(WAIT, rx.recv()).await.unwrap(),
        Some(frame(3))
    );
    a.close();
    b.close();
    let _ = at.await.unwrap();
    let _ = bt.await.unwrap();
}
#[tokio::test]
async fn dropping_or_aborting_driver_closes_handles_and_partial_frames() {
    let ((a, ad), (b, bd)) = drivers().await;
    drop(ad);
    assert!(!a.is_connected());
    assert!(!a.enqueue(frame(1), WAIT).await);
    drop(bd);
    assert!(!b.is_connected());
    let (a, mut remote) = connections().await;
    let (peer, driver) = a.into_driver().unwrap();
    assert!(peer.enqueue(frame(1), WAIT).await);
    let task = tokio::spawn(driver.run(|_, _| async { Ok(()) }));
    // The write fills the 64-byte stream before this task yields back.
    tokio::task::yield_now().await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(!peer.is_connected());
    assert!(!peer.enqueue(frame(2), WAIT).await);
    assert!(remote.receive().await.is_err());
}
#[tokio::test]
async fn handler_and_wire_errors_close_both_loops() {
    let ((a, ad), (b, bd)) = drivers().await;
    let at = tokio::spawn(ad.run(|_, _| async { Ok(()) }));
    let bt = tokio::spawn(bd.run(|_, _| async { Err(Error::from("handler failed")) }));
    assert!(a.enqueue(frame(1), WAIT).await);
    assert_eq!(bt.await.unwrap().unwrap_err().as_bytes(), b"handler failed");
    assert!(!b.is_connected());
    assert!(at.await.unwrap().is_err());
    assert!(!a.is_connected());
    let ((a, ad), (b, bd)) = drivers().await;
    let at = tokio::spawn(ad.run(|_, _| async { Ok(()) }));
    let bt = tokio::spawn(bd.run(|_, _| async { panic!("invalid frame reached callback") }));
    assert!(
        a.enqueue(
            Frame {
                message: 255,
                payload: vec![0; 4097]
            },
            WAIT
        )
        .await
    );
    assert!(at.await.unwrap().is_err());
    assert!(bt.await.unwrap().is_err());
    assert!(!a.is_connected());
    assert!(!b.is_connected());
}
