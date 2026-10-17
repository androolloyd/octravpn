//! Host policy through the real encrypted login and raw DERP stream driver.
//! The carried bytes are opaque fixtures, not proof of inner-IP enforcement.
use super::*;
use chrono::{Duration as ChronoDuration, Utc};
use headscale_core::derp::protocol::{
    encode_client_info_frame, encode_frame, open_server_info, ClientInfo, DerpNodeKeyPair, Frame,
    FrameDecoder, ServerInfo, MAX_INFO_LEN,
};
use octravpn_mesh::tailscale_wire::derp::drive_native_derp;
use std::{
    net::Ipv4Addr,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    task::JoinHandle,
    time::timeout,
};

const WAIT: Duration = Duration::from_secs(3);
const ALLOW: &str =
    r#"{"acls":[{"action":"accept","src":["100.64.0.1"],"dst":["100.64.0.2:443"]}]}"#;

struct Client {
    key: [u8; 32],
    io: Option<DuplexStream>,
    decoder: FrameDecoder,
    task: Option<JoinHandle<Result<()>>>,
}
impl Drop for Client {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}
impl Client {
    async fn connect(runtime: Arc<NativeDerpRuntime>, key: &DerpNodeKeyPair) -> Self {
        let (io, server) = tokio::io::duplex(4096);
        let public = runtime.public_key();
        let task = tokio::spawn(async move {
            drive_native_derp(runtime, server)
                .await
                .map_err(anyhow::Error::from)
        });
        let mut client = Self {
            key: key.public_key(),
            io: Some(io),
            decoder: FrameDecoder::new(MAX_INFO_LEN),
            task: Some(task),
        };
        assert_eq!(
            client.frame().await,
            Some(Frame::ServerKey {
                key: public,
                extra: vec![],
            })
        );
        let login = encode_client_info_frame(key, &public, &ClientInfo::regular()).unwrap();
        client.write(&login).await;
        let frame = client.frame().await.expect("encrypted ServerInfo");
        assert_eq!(
            open_server_info(key, &public, &frame).unwrap(),
            ServerInfo::current()
        );
        client.pong_barrier().await;
        client
    }

    async fn write(&mut self, encoded: &[u8]) {
        timeout(WAIT, async {
            let io = self.io.as_mut().unwrap();
            io.write_all(encoded).await.unwrap();
            io.flush().await.unwrap();
        })
        .await
        .expect("DERP client write stalled");
    }

    async fn send(&mut self, frame: Frame) {
        self.write(&encode_frame(&frame).unwrap()).await;
    }

    async fn frame(&mut self) -> Option<Frame> {
        timeout(WAIT, async {
            loop {
                if let Some(frame) = self.decoder.next_frame().unwrap() {
                    return Some(frame);
                }
                let mut bytes = [0; 1024];
                let count = self.io.as_mut().unwrap().read(&mut bytes).await.unwrap();
                if count == 0 {
                    return None;
                }
                self.decoder.push(&bytes[..count]);
            }
        })
        .await
        .expect("DERP frame or EOF did not arrive")
    }

    async fn pong_barrier(&mut self) {
        let nonce = *b"barrier!";
        self.send(Frame::Ping(nonce)).await;
        // A carried packet queued before this connection handles Ping must
        // precede its Pong in the same outbound queue. Never skip packets.
        for _ in 0..4 {
            match self.frame().await.expect("Pong before EOF") {
                Frame::Pong(value) => {
                    assert_eq!(value, nonce);
                    return;
                }
                Frame::PeerGone { .. } => {}
                other => panic!("unexpected frame before Pong: {other:?}"),
            }
        }
        panic!("too many control frames before Pong");
    }

    async fn refused(&mut self, expected: &str) {
        let task = self.task.as_mut().unwrap();
        let error = timeout(WAIT, task)
            .await
            .expect("revoked DERP driver remained live")
            .expect("DERP driver panicked")
            .expect_err("revoked DERP driver exited without refusal");
        self.task.take();
        assert!(error.to_string().contains(expected), "{error}");
    }

    async fn no_packet_before_eof(&mut self) {
        for _ in 0..4 {
            match self.frame().await {
                None => return,
                Some(Frame::PeerGone { .. }) => {}
                other => panic!("unexpected frame from revoked connection: {other:?}"),
            }
        }
        panic!("revoked connection did not reach EOF");
    }

    async fn close(mut self) {
        drop(self.io.take());
        if let Some(task) = self.task.as_mut() {
            timeout(WAIT, task)
                .await
                .expect("DERP driver did not close")
                .expect("DERP driver panicked")
                .expect("live DERP client failed during graceful close");
            self.task.take();
        }
    }
}

struct Fixture {
    _directory: tempfile::TempDir,
    machines: Arc<MachineRegistry>,
    policy: PolicyStore,
    available: Arc<AtomicBool>,
    runtime: Arc<NativeDerpRuntime>,
    source: DerpNodeKeyPair,
    destination: DerpNodeKeyPair,
}
impl Fixture {
    fn new(allow: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let machines = Arc::new(MachineRegistry::new());
        let policy = PolicyStore::new();
        if allow {
            Self::set_policy(&policy, ALLOW);
        }
        let available = Arc::new(AtomicBool::new(true));
        let current = available.clone();
        let runtime = load_native_derp_runtime(
            directory.path(),
            [0; 32],
            machines.clone(),
            policy.clone(),
            Arc::new(move || current.load(Ordering::SeqCst)),
            None,
        )
        .unwrap();
        let source = DerpNodeKeyPair::from_private_key([1; 32]).unwrap();
        let destination = DerpNodeKeyPair::from_private_key([2; 32]).unwrap();
        for (key, user, last) in [(&source, "alice", 1), (&destination, "bob", 2)] {
            let key = hex::encode(key.public_key());
            machines.upsert(
                key.clone(),
                MachineRecord::new_at(
                    Utc::now(),
                    key,
                    format!("machine-{user}"),
                    user.into(),
                    user.into(),
                    Ipv4Addr::new(100, 64, 0, last),
                    false,
                ),
            );
        }
        Self {
            _directory: directory,
            machines,
            policy,
            available,
            runtime,
            source,
            destination,
        }
    }

    fn set_policy(policy: &PolicyStore, raw: &str) {
        policy.set(
            octravpn_mesh::policy::parse_hujson_policy(raw).unwrap(),
            raw.into(),
        );
    }

    async fn clients(&self) -> (Client, Client) {
        let source = Client::connect(self.runtime.clone(), &self.source).await;
        let destination = Client::connect(self.runtime.clone(), &self.destination).await;
        (source, destination)
    }
}

async fn carry(source: &mut Client, destination: &mut Client, packet: &[u8]) {
    source
        .send(Frame::SendPacket {
            destination: destination.key,
            packet: packet.to_vec(),
        })
        .await;
    assert_eq!(
        destination.frame().await,
        Some(Frame::RecvPacket {
            source: source.key,
            packet: packet.to_vec(),
        })
    );
}

#[tokio::test]
async fn explicit_host_acl_carries_actual_registered_peer_packets_in_both_directions() {
    let fixture = Fixture::new(true);
    let (mut source, mut destination) = fixture.clients().await;
    carry(&mut source, &mut destination, b"allowed forward").await;
    carry(&mut destination, &mut source, b"allowed response").await;
    source.close().await;
    destination.pong_barrier().await;
    destination.close().await;
}

#[derive(Clone, Copy, Debug)]
enum Revoke {
    NoPolicy,
    Policy,
    SourceRemoved,
    DestinationRemoved,
    SourceExpired,
    DestinationExpired,
    HostUnavailable,
}

#[tokio::test]
async fn live_host_guards_refuse_actual_carriage_after_each_authority_is_revoked() {
    for revoke in [
        Revoke::NoPolicy,
        Revoke::Policy,
        Revoke::SourceRemoved,
        Revoke::DestinationRemoved,
        Revoke::SourceExpired,
        Revoke::DestinationExpired,
        Revoke::HostUnavailable,
    ] {
        let fixture = Fixture::new(!matches!(revoke, Revoke::NoPolicy));
        let (mut source, mut destination) = fixture.clients().await;
        if !matches!(revoke, Revoke::NoPolicy) {
            carry(&mut source, &mut destination, b"before revocation").await;
        }
        match revoke {
            Revoke::NoPolicy => {}
            Revoke::Policy => Fixture::set_policy(&fixture.policy, r#"{"acls":[]}"#),
            Revoke::SourceRemoved | Revoke::DestinationRemoved => {
                let key = if matches!(revoke, Revoke::SourceRemoved) {
                    source.key
                } else {
                    destination.key
                };
                assert!(fixture.machines.delete(&hex::encode(key)));
            }
            Revoke::SourceExpired | Revoke::DestinationExpired => {
                let key = if matches!(revoke, Revoke::SourceExpired) {
                    source.key
                } else {
                    destination.key
                };
                assert!(fixture.machines.set_expiry(
                    &hex::encode(key),
                    Some(Utc::now() - ChronoDuration::seconds(1)),
                ));
            }
            Revoke::HostUnavailable => fixture.available.store(false, Ordering::SeqCst),
        }

        source
            .send(Frame::SendPacket {
                destination: destination.key,
                packet: format!("forbidden after {revoke:?}").into_bytes(),
            })
            .await;
        let expected = if matches!(revoke, Revoke::NoPolicy | Revoke::Policy) {
            "DERP peer route was not admitted by verifier"
        } else {
            "DERP client was not admitted by verifier"
        };
        source.refused(expected).await;
        source.no_packet_before_eof().await;

        if matches!(
            revoke,
            Revoke::DestinationRemoved | Revoke::DestinationExpired | Revoke::HostUnavailable
        ) {
            // The successful pre-revocation carriage established a reverse
            // path. Source cleanup queues PeerGone, which must itself reject
            // the revoked destination before any further stream write.
            destination
                .refused("DERP client was not admitted by verifier")
                .await;
            destination.no_packet_before_eof().await;
        } else {
            destination.pong_barrier().await;
        }
        source.close().await;
        destination.close().await;
    }
}
