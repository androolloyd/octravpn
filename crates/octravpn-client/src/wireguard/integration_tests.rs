//! Real client + embedded service transport tests. The authority is a local
//! funded-session adapter fixture, not a blockchain/finality qualification.
use super::*;
use anyhow::Result;
use async_trait::async_trait;
use octravpn_core::{
    address::Address,
    control::{
        announce_opener_binding_payload, announce_signing_payload, AnnounceSessionRequest,
        SessionStateResponse,
    },
    receipt::ReceiptContext,
    session::SessionId,
    sig,
};
use octravpn_node::{
    admission::{FundedSession, RelayLifecycle, Revocation, SessionAuthority, SessionPermit},
    embedded::{Config, EmbeddedVpn, IpTunnelConfig},
};
use octravpn_tun::amnezia::WireTransport;
use std::{sync::Arc, time::Duration};
#[cfg(target_os = "linux")]
use tokio::net::UdpSocket;
use tokio::{sync::watch, task::JoinHandle};

struct Authority {
    session: FundedSession,
    revoked: Revocation,
}
#[async_trait]
impl SessionAuthority for Authority {
    async fn authorize(
        &self,
        request: &AnnounceSessionRequest,
        domain: &ReceiptContext,
    ) -> Result<Option<SessionPermit>> {
        Ok((&self.session.domain == domain)
            .then(|| {
                self.session
                    .authorize(request, self.revoked.clone(), Duration::from_secs(120))
            })
            .flatten())
    }
    async fn lifecycle(&self, _: &SessionId, domain: &ReceiptContext) -> Result<RelayLifecycle> {
        anyhow::ensure!(&self.session.domain == domain, "wrong receipt domain");
        Ok(if self.revoked.is_revoked() {
            RelayLifecycle::Terminal(11)
        } else {
            RelayLifecycle::Open
        })
    }
}
struct Fixture {
    _directory: tempfile::TempDir,
    client: KeyPair,
    request: AnnounceSessionRequest,
    domain: ReceiptContext,
    receipt_key: sig::PublicKey,
    authority: Arc<Authority>,
    endpoint: String,
    server_key: [u8; 32],
    base: String,
    stop: watch::Sender<bool>,
    server: JoinHandle<Result<()>>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.send_replace(true);
        self.server.abort();
    }
}
impl Fixture {
    async fn new(ip: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let client = KeyPair::from_secret_bytes(&[11; 32]);
        let wallet = KeyPair::from_secret_bytes(&[12; 32]);
        let receipt_key = Arc::new(KeyPair::from_secret_bytes(&[13; 32]));
        let secret = StaticSecret::from([14; 32]);
        let server_key = PublicKey::from(&secret).to_bytes();
        let session = SessionId::from_u64(93);
        let wg = super::public_key(&client);
        let hash = "ab".repeat(32);
        let request = AnnounceSessionRequest {
            client_sig: client.sign(&announce_signing_payload(
                &session,
                &client.public,
                &wg,
                &hash,
            )),
            opener_sig: wallet.sign(&announce_opener_binding_payload(
                &session,
                &client.public,
                &wg,
                &hash,
            )),
            session_id: session.clone(),
            client_pubkey: client.public,
            client_wg_pubkey: wg,
            open_tx_hash: hash.clone(),
            opener_pubkey: wallet.public,
        };
        let domain = ReceiptContext::v2(
            Address::from_pubkey(&[15; 32]),
            999,
            Address::from_pubkey(&[16; 32]),
        );
        let authority = Arc::new(Authority {
            session: FundedSession {
                domain: domain.clone(),
                session_id: session,
                opener: Address::from_pubkey(&wallet.public.0),
                client_pubkey: client.public,
                client_wg_pubkey: wg,
                open_tx_hash: hash,
                current_epoch: 10,
                expires_epoch: 20,
                escrow_ou: 1_000_000,
                open: true,
            },
            revoked: Revocation::default(),
        });
        let service = EmbeddedVpn::bind_with_ip_tunnel(
            Config {
                control_listen: "127.0.0.1:0".parse().unwrap(),
                tunnel_listen: "127.0.0.1:0".parse().unwrap(),
                data_dir: directory.path().to_owned(),
                receipt_key: receipt_key.clone(),
                wireguard_secret: secret,
                receipt_context: domain.clone(),
            },
            authority.clone(),
            ip.then(|| IpTunnelConfig {
                name: "ovpntest0".into(),
                address_book: None,
            }),
        )
        .await
        .unwrap();
        let endpoint = service.tunnel_addr().to_string();
        let base = format!("http://{}", service.control_addr().unwrap());
        let (stop, signal) = watch::channel(false);
        let server = tokio::spawn(service.run(signal));
        reqwest::Client::new()
            .post(format!("{base}/session"))
            .json(&request)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
        Self {
            _directory: directory,
            client,
            request,
            domain,
            receipt_key: receipt_key.public,
            authority,
            endpoint,
            server_key,
            base,
            stop,
            server,
        }
    }
    async fn tunnel(&self, limit: Option<u64>) -> Tunnel {
        tokio::time::timeout(
            Duration::from_secs(4),
            Tunnel::connect(
                self.request.session_id.clone(),
                &self.client,
                &self.endpoint,
                self.server_key,
                limit,
                WireTransport::Wireguard,
            ),
        )
        .await
        .unwrap()
        .unwrap()
    }
    async fn receipt(&self) -> SessionStateResponse {
        let state: SessionStateResponse = reqwest::Client::new()
            .get(format!(
                "{}/session/{}",
                self.base,
                self.request.session_id.to_hex()
            ))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        let proposal = state
            .proposed
            .as_ref()
            .expect("live session has signed proposal");
        assert_eq!(proposal.node_pubkey, self.receipt_key);
        assert_eq!(proposal.receipt.context, self.domain);
        assert_eq!(proposal.receipt.session_id, self.request.session_id);
        sig::verify(
            &proposal.node_pubkey,
            &proposal.receipt.signing_payload(),
            &proposal.node_sig,
        )
        .unwrap();
        state
    }
}

#[tokio::test]
async fn real_client_handshake_credit_ceiling_and_rejected_egress() {
    let fixture = Fixture::new(false).await;
    let mut tunnel = fixture.tunnel(Some(1)).await;
    assert!(tunnel
        .send(&[127, 0, 0, 1, 0, 9, 17])
        .await
        .unwrap_err()
        .to_string()
        .contains("credit ceiling"));
    assert_eq!(tunnel.traffic().total().unwrap(), 0);
    drop(tunnel);
    let mut tunnel = fixture.tunnel(None).await;
    tunnel.send(&[127, 0, 0, 1, 0, 9, 17]).await.unwrap();
    assert!(tunnel.traffic().submitted > 0);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        fixture.receipt().await.bytes_served,
        0,
        "refused egress is not billable"
    );
    fixture.authority.revoked.revoke();
    let status = reqwest::Client::new()
        .post(format!("{}/session", fixture.base))
        .json(&fixture.request)
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(status, 401);
    assert_eq!(fixture.receipt().await.bytes_served, 0);
}

#[cfg(target_os = "linux")]
fn isolated_namespace() {
    assert_eq!(
        std::env::var("OCTRAVPN_ISOLATED_TEST").as_deref(),
        Ok("1"),
        "run docker/vpn-transport/run.sh"
    );
    assert!(
        std::path::Path::new("/.dockerenv").exists(),
        "isolated Docker namespace required"
    );
    let interfaces = std::fs::read_dir("/sys/class/net")
        .unwrap()
        .map(|p| p.unwrap().file_name())
        .collect::<Vec<_>>();
    assert_eq!(
        interfaces,
        vec![std::ffi::OsString::from("lo")],
        "container must use --network none"
    );
    for row in std::fs::read_to_string("/proc/net/route")
        .unwrap()
        .lines()
        .skip(1)
    {
        let fields = row.split_whitespace().collect::<Vec<_>>();
        assert!(
            fields.len() < 8 || fields[1] != "00000000" || fields[7] != "00000000",
            "external default route is forbidden"
        );
    }
}

#[tokio::test]
async fn reconnect_real_wireguard_preserves_identity_and_traffic_floor() {
    let fixture = Fixture::new(false).await;
    let mut tunnel = fixture.tunnel(Some(100_000)).await;
    let mut control = tunnel.recovery().unwrap();
    let packet = b"\x7f\0\0\x01\0\x35reject-private-egress";
    tunnel.send(packet).await.unwrap();
    let before = tunnel.traffic().total().unwrap();
    assert!(before > 0);
    control.pause();
    tunnel.send(packet).await.unwrap();
    assert_eq!(before, tunnel.traffic().total().unwrap());
    // Re-admit the same wallet/session/WG binding; there is no funding path.
    let response = reqwest::Client::new()
        .post(format!("{}/session", fixture.base))
        .json(&fixture.request)
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::select! {
            result = async {
                let generation = control.handshake().await?;
                control.resume(generation)
            } => result.unwrap(),
            result = tunnel.recv() => panic!("reconnect produced unsolicited application data: {result:?}"),
        }
    }).await.unwrap();
    assert_eq!(before, tunnel.traffic().total().unwrap());
    tunnel.send(packet).await.unwrap();
    assert!(tunnel.traffic().total().unwrap() > before);
    assert_eq!(
        fixture.request.client_wg_pubkey,
        super::public_key(&fixture.client)
    );
    assert_eq!(fixture.receipt().await.bytes_served, 0);
}

#[cfg(target_os = "linux")]
async fn echo() -> (std::net::SocketAddrV4, JoinHandle<()>) {
    let socket = UdpSocket::bind("93.184.216.34:0")
        .await
        .expect("isolated public IPv4 alias must exist");
    let std::net::SocketAddr::V4(address) = socket.local_addr().unwrap() else {
        unreachable!()
    };
    let task = tokio::spawn(async move {
        let mut buffer = [0; 1500];
        let (length, source) = socket.recv_from(&mut buffer).await.unwrap();
        socket.send_to(&buffer[..length], source).await.unwrap();
    });
    (address, task)
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires Docker network-none public alias; docker/vpn-transport/run.sh"]
async fn isolated_real_client_udp_return_and_exact_receipt_accounting() {
    isolated_namespace();
    let (target, echo) = echo().await;
    let fixture = Fixture::new(false).await;
    let mut tunnel = fixture.tunnel(Some(100_000)).await;
    let mut payload = Vec::from(target.ip().octets());
    payload.extend_from_slice(&target.port().to_be_bytes());
    payload.extend_from_slice(b"real-paid-host-adapter-udp");
    tunnel.send(&payload).await.unwrap();
    let returned = tokio::time::timeout(Duration::from_secs(4), tunnel.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(returned, payload);
    echo.await.unwrap();
    let expected = tunnel.traffic().total().unwrap();
    let receipt = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let state = fixture.receipt().await;
            if state.bytes_served >= expected {
                break state;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(receipt.bytes_served, expected);
}

#[cfg(target_os = "linux")]
fn udp_packet(source: std::net::Ipv4Addr, target: std::net::SocketAddrV4, data: &[u8]) -> Vec<u8> {
    let length = 28 + data.len();
    let mut packet = vec![0; length];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(length as u16).to_be_bytes());
    packet[6] = 0x40;
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&target.ip().octets());
    packet[20..22].copy_from_slice(&40_000u16.to_be_bytes());
    packet[22..24].copy_from_slice(&target.port().to_be_bytes());
    packet[24..26].copy_from_slice(&((8 + data.len()) as u16).to_be_bytes());
    packet[28..].copy_from_slice(data);
    let mut sum: u32 = packet[..20]
        .chunks_exact(2)
        .map(|p| u32::from(u16::from_be_bytes([p[0], p[1]])))
        .sum();
    while sum > 65535 {
        sum = (sum & 65535) + (sum >> 16);
    }
    packet[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    packet
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires Docker network-none + NET_ADMIN + /dev/net/tun; docker/vpn-transport/run.sh"]
async fn isolated_real_client_wireguard_server_tun_and_raw_ipv4_return() {
    isolated_namespace();
    let (target, echo) = echo().await;
    let fixture = Fixture::new(true).await;
    let mut tunnel = fixture.tunnel(Some(100_000)).await;
    let assigned = octravpn_core::ip_tunnel::address(
        &fixture.request.session_id,
        &fixture.request.client_wg_pubkey,
    );
    let packet = udp_packet(assigned, target, b"raw-ip-kernel-return");
    octravpn_core::ip_tunnel::validate_outbound(&packet, assigned).unwrap();
    tunnel
        .send(&octravpn_core::ip_tunnel::encode(&packet).unwrap())
        .await
        .unwrap();
    let returned = tokio::time::timeout(Duration::from_secs(5), tunnel.recv())
        .await
        .unwrap()
        .unwrap();
    let packet = octravpn_core::ip_tunnel::decode(&returned).unwrap();
    octravpn_core::ip_tunnel::validate_inbound(packet, assigned).unwrap();
    assert_eq!(&packet[28..], b"raw-ip-kernel-return");
    echo.await.unwrap();
    let expected = tunnel.traffic().total().unwrap();
    let receipt = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let state = fixture.receipt().await;
            if state.bytes_served >= expected {
                break state;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(receipt.bytes_served, expected);
}
