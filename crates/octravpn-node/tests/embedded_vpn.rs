//! Real control HTTP and WireGuard UDP against an in-process host authority.
//! This qualifies service integration, not blockchain execution/finality.
use async_trait::async_trait;
use boringtun::noise::{Tunn, TunnResult};
use octravpn_core::{
    address::Address,
    control::{
        announce_opener_binding_payload, announce_signing_payload, AnnounceSessionRequest,
        SessionStateResponse,
    },
    onion::{build_onion, HopBuildInput},
    receipt::ReceiptContext,
    session::SessionId,
    sig::{KeyPair, Signature},
    tunnel_frame,
};
use octravpn_node::{
    admission::{FundedSession, RelayLifecycle, Revocation, SessionAuthority, SessionPermit},
    embedded::{Config, EmbeddedVpn},
};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{net::UdpSocket, sync::watch};
use x25519_dalek::{PublicKey, StaticSecret};

struct Authority {
    state: Mutex<(FundedSession, Revocation, bool)>,
}
#[async_trait]
impl SessionAuthority for Authority {
    async fn authorize(
        &self,
        request: &AnnounceSessionRequest,
        domain: &ReceiptContext,
    ) -> anyhow::Result<Option<SessionPermit>> {
        let state = self.state.lock().unwrap();
        Ok(if !state.2 || &state.0.domain != domain {
            None
        } else {
            state
                .0
                .authorize(request, state.1.clone(), Duration::from_secs(120))
        })
    }
    async fn lifecycle(
        &self,
        _: &SessionId,
        domain: &ReceiptContext,
    ) -> anyhow::Result<RelayLifecycle> {
        let state = self.state.lock().unwrap();
        anyhow::ensure!(
            state.2 && &state.0.domain == domain,
            "canonical host unavailable"
        );
        Ok(if state.1.is_revoked() {
            RelayLifecycle::Terminal(1)
        } else {
            RelayLifecycle::Open
        })
    }
}
fn request(wallet: &KeyPair, client: &KeyPair, wg: [u8; 32]) -> AnnounceSessionRequest {
    let session_id = SessionId::from_u64(73);
    let open_tx_hash = "ab".repeat(32);
    AnnounceSessionRequest {
        client_sig: client.sign(&announce_signing_payload(
            &session_id,
            &client.public,
            &wg,
            &open_tx_hash,
        )),
        opener_sig: wallet.sign(&announce_opener_binding_payload(
            &session_id,
            &client.public,
            &wg,
            &open_tx_hash,
        )),
        session_id,
        client_pubkey: client.public,
        client_wg_pubkey: wg,
        open_tx_hash,
        opener_pubkey: wallet.public,
    }
}
fn config(dir: &std::path::Path, context: &ReceiptContext) -> Config {
    Config {
        control_listen: "127.0.0.1:0".parse().unwrap(),
        tunnel_listen: "127.0.0.1:0".parse().unwrap(),
        data_dir: dir.to_owned(),
        receipt_key: Arc::new(KeyPair::from_secret_bytes(&[31; 32])),
        wireguard_secret: StaticSecret::from([41; 32]),
        receipt_context: context.clone(),
    }
}
async fn receipt(
    http: &reqwest::Client,
    base: &str,
    request: &AnnounceSessionRequest,
) -> SessionStateResponse {
    http.get(format!("{base}/session/{}", request.session_id.to_hex()))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap()
}
async fn send_frame(tunnel: &mut Tunn, socket: &UdpSocket, frame: &[u8]) -> Vec<u8> {
    let mut buffer = vec![0; 65536];
    let TunnResult::WriteToNetwork(packet) = tunnel.encapsulate(frame, &mut buffer) else {
        panic!("established tunnel must encrypt frame");
    };
    let packet = packet.to_vec();
    socket.send(&packet).await.unwrap();
    packet
}

#[tokio::test]
async fn authenticated_wireguard_revocation_and_receipts_survive_embedded_restart() {
    let directory = tempfile::tempdir().unwrap();
    let wallet = KeyPair::from_secret_bytes(&[11; 32]);
    let client = KeyPair::from_secret_bytes(&[21; 32]);
    let client_secret = StaticSecret::from([51; 32]);
    let request = request(&wallet, &client, PublicKey::from(&client_secret).to_bytes());
    let context = ReceiptContext::v2(
        Address::from_pubkey(&[61; 32]),
        999,
        Address::from_pubkey(&[71; 32]),
    );
    let authority = Arc::new(Authority {
        state: Mutex::new((
            FundedSession {
                domain: context.clone(),
                session_id: request.session_id.clone(),
                opener: Address::from_pubkey(&wallet.public.0),
                client_pubkey: client.public,
                client_wg_pubkey: request.client_wg_pubkey,
                open_tx_hash: request.open_tx_hash.clone(),
                current_epoch: 10,
                expires_epoch: 20,
                escrow_ou: 100,
                open: true,
            },
            Revocation::default(),
            true,
        )),
    });
    let service = EmbeddedVpn::bind(config(directory.path(), &context), authority.clone())
        .await
        .unwrap();
    assert!(
        EmbeddedVpn::bind(config(directory.path(), &context), authority.clone())
            .await
            .is_err(),
        "a second receipt writer must not start"
    );
    let base = format!("http://{}", service.control_addr().unwrap());
    let endpoint = service.tunnel_addr();
    let (stop, shutdown) = watch::channel(false);
    let task = tokio::spawn(service.run(shutdown));
    let http = reqwest::Client::new();
    let mut forged = request.clone();
    forged.client_sig = Signature([0; 64]);
    assert_eq!(
        http.post(format!("{base}/session"))
            .json(&forged)
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        http.post(format!("{base}/session"))
            .json(&request)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(endpoint).await.unwrap();
    let node_public = PublicKey::from(&StaticSecret::from([41; 32]));
    let mut tunnel = Tunn::new(client_secret, node_public, None, None, 0, None);
    let mut buffer = vec![0; 65536];
    let TunnResult::WriteToNetwork(packet) = tunnel.format_handshake_initiation(&mut buffer, false)
    else {
        panic!("handshake");
    };
    socket.send(packet).await.unwrap();
    let received = tokio::time::timeout(Duration::from_secs(3), socket.recv(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    let mut work = vec![0; 65536];
    if let TunnResult::WriteToNetwork(packet) =
        tunnel.decapsulate(None, &buffer[..received], &mut work)
    {
        socket.send(packet).await.unwrap();
    }
    // The non-public destination is intentionally refused by egress. Successful
    // metering still proves the real WG decrypt, session binding and onion peel.
    let onion = build_onion(
        &[HopBuildInput {
            static_pubkey: node_public.to_bytes(),
            endpoint: endpoint.to_string(),
        }],
        &[127, 0, 0, 1, 0, 9, 17],
    )
    .unwrap();
    let frame = tunnel_frame::encode(&request.session_id, &onion).unwrap();
    let encrypted = send_frame(&mut tunnel, &socket, &frame).await;
    let before = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let value = receipt(&http, &base, &request).await;
            if value.bytes_served > 0 {
                break value;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(before.bytes_served, 32 + onion.len() as u64);
    socket.send(&encrypted).await.unwrap(); // WG replay window rejects identical ciphertext.
    let wrong = tunnel_frame::encode(&SessionId::from_u64(74), &onion).unwrap();
    send_frame(&mut tunnel, &socket, &wrong).await;
    authority.state.lock().unwrap().1.revoke();
    send_frame(&mut tunnel, &socket, &frame).await;
    assert_eq!(
        http.post(format!("{base}/session"))
            .json(&request)
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    let stopped = receipt(&http, &base, &request).await;
    assert_eq!(stopped.bytes_served, before.bytes_served);
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();

    authority.state.lock().unwrap().2 = false;
    let service = EmbeddedVpn::bind(config(directory.path(), &context), authority.clone())
        .await
        .unwrap();
    let base = format!("http://{}", service.control_addr().unwrap());
    let (stop, shutdown) = watch::channel(false);
    let task = tokio::spawn(service.run(shutdown));
    assert_eq!(
        http.post(format!("{base}/session"))
            .json(&request)
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    {
        let mut state = authority.state.lock().unwrap();
        state.1 = Revocation::default();
        state.2 = true;
    }
    assert_eq!(
        http.post(format!("{base}/session"))
            .json(&request)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let restored = receipt(&http, &base, &request).await;
    assert!(restored.last_seq > stopped.last_seq);
    assert_eq!(restored.bytes_served, stopped.bytes_served);
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
}

#[test]
fn committed_bindings_reject_rotation_replay_expiry_and_empty_escrow() {
    let wallet = KeyPair::from_secret_bytes(&[81; 32]);
    let client = KeyPair::from_secret_bytes(&[82; 32]);
    let request = request(&wallet, &client, [83; 32]);
    let domain = ReceiptContext::v1_1(Address::from_pubkey(&[84; 32]), 999);
    let session = FundedSession {
        domain,
        session_id: request.session_id.clone(),
        opener: Address::from_pubkey(&wallet.public.0),
        client_pubkey: client.public,
        client_wg_pubkey: request.client_wg_pubkey,
        open_tx_hash: request.open_tx_hash.clone(),
        current_epoch: 10,
        expires_epoch: 20,
        escrow_ou: 100,
        open: true,
    };
    let revocation = Revocation::default();
    let permit = session
        .authorize(&request, revocation.clone(), Duration::from_secs(60))
        .unwrap();
    assert!(permit.live());
    revocation.revoke();
    assert!(!permit.live());
    assert!(session
        .authorize(&request, revocation, Duration::from_secs(60))
        .is_none());
    for change in 0..9 {
        let mut denied = session.clone();
        match change {
            0 => denied.escrow_ou = 0,
            1 => denied.current_epoch = denied.expires_epoch,
            2 => denied.open = false,
            3 => denied.client_wg_pubkey = [85; 32],
            4 => denied.client_pubkey = wallet.public,
            5 => denied.opener = Address::from_pubkey(&client.public.0),
            6 => denied.session_id = SessionId::from_u64(74),
            7 => denied.open_tx_hash = "cd".repeat(32),
            _ => denied.expires_epoch = 0,
        }
        assert!(
            denied
                .authorize(&request, Revocation::default(), Duration::from_secs(60))
                .is_none(),
            "case {change}"
        );
    }
    let mut forged = request;
    forged.opener_sig = Signature([0; 64]);
    assert!(session
        .authorize(&forged, Revocation::default(), Duration::from_secs(60))
        .is_none());
}

struct BlockingAuthority {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}
#[async_trait]
impl SessionAuthority for BlockingAuthority {
    async fn authorize(
        &self,
        _: &AnnounceSessionRequest,
        _: &ReceiptContext,
    ) -> anyhow::Result<Option<SessionPermit>> {
        self.entered.notify_one();
        self.release.notified().await;
        Ok(None)
    }
    async fn lifecycle(&self, _: &SessionId, _: &ReceiptContext) -> anyhow::Result<RelayLifecycle> {
        anyhow::bail!("no session")
    }
}

#[tokio::test]
async fn cancellation_retains_writer_exclusion_until_inflight_authority_request_drains() {
    let directory = tempfile::tempdir().unwrap();
    let context = ReceiptContext::v1_1(Address::from_pubkey(&[93; 32]), 999);
    let authority = Arc::new(BlockingAuthority {
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
    });
    let service = EmbeddedVpn::bind(config(directory.path(), &context), authority.clone())
        .await
        .unwrap();
    let base = format!("http://{}", service.control_addr().unwrap());
    let (_stop, shutdown) = watch::channel(false);
    let task = tokio::spawn(service.run(shutdown));
    let request = request(
        &KeyPair::from_secret_bytes(&[91; 32]),
        &KeyPair::from_secret_bytes(&[92; 32]),
        [94; 32],
    );
    let inflight = tokio::spawn(async move {
        reqwest::Client::new()
            .post(format!("{base}/session"))
            .json(&request)
            .send()
            .await
    });
    tokio::time::timeout(Duration::from_secs(3), authority.entered.notified())
        .await
        .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(
        EmbeddedVpn::bind(config(directory.path(), &context), authority.clone())
            .await
            .is_err(),
        "detached HTTP request still owns the writer lock"
    );
    authority.release.notify_one();
    let response = tokio::time::timeout(Duration::from_secs(3), inflight)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(response.status().is_client_error() || response.status().is_server_error());
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Ok(restarted) =
                EmbeddedVpn::bind(config(directory.path(), &context), authority.clone()).await
            {
                drop(restarted);
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let mut wrong_domain = context.clone();
    wrong_domain.chain_id += 1;
    assert!(
        EmbeddedVpn::bind(config(directory.path(), &wrong_domain), authority.clone())
            .await
            .is_err()
    );
    let mut wrong_key = config(directory.path(), &context);
    wrong_key.receipt_key = Arc::new(KeyPair::from_secret_bytes(&[95; 32]));
    assert!(EmbeddedVpn::bind(wrong_key, authority).await.is_err());
}
