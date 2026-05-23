//! End-to-end coverage for the parallel raw-rustls `/ts2021`
//! listener (`tailscale_wire::raw_tls::serve_raw_tls`).
//!
//! Replicates the wall the docker-interop harness used to hit before
//! the raw-listener fix landed: stock `tailscale up` opens TLS to
//! `:443`, sends `POST /ts2021` with `Upgrade:
//! tailscale-control-protocol`, expects `101 Switching Protocols`,
//! and then writes the Noise IK Initiation frame on the same TCP
//! socket. With `axum-server::bind_rustls` the hyper-rustls read
//! buffer drained the Initiation bytes before our handler regained
//! the socket — see `docs/tailscale-interop-blocker.md` 2026-05-19
//! §"P0 batch shipped".
//!
//! This test drives the equivalent flow against an ephemeral port
//! bound by `serve_raw_tls`, asserts:
//!
//!   1. `GET /key` over TLS routes through the inner axum router
//!      and returns the `OverTLSPublicKeyResponse` JSON.
//!   2. `POST /ts2021` over TLS routes to `drive_ts2021`, the server
//!      writes a valid Noise IK Reply frame back, and the initiator
//!      reaches handshake-finished state.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use octravpn_mesh::{
    ip_alloc::TailnetIpAllocator,
    tailscale_wire::{
        controlbase::{FrameHeader, Framed, MsgType},
        raw_tls::serve_raw_tls,
        tls::{self as wire_tls, SanConfig},
        MachineRegistry,
    },
    tailscale_wire_router, PreauthMinter, ServerNoiseKey, WireState,
};
use rustls::{
    pki_types::{pem::PemObject, CertificateDer},
    ClientConfig, RootCertStore,
};
use tempfile::tempdir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

fn octra_dns_store() -> headscale_api::dns::DnsStore {
    headscale_api::dns::DnsStore::from_spec(headscale_api::dns::DnsConfigSpec {
        base_domain: "octra.test".into(),
        ..Default::default()
    })
}

fn build_state() -> (WireState, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let server = Arc::new(ServerNoiseKey::load_or_generate(dir.path()).unwrap());
    let state = WireState {
        server_noise_key: server,
        preauth: Arc::new(PreauthMinter::new()),
        ip_allocator: Arc::new(TailnetIpAllocator::new("raw-tls-test")),
        machines: Arc::new(MachineRegistry::new()),
        registration_store: None,
        derp_map: Arc::new(octravpn_mesh::tailscale_wire::DerpMap::default()),
        policy: Arc::new(headscale_api::policy::PolicyStore::default()),
        knock: octravpn_mesh::tailscale_wire::KnockConfig::disabled(),
        dns: std::sync::Arc::new(octra_dns_store()),
        public_control_url: None,
        runtime_config: Arc::new(octravpn_mesh::tailscale_wire::RuntimeConfigSnapshot::default()),
        registration_cache: Arc::new(octravpn_mesh::tailscale_wire::RegistrationCache::new()),
        pings: Arc::new(octravpn_mesh::tailscale_wire::PingTracker::new()),
    };
    (state, dir)
}

/// Mint TLS material, then spawn `serve_raw_tls` on an ephemeral
/// port. Returns the bound address + the root cert (DER) that the
/// client should trust.
async fn spawn_raw_tls(state: WireState) -> (SocketAddr, CertificateDer<'static>) {
    let dir = tempdir().unwrap();
    let sans = SanConfig::with_hostname("localhost");
    let material = wire_tls::load_or_generate(dir.path(), &sans).unwrap();
    // Pull the DER cert for the client trust store.
    let cert_der: CertificateDer<'static> =
        CertificateDer::pem_slice_iter(material.cert_pem.as_bytes())
            .next()
            .unwrap()
            .unwrap();

    // Pick an ephemeral port via a throwaway bind.
    let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr: SocketAddr = std_listener.local_addr().unwrap();
    drop(std_listener);

    let server_config = Arc::clone(&material.server_config);
    let router = tailscale_wire_router(state.clone());
    let state_clone = state.clone();
    tokio::spawn(async move {
        let _ = serve_raw_tls(addr, server_config, router, state_clone).await;
    });

    // Tiny settle window so the listener is bound before the client
    // dials in. The port reservation above is racy with another
    // process on a busy CI host; the loop in
    // `get_key_through_raw_tls` re-dials if needed.
    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, cert_der)
}

fn client_config_trusting(cert: &CertificateDer<'static>) -> Arc<ClientConfig> {
    // Ensure the aws-lc-rs provider is installed for the client side.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut roots = RootCertStore::empty();
    roots.add(cert.clone()).unwrap();
    let mut cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(cfg)
}

async fn dial_tls(
    addr: SocketAddr,
    client_cfg: Arc<ClientConfig>,
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let server_name = rustls::pki_types::ServerName::try_from("localhost")
        .unwrap()
        .to_owned();
    // Retry a couple of times against the race between port-reservation
    // teardown and `serve_raw_tls` re-binding.
    for _ in 0..10 {
        if let Ok(tcp) = TcpStream::connect(addr).await {
            let connector = tokio_rustls::TlsConnector::from(client_cfg.clone());
            if let Ok(s) = connector.connect(server_name.clone(), tcp).await {
                return s;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("could not dial raw_tls listener at {addr}");
}

/// `GET /key` over the raw-tls listener must hit the inner axum
/// router and return the `OverTLSPublicKeyResponse` JSON.
#[tokio::test]
async fn non_ts2021_post_dispatches_to_router() {
    let (state, _dir) = build_state();
    let expected_pub = format!("mkey:{}", state.server_noise_key.public_hex());
    let (addr, cert) = spawn_raw_tls(state).await;
    let client_cfg = client_config_trusting(&cert);
    let mut s = dial_tls(addr, client_cfg).await;

    let req = b"GET /key HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    s.write_all(req).await.unwrap();
    s.flush().await.unwrap();

    let mut resp = Vec::new();
    s.read_to_end(&mut resp).await.unwrap();
    let text = String::from_utf8_lossy(&resp);
    assert!(
        text.starts_with("HTTP/1.1 200"),
        "expected 200 from /key route, got: {text}"
    );
    assert!(
        text.contains(&expected_pub),
        "response body should contain the server pubkey {expected_pub}:\n{text}"
    );
}

/// `POST /ts2021` with the upgrade header must reach `drive_ts2021`
/// over the unbuffered TLS stream, write the 101 response, and
/// respond to a Noise IK Initiation frame with a valid Reply frame.
///
/// This is the regression test for the hyper-rustls read-buffer drain
/// (see module doc + `docs/tailscale-interop-blocker.md` 2026-05-19
/// §"P0 batch shipped"). If the listener is wired through axum-server
/// the test hangs at `read_frame()` because the Initiation bytes are
/// trapped in hyper's TLS read buffer.
#[tokio::test]
async fn ts2021_post_dispatches_to_drive_ts2021_over_tls() {
    let (state, _dir) = build_state();
    let server_pub = state.server_noise_key.public_bytes();
    let initiator = state.server_noise_key.build_initiator(&server_pub).unwrap();
    let (addr, cert) = spawn_raw_tls(state).await;
    let client_cfg = client_config_trusting(&cert);
    let mut s = dial_tls(addr, client_cfg).await;

    // Send the upgrade request. We deliberately put the Initiation
    // frame in the SAME write as the headers so the server sees them
    // arrive in the same read — this is the wire pattern that broke
    // before the raw_tls fix.
    let upgrade = b"POST /ts2021 HTTP/1.1\r\n\
        Host: localhost\r\n\
        Upgrade: tailscale-control-protocol\r\n\
        Connection: Upgrade\r\n\
        Content-Length: 0\r\n\
        \r\n";
    let mut payload = upgrade.to_vec();

    // Build the Initiation frame and append.
    let mut init = initiator;
    let mut init_body = vec![0u8; 1024];
    let n = init.write_message(b"", &mut init_body).unwrap();
    init_body.truncate(n);
    // Upstream layout: [version:u16be][type=1:u8][len:u16be][body...].
    // See controlbase.rs::MsgType doc.
    payload.extend_from_slice(&39u16.to_be_bytes());
    payload.push(MsgType::Initiation as u8);
    payload.extend_from_slice(&(init_body.len() as u16).to_be_bytes());
    payload.extend_from_slice(&init_body);
    s.write_all(&payload).await.unwrap();
    s.flush().await.unwrap();

    // Read the 101 response line + headers off the stream.
    let mut header_buf = Vec::with_capacity(512);
    let mut tmp = [0u8; 256];
    loop {
        let n = s.read(&mut tmp).await.unwrap();
        if n == 0 {
            break;
        }
        header_buf.extend_from_slice(&tmp[..n]);
        if header_buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let header_text = String::from_utf8_lossy(&header_buf);
    assert!(
        header_text.starts_with("HTTP/1.1 101"),
        "expected 101 Switching Protocols, got: {header_text}"
    );
    assert!(
        header_text
            .to_ascii_lowercase()
            .contains("upgrade: tailscale-control-protocol"),
        "expected Upgrade header echo: {header_text}"
    );

    // Split off any post-101 bytes that already arrived (the Reply
    // frame may have been sent in the same TLS record).
    let end = header_buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap()
        + 4;
    let post_headers = header_buf[end..].to_vec();

    // From here on the stream speaks controlbase framing. Wrap the
    // remainder in a Framed reader, prefixing any bytes the server
    // already wrote post-101.
    let prefixed = ClientPrefixedStream::new(post_headers, s);
    let mut framed = Framed::new(prefixed);
    let (hdr, reply_body) = tokio::time::timeout(Duration::from_secs(5), framed.read_frame())
        .await
        .expect("server must respond with Reply frame within 5s — drain wall regression?")
        .expect("read reply frame");
    assert!(matches!(
        hdr,
        FrameHeader::Regular {
            msg_type: MsgType::Reply,
            ..
        }
    ));
    let mut throw = vec![0u8; 1024];
    init.read_message(&reply_body, &mut throw)
        .expect("noise reply decrypts");
    assert!(init.is_handshake_finished(), "initiator must finish IK");
}

/// Tiny adapter mirroring `raw_tls::PrefixedStream` for the client
/// side of the integration test. Lets us prepend bytes consumed in
/// the header-read phase before delegating to the underlying TLS
/// stream.
struct ClientPrefixedStream<T> {
    prefix: Vec<u8>,
    offset: usize,
    inner: T,
}

impl<T> ClientPrefixedStream<T> {
    fn new(prefix: Vec<u8>, inner: T) -> Self {
        Self {
            prefix,
            offset: 0,
            inner,
        }
    }
}

impl<T: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for ClientPrefixedStream<T> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.offset < self.prefix.len() {
            let remaining = &self.prefix[self.offset..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            self.offset += n;
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for ClientPrefixedStream<T> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
