use super::*;
use crate::gateway::{StockCircleConfig, StockPortalConfig};
use axum::routing::get;
use octra_browser::http::Portal;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::rustls::pki_types::ServerName;

struct Identity {
    _directory: tempfile::TempDir,
    config: TlsConfig,
    certificate: CertificateDer<'static>,
}

fn identity() -> Identity {
    let generated = rcgen::generate_simple_self_signed(vec!["portal.fixture.test".into()]).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let config = TlsConfig {
        certificate: directory.path().join("chain.pem"),
        private_key: directory.path().join("key.pem"),
    };
    std::fs::write(&config.certificate, generated.cert.pem()).unwrap();
    std::fs::write(&config.private_key, generated.key_pair.serialize_pem()).unwrap();
    Identity {
        certificate: generated.cert.der().clone(),
        config,
        _directory: directory,
    }
}

fn client(certificate: Option<CertificateDer<'static>>) -> tokio_rustls::TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    if let Some(certificate) = certificate {
        roots.add(certificate).unwrap();
    }
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    tokio_rustls::TlsConnector::from(Arc::new(config))
}

#[test]
fn stock_portal_cannot_become_a_public_or_generic_gateway() {
    let identity = identity();
    let circle = octra_node_protocol::transaction::address_from_public_key(
        b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    );
    let config = StockPortalConfig {
        listen: "198.18.0.1:443".parse().unwrap(),
        origin: "https://portal.fixture.test".into(),
        portal: Portal::new(
            std::str::from_utf8(&circle).unwrap(),
            ["/index.html".into()],
        )
        .unwrap(),
        tls: identity.config,
    };
    config.validate().unwrap();
    for listen in [
        "0.0.0.0:443",
        "127.0.0.1:443",
        "198.18.0.2:443",
        "198.18.0.1:80",
    ] {
        let mut changed = config.clone();
        changed.listen = listen.parse().unwrap();
        assert!(changed.validate().is_err(), "{listen}");
    }
    let mut changed = config.clone();
    changed.origin = "http://portal.fixture.test".into();
    assert!(changed.validate().is_err());
    let mut raw = serde_json::to_value(&config).unwrap();
    assert!(serde_json::from_value::<StockPortalConfig>(raw.clone()).is_ok());
    raw["sites"] = serde_json::json!({"arbitrary.fixture.test":config.portal.circle()});
    assert!(serde_json::from_value::<StockPortalConfig>(raw).is_err());
}

#[test]
fn paid_circle_listener_cannot_replace_the_free_portal_or_choose_another_bind() {
    let identity = identity();
    let config = StockCircleConfig {
        origin: "https://circles.fixture.test".into(),
        sites: std::collections::BTreeMap::default(),
        tls: identity.config,
    };
    config.validate().unwrap();
    let valid = serde_json::to_value(&config).unwrap();
    assert!(serde_json::from_value::<StockCircleConfig>(valid.clone()).is_ok());
    for (field, value) in [
        ("listen", serde_json::json!("0.0.0.0:443")),
        (
            "portal",
            serde_json::json!({"circle":"ignored","paths":["/index.html"]}),
        ),
    ] {
        let mut changed = valid.clone();
        changed[field] = value;
        assert!(serde_json::from_value::<StockCircleConfig>(changed).is_err());
    }
    let mut changed = config;
    changed
        .sites
        .insert("*.fixture.test".into(), "invalid".into());
    assert!(changed.validate().is_err());
}

#[test]
fn portal_tls_refuses_wrong_key_empty_chain_and_oversized_material() {
    let first = identity();
    let second = identity();
    load(&first.config).unwrap();
    assert!(load(&TlsConfig {
        certificate: first.config.certificate.clone(),
        private_key: second.config.private_key,
    })
    .is_err());
    std::fs::write(&first.config.certificate, []).unwrap();
    assert!(load(&first.config).is_err());
    std::fs::write(&first.config.certificate, vec![b'x'; 1_048_577]).unwrap();
    assert!(load(&first.config).is_err());
    let first = identity();
    std::fs::write(&first.config.private_key, vec![b'x'; 65_537]).unwrap();
    assert!(load(&first.config).is_err());
}

#[tokio::test]
async fn real_tls_verifies_name_and_trust_then_releases_partial_handshakes_on_stop() {
    let identity = identity();
    let acceptor = load(&identity.config).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, shutdown) = watch::channel(false);
    let worker = tokio::spawn(serve(
        listener,
        Router::new().route("/index.html", get(|| async { "fixed portal" })),
        acceptor,
        shutdown,
    ));
    let connector = client(Some(identity.certificate.clone()));
    let valid = ServerName::try_from("portal.fixture.test").unwrap();
    let wrong = ServerName::try_from("other.fixture.test").unwrap();
    let stream = tokio::net::TcpStream::connect(address).await.unwrap();
    assert!(connector.connect(wrong, stream).await.is_err());
    let stream = tokio::net::TcpStream::connect(address).await.unwrap();
    assert!(client(None).connect(valid.clone(), stream).await.is_err());
    // Invalid clients cannot terminate the listener or select plaintext.
    let stream = tokio::net::TcpStream::connect(address).await.unwrap();
    let mut stream = connector.connect(valid, stream).await.unwrap();
    stream
        .write_all(
            b"GET /index.html HTTP/1.1\r\nHost: portal.fixture.test\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200"));
    assert!(response.ends_with(b"fixed portal"));
    let mut partial = tokio::net::TcpStream::connect(address).await.unwrap();
    partial.write_all(&[0x16, 0x03]).await.unwrap();
    stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(2), worker)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(TcpListener::bind(address).await.is_ok());
}
