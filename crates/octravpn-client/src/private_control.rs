//! Private purchase transport. The caller persists the signed request before
//! exchange and reuses it after an ambiguous result. A verified reply still
//! requires local quote consent and canonical note confirmation.
mod endpoint;
use anyhow::{ensure, Context, Result};
pub use endpoint::Endpoint;
use octravpn_core::payments::{
    PrivateTarget, SignedConnect, SignedPrivateReply, SignedPrivateRequest, SignedShieldedStatus,
};
use std::{sync::Arc, time::Duration};

pub struct PrivateControl {
    endpoint: reqwest::Url,
    target: PrivateTarget,
    http: reqwest::Client,
    peer: Option<std::net::SocketAddrV4>,
}

#[async_trait::async_trait]
impl octravpn_core::payments::PrivateExchange for PrivateControl {
    async fn exchange(&self, request: &SignedPrivateRequest) -> Result<SignedPrivateReply> {
        Self::exchange(self, request).await
    }
}

impl PrivateControl {
    pub(crate) fn retryable(error: &anyhow::Error) -> bool {
        error.is::<octravpn_core::payments::Unavailable>()
            || error
                .downcast_ref::<reqwest::Error>()
                .is_some_and(|error| error.is_connect() || error.is_timeout() || error.is_body())
    }
    /// The separately accepted CA and TLS key pins are required; private requests never use
    /// cleartext HTTP, ambient proxy settings, redirects or system roots.
    pub fn new(
        origin: &str,
        target: PrivateTarget,
        ca_pem: &str,
        spki_pins: Vec<[u8; 32]>,
    ) -> Result<Self> {
        Self::at(origin, target, ca_pem, spki_pins, None)
    }

    /// Use an accepted socket address without consulting DNS. TLS still checks
    /// the original hostname, accepted CA and SPKI keys; no fallback is added.
    pub fn new_pinned(
        origin: &str,
        target: PrivateTarget,
        ca_pem: &str,
        spki_pins: Vec<[u8; 32]>,
        peer: std::net::SocketAddrV4,
    ) -> Result<Self> {
        Self::at(origin, target, ca_pem, spki_pins, Some(peer))
    }

    pub(crate) fn at(
        origin: &str,
        target: PrivateTarget,
        ca_pem: &str,
        spki_pins: Vec<[u8; 32]>,
        peer: Option<std::net::SocketAddrV4>,
    ) -> Result<Self> {
        use rustls::{
            client::WebPkiServerVerifier,
            pki_types::{pem::PemObject, CertificateDer},
            RootCertStore,
        };
        let mut endpoint = reqwest::Url::parse(origin)?;
        ensure!(
            endpoint.scheme() == "https"
                && endpoint.host_str().is_some()
                && endpoint.username().is_empty()
                && endpoint.password().is_none()
                && endpoint.query().is_none()
                && endpoint.fragment().is_none()
                && endpoint.path() == "/",
            "private control requires a bare HTTPS origin"
        );
        target.pool.validate()?;
        octravpn_core::parse_native_address(target.directory.display())?;
        ensure!(ca_pem.len() <= 16_384, "private control CA exceeds bound");
        ensure!(
            (1..=4).contains(&spki_pins.len()),
            "private control requires one to four accepted TLS keys"
        );
        let mut certificates = CertificateDer::pem_slice_iter(ca_pem.as_bytes())
            .collect::<std::result::Result<Vec<_>, _>>()?;
        ensure!(
            certificates.len() == 1,
            "private control requires exactly one accepted CA"
        );
        let mut roots = RootCertStore::empty();
        roots.add(certificates.remove(0))?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let inner = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
            .build()?;
        let verifier = Arc::new(octravpn_core::spki_verifier::SpkiPinVerifier::new(
            spki_pins, inner,
        ));
        let tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        let mut http = reqwest::Client::builder()
            .no_proxy()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(60))
            .use_preconfigured_tls(tls);
        if let Some(peer) = peer {
            ensure!(
                endpoint.port_or_known_default() == Some(peer.port()),
                "private control pin port differs"
            );
            let host = endpoint
                .host_str()
                .context("private control host missing")?;
            if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                ensure!(
                    ip == std::net::IpAddr::V4(*peer.ip()),
                    "private control pin IP differs"
                );
            }
            http = http.resolve(host, peer.into());
        }
        let http = http.build()?;
        endpoint.set_path("/shielded/purchase");
        Ok(Self {
            endpoint,
            target,
            http,
            peer,
        })
    }
    pub(crate) fn peer_pin(&self) -> Option<std::net::SocketAddrV4> {
        self.peer
    }
    pub async fn exchange(&self, request: &SignedPrivateRequest) -> Result<SignedPrivateReply> {
        request.verify()?;
        ensure!(
            request.request.target == self.target,
            "private request differs from accepted target"
        );
        let bytes = self.post("/shielded/purchase", request).await?;
        let reply: SignedPrivateReply = serde_json::from_slice(&bytes)?;
        reply.verify(request)?;
        Ok(reply)
    }

    /// Authenticated private admission/status only. This cannot submit native
    /// payments and accepts no public channel accounting as private funding.
    pub async fn connect(&self, request: &SignedConnect) -> Result<SignedShieldedStatus> {
        request.verify()?;
        ensure!(
            request.request.binding.deployment == self.target.pool,
            "private connection differs from accepted pool"
        );
        let bytes = self.post("/shielded/connect", request).await?;
        let signed: SignedShieldedStatus = serde_json::from_slice(&bytes)?;
        signed.verify()?;
        ensure!(
            signed.operator_key == self.target.operator
                && signed.status.connection == request.request,
            "private status differs from accepted operator/connection"
        );
        Ok(signed)
    }

    async fn post<T: serde::Serialize + Sync>(&self, path: &str, body: &T) -> Result<Vec<u8>> {
        let mut endpoint = self.endpoint.clone();
        endpoint.set_path(path);
        let mut response = self.http.post(endpoint).json(body).send().await?;
        if matches!(response.status().as_u16(), 408 | 429 | 502 | 503 | 504) {
            return Err(octravpn_core::payments::Unavailable::new(
                "private control temporarily unavailable",
            )
            .into());
        }
        ensure!(response.status().is_success(), "private purchase refused");
        ensure!(
            response
                .content_length()
                .is_none_or(|length| length <= 131_072),
            "private reply exceeds bound"
        );
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .context("private reply interrupted; retry the same request")?
        {
            ensure!(
                bytes.len() + chunk.len() <= 131_072,
                "private reply exceeds bound"
            );
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use octravpn_core::{
        payments::{Deployment, PrivateAction, PrivateRequest},
        Address, KeyPair,
    };
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    use tokio_rustls::{
        rustls::{self, pki_types::PrivatePkcs8KeyDer},
        TlsAcceptor,
    };

    #[tokio::test]
    async fn tls_control_checks_pinned_ca_target_reply_redirect_and_size() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let pin =
            octravpn_core::spki_verifier::SpkiPinVerifier::fingerprint(cert.cert.der()).unwrap();
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into(),
            )
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!(
            "https://localhost:{}/",
            listener.local_addr().unwrap().port()
        );
        let operator = KeyPair::from_secret_bytes(&[1; 32]);
        let target = PrivateTarget {
            chain_origin: [3; 32],
            pool: Deployment {
                domain: "ab".repeat(32),
                program: Address::from_pubkey(&operator.public.0),
            },
            directory: Address::from_pubkey(&[5; 32]),
            operator: operator.public,
        };
        let make = |id| {
            SignedPrivateRequest::sign(
                PrivateRequest {
                    target: target.clone(),
                    id: [id; 32],
                    valid_from_ms: 1,
                    expires_ms: 100,
                    action: PrivateAction::Open {
                        offer: 0,
                        ceiling_ou: 10,
                    },
                },
                &KeyPair::from_secret_bytes(&[2; 32]),
            )
            .unwrap()
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = calls.clone();
        let job = tokio::spawn(async move {
            'connections: loop {
                let (tcp, _) = listener.accept().await.unwrap();
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    continue;
                };
                let mut bytes = Vec::new();
                let (end, length) = loop {
                    let Ok(byte) = tls.read_u8().await else {
                        continue 'connections;
                    };
                    bytes.push(byte);
                    assert!(bytes.len() < 131_072);
                    if bytes.ends_with(b"\r\n\r\n") {
                        let headers = String::from_utf8(bytes.clone()).unwrap();
                        assert!(headers.starts_with("POST /shielded/purchase HTTP/1.1\r\n"));
                        let length = headers
                            .lines()
                            .find_map(|line| {
                                line.to_ascii_lowercase()
                                    .strip_prefix("content-length: ")
                                    .map(str::to_owned)
                            })
                            .unwrap()
                            .parse::<usize>()
                            .unwrap();
                        break (bytes.len(), length);
                    }
                };
                assert!(length < 131_072);
                bytes.resize(end + length, 0);
                tls.read_exact(&mut bytes[end..]).await.unwrap();
                let request: SignedPrivateRequest = serde_json::from_slice(&bytes[end..]).unwrap();
                request.verify().unwrap();
                counted.fetch_add(1, Ordering::SeqCst);
                let (status, body, extra) = match request.request.id[0] {
                    7 => ("503 Service Unavailable", String::new(), ""),
                    8 => ("403 Forbidden", String::new(), ""),
                    9 => ("429 Too Many Requests", String::new(), ""),
                    3 => (
                        "302 Found",
                        String::new(),
                        "Location: https://example.invalid/\r\n",
                    ),
                    4 | 6 => ("200 OK", "x".repeat(131_073), ""),
                    _ => {
                        let mut reply =
                            SignedPrivateReply::sign(&request, b"authenticated", &operator)
                                .unwrap();
                        if request.request.id[0] == 5 {
                            reply.request_hash[0] ^= 1;
                        }
                        ("200 OK", serde_json::to_string(&reply).unwrap(), "")
                    }
                };
                let (header, body) = if request.request.id[0] == 6 {
                    ("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_owned(), format!("{:X}\r\n{body}\r\n0\r\n\r\n", body.len()))
                } else {
                    (format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n", body.len()), body)
                };
                let _ = tls.write_all(header.as_bytes()).await;
                let _ = tls.write_all(body.as_bytes()).await;
                let _ = tls.shutdown().await;
            }
        });
        let client =
            PrivateControl::new(&origin, target.clone(), &cert.cert.pem(), vec![pin]).unwrap();
        let request = make(1);
        assert_eq!(
            octravpn_core::payments::PrivateExchange::exchange(&client, &request)
                .await
                .unwrap()
                .verify(&request)
                .unwrap(),
            b"authenticated"
        );
        for id in [3, 4, 5, 6] {
            let error = client.exchange(&make(id)).await.err().unwrap();
            assert!(!PrivateControl::retryable(&error));
        }
        for (id, temporary) in [(7, true), (8, false), (9, true)] {
            let error = client.exchange(&make(id)).await.err().unwrap();
            assert_eq!(PrivateControl::retryable(&error), temporary);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 8);
        let other_ca = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let wrong_ca =
            PrivateControl::new(&origin, target.clone(), &other_ca.cert.pem(), vec![pin]).unwrap();
        assert!(wrong_ca.exchange(&request).await.is_err());
        let wrong_pin =
            PrivateControl::new(&origin, target.clone(), &cert.cert.pem(), vec![[0; 32]]).unwrap();
        assert!(wrong_pin.exchange(&request).await.is_err());
        let wrong_host = PrivateControl::new(
            &origin.replace("localhost", "127.0.0.1"),
            target.clone(),
            &cert.cert.pem(),
            vec![pin],
        )
        .unwrap();
        assert!(wrong_host.exchange(&request).await.is_err());
        assert!(PrivateControl::new(&origin, target.clone(), &cert.cert.pem(), vec![]).is_err());
        let mut wrong = request.request.clone();
        wrong.target.chain_origin[0] ^= 1;
        let wrong =
            SignedPrivateRequest::sign(wrong, &KeyPair::from_secret_bytes(&[2; 32])).unwrap();
        assert!(client.exchange(&wrong).await.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 8);
        for bad in [
            "http://localhost/",
            "https://u:p@localhost/",
            "https://localhost/path",
            "https://localhost/?q=1",
            "https://localhost/#frag",
        ] {
            assert!(PrivateControl::new(bad, target.clone(), &cert.cert.pem(), vec![pin]).is_err());
        }
        assert!(
            client.exchange(&request).await.is_ok(),
            "TLS server must still be live after all refusals"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 9);
        job.abort();
        let _ = job.await;
    }
}
