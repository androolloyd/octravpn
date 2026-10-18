//! Bounded HTTPS transport for the fixed Circle portal on the VPN interface.
use super::TlsConfig;
use anyhow::{ensure, Context, Result};
use axum::Router;
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use std::{fs::File, io::Read, sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::watch, task::JoinSet};
use tokio_rustls::{
    rustls::{
        self,
        pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
    },
    TlsAcceptor,
};
use zeroize::Zeroizing;

const CONNECTIONS: usize = 64;
const HANDSHAKE: Duration = Duration::from_secs(10);
const DRAIN: Duration = Duration::from_secs(5);
const CONNECTION_LIFETIME: Duration = Duration::from_secs(60);

fn material(path: &std::path::Path, limit: u64) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    File::open(path)?.take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= limit,
        "portal TLS material is too large"
    );
    Ok(bytes)
}

pub(super) fn load(config: &TlsConfig) -> Result<TlsAcceptor> {
    let certificates =
        material(&config.certificate, 1_048_576).context("cannot load portal certificate chain")?;
    let chain = CertificateDer::pem_slice_iter(&certificates)
        .take(17)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("invalid portal certificate chain")?;
    ensure!(
        !chain.is_empty() && chain.len() <= 16,
        "invalid portal chain length"
    );
    let private =
        material(&config.private_key, 65_536).context("cannot load portal private key")?;
    let key = PrivateKeyDer::from_pem_slice(&private).context("invalid portal private key")?;
    let mut server = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(chain, key)
    .context("portal TLS certificate and key differ")?;
    server.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(server)))
}

async fn stopped(shutdown: &mut watch::Receiver<bool>) {
    while !*shutdown.borrow_and_update() {
        if shutdown.changed().await.is_err() {
            break;
        }
    }
}

pub(super) async fn serve(
    listener: TcpListener,
    app: Router,
    acceptor: TlsAcceptor,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let mut tasks = JoinSet::new();
    let result = loop {
        tokio::select! {
            biased;
            () = stopped(&mut shutdown) => break Ok(()),
            finished = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Err(error)) = finished {
                    if error.is_panic() { break Err(error.into()); }
                }
            }
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(value) => value,
                    Err(error) => break Err(error.into()),
                };
                if tasks.len() >= CONNECTIONS {
                    drop(stream);
                    continue;
                }
                let acceptor = acceptor.clone();
                let app = app.clone();
                let mut shutdown = shutdown.clone();
                tasks.spawn(async move {
                    let stream = tokio::select! {
                        biased;
                        () = stopped(&mut shutdown) => return,
                        result = tokio::time::timeout(HANDSHAKE, acceptor.accept(stream)) => {
                            match result { Ok(Ok(stream)) => stream, _ => return }
                        }
                    };
                    let mut builder = hyper::server::conn::http1::Builder::new();
                    builder.timer(TokioTimer::new())
                        .header_read_timeout(HANDSHAKE)
                        .max_buf_size(32_768);
                    let connection = builder.serve_connection(
                        TokioIo::new(stream), TowerToHyperService::new(app),
                    );
                    tokio::pin!(connection);
                    tokio::select! {
                        biased;
                        () = stopped(&mut shutdown) => {},
                        () = tokio::time::sleep(CONNECTION_LIFETIME) => {},
                        _ = &mut connection => return,
                    }
                    connection.as_mut().graceful_shutdown();
                    let _ = tokio::time::timeout(DRAIN, connection).await;
                });
            }
        }
    };
    // Bound the whole service drain as well as each TLS connection. Dropping
    // this owning JoinSet also aborts all connections on parent cancellation.
    if tokio::time::timeout(DRAIN, async { while tasks.join_next().await.is_some() {} })
        .await
        .is_err()
    {
        tasks.shutdown().await;
    }
    result
}

#[cfg(test)]
mod tests;
