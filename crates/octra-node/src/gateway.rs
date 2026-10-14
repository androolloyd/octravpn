//! Canonical public Circle reads behind a tailnet HTTPS reverse proxy.
use crate::{Host, Node, Shared};
use anyhow::{ensure, Result};
use axum::{extract::State, http::StatusCode, response::IntoResponse, Router};
use octra_browser::http::Gateway;
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc};
use tokio::{net::TcpListener, sync::watch};
use tower::ServiceExt;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: SocketAddr,
    pub origin: String,
}

pub struct Service {
    listener: TcpListener,
    state: (Arc<Shared>, String),
}

impl<A: Host> Node<A> {
    pub async fn bind_gateway(&self, config: Config) -> Result<Service> {
        ensure!(
            config.listen.ip().is_loopback(),
            "gateway backend must bind loopback"
        );
        Gateway::validate_origin(&config.origin)?;
        Ok(Service {
            listener: TcpListener::bind(config.listen).await?,
            state: (self.shared.clone(), config.origin),
        })
    }
}

impl Service {
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    pub async fn run(self, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        axum::serve(
            self.listener,
            Router::new().fallback(dispatch).with_state(self.state),
        )
        .with_graceful_shutdown(async move {
            while !*shutdown.borrow_and_update() {
                if shutdown.changed().await.is_err() {
                    break;
                }
            }
        })
        .await?;
        Ok(())
    }
}

async fn dispatch(
    State((shared, origin)): State<(Arc<Shared>, String)>,
    request: axum::extract::Request,
) -> axum::response::Response {
    let Ok(serving) = shared.current() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [("cache-control", "no-store")],
            "Node is synchronizing",
        )
            .into_response();
    };
    // Capture one already audited root for the whole request. No RPC fallback,
    // wallet, decryption capability or transaction bridge crosses this boundary.
    let Ok(gateway) = Gateway::new(Arc::new(serving.committed.assets.clone()), &origin) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    match gateway.router().oneshot(request).await {
        Ok(response) => response,
        Err(never) => match never {},
    }
}
