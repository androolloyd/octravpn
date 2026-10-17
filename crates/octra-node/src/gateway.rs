//! Canonical public Circle reads behind a tailnet HTTPS reverse proxy.
use crate::{Host, Node, Shared};
use anyhow::{ensure, Result};
use axum::{extract::State, http::StatusCode, response::IntoResponse, Router};
use octra_browser::http::{Gateway, Portal};
use octra_node_runtime::circle_assets::RetainedAssets;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Instant,
};
use tokio::{net::TcpListener, sync::watch};
use tower::ServiceExt;
mod cache;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: SocketAddr,
    pub origin: String,
    /// HTTPS DNS hostname to Circle. All website paths read canonical assets.
    #[serde(default)]
    pub sites: BTreeMap<String, String>,
    /// Unpaid onboarding assets on `origin` only. Mutually exclusive with sites.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub portal: Option<Portal>,
}

pub struct Service {
    listener: TcpListener,
    state: Arc<GatewayState>,
}

struct GatewayState {
    shared: Arc<Shared>,
    origin: String,
    sites: BTreeMap<String, String>,
    portal: Option<Portal>,
    retained: Mutex<cache::Cache<RetainedAssets>>,
}

impl<A: Host> Node<A> {
    pub async fn bind_gateway(&self, config: Config) -> Result<Service> {
        self.published().bind_gateway(config).await
    }
}

impl crate::published::Handle {
    pub(crate) async fn bind_gateway(&self, config: Config) -> Result<Service> {
        ensure!(
            config.listen.ip().is_loopback(),
            "gateway backend must bind loopback"
        );
        Gateway::validate_origin(&config.origin)?;
        ensure!(
            config.portal.is_none() || config.sites.is_empty(),
            "unpaid portal cannot grant broad Circle site access"
        );
        for (host, circle) in &config.sites {
            Gateway::validate_origin(&format!("https://{host}"))?;
            Gateway::validate_site(circle)?;
        }
        Ok(Service {
            listener: TcpListener::bind(config.listen).await?,
            state: Arc::new(GatewayState {
                shared: self.shared.clone(),
                origin: config.origin,
                sites: config.sites,
                portal: config.portal,
                retained: Mutex::new(cache::Cache::default()),
            }),
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
    State(state): State<Arc<GatewayState>>,
    request: axum::extract::Request,
) -> axum::response::Response {
    let Ok((current, ticket)) = state.shared.gateway_view() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [("cache-control", "no-store")],
            "Node is synchronizing",
        )
            .into_response();
    };
    // Retain only authenticated read capabilities, never historical whole trees
    // or wallet/execution hosts. A client-supplied scope cannot create authority.
    let selected = {
        let Ok(mut retained) = state.retained.lock() else {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        };
        let now = Instant::now();
        if retained
            .remember(current.identity().clone(), current.clone(), now)
            .is_err()
        {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        if let Some(path) = request.uri().path().strip_prefix("/snapshots/") {
            let scope = path.split('/').next().unwrap_or_default();
            let Some((identity, capability)) = retained.get(scope, now) else {
                return StatusCode::BAD_REQUEST.into_response();
            };
            if capability.identity() != &identity {
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
            capability
        } else {
            current
        }
    };
    let host = request
        .headers()
        .get("host")
        .and_then(|host| host.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let host = host.strip_suffix(":443").unwrap_or(&host);
    let site = state.sites.get(host);
    let origin = if site.is_some() {
        format!("https://{host}")
    } else {
        state.origin.clone()
    };
    let gateway = Gateway::new(Arc::new(selected), &origin).and_then(|gateway| {
        if let Some(portal) = &state.portal {
            gateway.with_portal(portal.clone())
        } else {
            match site {
                Some(circle) => gateway.with_site(circle),
                None => Ok(gateway),
            }
        }
    });
    let Ok(gateway) = gateway else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    match gateway.router().oneshot(request).await {
        Ok(response) if state.shared.gateway_view_still_valid(&ticket) => response,
        Ok(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            [("cache-control", "no-store")],
            "Node is synchronizing",
        )
            .into_response(),
        Err(never) => match never {},
    }
}
