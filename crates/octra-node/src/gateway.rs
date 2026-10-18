//! Canonical public Circle reads behind a tailnet HTTPS reverse proxy.
use crate::{Host, Node, Shared};
use anyhow::{ensure, Result};
use axum::{extract::State, http::StatusCode, response::IntoResponse, Router};
use octra_browser::http::{Gateway, Portal};
use octra_node_runtime::circle_assets::RetainedAssets;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Instant,
};
use tokio::{net::TcpListener, sync::watch};
use tower::ServiceExt;
mod cache;
mod tls;

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

/// Operator-provisioned TLS identity. Private key material never enters Circle
/// state or browser configuration.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub certificate: PathBuf,
    pub private_key: PathBuf,
}
impl TlsConfig {
    fn resolve_paths(&mut self, parent: &Path) {
        for path in [&mut self.certificate, &mut self.private_key] {
            if path.is_relative() {
                *path = parent.join(&*path);
            }
        }
    }
}

/// The stock-client free route grants one canonical Circle asset capability,
/// never the general gateway or RPC service.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StockPortalConfig {
    pub listen: SocketAddr,
    pub origin: String,
    pub portal: Portal,
    pub tls: TlsConfig,
}

impl StockPortalConfig {
    pub(crate) fn resolve_paths(&mut self, parent: &Path) {
        self.tls.resolve_paths(parent);
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.listen.ip() == IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1))
                && self.listen.port() == 443,
            "stock portal must bind the VPN gateway at 198.18.0.1:443"
        );
        Gateway::validate_origin(&self.origin)?;
        Ok(())
    }
}

/// Canonical Circle browsing on a separate, paid stock-client route. The fixed
/// internal port cannot widen the registration-only portal's read capability.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StockCircleConfig {
    pub origin: String,
    #[serde(default)]
    pub sites: BTreeMap<String, String>,
    pub tls: TlsConfig,
}
impl StockCircleConfig {
    pub(crate) fn resolve_paths(&mut self, parent: &Path) {
        self.tls.resolve_paths(parent);
    }

    pub fn validate(&self) -> Result<()> {
        Gateway::validate_origin(&self.origin)?;
        for (host, circle) in &self.sites {
            Gateway::validate_origin(&format!("https://{host}"))?;
            Gateway::validate_site(circle)?;
        }
        Ok(())
    }
}

pub struct Service {
    listener: TcpListener,
    state: Arc<GatewayState>,
    tls: Option<tokio_rustls::TlsAcceptor>,
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

    pub async fn bind_stock_portal(&self, config: StockPortalConfig) -> Result<Service> {
        self.published().bind_stock_portal(config).await
    }

    pub async fn bind_stock_circle_gateway(&self, config: StockCircleConfig) -> Result<Service> {
        self.published().bind_stock_circle_gateway(config).await
    }
}

impl crate::published::Handle {
    pub(crate) async fn bind_gateway(&self, config: Config) -> Result<Service> {
        ensure!(
            config.listen.ip().is_loopback(),
            "gateway backend must bind loopback"
        );
        self.bind(config, None).await
    }

    pub(crate) async fn bind_stock_portal(&self, config: StockPortalConfig) -> Result<Service> {
        config.validate()?;
        let acceptor = tls::load(&config.tls)?;
        self.bind(
            Config {
                listen: config.listen,
                origin: config.origin,
                sites: BTreeMap::new(),
                portal: Some(config.portal),
            },
            Some(acceptor),
        )
        .await
    }

    pub(crate) async fn bind_stock_circle_gateway(
        &self,
        config: StockCircleConfig,
    ) -> Result<Service> {
        config.validate()?;
        let acceptor = tls::load(&config.tls)?;
        self.bind(
            Config {
                listen: SocketAddr::from(([198, 18, 0, 1], 8443)),
                origin: config.origin,
                sites: config.sites,
                portal: None,
            },
            Some(acceptor),
        )
        .await
    }

    async fn bind(
        &self,
        config: Config,
        tls: Option<tokio_rustls::TlsAcceptor>,
    ) -> Result<Service> {
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
            tls,
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
        let app = Router::new().fallback(dispatch).with_state(self.state);
        if let Some(acceptor) = self.tls {
            return tls::serve(self.listener, app, acceptor, shutdown).await;
        }
        axum::serve(self.listener, app)
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
