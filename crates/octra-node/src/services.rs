use std::{net::SocketAddr, sync::Arc};

use anyhow::{Context, Result};
use axum::{extract::State, http::StatusCode, response::IntoResponse, Router};
use octravpn_node::embedded::{Config, EmbeddedVpn};
use tokio::{net::TcpListener, sync::watch};
use tower::ServiceExt;

use crate::{vpn::Settlement, Host, Node, Shared};

/// Bound browser, HTTP control and WireGuard sockets in the same process.
/// Dropping or cancelling the running service revokes its canonical admission.
pub struct Services {
    browser: TcpListener,
    vpn: Vpn,
    shared: Arc<Shared>,
}
enum Vpn {
    Legacy(EmbeddedVpn),
    Payments(octravpn_node::payments::Service),
}
impl Vpn {
    fn control_addr(&self) -> Result<SocketAddr> {
        match self {
            Self::Legacy(vpn) => vpn.control_addr(),
            Self::Payments(vpn) => vpn.control_addr(),
        }
    }
    fn tunnel_addr(&self) -> SocketAddr {
        match self {
            Self::Legacy(vpn) => vpn.tunnel_addr(),
            Self::Payments(vpn) => vpn.tunnel_addr(),
        }
    }
    async fn run(self, shutdown: watch::Receiver<bool>) -> Result<()> {
        match self {
            Self::Legacy(vpn) => vpn.run(shutdown).await,
            Self::Payments(vpn) => vpn.run(shutdown).await,
        }
    }
}

impl<A: Host> Node<A> {
    /// The browser and private VPN share this node's exact publication. No
    /// second node or independently trusted RPC is used for admission.
    #[cfg(feature = "private-payments-experimental")]
    pub async fn bind_shielded(
        &self,
        browser_listen: SocketAddr,
        config: octravpn_node::payments::Config,
        wallet: &crate::vpn::payments::shielded::wallet::Wallet,
    ) -> Result<Services> {
        self.bind_shielded_mode(browser_listen, config, wallet, None)
            .await
    }
    #[cfg(feature = "private-payments-experimental")]
    pub async fn bind_shielded_purchases(
        &self,
        browser_listen: SocketAddr,
        config: octravpn_node::payments::Config,
        wallet: &crate::vpn::payments::shielded::wallet::Wallet,
        policy: crate::vpn::payments::shielded::wallet::rpc::Policy,
    ) -> Result<Services> {
        self.bind_shielded_mode(browser_listen, config, wallet, Some(policy))
            .await
    }
    #[cfg(feature = "private-payments-experimental")]
    async fn bind_shielded_mode(
        &self,
        browser_listen: SocketAddr,
        config: octravpn_node::payments::Config,
        wallet: &crate::vpn::payments::shielded::wallet::Wallet,
        policy: Option<crate::vpn::payments::shielded::wallet::rpc::Policy>,
    ) -> Result<Services> {
        anyhow::ensure!(
            wallet.belongs_to(&self.shared),
            "private wallet belongs to another node publication"
        );
        anyhow::ensure!(
            browser_listen.ip().is_loopback(),
            "browser must bind loopback"
        );
        let browser = TcpListener::bind(browser_listen).await?;
        let vpn = if let Some(policy) = policy {
            wallet.bind_purchase_service(config, policy).await?
        } else {
            wallet.bind_service(config).await?
        };
        Ok(Services {
            browser,
            vpn: Vpn::Payments(vpn),
            shared: self.shared.clone(),
        })
    }
    /// Native payment-plan service; canonical admission and the browser share
    /// one publication. The settlement publisher must await canonical claims.
    pub async fn bind_payments(
        &self,
        browser_listen: SocketAddr,
        config: octravpn_node::payments::Config,
        payments: Arc<crate::vpn::payments::Payments>,
        settlement: Arc<dyn octravpn_node::payments::Settlement>,
    ) -> Result<Services> {
        anyhow::ensure!(
            browser_listen.ip().is_loopback(),
            "browser must bind loopback"
        );
        let browser = TcpListener::bind(browser_listen).await?;
        let vpn = octravpn_node::payments::Service::bind(config, payments, settlement).await?;
        Ok(Services {
            browser,
            vpn: Vpn::Payments(vpn),
            shared: self.shared.clone(),
        })
    }
    pub async fn bind(
        &self,
        browser_listen: SocketAddr,
        vpn: Config,
        settlement: Arc<dyn Settlement>,
    ) -> Result<Services> {
        self.bind_with_ip_tunnel(browser_listen, vpn, settlement, None)
            .await
    }

    pub async fn bind_with_ip_tunnel(
        &self,
        browser_listen: SocketAddr,
        vpn: Config,
        settlement: Arc<dyn Settlement>,
        ip_tunnel: Option<octravpn_node::embedded::IpTunnelConfig>,
    ) -> Result<Services> {
        self.published()
            .bind_with_ip_tunnel(browser_listen, vpn, settlement, ip_tunnel)
            .await
    }
}

impl crate::published::Handle {
    pub(crate) async fn bind_with_ip_tunnel(
        &self,
        browser_listen: SocketAddr,
        vpn: Config,
        settlement: Arc<dyn Settlement>,
        ip_tunnel: Option<octravpn_node::embedded::IpTunnelConfig>,
    ) -> Result<Services> {
        anyhow::ensure!(
            browser_listen.ip().is_loopback(),
            "browser must bind loopback"
        );
        let browser = TcpListener::bind(browser_listen).await?;
        let vpn = EmbeddedVpn::bind_with_ip_tunnel(vpn, self.vpn_authority(settlement), ip_tunnel)
            .await?;
        Ok(Services {
            browser,
            vpn: Vpn::Legacy(vpn),
            shared: self.shared.clone(),
        })
    }
}

impl Services {
    pub(crate) fn with_stock_exit(
        mut self,
        exit: Option<Arc<octravpn_node::stock::Exit>>,
    ) -> Result<Self> {
        if let Some(exit) = exit {
            self.vpn = match self.vpn {
                Vpn::Payments(vpn) => Vpn::Payments(vpn.with_stock_exit(exit)?),
                Vpn::Legacy(_) => anyhow::bail!("stock exit requires canonical prepaid mode"),
            };
        }
        Ok(self)
    }
    pub(crate) fn with_settlement(
        mut self,
        publisher: Arc<dyn octravpn_node::embedded::ReceiptSettlement>,
    ) -> Self {
        if let Vpn::Legacy(vpn) = self.vpn {
            self.vpn = Vpn::Legacy(vpn.with_settlement(publisher));
        }
        self
    }
    pub fn browser_addr(&self) -> Result<SocketAddr> {
        Ok(self.browser.local_addr()?)
    }
    pub fn control_addr(&self) -> Result<SocketAddr> {
        self.vpn.control_addr()
    }
    pub fn tunnel_addr(&self) -> SocketAddr {
        self.vpn.tunnel_addr()
    }

    pub async fn run(self, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        let Self {
            browser,
            vpn,
            shared,
        } = self;
        let (stop, stopped) = watch::channel(false);
        let guard = Stop {
            shared: shared.clone(),
            signal: stop,
        };
        let mut browser_stop = stopped.clone();
        let router = browser_router(shared);
        let mut browser = Box::pin(std::future::IntoFuture::into_future(
            axum::serve(browser, router).with_graceful_shutdown(async move {
                let _ = browser_stop.wait_for(|v| *v).await;
            }),
        ));
        let mut vpn = Box::pin(vpn.run(stopped));
        let mut browser_done = false;
        let mut vpn_done = false;
        let result = tokio::select! {
            result = &mut browser => { browser_done = true; result.context("Circle browser stopped") },
            result = &mut vpn => { vpn_done = true; result.context("VPN service stopped") },
            () = async {
                while !*shutdown.borrow_and_update() {
                    if shutdown.changed().await.is_err() { break; }
                }
            } => Ok(()),
        };
        guard.stop();
        // Keep polling both services while they drain. Dropping this operation
        // closes their sockets; the VPN's receipt handles retain its writer lock.
        let drain = async {
            tokio::join!(
                async {
                    if !browser_done {
                        let _ = browser.await;
                    }
                },
                async {
                    if !vpn_done {
                        let _ = vpn.await;
                    }
                },
            );
        };
        let _ = tokio::time::timeout(std::time::Duration::from_secs(6), drain).await;
        result
    }
}

pub(crate) fn browser_router(shared: Arc<Shared>) -> Router {
    Router::new().fallback(dispatch).with_state(shared)
}

async fn dispatch(
    State(shared): State<Arc<Shared>>,
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
    // Each router and every resource URL remain bound to one exact root.
    // Old resource URLs fail the scope check after a new head is published.
    match serving.router.clone().oneshot(request).await {
        Ok(response) => response,
        Err(never) => match never {},
    }
}

struct Stop {
    shared: Arc<Shared>,
    signal: watch::Sender<bool>,
}
impl Stop {
    fn stop(&self) {
        self.shared.suspend("services stopped");
        self.signal.send_replace(true);
    }
}
impl Drop for Stop {
    fn drop(&mut self) {
        self.stop();
    }
}
