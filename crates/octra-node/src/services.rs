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
    vpn: EmbeddedVpn,
    shared: Arc<Shared>,
}

impl<A: Host> Node<A> {
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
            vpn,
            shared: self.shared.clone(),
        })
    }
}

impl Services {
    pub(crate) fn with_settlement(
        mut self,
        publisher: Arc<dyn octravpn_node::embedded::ReceiptSettlement>,
    ) -> Self {
        self.vpn = self.vpn.with_settlement(publisher);
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
        let router = Router::new().fallback(dispatch).with_state(shared);
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
