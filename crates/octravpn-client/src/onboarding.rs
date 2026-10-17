//! Read-only loopback onboarding pages for personal mesh and paid providers.
//! The CLI owns the provider wallet and submits after the balance gate;
//! HTTP requests can never trigger a signature, payment, or network route.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result};
use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::get,
    Router,
};
use octravpn_core::{address::Address, rpc::RpcClient};
use tokio::task::JoinHandle;
use tracing::warn;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Checking,
    NeedsFunds(u128),
    RpcUnavailable,
    Opening,
    Connected,
}

#[derive(Clone)]
struct Page {
    host: String,
    kind: PageKind,
}

#[derive(Clone)]
enum PageKind {
    Personal {
        login_server: String,
    },
    Provider {
        wallet: String,
        needed_ou: u128,
        phase: Arc<Mutex<Phase>>,
    },
}

/// The page stays available for the life of the funded connection. Dropping
/// it closes the listener; no server or secret persists after disconnect.
pub(crate) struct Onboarding {
    page: Page,
    addr: SocketAddr,
    server: JoinHandle<()>,
}

impl Onboarding {
    pub(crate) async fn start(wallet: &Address, needed_ou: u128) -> Result<Self> {
        Self::start_inner(
            PageKind::Provider {
                wallet: wallet.display().to_owned(),
                needed_ou,
                phase: Arc::new(Mutex::new(Phase::Checking)),
            },
            true,
        )
        .await
    }

    #[cfg(test)]
    async fn start_without_browser(wallet: &Address, needed_ou: u128) -> Result<Self> {
        Self::start_inner(
            PageKind::Provider {
                wallet: wallet.display().to_owned(),
                needed_ou,
                phase: Arc::new(Mutex::new(Phase::Checking)),
            },
            false,
        )
        .await
    }

    pub(crate) async fn personal(login_server: &str) -> Result<Self> {
        Self::personal_inner(login_server, true).await
    }

    #[cfg(test)]
    async fn personal_without_browser(login_server: &str) -> Result<Self> {
        Self::personal_inner(login_server, false).await
    }

    async fn personal_inner(login_server: &str, open_browser: bool) -> Result<Self> {
        let parsed =
            reqwest::Url::parse(login_server).context("parse Octranet login-server URL")?;
        let host = parsed.host_str().unwrap_or_default();
        let secure_origin = parsed.scheme() == "https"
            || (parsed.scheme() == "http"
                && matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "::1"));
        anyhow::ensure!(
            secure_origin
                && !host.is_empty()
                && parsed.username().is_empty()
                && parsed.password().is_none()
                && parsed.query().is_none()
                && parsed.fragment().is_none()
                && parsed.path() == "/",
            "login-server must be an HTTPS origin (HTTP allowed only on loopback) with no credentials, path, query, or fragment"
        );
        Self::start_inner(
            PageKind::Personal {
                login_server: parsed.to_string().trim_end_matches('/').to_owned(),
            },
            open_browser,
        )
        .await
    }

    async fn start_inner(kind: PageKind, open_browser: bool) -> Result<Self> {
        let listener =
            tokio::net::TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
                .await
                .context("bind loopback onboarding page")?;
        let addr = listener.local_addr().context("read onboarding listener")?;
        let page = Page {
            host: addr.to_string(),
            kind,
        };
        let router = Router::new()
            .route("/", get(index))
            .with_state(page.clone());
        let server = tokio::spawn(async move {
            if let Err(error) = axum::serve(listener, router).await {
                warn!(%error, "onboarding page stopped");
            }
        });
        let session = Self { page, addr, server };
        let url = session.url();
        println!("Octranet onboarding: {url}");
        if open_browser {
            if let Err(error) = crate::portal::open_in_browser(&url) {
                warn!(%error, "could not open onboarding page; paste the URL in a browser");
            }
        }
        Ok(session)
    }

    fn url(&self) -> String {
        format!("http://{}/", self.addr)
    }

    fn phase(&self, phase: Phase) {
        if let PageKind::Provider { phase: current, .. } = &self.page.kind {
            *current.lock().unwrap_or_else(|e| e.into_inner()) = phase;
        }
    }

    /// Wait for enough wallet funds for the chosen escrow ceiling and an
    /// estimated opening/settlement fee reserve. The chain still validates
    /// the signed opening; this preflight grants no network access.
    pub(crate) async fn wait_for_funds(&self, rpc: &RpcClient, wallet: &Address) -> Result<()> {
        self.wait_for_funds_with_interval(rpc, wallet, Duration::from_secs(3))
            .await
    }

    async fn wait_for_funds_with_interval(
        &self,
        rpc: &RpcClient,
        wallet: &Address,
        interval: Duration,
    ) -> Result<()> {
        let PageKind::Provider { needed_ou, .. } = &self.page.kind else {
            anyhow::bail!("funding wait is available only for paid provider sessions");
        };
        loop {
            match rpc.balance(wallet).await {
                Ok(balance) => {
                    let available = balance
                        .raw
                        .parse::<u128>()
                        .context("invalid raw wallet balance from RPC")?;
                    if available >= *needed_ou {
                        self.phase(Phase::Opening);
                        return Ok(());
                    }
                    self.phase(Phase::NeedsFunds(available));
                }
                Err(error) => {
                    warn!(%error, "onboarding balance lookup failed; retrying");
                    self.phase(Phase::RpcUnavailable);
                }
            }
            tokio::select! {
                _ = tokio::time::sleep(interval) => {},
                signal = tokio::signal::ctrl_c() => {
                    signal.context("cancel onboarding")?;
                    anyhow::bail!("onboarding cancelled before funding");
                }
            }
        }
    }

    pub(crate) fn connected(&self) {
        self.phase(Phase::Connected);
    }

    pub(crate) async fn until_cancelled(&self) -> Result<()> {
        tokio::signal::ctrl_c()
            .await
            .context("wait for onboarding stop")
    }
}

impl Drop for Onboarding {
    fn drop(&mut self) {
        self.server.abort();
    }
}

async fn index(State(page): State<Page>, headers: HeaderMap) -> Response {
    // Literal loopback Host prevents DNS rebinding from exposing the wallet
    // address or connection state to a remote web origin.
    if headers.get(header::HOST).and_then(|v| v.to_str().ok()) != Some(page.host.as_str()) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let content = match &page.kind {
        PageKind::Personal { login_server } => format!(
            "<h2>Personal Octranet</h2><p>Creating a personal tailnet has no treasury deposit. Traffic carried on your own Octranet infrastructure has no operator toll; another operator carrying or exiting traffic must be paid in OCT. This stock Tailscale join does not open or meter a paid carrier session. Circle deployment and other chain transactions still have ordinary OCT fees. A chain-anchored personal mesh requires the new v5 application, an owner Circle member asset, and a node enforcing that root.</p><p>Login server:</p><code>{}</code><ol><li>Ask your Octranet administrator for a one-use pre-auth key minted by the running mesh daemon. Save it to a private local file.</li><li>On this device, run <code>tailscale up --login-server {} --auth-key=file:/path/to/one-use-key</code> in a terminal.</li><li>Check <code>tailscale status</code> before browsing your mesh services.</li></ol><h2>Paid provider exit</h2><p>Use <code>octravpn connect-v3 --tun-name NAME --onboard</code> with that provider's committed Circle and settlement app to see a funding/status page for a separate paid tunnel. This does not change host routes. On Linux, add <code>--paid-exit</code> to opt into a guarded public IPv4 exit route after tunnel authentication. Automatic paid-exit federation between stock Octranets is not active.</p><p class=\"note\">This local guide does not hold the join key, invoke Tailscale, or claim the mesh is connected. It does not set an exit route.</p>",
            escape_html(login_server),
            escape_html(login_server),
        ),
        PageKind::Provider { wallet, needed_ou, phase } => {
            let phase = *phase.lock().unwrap_or_else(|e| e.into_inner());
            let (title, detail) = match phase {
                Phase::Checking => ("Checking wallet", "Reading the current on-chain balance.".into()),
                Phase::NeedsFunds(available) => (
                    "Fund this wallet",
                    format!(
                        "Available: {available} raw OU. Estimated needed: {needed_ou} raw OU (session escrow plus transaction fee reserve). Send OCT to the address below with your normal wallet, then leave this page open."
                    ),
                ),
                Phase::RpcUnavailable => (
                    "Waiting for Octra RPC",
                    "Balance lookup failed. The client will retry; no session has been opened.".into(),
                ),
                Phase::Opening => (
                    "Opening provider session",
                    "Funding is present. The client is verifying and opening its canonical paid session; traffic remains closed until the operator authenticates.".into(),
                ),
                Phase::Connected => (
                    "Provider VPN connected",
                    "The paid provider tunnel authenticated. Traffic uses host routes configured for this TUN; on Linux, the separate opt-in --paid-exit route guard can carry public IPv4 browsing.".into(),
                ),
            };
            format!("<h2>{title}</h2><p>{detail}</p><p>Wallet address:</p><code>{}</code><p class=\"note\">The operator sets the OCT traffic rate, including zero; the protocol takes no commission. Self-carried Octranet traffic has no operator toll. This client does not meter stock Tailscale relay traffic or enable paid federation between Octranets. This page never asks for a private key or signs a transaction.</p>", escape_html(wallet))
        }
    };
    let body = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta http-equiv=\"refresh\" content=\"3\"><title>Octranet onboarding</title><style>body{{font:16px system-ui,sans-serif;max-width:42rem;margin:4rem auto;padding:0 1rem;line-height:1.5;color:#172230}}code{{display:block;overflow-wrap:anywhere;padding:1rem;background:#eef2f8;border-radius:.5rem}}.note{{color:#536171}}</style></head><body><h1>Octranet onboarding</h1>{content}</body></html>"
    );
    (
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::REFERRER_POLICY, "no-referrer"),
            (header::CONTENT_SECURITY_POLICY, "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"),
        ],
        Html(body),
    )
        .into_response()
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::post, Json};
    use octravpn_core::sig::KeyPair;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn funding_page_waits_and_then_marks_opening_without_http_side_effects() {
        let wallet = Address::from_pubkey(&KeyPair::from_secret_bytes(&[9; 32]).public.0);
        let queries = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&queries);
        let rpc = Router::new().route(
            "/",
            post(move |Json(request): Json<serde_json::Value>| {
                let count = Arc::clone(&count);
                async move {
                    assert_eq!(request["method"], "octra_balance");
                    let call = count.fetch_add(1, Ordering::SeqCst);
                    Json(json!({"jsonrpc":"2.0","id":request["id"],"result":{
                        "balance_raw":if call == 0 {"100"} else {"2100"},
                        "balance":"0.0021","nonce":0,"pending_nonce":0
                    }}))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rpc_addr = listener.local_addr().unwrap();
        let rpc_task = tokio::spawn(async move { axum::serve(listener, rpc).await.unwrap() });
        let page = Onboarding::start_without_browser(&wallet, 2_000)
            .await
            .unwrap();
        let client = reqwest::Client::new();
        let url = page.url();
        let rpc = RpcClient::new(format!("http://{rpc_addr}"));
        let waiting = page.wait_for_funds_with_interval(&rpc, &wallet, Duration::from_millis(100));
        tokio::pin!(waiting);
        tokio::select! {
            _ = &mut waiting => panic!("first balance was insufficient"),
            _ = tokio::time::sleep(Duration::from_millis(30)) => {},
        }
        let response = client.get(&url).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.text().await.unwrap();
        assert!(body.contains("Fund this wallet"));
        assert!(body.contains(&wallet.display()));
        assert!(body.contains("Self-carried Octranet traffic has no operator toll"));
        tokio::time::timeout(Duration::from_secs(5), waiting)
            .await
            .expect("funding poll timed out")
            .unwrap();
        assert!(client
            .get(&url)
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap()
            .contains("Opening provider session"));
        page.connected();
        assert!(client
            .get(&url)
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap()
            .contains("Provider VPN connected"));
        assert_eq!(
            client.post(&url).send().await.unwrap().status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
        assert_eq!(
            client
                .get(&url)
                .header(header::HOST, "evil.example")
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
        rpc_task.abort();
    }

    #[tokio::test]
    async fn personal_guide_is_read_only_and_requires_a_clean_login_origin() {
        let page = Onboarding::personal_without_browser("https://mesh.example")
            .await
            .unwrap();
        let client = reqwest::Client::new();
        let url = page.url();
        let response = client.get(&url).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.text().await.unwrap();
        assert!(body
            .contains("Traffic carried on your own Octranet infrastructure has no operator toll"));
        assert!(body.contains("another operator carrying or exiting traffic must be paid in OCT"));
        assert!(body.contains("tailscale up --login-server https://mesh.example"));
        assert!(body.contains("--auth-key=file:/path/to/one-use-key"));
        assert!(body.contains("Paid provider exit"));
        assert!(
            body.contains("Automatic paid-exit federation between stock Octranets is not active")
        );
        assert!(!body.contains("secret"));
        assert_eq!(
            client.post(&url).send().await.unwrap().status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
        assert!(
            Onboarding::personal_without_browser("https://user:secret@mesh.example")
                .await
                .is_err()
        );
        assert!(
            Onboarding::personal_without_browser("https://mesh.example/path")
                .await
                .is_err()
        );
        assert!(Onboarding::personal_without_browser("http://mesh.example")
            .await
            .is_err());
    }
}
