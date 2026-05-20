//! `oct://` browser portal — local HTTP server that resolves circle
//! assets and renders them in the operator's system browser.
//!
//! Entry points:
//!   * [`run_portal`] — long-running axum server, blocks until shutdown.
//!   * [`is_running`] — non-mutating probe to detect a sibling portal
//!     already listening on a given loopback port.
//!   * [`open_in_browser`] — best-effort `open` / `xdg-open` / `start`.
//!
//! The route table + render dispatch live in [`routes`].

use std::net::SocketAddr;

use anyhow::{Context, Result};
use tracing::info;

use crate::portal::chain::PortalChain;

pub(crate) mod chain;
pub(crate) mod mime;
pub(crate) mod routes;
pub(crate) mod static_assets;

pub(crate) use routes::PortalState;

/// Default loopback bind for `octravpn portal`.
pub(crate) const DEFAULT_PORTAL_PORT: u16 = 51_823;

/// Run the portal until `tokio::signal::ctrl_c` fires (or the listener
/// bind fails). Returns `Ok(())` on graceful shutdown.
pub(crate) async fn run_portal(chain: PortalChain, bind: SocketAddr) -> Result<()> {
    let state = PortalState::new(chain);
    let router = routes::router(state);

    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("bind portal {bind}"))?;
    let actual = listener.local_addr().context("read portal listener addr")?;
    info!(addr = %actual, "octravpn portal listening");
    println!("octravpn portal listening on http://{actual}/");
    println!("  paste oct:// URLs in the address bar, or click an oct:// link");
    println!("  Ctrl-C to stop");

    axum::serve(listener, router)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .context("portal axum serve")?;
    Ok(())
}

/// Non-mutating probe: returns `true` if `GET /healthz` on the given
/// address answers within ~1 second. Used by `open-url --portal` to
/// decide whether to spawn a fresh portal task or hand off to a running
/// one.
pub(crate) async fn is_running(addr: SocketAddr) -> bool {
    let url = format!("http://{addr}/healthz");
    let Ok(client) = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(1_000))
        .build()
    else {
        return false;
    };
    matches!(client.get(&url).send().await, Ok(r) if r.status().is_success())
}

/// Wait up to `total` for the portal at `addr` to become healthy.
/// Returns `true` if `/healthz` answers within the budget.
pub(crate) async fn wait_until_running(addr: SocketAddr, total: std::time::Duration) -> bool {
    let deadline = std::time::Instant::now() + total;
    loop {
        if is_running(addr).await {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
    }
}

/// Open a URL in the system browser. Returns `Ok(())` if a launcher
/// was found and exited successfully; logs (does not propagate) the
/// failure otherwise — the portal still works without an auto-launch.
pub(crate) fn open_in_browser(url: &str) -> Result<()> {
    // No new dep — we shell out to the OS launcher, which mirrors what
    // the `webbrowser` crate does internally on the platforms we care
    // about. `Command::status` so the child runs detached.
    #[cfg(target_os = "macos")]
    let (cmd, args) = ("open", vec![url.to_string()]);
    #[cfg(target_os = "windows")]
    let (cmd, args) = (
        "cmd",
        vec![
            "/C".to_string(),
            "start".to_string(),
            "".to_string(),
            url.to_string(),
        ],
    );
    #[cfg(target_os = "linux")]
    let (cmd, args) = ("xdg-open", vec![url.to_string()]);
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    let (cmd, args) = ("open", vec![url.to_string()]);

    let status = std::process::Command::new(cmd)
        .args(&args)
        .status()
        .with_context(|| format!("spawn `{cmd}` to open {url}"))?;
    if !status.success() {
        anyhow::bail!("`{cmd}` exited {status}");
    }
    Ok(())
}

// ── tests for the in-process portal server ───────────────────────────
//
// These exercise the auto-port-0 listener spawn that `run_portal` uses,
// the `/healthz` probe path, and concurrent connection handling. They
// deliberately don't shell out to the `octravpn portal` binary (that's
// covered in `tests/portal_integration.rs`); they spin the router up
// directly so we exercise the same code path the CLI does.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::portal::routes::router;
    use octravpn_core::rpc::RpcClient;
    use std::time::Duration;

    async fn spawn_test_portal() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let rpc = RpcClient::new("http://127.0.0.1:1");
        let chain = PortalChain::from_rpc(rpc, "octPROG".into(), 0);
        let state = PortalState::new(chain);
        let app = router(state);
        let listener = tokio::net::TcpListener::bind::<SocketAddr>("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        assert!(
            wait_until_running(addr, Duration::from_secs(2)).await,
            "portal test server did not become healthy"
        );
        (addr, handle)
    }

    #[tokio::test]
    async fn is_running_returns_true_for_live_portal() {
        let (addr, h) = spawn_test_portal().await;
        let up = is_running(addr).await;
        assert!(up, "live portal must answer /healthz");
        h.abort();
    }

    #[tokio::test]
    async fn is_running_returns_false_for_unreachable_addr() {
        // Port 1 is almost certainly closed.
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let up = is_running(addr).await;
        assert!(!up);
    }

    #[tokio::test]
    async fn wait_until_running_short_circuits_when_already_up() {
        let (addr, h) = spawn_test_portal().await;
        let ok = wait_until_running(addr, Duration::from_millis(500)).await;
        assert!(ok);
        h.abort();
    }

    #[tokio::test]
    async fn wait_until_running_times_out_when_no_listener() {
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let start = std::time::Instant::now();
        let ok = wait_until_running(addr, Duration::from_millis(250)).await;
        assert!(!ok, "no listener → should time out");
        // Should not exceed the budget by more than ~200ms.
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn portal_listens_on_auto_assigned_port_zero() {
        // Bind to :0 → kernel picks a free port. That's the production
        // path for the integration harness and for ad-hoc tests.
        let (addr, h) = spawn_test_portal().await;
        assert!(addr.port() != 0, "kernel must assign a real port");
        // GET / works.
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let resp = client.get(format!("http://{addr}/")).send().await.unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        let body = resp.text().await.unwrap();
        assert!(body.contains("octra portal"));
        h.abort();
    }

    #[tokio::test]
    async fn portal_handles_concurrent_health_checks() {
        // 100 simultaneous /healthz probes — none must error or
        // hang past a generous budget.
        let (addr, h) = spawn_test_portal().await;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let mut handles = Vec::with_capacity(100);
        for _ in 0..100 {
            let c = client.clone();
            handles.push(tokio::spawn(async move {
                c.get(format!("http://{addr}/healthz")).send().await
            }));
        }
        for j in handles {
            let r = j.await.expect("task did not panic").expect("HTTP error");
            assert_eq!(r.status().as_u16(), 200);
        }
        h.abort();
    }

    #[tokio::test]
    async fn portal_serves_index_and_healthz_under_one_runtime() {
        // Multiple sequential GETs share a runtime / connection pool —
        // the portal must not get wedged after the first request.
        let (addr, h) = spawn_test_portal().await;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        for _ in 0..5 {
            let r = client
                .get(format!("http://{addr}/healthz"))
                .send()
                .await
                .unwrap();
            assert_eq!(r.status().as_u16(), 200);
        }
        let r = client.get(format!("http://{addr}/")).send().await.unwrap();
        assert_eq!(r.status().as_u16(), 200);
        h.abort();
    }

    #[tokio::test]
    async fn portal_serves_404_for_unknown_routes() {
        let (addr, h) = spawn_test_portal().await;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let r = client
            .get(format!("http://{addr}/this-route-does-not-exist"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 404);
        h.abort();
    }
}
