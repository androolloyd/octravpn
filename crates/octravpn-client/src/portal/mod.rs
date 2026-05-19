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
    let actual = listener
        .local_addr()
        .context("read portal listener addr")?;
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
    let (cmd, args) = ("cmd", vec!["/C".to_string(), "start".to_string(), "".to_string(), url.to_string()]);
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
