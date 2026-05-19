//! End-to-end integration for the `oct://` browser portal.
//!
//! Spins up:
//!   1. A stub chain RPC (axum on a random loopback port) that serves
//!      `circle_asset_ciphertext_by_resource_key` with a synthetic
//!      JSON policy.
//!   2. The portal itself, pointed at the stub RPC.
//!
//! Then walks: GET / (index) → GET /confirm?u=… (interstitial) →
//! POST /approve → GET /o/<b64> (render).
//!
//! This is a black-box test through the real axum routes — the only
//! mock is the chain RPC itself. Validates that the security gates
//! (confirm + sandbox) fire end-to-end, not just in unit-tests.

use std::{net::SocketAddr, time::Duration};

use axum::{routing::post, Json, Router};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine as _};
use octravpn_core::circle::{encrypt_sealed_bytes, PaddingClass};
use serde_json::json;

#[tokio::test]
async fn portal_walks_index_confirm_resolve_render() {
    // ─── 1. start mock chain RPC ────────────────────────────────────
    let mock_rpc: Router = Router::new().route(
        "/",
        post(|axum::Json(req): axum::Json<serde_json::Value>| async move {
            let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("");
            let id = req.get("id").cloned().unwrap_or(json!(1));
            if method == "circle_asset_ciphertext_by_resource_key" {
                let payload = br#"{"endpoint":"vpn.example:51820","region":"us-east"}"#;
                let b64 = base64::engine::general_purpose::STANDARD.encode(payload);
                Json(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "ciphertext_b64": b64,
                        "plaintext_hash": "0".repeat(64),
                        "key_id": "default",
                    }
                }))
            } else {
                Json(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": { "code": -32601, "message": "method not found" },
                }))
            }
        }),
    );
    let rpc_listener =
        tokio::net::TcpListener::bind::<SocketAddr>("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
    let rpc_addr = rpc_listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(rpc_listener, mock_rpc).await.unwrap();
    });

    // ─── 2. start portal on a random loopback port ──────────────────
    // The portal is internal to octravpn-client; we drive it through
    // the binary by importing the routes module from the crate. But
    // integration tests don't see `pub(crate)` items. So we exercise
    // the portal via its public CLI surface instead — spawn the
    // binary, then HTTP it.
    let bin = env!("CARGO_BIN_EXE_octravpn");

    // Build a config file pointing at the mock RPC.
    let tmp = tempfile::tempdir().unwrap();
    let wallet = tmp.path().join("wallet.hex");
    std::fs::write(
        &wallet,
        "deadbeefcafebabe0011223344556677deadbeefcafebabe0011223344556677",
    )
    .unwrap();
    let cfg = tmp.path().join("client.toml");
    std::fs::write(
        &cfg,
        format!(
            r#"
[chain]
rpc_url          = "http://{rpc_addr}/"
program_addr     = "octPROG_TEST"
protocol_version = "v3"

[wallet]
addr        = "octADDR_TEST"
secret_path = "{}"
"#,
            wallet.display(),
        ),
    )
    .unwrap();

    // Pick a free port for the portal.
    let portal_listener =
        std::net::TcpListener::bind::<SocketAddr>("127.0.0.1:0".parse().unwrap()).unwrap();
    let portal_addr = portal_listener.local_addr().unwrap();
    drop(portal_listener); // release so the spawned binary can bind it

    // Spawn the portal as a child process. tokio::process so we can
    // shut it down at the end.
    let mut child = tokio::process::Command::new(bin)
        .args([
            "--config",
            &cfg.display().to_string(),
            "portal",
            "--bind",
            &portal_addr.to_string(),
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn octravpn portal");

    // Wait for the portal to come up.
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let mut up = false;
    for _ in 0..50 {
        if let Ok(r) = http
            .get(format!("http://{portal_addr}/healthz"))
            .send()
            .await
        {
            if r.status().is_success() {
                up = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(up, "portal didn't come up on {portal_addr}");

    // ─── 3. walk index ──────────────────────────────────────────────
    let body = http
        .get(format!("http://{portal_addr}/"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(body.contains("octra portal"));

    // ─── 4. /o/<b64> for an unknown circle returns the confirm page
    let oct_url = "oct://circleINTEG/policy.json";
    let b64 = B64URL.encode(oct_url.as_bytes());
    let body = http
        .get(format!("http://{portal_addr}/o/{b64}"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        body.contains("Approve this circle?"),
        "expected confirm page, got: {body}",
    );

    // Extract the HMAC token from the form for the next step. We
    // search for `name="token" value="..."`.
    let token_marker = "name=\"token\" value=\"";
    let start = body.find(token_marker).expect("token field");
    let after = &body[start + token_marker.len()..];
    let end = after.find('"').unwrap();
    let token = &after[..end];
    assert!(
        token.len() == 64,
        "expected 32-byte hex token, got {}: {token}",
        token.len()
    );

    // ─── 5. POST /approve ───────────────────────────────────────────
    let approve = http
        .post(format!("http://{portal_addr}/approve"))
        .form(&[
            ("circle", "circleINTEG"),
            ("token", token),
            ("next", &format!("/o/{b64}")),
        ])
        .send()
        .await
        .unwrap();
    assert!(
        approve.status().is_success() || approve.status().is_redirection(),
        "approve status: {}",
        approve.status(),
    );

    // ─── 6. now /o/<b64> renders the JSON asset ─────────────────────
    let body = http
        .get(format!("http://{portal_addr}/o/{b64}"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        body.contains("us-east"),
        "expected fetched policy in body: {body}",
    );
    // Sandbox isn't applied to JSON (only HTML) — assert the body is
    // NOT wrapped in a sandbox iframe.
    assert!(!body.contains("sandbox=\"allow-popups\""));

    // ─── 7. /api/resolve agrees with what we just rendered ──────────
    let v: serde_json::Value = http
        .get(format!(
            "http://{portal_addr}/api/resolve?u={}",
            urlencode(oct_url)
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v.get("circle_id").and_then(|x| x.as_str()), Some("circleINTEG"));
    assert_eq!(v.get("path").and_then(|x| x.as_str()), Some("/policy.json"));
    assert_eq!(v.get("allowed").and_then(serde_json::Value::as_bool), Some(true));

    // Shutdown.
    let _ = child.kill().await;
}

/// End-to-end: the chain serves a SEALED asset, the portal is booted
/// with `OCTRAVPN_SEALED_PASSPHRASE` set, and the rendered page contains
/// the plaintext JSON's distinctive fields — proving the decrypt path
/// runs before the MIME sniff.
#[tokio::test]
async fn portal_decrypts_sealed_asset_with_env_passphrase() {
    let circle_id = "octCIRCLE_SEALED";
    let key_id = "default";
    let passphrase = "integration-test-passphrase";
    let plaintext = br#"{"endpoint":"vpn-sealed.example:51820","region":"eu-west","distinctive_field":"decrypted_ok"}"#;
    let (ct_b64, ph_hex) =
        encrypt_sealed_bytes(circle_id, key_id, passphrase, plaintext, PaddingClass::None)
            .expect("fixture seal");

    // ─── 1. mock chain RPC, serving the sealed envelope ─────────────
    let mock_rpc: Router = Router::new().route(
        "/",
        post(move |axum::Json(req): axum::Json<serde_json::Value>| {
            let ct = ct_b64.clone();
            let ph = ph_hex.clone();
            async move {
                let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("");
                let id = req.get("id").cloned().unwrap_or(json!(1));
                if method == "circle_asset_ciphertext_by_resource_key" {
                    Json(json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "ciphertext_b64": ct,
                            "plaintext_hash": ph,
                            "key_id": "default",
                        }
                    }))
                } else {
                    Json(json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": { "code": -32601, "message": "method not found" },
                    }))
                }
            }
        }),
    );
    let rpc_listener =
        tokio::net::TcpListener::bind::<SocketAddr>("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
    let rpc_addr = rpc_listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(rpc_listener, mock_rpc).await.unwrap();
    });

    // ─── 2. build a config + spawn the portal binary ────────────────
    let bin = env!("CARGO_BIN_EXE_octravpn");
    let tmp = tempfile::tempdir().unwrap();
    let wallet = tmp.path().join("wallet.hex");
    std::fs::write(
        &wallet,
        "deadbeefcafebabe0011223344556677deadbeefcafebabe0011223344556677",
    )
    .unwrap();
    let cfg = tmp.path().join("client.toml");
    std::fs::write(
        &cfg,
        format!(
            r#"
[chain]
rpc_url          = "http://{rpc_addr}/"
program_addr     = "octPROG_TEST"
protocol_version = "v3"

[wallet]
addr        = "octADDR_TEST"
secret_path = "{}"
"#,
            wallet.display(),
        ),
    )
    .unwrap();

    let portal_listener =
        std::net::TcpListener::bind::<SocketAddr>("127.0.0.1:0".parse().unwrap()).unwrap();
    let portal_addr = portal_listener.local_addr().unwrap();
    drop(portal_listener);

    let mut child = tokio::process::Command::new(bin)
        .args([
            "--config",
            &cfg.display().to_string(),
            "portal",
            "--bind",
            &portal_addr.to_string(),
        ])
        .env("OCTRAVPN_SEALED_PASSPHRASE", passphrase)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn octravpn portal");

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let mut up = false;
    for _ in 0..50 {
        if let Ok(r) = http
            .get(format!("http://{portal_addr}/healthz"))
            .send()
            .await
        {
            if r.status().is_success() {
                up = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(up, "portal didn't come up on {portal_addr}");

    // ─── 3. approve the circle ──────────────────────────────────────
    let oct_url = format!("oct://{circle_id}/policy.json");
    let b64 = B64URL.encode(oct_url.as_bytes());
    let confirm_body = http
        .get(format!("http://{portal_addr}/o/{b64}"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let token_marker = "name=\"token\" value=\"";
    let start = confirm_body.find(token_marker).expect("token field");
    let after = &confirm_body[start + token_marker.len()..];
    let end = after.find('"').unwrap();
    let token = &after[..end];
    let resp = http
        .post(format!("http://{portal_addr}/approve"))
        .form(&[
            ("circle", circle_id),
            ("token", token),
            ("next", &format!("/o/{b64}")),
        ])
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success() || resp.status().is_redirection(),
        "approve status: {}",
        resp.status(),
    );

    // ─── 4. fetch + render → plaintext field appears in the body ────
    let body = http
        .get(format!("http://{portal_addr}/o/{b64}"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        body.contains("decrypted_ok"),
        "expected decrypted plaintext in body: {body}",
    );
    assert!(
        body.contains("vpn-sealed.example:51820"),
        "expected decrypted endpoint in body: {body}",
    );
    // The decrypted JSON went through the JSON arm of the MIME sniffer
    // (so the body is *not* wrapped in the sandbox iframe).
    assert!(!body.contains("sandbox=\"allow-popups\""));

    let _ = child.kill().await;
}

/// Negative end-to-end: no passphrase configured, a sealed asset must
/// surface the 412 passphrase-config page rather than Save-As.
#[tokio::test]
async fn portal_412s_sealed_asset_when_passphrase_missing() {
    let circle_id = "octCIRCLE_NEEDS_PP";
    let key_id = "default";
    let plaintext = br#"{"k":"v"}"#;
    let (ct_b64, ph_hex) =
        encrypt_sealed_bytes(circle_id, key_id, "operator-secret", plaintext, PaddingClass::None)
            .expect("fixture seal");

    let mock_rpc: Router = Router::new().route(
        "/",
        post(move |axum::Json(req): axum::Json<serde_json::Value>| {
            let ct = ct_b64.clone();
            let ph = ph_hex.clone();
            async move {
                let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("");
                let id = req.get("id").cloned().unwrap_or(json!(1));
                if method == "circle_asset_ciphertext_by_resource_key" {
                    Json(json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "ciphertext_b64": ct,
                            "plaintext_hash": ph,
                            "key_id": "default",
                        }
                    }))
                } else {
                    Json(json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": { "code": -32601, "message": "method not found" },
                    }))
                }
            }
        }),
    );
    let rpc_listener =
        tokio::net::TcpListener::bind::<SocketAddr>("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
    let rpc_addr = rpc_listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(rpc_listener, mock_rpc).await.unwrap();
    });

    let bin = env!("CARGO_BIN_EXE_octravpn");
    let tmp = tempfile::tempdir().unwrap();
    let wallet = tmp.path().join("wallet.hex");
    std::fs::write(
        &wallet,
        "deadbeefcafebabe0011223344556677deadbeefcafebabe0011223344556677",
    )
    .unwrap();
    let cfg = tmp.path().join("client.toml");
    std::fs::write(
        &cfg,
        format!(
            r#"
[chain]
rpc_url          = "http://{rpc_addr}/"
program_addr     = "octPROG_TEST"
protocol_version = "v3"

[wallet]
addr        = "octADDR_TEST"
secret_path = "{}"
"#,
            wallet.display(),
        ),
    )
    .unwrap();

    let portal_listener =
        std::net::TcpListener::bind::<SocketAddr>("127.0.0.1:0".parse().unwrap()).unwrap();
    let portal_addr = portal_listener.local_addr().unwrap();
    drop(portal_listener);

    let mut child = tokio::process::Command::new(bin)
        .args([
            "--config",
            &cfg.display().to_string(),
            "portal",
            "--bind",
            &portal_addr.to_string(),
        ])
        // Deliberately unset; ensure the env isn't inherited from CI.
        .env_remove("OCTRAVPN_SEALED_PASSPHRASE")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn octravpn portal");

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let mut up = false;
    for _ in 0..50 {
        if let Ok(r) = http
            .get(format!("http://{portal_addr}/healthz"))
            .send()
            .await
        {
            if r.status().is_success() {
                up = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(up, "portal didn't come up on {portal_addr}");

    // Approve + fetch.
    let oct_url = format!("oct://{circle_id}/policy.json");
    let b64 = B64URL.encode(oct_url.as_bytes());
    let confirm_body = http
        .get(format!("http://{portal_addr}/o/{b64}"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let token_marker = "name=\"token\" value=\"";
    let start = confirm_body.find(token_marker).expect("token field");
    let after = &confirm_body[start + token_marker.len()..];
    let end = after.find('"').unwrap();
    let token = &after[..end];
    let _ = http
        .post(format!("http://{portal_addr}/approve"))
        .form(&[
            ("circle", circle_id),
            ("token", token),
            ("next", &format!("/o/{b64}")),
        ])
        .send()
        .await
        .unwrap();

    let resp = http
        .get(format!("http://{portal_addr}/o/{b64}"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        412,
        "expected 412 Precondition Failed when passphrase missing",
    );
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("OCTRAVPN_SEALED_PASSPHRASE"),
        "expected env-var name in the error page: {body}",
    );

    let _ = child.kill().await;
}

fn urlencode(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}
