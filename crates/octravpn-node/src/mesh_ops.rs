//! Operator-facing remote control surface for the mesh control plane.
//!
//! These subcommands wrap the bearer-gated HTTP routes exposed by the
//! headscale-rs admin router so operators don't need the sibling repo's
//! `headscale-cli` binary installed. They are pure clients — no daemon
//! dependency on this end; the URL is provided via `--remote`.
//!
//! Wrapped routes:
//!
//!   * `GET  /api/v1/machines`        → `mesh status`
//!   * `GET  /api/v1/policy`          → `mesh policy get`
//!   * `PUT  /api/v1/policy`          → `mesh policy set --file <hujson>`
//!   * `POST /api/v1/policy/validate` → `mesh policy validate --file <hujson>`
//!
//! The token is read from `--admin-token` or the `OCTRAVPN_ADMIN_TOKEN`
//! env var (same precedence as `mesh serve`).
//!
//! The shapes are intentionally permissive — we parse with `serde_json`
//! into a `Value` and re-serialise so a future-compatible admin server
//! that adds fields doesn't break our CLI.

use std::{
    fs,
    path::PathBuf,
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const DEFAULT_REMOTE: &str = "http://127.0.0.1:51821";
const DEFAULT_TIMEOUT_SECS: u64 = 5;

#[derive(Args, Debug, Clone)]
pub(crate) struct MeshStatusArgs {
    /// Mesh-control admin URL. Defaults to `http://127.0.0.1:51821`.
    #[arg(long, default_value = DEFAULT_REMOTE)]
    pub remote: String,
    /// Bearer token. Falls back to `OCTRAVPN_ADMIN_TOKEN`.
    #[arg(long)]
    pub admin_token: Option<String>,
    /// Print the raw JSON body (one machine per array element). When
    /// unset the command prints a human-friendly two-column roster.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

#[derive(Subcommand, Debug, Clone)]
pub(crate) enum MeshPolicyCmd {
    /// Fetch the currently-loaded policy document.
    Get(MeshPolicyGetArgs),
    /// Replace the policy document with the contents of `--file`.
    Set(MeshPolicySetArgs),
    /// Parse-only validation — never mutates the live store.
    Validate(MeshPolicySetArgs),
}

#[derive(Args, Debug, Clone)]
pub(crate) struct MeshPolicyGetArgs {
    #[arg(long, default_value = DEFAULT_REMOTE)]
    pub remote: String,
    #[arg(long)]
    pub admin_token: Option<String>,
    /// When set, write the policy's `raw` hujson to this file instead of
    /// stdout. Useful as a quick backup before a PUT.
    #[arg(long)]
    pub out: Option<PathBuf>,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct MeshPolicySetArgs {
    #[arg(long, default_value = DEFAULT_REMOTE)]
    pub remote: String,
    #[arg(long)]
    pub admin_token: Option<String>,
    /// Path to the hujson policy file to PUT / validate. `-` reads
    /// from stdin.
    #[arg(long)]
    pub file: PathBuf,
}

// ---------------------------------------------------------------------------
// Entry points (sync — they own a current-thread runtime internally,
// matching the style of `cli_ops::run_health`).
// ---------------------------------------------------------------------------

pub(crate) fn run_status(args: MeshStatusArgs) -> Result<i32> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("build current-thread runtime")?;
    let token = resolve_token(args.admin_token.as_deref());
    let body = rt.block_on(get_machines(&args.remote, token.as_deref()))?;
    render_status(&body, args.json);
    Ok(0)
}

pub(crate) fn run_policy(cmd: MeshPolicyCmd) -> Result<i32> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("build current-thread runtime")?;
    match cmd {
        MeshPolicyCmd::Get(args) => {
            let token = resolve_token(args.admin_token.as_deref());
            let body = rt.block_on(get_policy(&args.remote, token.as_deref()))?;
            handle_policy_get(&body, args.out.as_deref())?;
            Ok(0)
        }
        MeshPolicyCmd::Set(args) => {
            let token = resolve_token(args.admin_token.as_deref());
            let raw = read_policy_file(&args.file)?;
            let (status, body) = rt.block_on(put_policy(&args.remote, token.as_deref(), &raw))?;
            render_policy_mutation("set", status, &body);
            Ok(if status.is_success() { 0 } else { 1 })
        }
        MeshPolicyCmd::Validate(args) => {
            let token = resolve_token(args.admin_token.as_deref());
            let raw = read_policy_file(&args.file)?;
            let (status, body) =
                rt.block_on(validate_policy(&args.remote, token.as_deref(), &raw))?;
            render_policy_mutation("validate", status, &body);
            Ok(if status.is_success() { 0 } else { 1 })
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

fn resolve_token(explicit: Option<&str>) -> Option<String> {
    explicit
        .map(str::to_owned)
        .or_else(|| std::env::var("OCTRAVPN_ADMIN_TOKEN").ok())
}

/// Resolve a knock PSK for outbound CLI requests.
///
/// Returns the decoded 32-byte secret read from the `OCTRAVPN_KNOCK_PSK`
/// env var (base64-encoded, per the operator URL convention). When the
/// env var is unset or empty, returns `None` and the admin request is
/// sent without a knock header — matching the server's default-off
/// posture.
///
/// Issue #232: `mesh status` / `mesh policy` wrap bearer-gated admin
/// routes; when the operator opts into the PSK-gated wire surface, the
/// CLI must knock-authenticate first or the request gets a generic 404
/// from the knock middleware before the bearer check ever runs.
fn resolve_knock_psk() -> Option<[u8; 32]> {
    let raw = std::env::var("OCTRAVPN_KNOCK_PSK").ok()?;
    if raw.is_empty() {
        return None;
    }
    match octravpn_mesh::knock::decode_psk(raw.trim()) {
        Ok(psk) => Some(psk),
        Err(e) => {
            eprintln!("warning: OCTRAVPN_KNOCK_PSK decode failed ({e}); proceeding without knock");
            None
        }
    }
}

/// Apply the knock header to `req` if `OCTRAVPN_KNOCK_PSK` is set.
fn with_knock(mut req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    if let Some(psk) = resolve_knock_psk() {
        let knock = octravpn_mesh::knock::current_knock(
            &psk,
            octravpn_mesh::knock::DEFAULT_WINDOW_SECS,
        );
        req = req.header(octravpn_mesh::knock::KNOCK_HEADER, knock);
    }
    req
}

fn build_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
        // The mesh-control self-signed cert isn't in the system trust
        // store on the operator's host; accept self-signed against an
        // explicitly-passed admin URL. This is the same trust posture
        // as `cli_ops::probe_remote_health`.
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| anyhow!("build http client: {e}"))
}

fn url_join(remote: &str, path: &str) -> String {
    let trimmed = remote.trim_end_matches('/');
    format!("{trimmed}{path}")
}

async fn get_machines(remote: &str, token: Option<&str>) -> Result<Value> {
    let client = build_client()?;
    let mut req = client.get(url_join(remote, "/api/v1/machines"));
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    req = with_knock(req);
    let resp = req.send().await.with_context(|| format!("GET {remote}/api/v1/machines"))?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        bail!("GET /api/v1/machines: {status}: {}", trim(&body, 200));
    }
    serde_json::from_str(&body).with_context(|| format!("parse machines body: {}", trim(&body, 200)))
}

async fn get_policy(remote: &str, token: Option<&str>) -> Result<Value> {
    let client = build_client()?;
    let mut req = client.get(url_join(remote, "/api/v1/policy"));
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    req = with_knock(req);
    let resp = req.send().await.with_context(|| format!("GET {remote}/api/v1/policy"))?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        bail!("GET /api/v1/policy: {status}: {}", trim(&body, 200));
    }
    serde_json::from_str(&body).with_context(|| format!("parse policy body: {}", trim(&body, 200)))
}

async fn put_policy(
    remote: &str,
    token: Option<&str>,
    raw: &str,
) -> Result<(reqwest::StatusCode, Value)> {
    let client = build_client()?;
    let mut req = client
        .put(url_join(remote, "/api/v1/policy"))
        .header("content-type", "application/json")
        .body(raw.as_bytes().to_vec());
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    req = with_knock(req);
    let resp = req.send().await.with_context(|| format!("PUT {remote}/api/v1/policy"))?;
    let status = resp.status();
    let body_text = resp.text().await.unwrap_or_default();
    let body =
        serde_json::from_str::<Value>(&body_text).unwrap_or(Value::String(body_text.clone()));
    Ok((status, body))
}

async fn validate_policy(
    remote: &str,
    token: Option<&str>,
    raw: &str,
) -> Result<(reqwest::StatusCode, Value)> {
    let client = build_client()?;
    let mut req = client
        .post(url_join(remote, "/api/v1/policy/validate"))
        .header("content-type", "application/json")
        .body(raw.as_bytes().to_vec());
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    req = with_knock(req);
    let resp = req
        .send()
        .await
        .with_context(|| format!("POST {remote}/api/v1/policy/validate"))?;
    let status = resp.status();
    let body_text = resp.text().await.unwrap_or_default();
    let body =
        serde_json::from_str::<Value>(&body_text).unwrap_or(Value::String(body_text.clone()));
    Ok((status, body))
}

// ---------------------------------------------------------------------------
// IO helpers
// ---------------------------------------------------------------------------

fn read_policy_file(path: &std::path::Path) -> Result<String> {
    if path.as_os_str() == "-" {
        use std::io::Read;
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf).context("read stdin")?;
        Ok(buf)
    } else {
        fs::read_to_string(path).with_context(|| format!("read {}", path.display()))
    }
}

fn handle_policy_get(body: &Value, out: Option<&std::path::Path>) -> Result<()> {
    let raw = body
        .get("raw")
        .and_then(Value::as_str)
        .unwrap_or("");
    let loaded = body
        .get("loaded")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if let Some(p) = out {
        fs::write(p, raw.as_bytes())
            .with_context(|| format!("write {}", p.display()))?;
        eprintln!(
            "mesh policy get: wrote {} byte(s) to {} (loaded={loaded})",
            raw.len(),
            p.display()
        );
    } else if loaded {
        println!("{raw}");
    } else {
        println!("(no policy loaded — wire layer falls back to allow-all)");
    }
    Ok(())
}

fn render_status(body: &Value, json: bool) {
    if json {
        match serde_json::to_string_pretty(body) {
            Ok(s) => println!("{s}"),
            Err(e) => eprintln!("mesh status: serialize: {e}"),
        }
        return;
    }
    let arr: &[Value] = body.as_array().map_or(&[][..], Vec::as_slice);
    if arr.is_empty() {
        println!("(no machines registered)");
        return;
    }
    println!("{:<18}  {:<24}  {:<20}  online", "id", "hostname", "ipv4");
    for m in arr {
        let id = m
            .get("id")
            .map(short_string)
            .unwrap_or_else(|| "-".into());
        let hostname = m
            .get("hostname")
            .and_then(Value::as_str)
            .unwrap_or("-")
            .to_string();
        let ipv4 = m
            .get("ipv4")
            .and_then(Value::as_str)
            .unwrap_or("-")
            .to_string();
        let online = m
            .get("online")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        println!("{id:<18}  {hostname:<24}  {ipv4:<20}  {online}");
    }
}

fn short_string(v: &Value) -> String {
    match v {
        Value::String(s) if s.len() > 16 => format!("{}…", &s[..16]),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn render_policy_mutation(label: &str, status: reqwest::StatusCode, body: &Value) {
    if status.is_success() {
        println!(
            "mesh policy {label}: {} OK ({})",
            status,
            trim(&body.to_string(), 200)
        );
    } else {
        eprintln!(
            "mesh policy {label}: {} FAIL ({})",
            status,
            trim(&body.to_string(), 200)
        );
    }
}

fn trim(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max])
    }
}

// ---------------------------------------------------------------------------
// Shapes (kept in sync with `headscale_api::admin` JSON encodings).
// These are not surfaced publicly — they exist so the unit tests can
// construct fixture bodies type-safely.
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct MachineFixture {
    pub id: String,
    pub hostname: String,
    pub ipv4: String,
    #[serde(default)]
    pub online: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    /// Minimal in-process axum mock for `/api/v1/machines` and the
    /// `/api/v1/policy{,/validate}` triple. Records request bodies so
    /// each test can assert the payload.
    struct MockAdmin {
        addr: SocketAddr,
        last_put: Arc<Mutex<Option<String>>>,
        last_validate: Arc<Mutex<Option<String>>>,
        _join: tokio::task::JoinHandle<()>,
    }

    impl MockAdmin {
        async fn spawn(
            token: Option<String>,
            machines: Value,
            policy: Value,
            put_status: u16,
            validate_status: u16,
        ) -> Self {
            use axum::{
                extract::State,
                http::{HeaderMap, StatusCode},
                routing::{get, post},
                Json, Router,
            };

            #[derive(Clone)]
            struct Ctx {
                token: Option<Arc<str>>,
                machines: Arc<Value>,
                policy: Arc<Value>,
                last_put: Arc<Mutex<Option<String>>>,
                last_validate: Arc<Mutex<Option<String>>>,
                put_status: u16,
                validate_status: u16,
            }

            fn auth_ok(ctx: &Ctx, headers: &HeaderMap) -> bool {
                match ctx.token.as_deref() {
                    None => true,
                    Some(want) => headers
                        .get(axum::http::header::AUTHORIZATION)
                        .and_then(|v| v.to_str().ok())
                        .and_then(|h| h.strip_prefix("Bearer "))
                        .is_some_and(|t| t == want),
                }
            }

            async fn list_machines(
                State(ctx): State<Ctx>,
                headers: HeaderMap,
            ) -> axum::response::Response {
                use axum::response::IntoResponse;
                if !auth_ok(&ctx, &headers) {
                    return (StatusCode::UNAUTHORIZED, "").into_response();
                }
                Json((*ctx.machines).clone()).into_response()
            }

            async fn get_policy(
                State(ctx): State<Ctx>,
                headers: HeaderMap,
            ) -> axum::response::Response {
                use axum::response::IntoResponse;
                if !auth_ok(&ctx, &headers) {
                    return (StatusCode::UNAUTHORIZED, "").into_response();
                }
                Json((*ctx.policy).clone()).into_response()
            }

            async fn put_policy_h(
                State(ctx): State<Ctx>,
                headers: HeaderMap,
                body: String,
            ) -> axum::response::Response {
                use axum::response::IntoResponse;
                if !auth_ok(&ctx, &headers) {
                    return (StatusCode::UNAUTHORIZED, "").into_response();
                }
                *ctx.last_put.lock().await = Some(body);
                let status = StatusCode::from_u16(ctx.put_status).unwrap();
                (status, Json(json!({"applied": status.is_success()}))).into_response()
            }

            async fn validate_h(
                State(ctx): State<Ctx>,
                headers: HeaderMap,
                body: String,
            ) -> axum::response::Response {
                use axum::response::IntoResponse;
                if !auth_ok(&ctx, &headers) {
                    return (StatusCode::UNAUTHORIZED, "").into_response();
                }
                *ctx.last_validate.lock().await = Some(body);
                let status = StatusCode::from_u16(ctx.validate_status).unwrap();
                (status, Json(json!({"ok": status.is_success()}))).into_response()
            }

            let last_put = Arc::new(Mutex::new(None));
            let last_validate = Arc::new(Mutex::new(None));
            let ctx = Ctx {
                token: token.map(Arc::from),
                machines: Arc::new(machines),
                policy: Arc::new(policy),
                last_put: last_put.clone(),
                last_validate: last_validate.clone(),
                put_status,
                validate_status,
            };

            let app = Router::new()
                .route("/api/v1/machines", get(list_machines))
                .route("/api/v1/policy", get(get_policy).put(put_policy_h))
                .route("/api/v1/policy/validate", post(validate_h))
                .with_state(ctx);

            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let join = tokio::spawn(async move {
                let _ = axum::serve(listener, app).await;
            });
            // Yield once so the listener is accepting before the test
            // dials in.
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            Self {
                addr,
                last_put,
                last_validate,
                _join: join,
            }
        }

        fn url(&self) -> String {
            format!("http://{}", self.addr)
        }
    }

    #[tokio::test]
    async fn mesh_status_lists_machines_from_remote() {
        let machines = json!([
            { "id": "m-aaaa", "hostname": "peer-1", "ipv4": "100.64.0.10", "online": true },
            { "id": "m-bbbb", "hostname": "peer-2", "ipv4": "100.64.0.11", "online": false },
        ]);
        let mock = MockAdmin::spawn(None, machines.clone(), Value::Null, 200, 200).await;
        let body = get_machines(&mock.url(), None).await.unwrap();
        let arr = body.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["hostname"], "peer-1");
    }

    #[tokio::test]
    async fn mesh_status_rejected_without_token_when_required() {
        let machines = json!([]);
        let mock = MockAdmin::spawn(
            Some("right".into()),
            machines,
            Value::Null,
            200,
            200,
        )
        .await;
        let err = get_machines(&mock.url(), None).await.err().unwrap();
        assert!(format!("{err:#}").contains("401"));
    }

    #[tokio::test]
    async fn mesh_policy_get_returns_raw_hujson() {
        let policy = json!({
            "loaded": true,
            "raw": r#"{"version":1,"rules":[]}"#,
        });
        let mock = MockAdmin::spawn(None, json!([]), policy, 200, 200).await;
        let body = get_policy(&mock.url(), None).await.unwrap();
        assert_eq!(body["loaded"], Value::Bool(true));
        assert!(body["raw"].as_str().unwrap().contains("version"));
    }

    #[tokio::test]
    async fn mesh_policy_set_round_trips_payload() {
        let mock = MockAdmin::spawn(
            Some("tok".into()),
            json!([]),
            json!({"loaded": false, "raw": ""}),
            200,
            200,
        )
        .await;
        let payload = r#"{"version":1,"rules":[{"action":"deny","src":["*"],"dst":["*"],"ports":["*/*"]}]}"#;
        let (status, body) = put_policy(&mock.url(), Some("tok"), payload).await.unwrap();
        assert!(status.is_success());
        assert_eq!(body["applied"], Value::Bool(true));
        let captured = mock.last_put.lock().await.clone().unwrap();
        assert_eq!(captured, payload);
    }

    #[tokio::test]
    async fn mesh_policy_validate_surfaces_400_on_bad_doc() {
        let mock = MockAdmin::spawn(None, json!([]), json!({"loaded": false}), 200, 400).await;
        let (status, body) = validate_policy(&mock.url(), None, "not even json").await.unwrap();
        assert_eq!(status.as_u16(), 400);
        assert_eq!(body["ok"], Value::Bool(false));
        let captured = mock.last_validate.lock().await.clone().unwrap();
        assert_eq!(captured, "not even json");
    }

    #[test]
    fn url_join_handles_trailing_slash() {
        assert_eq!(
            url_join("http://x:1/", "/api/v1/machines"),
            "http://x:1/api/v1/machines"
        );
        assert_eq!(
            url_join("http://x:1", "/api/v1/machines"),
            "http://x:1/api/v1/machines"
        );
    }

    #[test]
    fn resolve_token_prefers_explicit() {
        std::env::set_var("OCTRAVPN_ADMIN_TOKEN", "from-env");
        assert_eq!(resolve_token(Some("explicit")).as_deref(), Some("explicit"));
        assert_eq!(resolve_token(None).as_deref(), Some("from-env"));
        std::env::remove_var("OCTRAVPN_ADMIN_TOKEN");
        assert_eq!(resolve_token(None), None);
    }
}
