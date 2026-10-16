//! Native main HTTP interface over the same authenticated committed reader as RPC.
use super::{native, Context};
use axum::{
    body::{self, Body},
    extract::State,
    http::{header, HeaderName, HeaderValue, Method, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::any,
    Router,
};
use octra_node_protocol::{
    consensus::profile::Settings,
    light_rpc::json,
    native_integer,
    native_json::Document,
    state_sync::{http as wire, manifest, range_part::Encoded},
};
use octra_node_runtime::{account_store, canonical::Head, state_batch::StateBatch};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Semaphore;
mod certificate;
mod range;

pub(crate) struct Service {
    data: PathBuf,
    public_key: Vec<u8>,
    chain: Vec<u8>,
    enabled: bool,
    certificate_path: PathBuf,
    snapshot_root: PathBuf,
    certificates: Arc<certificate::Service>,
    ranges: Arc<range::Service>,
    chunks: Arc<Semaphore>,
}
fn os_path(raw: &[u8]) -> PathBuf {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        PathBuf::from(std::ffi::OsStr::from_bytes(raw))
    }
    #[cfg(not(unix))]
    {
        PathBuf::from(String::from_utf8_lossy(raw).as_ref())
    }
}
fn lower_hex(raw: &[u8]) -> bool {
    raw.len() == 64
        && raw
            .iter()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
}
impl Service {
    /// Environment is sampled only here for the local-development launch path.
    /// Public launches supply the immutable captured Settings used by consensus.
    pub(crate) fn new(
        data: PathBuf,
        settings: Option<&Settings>,
        chain_id: Vec<u8>,
        public_key: Vec<u8>,
    ) -> Self {
        let get = |name: &str| match settings {
            Some(settings) => settings.get(name).map(<[u8]>::to_vec),
            None => std::env::var_os(name).map(|v| v.as_encoded_bytes().to_vec()),
        };
        let enabled = get("OCTRA_STATE_SYNC_ENABLE")
            .is_some_and(|v| matches!(v.as_slice(), b"1" | b"true" | b"yes"))
            || get("OCTRA_STATE_SYNC_EXPORTERS").is_some_and(|v| !v.trim_ascii().is_empty());
        let certificate_path = get("OCTRA_STATE_SYNC_CERT")
            .filter(|v| !v.trim_ascii().is_empty())
            .map_or_else(
                || data.join("state_sync/certificate.json"),
                |v| os_path(v.trim_ascii()),
            );
        let snapshot_root = get("OCTRA_STATE_SYNC_SNAPSHOT_DIR")
            .filter(|v| !v.trim_ascii().is_empty())
            .map_or_else(|| data.join("state_sync_snapshots"), |v| os_path(&v));
        let chunk_reads = get("OCTRA_STATE_SYNC_MAX_ACTIVE_CHUNK_READS")
            .as_deref()
            .and_then(native_integer::parse_int63)
            .unwrap_or(8)
            .clamp(1, 64) as usize;
        Self {
            data,
            public_key,
            enabled,
            certificate_path,
            snapshot_root,
            certificates: certificate::Service::new(chain_id.clone(), get),
            chain: chain_id,
            ranges: Arc::new(range::Service::default()),
            chunks: Arc::new(Semaphore::new(chunk_reads)),
        }
    }
    pub(crate) fn shutdown(&self) {
        self.certificates.shutdown();
        self.ranges.shutdown();
        self.chunks.close();
    }
}

pub(crate) fn router() -> Router<Arc<Context>> {
    let mut router = Router::new();
    for path in [
        "/",
        "/status",
        "/metrics",
        "/state-sync/head",
        "/state-sync/range",
        "/state-sync/readiness",
        "/state-sync/client-progress",
        "/state-sync/manifest",
        "/state-sync/chunk",
        "/favicon.ico",
    ] {
        router = router.route(path, any(handle));
    }
    router.fallback(handle)
}
/// Apply after the shared router is assembled so /rpc observes native transport
/// timeout and connection lifetime too. JSON-RPC retains its own byte budget.
pub(crate) fn native_layer(router: Router) -> Router {
    router.layer(middleware::from_fn(transport))
}
async fn transport(request: Request<Body>, next: Next) -> Response {
    let rpc = request.uri().path() == "/rpc";
    let mut response = if request.method() == Method::OPTIONS {
        let mut response = StatusCode::OK.into_response();
        response.headers_mut().insert(
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_static("*"),
        );
        response.headers_mut().insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("GET, POST, DELETE, OPTIONS"),
        );
        response.headers_mut().insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("Content-Type, Authorization"),
        );
        response
    } else {
        match tokio::time::timeout(Duration::from_secs(30), next.run(request)).await {
            Ok(response) => response,
            Err(_) => (
                StatusCode::GATEWAY_TIMEOUT,
                b"{\"error\":\"request timeout\"}".as_slice().to_vec(),
            )
                .into_response(),
        }
    };
    response
        .headers_mut()
        .insert(header::CONNECTION, HeaderValue::from_static("close"));
    if rpc
        && response
            .headers()
            .get(header::CONTENT_TYPE)
            .is_some_and(|value| value.as_bytes().starts_with(b"application/json"))
    {
        response
            .headers_mut()
            .entry(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .or_insert(HeaderValue::from_static("*"));
    }
    response
}
fn json_response(status: StatusCode, raw: Vec<u8>) -> Response {
    let mut response = (status, raw).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response.headers_mut().insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    response
}
fn error(status: StatusCode, kind: &str, reason: impl AsRef<[u8]>) -> Response {
    json_response(
        status,
        json::object(&[
            ("status", json::string(b"error")),
            (
                "error",
                json::object(&[
                    ("type", json::string(kind)),
                    ("reason", json::string(reason)),
                ]),
            ),
        ]),
    )
}
fn retry(status: StatusCode, kind: &str, reason: impl AsRef<[u8]>, after: u64) -> Response {
    let mut response = error(status, kind, reason);
    response.headers_mut().insert(
        header::RETRY_AFTER,
        HeaderValue::from_str(&after.to_string()).expect("integer header"),
    );
    response
}
fn certificate_error(error: &certificate::Error, kind: &str, status: StatusCode) -> Response {
    if error.retryable() {
        retry(
            StatusCode::TOO_MANY_REQUESTS,
            "state_sync_busy",
            error.reason(),
            1,
        )
    } else {
        self::error(status, kind, error.reason())
    }
}
fn unavailable(reason: impl std::fmt::Display) -> Response {
    error(
        StatusCode::SERVICE_UNAVAILABLE,
        "service_unavailable",
        reason.to_string(),
    )
}
fn disabled() -> Response {
    error(
        StatusCode::FORBIDDEN,
        "state_sync_disabled",
        "state sync RPC is disabled",
    )
}
fn head(record: &Head) -> wire::Head {
    wire::Head {
        epoch: record.cursor.epoch.0 as i64,
        state_root: hex::encode(record.cursor.state_root.0).into_bytes(),
        txid_hi: record.txid_hi,
        irmin_commit: Some(record.irmin_commit.as_bytes().to_vec()),
    }
}
type QueryRow = (Vec<u8>, Vec<Vec<u8>>);
fn decode_query(raw: &str) -> Vec<QueryRow> {
    fn decode(raw: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(raw.len());
        let mut i = 0;
        while i < raw.len() {
            if raw[i] == b'%' && i + 2 < raw.len() {
                if let (Some(a), Some(b)) = (
                    (raw[i + 1] as char).to_digit(16),
                    (raw[i + 2] as char).to_digit(16),
                ) {
                    out.push((a * 16 + b) as u8);
                    i += 3;
                    continue;
                }
            }
            out.push(if raw[i] == b'+' { b' ' } else { raw[i] });
            i += 1;
        }
        out
    }
    raw.as_bytes()
        .split(|b| *b == b'&')
        .filter(|v| !v.is_empty())
        .map(|v| {
            let position = v.iter().position(|b| *b == b'=');
            match position {
                Some(i) => (
                    decode(&v[..i]),
                    v[i + 1..].split(|b| *b == b',').map(decode).collect(),
                ),
                None => (decode(v), vec![]),
            }
        })
        .collect()
}
fn query<'a>(rows: &'a [QueryRow], key: &[u8]) -> Option<&'a [u8]> {
    rows.iter()
        .find(|(k, _)| k == key)
        .and_then(|(_, v)| v.first().map(Vec::as_slice))
}
async fn handle(State(host): State<Arc<Context>>, request: Request<Body>) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    if method == Method::GET && path == "/favicon.ico" {
        return StatusCode::NOT_FOUND.into_response();
    }
    if method == Method::GET && path == "/" {
        return match host.node.legacy_status() {
            Ok(legacy) => json_response(
                StatusCode::OK,
                json::object(&[
                    ("node", json::string(b"octra")),
                    ("version", json::string(b"3.0.0")),
                    ("validator", json::string(&host.address)),
                    ("epoch", json::number(legacy.epoch)),
                    ("status", json::string(b"running")),
                ]),
            ),
            Err(reason) => unavailable(reason),
        };
    }
    if method == Method::GET && path == "/status" {
        return status(&host).await;
    }
    if method == Method::GET && path == "/metrics" {
        return match native::invoke(&host, b"node_metrics", b"[]").await {
            Ok(raw) => json_response(StatusCode::OK, raw),
            Err(_) => unavailable("native metrics unavailable"),
        };
    }
    let state_sync = (method == Method::GET
        && matches!(
            path.as_str(),
            "/state-sync/head"
                | "/state-sync/range"
                | "/state-sync/readiness"
                | "/state-sync/manifest"
                | "/state-sync/chunk"
        ))
        || (method == Method::POST && path == "/state-sync/client-progress");
    if state_sync {
        if !host.http.enabled {
            return disabled();
        }
        if host.http.chain != host.node.chain().chain_id.as_bytes() {
            return unavailable("state sync launch chain mismatch");
        }
        let rows = decode_query(request.uri().query().unwrap_or(""));
        return match path.as_str() {
            "/state-sync/head" => live_head(&host).await,
            "/state-sync/manifest" => manifest_response(&host).await,
            "/state-sync/chunk" => chunk(&host, &rows).await,
            "/state-sync/range" => range_response(&host, &rows).await,
            "/state-sync/readiness" => readiness(&host).await,
            "/state-sync/client-progress" => progress(request).await,
            _ => unreachable!(),
        };
    }
    if legacy(&method, &path) {
        return error(
            StatusCode::GONE,
            "unknown",
            "DEPRECATED: REST compatibility endpoint removed; use POST /rpc.",
        );
    }
    error(
        StatusCode::NOT_FOUND,
        "not_found",
        format!("no route: {method} {path}"),
    )
}
async fn live_head(host: &Arc<Context>) -> Response {
    let loaded = host
        .http
        .certificates
        .load(host.http.certificate_path.clone())
        .await;
    if let Err(reason) = &loaded {
        if reason.retryable() {
            return certificate_error(
                reason,
                "state_sync_unavailable",
                StatusCode::SERVICE_UNAVAILABLE,
            );
        }
    }
    let snapshot = loaded.ok().map(|v| v.certificate.draft().checkpoint.epoch);
    let captured = match host.node.head().await {
        Ok(head) => head,
        Err(reason) => return unavailable(reason),
    };
    let current = match host.node.legacy_status_at(&captured) {
        Ok(status) => status.epoch,
        Err(reason) => return unavailable(reason),
    };
    json_response(
        StatusCode::OK,
        wire::head_response(current, Some(&head(&captured)), snapshot),
    )
}
async fn manifest_response(host: &Arc<Context>) -> Response {
    let loaded = match host
        .http
        .certificates
        .load(host.http.certificate_path.clone())
        .await
    {
        Ok(loaded) => loaded,
        Err(reason) => {
            return certificate_error(
                &reason,
                "state_sync_unavailable",
                StatusCode::SERVICE_UNAVAILABLE,
            )
        }
    };
    let current = match host.node.legacy_status() {
        Ok(status) => status.epoch.saturating_sub(1).max(0),
        Err(reason) => return unavailable(reason),
    };
    let snapshot = loaded.certificate.draft().checkpoint.epoch;
    let lag = current.saturating_sub(snapshot).max(0);
    if lag > wire::SNAPSHOT_LAG_MAX {
        return error(StatusCode::SERVICE_UNAVAILABLE,"state_sync_old_epoch",format!("state sync snapshot is behind live head snapshot_epoch = {snapshot} head_epoch = {current} lag = {lag} limit = {}",wire::SNAPSHOT_LAG_MAX));
    }
    let hash = loaded.certificate.draft().manifest_hash.clone();
    let mut response = (StatusCode::OK, loaded.raw).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=30"),
    );
    if set_header(&mut response, "x-octra-manifest-sha256", &hash).is_err() {
        return unavailable("invalid manifest header");
    }
    response
}
async fn readiness(host: &Arc<Context>) -> Response {
    let Some(finality) = &host.finality else {
        return json_response(
            StatusCode::OK,
            json::object(&[
                ("version", json::string(b"octra-observer-ready")),
                ("status", json::string(b"not_ready")),
            ]),
        );
    };
    match finality
        .readiness(&host.http.data, &host.http.public_key)
        .await
    {
        Ok(Some(raw)) => json_response(StatusCode::OK, raw),
        Ok(None) => json_response(
            StatusCode::OK,
            json::object(&[
                ("version", json::string(b"octra-observer-ready")),
                ("status", json::string(b"not_ready")),
            ]),
        ),
        Err(_) => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "state_sync_bad_readiness",
            "readiness marker is corrupt",
        ),
    }
}
async fn progress(request: Request<Body>) -> Response {
    let Ok(raw) = body::to_bytes(request.into_body(), wire::PROGRESS_MAX).await else {
        return error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "request_too_large",
            "request body too large",
        );
    };
    let Ok(doc) = Document::parse(&raw) else {
        return error(
            StatusCode::BAD_REQUEST,
            "malformed_transaction",
            "invalid JSON",
        );
    };
    let progress = match wire::Progress::parse(&doc) {
        Ok(progress) => progress,
        Err(reason) => {
            return error(
                StatusCode::BAD_REQUEST,
                "state_sync_bad_progress",
                reason.to_string(),
            )
        }
    };
    // Telemetry is intentionally unauthenticated in the adopted interface. It
    // cannot publish state, readiness, trust, files or validator authority.
    eprintln!("state_sync client_progress peer={:?} phase={:?} path={:?} file_done={} file_size={} total_done={} total_size={} rate_bps={} eta_seconds={:?}",
        String::from_utf8_lossy(&progress.peer),String::from_utf8_lossy(&progress.phase),String::from_utf8_lossy(&progress.path),
        progress.file_done,progress.file_size,progress.total_done,progress.total_size,progress.rate_bps,progress.eta_seconds);
    json_response(StatusCode::OK, b"{\"ok\":true}".to_vec())
}
async fn range_response(host: &Arc<Context>, rows: &[QueryRow]) -> Response {
    let query = match wire::RangeQuery::parse(
        query(rows, b"from_epoch"),
        query(rows, b"max_epochs"),
        query(rows, b"part"),
        query(rows, b"sha256"),
    ) {
        Ok(query) => query,
        Err(reason) => {
            return error(
                StatusCode::BAD_REQUEST,
                "state_sync_bad_range_request",
                reason.to_string(),
            )
        }
    };
    let captured = match host.node.head().await {
        Ok(head) => head,
        Err(reason) => return unavailable(reason),
    };
    let key = range::Key {
        head: captured.clone(),
        query: query.clone(),
    };
    let owned = host.clone();
    match host
        .http
        .ranges
        .load(key, move |cancelled| {
            Box::pin(read_range(owned, captured, query, cancelled))
        })
        .await
    {
        Ok(raw) => json_response(StatusCode::OK, raw),
        Err(range::Error::Invalid(reason)) => {
            error(StatusCode::BAD_REQUEST, "state_sync_range_part", reason)
        }
        Err(reason) => retry(
            StatusCode::SERVICE_UNAVAILABLE,
            "state_sync_range_busy",
            reason.reason(),
            2,
        ),
    }
}
fn unchanged(host: &Context, captured: &Head) -> Result<(), range::Error> {
    if host.node.cached_head().as_ref() == Some(captured) {
        Ok(())
    } else {
        Err(range::Error::Changed)
    }
}
async fn read_range(
    host: Arc<Context>,
    captured: Head,
    query: wire::RangeQuery,
    cancelled: Arc<AtomicBool>,
) -> Result<Encoded, range::Error> {
    let check = || {
        if cancelled.load(Ordering::Acquire) {
            Err(range::Error::Stopped)
        } else {
            unchanged(&host, &captured)
        }
    };
    check()?;
    let Some(finality) = &host.finality else {
        let raw = wire::range_response(Some(&head(&captured)), &query, &wire::RangeResult::Missing)
            .map_err(|e| range::Error::Invalid(e.to_string()))?;
        return Encoded::encode(raw).map_err(|e| range::Error::Invalid(e.to_string()));
    };
    let mut records = vec![];
    let mut next = None;
    let mut bytes = 0usize;
    let mut internal = None;
    for i in 0..query.max_epochs.min(16) {
        let epoch = query.from_epoch + i;
        let retained = host.node.reader().head_for_epoch_opt(epoch as u64).await;
        check()?;
        let retained = match retained {
            Ok(Some(retained)) if retained.cursor.sequence.0 > 0 => retained,
            Ok(None) => {
                if !records.is_empty() {
                    next = Some(epoch);
                }
                break;
            }
            Ok(Some(_)) => break,
            Err(reason) => {
                internal = Some(reason.to_string().into_bytes());
                break;
            }
        };
        let record = finality
            .record_bounded(
                retained.cursor.sequence,
                octra_node_protocol::state_sync::range_part::FULL_MAX,
            )
            .await;
        check()?;
        let record = match record {
            Ok(Some(record)) => record,
            Err(
                reason @ (octra_node_runtime::finality::Error::Store(_)
                | octra_node_runtime::finality::Error::Unavailable(_)),
            ) => {
                internal = Some(reason.to_string().into_bytes());
                break;
            }
            Ok(None) | Err(_) => break,
        };
        let Ok(size) = wire::record_size(&record) else {
            break;
        };
        if bytes.saturating_add(size) > 4_000_000 && !records.is_empty() {
            next = Some(epoch);
            break;
        }
        bytes = bytes.saturating_add(size);
        records.push(record);
        if i + 1 >= query.max_epochs.min(16) {
            next = Some(epoch + 1);
        }
    }
    let result = if let Some(reason) = internal {
        wire::RangeResult::Retry(reason)
    } else if records.is_empty() {
        wire::RangeResult::Missing
    } else {
        wire::RangeResult::Records {
            records,
            next_epoch: next,
        }
    };
    check()?;
    let response_head = head(&captured);
    let encoded = tokio::task::spawn_blocking(move || {
        let raw = wire::range_response(Some(&response_head), &query, &result)
            .map_err(|_| range::Error::Missing)?;
        Encoded::encode(raw).map_err(|e| range::Error::Invalid(e.to_string()))
    })
    .await
    .map_err(|_| range::Error::Missing)??;
    check()?;
    Ok(encoded)
}
fn denomination(value: &num_bigint::BigInt) -> Vec<u8> {
    let unit = num_bigint::BigInt::from(1_000_000);
    let whole = value / &unit;
    let remainder = value % &unit;
    if remainder == num_bigint::BigInt::from(0) {
        whole.to_string().into_bytes()
    } else {
        format!("{whole}.{remainder:06}").into_bytes()
    }
}
async fn status(host: &Arc<Context>) -> Response {
    let view = match host.node.snapshot() {
        Ok(view) => view,
        Err(reason) => return unavailable(reason),
    };
    let legacy = match host.node.legacy_status_at(view.head()) {
        Ok(status) => status,
        Err(reason) => return unavailable(reason),
    };
    let address = host.address.clone();
    let policy = host.executor.emission_policy();
    let fallback = if policy.emission_guard {
        policy.legacy_total.clone()
    } else {
        None
    };
    let result = host
        .executor
        .read(move || {
            let ledger = account_store::ledger(&StateBatch::from_snapshot(view.state().clone()))
                .map_err(|_| octra_node_protocol::rpc::Fault::new(110, b"service unavailable"))?;
            let total = view
                .state()
                .get(&[b"meta", b"total_supply"])
                .or(fallback.as_deref())
                .and_then(native_integer::parse_integer)
                .filter(|n| {
                    n >= ledger.total_supply()
                        && n <= &num_bigint::BigInt::from(octra_node_protocol::state::MAX_SUPPLY)
                })
                .ok_or_else(|| octra_node_protocol::rpc::Fault::new(110, b"service unavailable"))?;
            let encrypted = &total - ledger.total_supply();
            let head = head(view.head());
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| octra_node_protocol::rpc::Fault::new(110, b"service unavailable"))?
                .as_secs_f64();
            let timestamp = octra_node_protocol::transaction::native_float(timestamp)
                .map_err(|_| octra_node_protocol::rpc::Fault::new(110, b"service unavailable"))?
                .into_bytes();
            Ok(json::object(&[
                ("current_epoch", json::number(legacy.epoch)),
                ("validator", json::string(address)),
                ("root_count", json::number(legacy.roots)),
                ("timestamp", timestamp),
                ("total_accounts", json::number(ledger.accounts().len())),
                ("total_supply", json::string(denomination(&total))),
                ("circulating_supply", json::string(denomination(&total))),
                ("encrypted_supply", json::string(denomination(&encrypted))),
                ("active_accounts", json::number(ledger.active_accounts())),
                ("network_version", json::string(b"v3.0.0-irmin")),
                ("storage_backend", json::string(b"sqlite")),
                ("head_epoch", json::number(head.epoch)),
                ("state_root", json::string(&head.state_root)),
                ("txid_hi", json::string(head.txid_hi.to_string())),
                ("irmin_commit", json::optional(head.irmin_commit.as_deref())),
            ]))
        })
        .await;
    match result {
        Ok(raw) => json_response(StatusCode::OK, raw),
        Err(_) => unavailable("native status unavailable"),
    }
}
fn set_header(
    response: &mut Response,
    name: &'static str,
    value: &[u8],
) -> Result<(), axum::http::header::InvalidHeaderValue> {
    response.headers_mut().insert(
        HeaderName::from_static(name),
        HeaderValue::from_bytes(value)?,
    );
    Ok(())
}
fn valid_id(id: &[u8]) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(b))
}
fn normalized_path(path: &[u8]) -> bool {
    !path.is_empty()
        && !path.starts_with(b"/")
        && !path.contains(&0)
        && !path.contains(&b'\\')
        && path
            .split(|b| *b == b'/')
            .all(|part| !part.is_empty() && part != b"." && part != b"..")
}
fn allowed_path(path: &[u8]) -> bool {
    let components = path.split(|b| *b == b'/');
    (path == b"irmin_store/store.control"
        || components.into_iter().all(|part| {
            !matches!(part, b"lock" | b"lock.mdb" | b".-lock" | b"store.control")
                && !part.starts_with(b"index.bak")
        }))
        && path != b"commit_journal.log"
        && (matches!(
            path,
            b"HEAD.json" | b"state_root" | b"ready_roots" | b"ledger.dat"
        ) || [
            b"irmin_store/".as_slice(),
            b"chaindata/",
            b"pvac/",
            b"preverify_receipts/",
        ]
        .iter()
        .any(|prefix| path.starts_with(prefix)))
}
async fn snapshot_certificate(
    service: &Service,
    snapshot: &Path,
    id: &[u8],
) -> Result<certificate::Loaded, certificate::Error> {
    let archived = service
        .certificates
        .load(snapshot.join(".certificate.json"))
        .await;
    match archived {
        Ok(loaded) if loaded.certificate.draft().manifest.snapshot_id == id => Ok(loaded),
        Ok(_) => Err(certificate::Error::Invalid(
            "state sync snapshot certificate mismatch".into(),
        )),
        Err(reason) if reason.retryable() => Err(reason),
        Err(archived_error) => match service
            .certificates
            .load(service.certificate_path.clone())
            .await
        {
            Ok(loaded) if loaded.certificate.draft().manifest.snapshot_id == id => Ok(loaded),
            Ok(_) => Err(certificate::Error::Invalid(
                "state sync snapshot is not retained".into(),
            )),
            Err(reason) if reason.retryable() => Err(reason),
            Err(_) => Err(archived_error),
        },
    }
}
enum ChunkError {
    Unavailable(&'static str),
    Corrupt,
}
async fn chunk(host: &Arc<Context>, rows: &[QueryRow]) -> Response {
    let path = query(rows, b"path").unwrap_or_default();
    let sha256 = query(rows, b"sha256").unwrap_or_default();
    let snapshot_id = query(rows, b"snapshot").unwrap_or_default();
    let index = query(rows, b"index")
        .and_then(native_integer::parse_int63)
        .unwrap_or(-1);
    if index < 0 || !lower_hex(sha256) || !valid_id(snapshot_id) || !normalized_path(path) {
        return error(
            StatusCode::BAD_REQUEST,
            "state_sync_bad_chunk_request",
            "invalid chunk request",
        );
    }
    let snapshot = host.http.snapshot_root.join(os_path(snapshot_id));
    match tokio::fs::symlink_metadata(&snapshot).await {
        Ok(metadata) if metadata.is_dir() => {}
        Err(reason) if reason.kind() == std::io::ErrorKind::NotFound => {
            return error(
                StatusCode::GONE,
                "state_sync_snapshot_expired",
                "state sync snapshot expired; restart with the current manifest",
            )
        }
        _ => {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "state_sync_chunk_unavailable",
                "snapshot read failed",
            )
        }
    }
    let loaded = match snapshot_certificate(&host.http, &snapshot, snapshot_id).await {
        Ok(loaded) => loaded,
        Err(reason) => {
            return certificate_error(
                &reason,
                "state_sync_snapshot_unavailable",
                StatusCode::NOT_FOUND,
            )
        }
    };
    let draft = loaded.certificate.draft();
    if draft.manifest.snapshot_id != snapshot_id {
        return error(
            StatusCode::BAD_REQUEST,
            "state_sync_snapshot_mismatch",
            "snapshot id mismatch",
        );
    }
    let Some(file) = draft.manifest.files.iter().find(|file| file.path == path) else {
        return error(
            StatusCode::BAD_REQUEST,
            "state_sync_bad_chunk_request",
            "manifest file not found",
        );
    };
    let Some(descriptor) = file.chunks.iter().find(|chunk| chunk.index == index) else {
        return error(
            StatusCode::BAD_REQUEST,
            "state_sync_bad_chunk_request",
            "manifest chunk not found",
        );
    };
    if descriptor.sha256 != sha256 {
        return error(
            StatusCode::BAD_REQUEST,
            "state_sync_bad_chunk_request",
            "manifest chunk hash mismatch",
        );
    }
    if descriptor.offset > (1i64 << 62) - 1 {
        return error(
            StatusCode::BAD_REQUEST,
            "state_sync_bad_chunk_request",
            "chunk offset exceeds platform limit",
        );
    }
    let Ok(permit) = host.http.chunks.clone().try_acquire_owned() else {
        return retry(
            StatusCode::TOO_MANY_REQUESTS,
            "state_sync_busy",
            "state sync source is busy",
            3,
        );
    };
    let descriptor = descriptor.clone();
    let expected_hash = descriptor.sha256.clone();
    let manifest_hash = draft.manifest_hash.clone();
    let path = path.to_vec();
    let snapshot_id = snapshot_id.to_vec();
    let owned_snapshot = snapshot.clone();
    let payload = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        if !allowed_path(&path) {
            return Err(ChunkError::Unavailable("path not allowed"));
        }
        let _ready = certificate::open(&owned_snapshot, b".ready.json")
            .map_err(|_| ChunkError::Unavailable("snapshot not found"))?;
        let file = certificate::open(&owned_snapshot, &path)
            .map_err(|_| ChunkError::Unavailable("file not found"))?;
        let metadata = file
            .metadata()
            .map_err(|_| ChunkError::Unavailable("snapshot read failed"))?;
        if descriptor.offset < 0 || descriptor.size <= 0 {
            return Err(ChunkError::Unavailable("invalid offset/len"));
        }
        let length = metadata
            .len()
            .saturating_sub(descriptor.offset as u64)
            .min(descriptor.size as u64)
            .min(manifest::CHUNK_MAX as u64) as usize;
        let mut raw = vec![0u8; length];
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileExt;
            let mut read = 0;
            while read < raw.len() {
                let n = file
                    .read_at(&mut raw[read..], descriptor.offset as u64 + read as u64)
                    .map_err(|_| ChunkError::Unavailable("snapshot read failed"))?;
                if n == 0 {
                    break;
                }
                read += n;
            }
            raw.truncate(read);
        }
        #[cfg(not(unix))]
        {
            return Err(ChunkError::Unavailable("snapshot read failed"));
        }
        if raw.len() != descriptor.size as usize
            || hex::encode(Sha256::digest(&raw)).as_bytes() != descriptor.sha256
        {
            return Err(ChunkError::Corrupt);
        }
        Ok(raw)
    })
    .await;
    let payload = match payload {
        Ok(Ok(payload)) => payload,
        Ok(Err(ChunkError::Corrupt)) => {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "state_sync_source_corrupt",
                "snapshot chunk failed local integrity check",
            )
        }
        Ok(Err(ChunkError::Unavailable(reason))) => {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "state_sync_chunk_unavailable",
                reason,
            )
        }
        Err(_) => {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "state_sync_chunk_unavailable",
                "snapshot read failed",
            )
        }
    };
    let lease =
        tokio::task::spawn_blocking(move || renew_lease(&snapshot, SystemTime::now())).await;
    match lease {
        Ok(Ok(())) => {}
        Ok(Err(reason)) => eprintln!("state_sync lease_renew_failed reason={reason:?}"),
        Err(reason) => eprintln!("state_sync lease_renew_failed reason={reason:?}"),
    }
    let mut response = (StatusCode::OK, payload).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    response.headers_mut().insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=31536000, immutable"),
    );
    for (name, value) in [
        ("x-octra-chunk-sha256", expected_hash),
        ("x-octra-manifest-sha256", manifest_hash),
        ("x-octra-chunk-index", index.to_string().into_bytes()),
        ("x-octra-snapshot", snapshot_id),
    ] {
        if set_header(&mut response, name, &value).is_err() {
            return unavailable("invalid chunk header");
        }
    }
    response
}
fn renew_lease(snapshot: &Path, now: SystemTime) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use rustix::fs::{open, openat, Mode, OFlags};
        let directory = open(
            snapshot,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        match openat(&directory, "download.lease", flags, Mode::empty()) {
            Ok(descriptor) => {
                let file: std::fs::File = descriptor.into();
                let metadata = file.metadata()?;
                if !metadata.is_file() {
                    return Err(std::io::Error::other(
                        "state sync lease marker is not a regular file",
                    ));
                }
                if now
                    .duration_since(metadata.modified()?)
                    .map_or(true, |age| age < Duration::from_secs(60))
                {
                    return Ok(());
                }
            }
            Err(error) if error == rustix::io::Errno::NOENT => {}
            Err(error) => return Err(error.into()),
        }
        let file: std::fs::File = openat(
            &directory,
            "download.lease",
            OFlags::WRONLY | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )?
        .into();
        if !file.metadata()?.is_file() {
            return Err(std::io::Error::other(
                "state sync lease marker is not a regular file",
            ));
        }
        file.set_times(
            std::fs::FileTimes::new()
                .set_accessed(now)
                .set_modified(now),
        )
    }
    #[cfg(not(unix))]
    {
        let _ = (snapshot, now);
        Err(std::io::Error::other(
            "safe snapshot lease access requires Unix",
        ))
    }
}
fn legacy(method: &Method, path: &str) -> bool {
    if method == Method::GET {
        if matches!(
            path,
            "/total-txs"
                | "/circulating-supply"
                | "/total-supply"
                | "/max-supply"
                | "/trees"
                | "/txs"
                | "/epochs"
                | "/epoch/current"
                | "/network/stats"
                | "/staging"
                | "/staging/stats"
                | "/staging/estimate-ou"
                | "/webhooks"
                | "/pending_private_transfers"
        ) {
            return true;
        }
        return [
            "/balance/",
            "/public_key/",
            "/address/",
            "/rejected/",
            "/validate-address/",
            "/tree/",
            "/tx/",
            "/epoch/",
            "/view_encrypted_balance/",
            "/encrypted_cipher/",
            "/private_transactions/",
            "/contract/",
        ]
        .iter()
        .any(|prefix| path.starts_with(prefix));
    }
    if method == Method::POST {
        return matches!(
            path,
            "/send-tx"
                | "/encrypt_balance"
                | "/decrypt_balance"
                | "/register_pvac_pubkey"
                | "/private_transfer"
                | "/claim_private_transfer"
                | "/send-batch"
                | "/deploy-contract"
                | "/call-contract"
                | "/contract/call-view"
                | "/webhooks"
                | "/validate-address"
        );
    }
    method == Method::DELETE
        && ["/staging/remove/", "/webhooks/"]
            .iter()
            .any(|prefix| path.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;
    #[test]
    fn native_uri_query_vectors_preserve_bare_keys_commas_and_duplicate_precedence() {
        use base64::{engine::general_purpose::STANDARD, Engine};
        use serde_json::json;
        let report: serde_json::Value = serde_json::from_str(include_str!(
            "../../../octra-node-protocol/tests/fixtures/state-sync-http.json"
        ))
        .unwrap();
        let mut count = 0;
        for case in report["cases"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|case| case["op"] == "query")
        {
            let rows = decode_query(case["query"].as_str().unwrap());
            let projected = rows
                .iter()
                .map(|(key, values)| {
                    json!([
                        STANDARD.encode(key),
                        values
                            .iter()
                            .map(|v| STANDARD.encode(v))
                            .collect::<Vec<_>>()
                    ])
                })
                .collect::<Vec<_>>();
            let selected = [b"from_epoch".as_slice(), b"path", b"bare"]
                .into_iter()
                .map(|key| {
                    query(&rows, key).map_or(serde_json::Value::Null, |v| json!(STANDARD.encode(v)))
                })
                .collect::<Vec<_>>();
            assert_eq!(
                json!({"selected":selected,"rows":projected}),
                case["expected"]["ok"],
                "{case}"
            );
            count += 1;
        }
        assert_eq!(count, 3);
    }
    #[tokio::test]
    async fn native_error_body_vectors_match_adopted_http_oracle() {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let report: serde_json::Value = serde_json::from_str(include_str!(
            "../../../octra-node-protocol/tests/fixtures/state-sync-http.json"
        ))
        .unwrap();
        let mut count = 0;
        for case in report["cases"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|case| case["op"] == "error")
        {
            let response = error(
                StatusCode::BAD_REQUEST,
                case["type"].as_str().unwrap(),
                case["reason"].as_str().unwrap(),
            );
            let body = body::to_bytes(response.into_body(), 1024).await.unwrap();
            assert_eq!(
                body.as_ref(),
                STANDARD
                    .decode(case["expected"]["ok"].as_str().unwrap())
                    .unwrap()
            );
            count += 1;
        }
        assert_eq!(count, 3);
    }
    #[tokio::test]
    async fn native_transport_applies_preflight_close_and_rpc_cors() {
        let router = native_layer(Router::new().route(
            "/rpc",
            axum::routing::post(|| async {
                (
                    [(header::CONTENT_TYPE, "application/json")],
                    b"{\"result\":true}".as_slice(),
                )
            }),
        ));
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/unknown")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CONNECTION], "close");
        assert_eq!(
            response.headers()[header::ACCESS_CONTROL_ALLOW_METHODS],
            "GET, POST, DELETE, OPTIONS"
        );
        assert!(body::to_bytes(response.into_body(), 1)
            .await
            .unwrap()
            .is_empty());
        let response = router
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/rpc")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
        assert_eq!(response.headers()[header::CONNECTION], "close");
        assert_eq!(
            body::to_bytes(response.into_body(), 100)
                .await
                .unwrap()
                .as_ref(),
            b"{\"result\":true}"
        );
    }
    #[tokio::test]
    async fn progress_rejects_oversize_malformed_and_nonobject_before_acknowledging() {
        let response = progress(Request::new(Body::from(vec![b' '; wire::PROGRESS_MAX + 1]))).await;
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(body::to_bytes(response.into_body(),1024).await.unwrap().as_ref(),b"{\"status\":\"error\",\"error\":{\"type\":\"request_too_large\",\"reason\":\"request body too large\"}}");
        for (input, reason) in [
            (b"{".as_slice(), b"invalid JSON".as_slice()),
            (b"[]", b"progress report must be a JSON object"),
        ] {
            let response = progress(Request::new(Body::from(input.to_vec()))).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let raw = body::to_bytes(response.into_body(), 1024).await.unwrap();
            assert!(raw.windows(reason.len()).any(|v| v == reason));
        }
        let response = progress(Request::new(Body::from(
            b"{\"peer\":\"untrusted\",\"ready_epoch\":9000}".to_vec(),
        )))
        .await;
        assert_eq!(
            body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap()
                .as_ref(),
            b"{\"ok\":true}"
        );
    }
    #[test]
    fn native_queries_keep_first_value_and_decode_arbitrary_bytes() {
        let rows = decode_query("from_epoch=2&from_epoch=999&path=a%2Fb%FF+z");
        assert_eq!(query(&rows, b"from_epoch"), Some(b"2".as_slice()));
        assert_eq!(query(&rows, b"path"), Some(b"a/b\xff z".as_slice()));
        assert!(legacy(&Method::GET, "/tx/hash"));
        assert!(!legacy(&Method::POST, "/tx/hash"));
        assert!(!normalized_path(b"../secret"));
        assert!(!allowed_path(b"irmin_store/index.bak123/value"));
        assert!(allowed_path(b"irmin_store/store.control"));
    }
    #[cfg(unix)]
    #[test]
    fn snapshot_descriptor_access_rejects_symlinks_and_lease_preserves_content() {
        use std::{
            fs,
            os::unix::{fs::symlink, fs::MetadataExt},
        };
        let directory = tempfile::tempdir().unwrap();
        let snapshot = directory.path().join("snapshot");
        fs::create_dir(&snapshot).unwrap();
        fs::write(snapshot.join("ledger.dat"), b"snapshot bytes").unwrap();
        assert!(certificate::open(&snapshot, b"ledger.dat").is_ok());
        fs::write(directory.path().join("private"), b"private bytes").unwrap();
        symlink(directory.path().join("private"), snapshot.join("escape")).unwrap();
        assert!(certificate::open(&snapshot, b"escape").is_err());
        symlink(directory.path(), snapshot.join("dir")).unwrap();
        assert!(certificate::open(&snapshot, b"dir/private").is_err());
        let lease = snapshot.join("download.lease");
        fs::write(&lease, b"retained lease contents").unwrap();
        let now = SystemTime::now();
        fs::File::open(&lease)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(now - Duration::from_secs(120)))
            .unwrap();
        let inode = fs::metadata(&lease).unwrap().ino();
        renew_lease(&snapshot, now).unwrap();
        assert_eq!(fs::read(&lease).unwrap(), b"retained lease contents");
        assert_eq!(fs::metadata(&lease).unwrap().ino(), inode);
        let modified = fs::metadata(&lease).unwrap().modified().unwrap();
        renew_lease(&snapshot, now + Duration::from_secs(30)).unwrap();
        assert_eq!(fs::metadata(&lease).unwrap().modified().unwrap(), modified);
        fs::remove_file(&lease).unwrap();
        symlink(directory.path().join("private"), &lease).unwrap();
        assert!(renew_lease(&snapshot, now).is_err());
        assert_eq!(
            fs::read(directory.path().join("private")).unwrap(),
            b"private bytes"
        );
    }
}
