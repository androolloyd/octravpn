use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use http_body_util::BodyExt;
use octra_browser::{
    http::{Browser, Gateway},
    Asset, AssetResolver, Error, OctUrl, Provenance, SnapshotIdentity,
};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
};
use tower::ServiceExt;
struct Resolver {
    assets: BTreeMap<(String, String), (String, Vec<u8>)>,
    changed: AtomicBool,
    reads: AtomicUsize,
}
fn provenance() -> Provenance {
    Provenance::Canonical(SnapshotIdentity {
        chain_id: "browser-test".into(),
        genesis_root: "00".repeat(32),
        epoch: 3,
        state_root: "11".repeat(32),
        ledger_root: "22".repeat(64),
        irmin_commit: "33".repeat(64),
    })
}
#[async_trait]
impl AssetResolver for Resolver {
    fn provenance(&self) -> Provenance {
        provenance()
    }
    async fn resolve(&self, url: &OctUrl) -> Result<Asset, Error> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        let (typ, bytes) = self
            .assets
            .get(&(url.circle_id.clone(), url.path.clone()))
            .ok_or(Error::NotFound)?;
        Ok(Asset {
            bytes: Arc::from(bytes.clone()),
            content_type: typ.clone(),
            provenance: if self.changed.load(Ordering::Relaxed) {
                Provenance::UnpinnedRpc
            } else {
                provenance()
            },
        })
    }
}
fn fixture() -> Arc<Resolver> {
    Arc::new(Resolver{assets:[
        (("one".into(),"/docs/index.html".into()),("text/html".into(),br#"<base href="https://evil/"><h1>Circle</h1><link rel="stylesheet" href="style.css"><img src="image.svg"><a id="next" href="oct://two/about?q=1#section" onclick="alert(1)">Other</a><script>fetch('https://evil/')</script><iframe srcdoc="evil"></iframe><a href="javascript:alert(1)">Bad</a>"#.to_vec())),
        (("two".into(),"/about".into()),("text/html".into(),b"<h1>Other Circle</h1>".to_vec())),
        (("octMixedCASE".into(),"/data.json".into()),("application/json".into(),b"{\"value\":42}\n".to_vec())),
    ].into(),changed:AtomicBool::new(false),reads:AtomicUsize::new(0)})
}
async fn request(
    router: Router,
    path: &str,
    host: &str,
) -> (StatusCode, axum::http::HeaderMap, String) {
    let response = router
        .oneshot(
            Request::builder()
                .uri(path)
                .header("host", host)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, headers, String::from_utf8(body.to_vec()).unwrap())
}
#[tokio::test]
async fn root_documents_and_cross_circle_links_keep_the_snapshot_scope() {
    let resolver = fixture();
    let browser = Browser::new(resolver.clone(), "/circles").unwrap();
    let scope = browser.provenance().id();
    let root = OctUrl::parse("oct://one/docs/").unwrap();
    let view = browser.view_url(&root);
    let asset = browser.asset_url(&root);
    let app = Router::new().nest("/circles", browser.router());
    let (status, headers, body) = request(app.clone(), &asset, "127.0.0.1:8400").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains(&format!("/circles/asset/{scope}/one/docs/style.css")));
    assert!(body.contains(&format!("/circles/view/{scope}/two/about?q=1#section")));
    for removed in [
        "<base",
        "<script",
        "<iframe",
        "onclick",
        "javascript:",
        "https://evil",
    ] {
        assert!(!body.contains(removed), "{removed}");
    }
    assert_eq!(headers["cache-control"], "no-store");
    assert_eq!(headers["x-content-type-options"], "nosniff");
    assert!(headers["content-security-policy"]
        .to_str()
        .unwrap()
        .contains("script-src 'none'"));
    let (status, _, body) = request(app.clone(), &view, "127.0.0.1:8400").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Epoch 3"));
    assert!(body.contains("sandbox="));
    let (status, _, body) = request(
        app,
        &format!("/circles/asset/{scope}/two/about?q=1"),
        "[::1]:8400",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Other Circle"));
}
#[tokio::test]
async fn wrong_host_scope_and_changed_snapshot_never_serve_assets() {
    let resolver = fixture();
    let browser = Browser::new(resolver.clone(), "").unwrap();
    let url = browser.asset_url(&OctUrl::parse("oct://two/about").unwrap());
    let wrong = url.replace(&browser.provenance().id(), &"f".repeat(64));
    let app = browser.router();
    for host in ["localhost", "127.0.0.1.evil", "example.com", "192.168.1.1"] {
        assert_eq!(
            request(app.clone(), &url, host).await.0,
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        request(app.clone(), &wrong, "127.0.0.1").await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(resolver.reads.load(Ordering::Relaxed), 0);
    resolver.changed.store(true, Ordering::Relaxed);
    let (status, _, body) = request(app, &url, "127.0.0.1").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(!body.contains("Other Circle"));
}

const GATEWAY_HOST: &str = "circles.example.ts.net";
const GATEWAY_ORIGIN: &str = "https://circles.example.ts.net";

#[tokio::test]
async fn gateway_serves_documents_directly_and_pins_subresources() {
    let gateway = Gateway::new(fixture(), GATEWAY_ORIGIN).unwrap().router();
    let (status, headers, body) =
        request(gateway.clone(), "/circles/one/docs/", GATEWAY_HOST).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("<h1>Circle</h1>"));
    assert!(!body.contains("<iframe"));
    assert!(!body.contains("circle-host"));
    assert!(!body.contains("<script"));
    assert!(!body.contains("https://evil"));
    assert!(body.contains("/circles/two/about?q=1#section"));
    assert!(body.contains(&format!(
        "/snapshots/{}/one/docs/style.css",
        provenance().id()
    )));
    assert_eq!(headers["x-octra-chain"], "browser-test");
    assert_eq!(headers["x-octra-epoch"], "3");
    assert_eq!(headers["x-octra-state-root"], "11".repeat(32));
    assert!(headers["content-security-policy"]
        .to_str()
        .unwrap()
        .contains(&format!(
            "{GATEWAY_ORIGIN}/snapshots/{}/one/",
            provenance().id()
        )));
    let (status, _, body) = request(gateway, "/circles/two/about?q=1", GATEWAY_HOST).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Other Circle"));
}

#[tokio::test]
async fn gateway_preserves_case_bytes_and_head_for_nonbrowser_clients() {
    let gateway = Gateway::new(fixture(), GATEWAY_ORIGIN).unwrap().router();
    let path = "/circles/octMixedCASE/data.json";
    let (status, headers, body) = request(gateway.clone(), path, GATEWAY_HOST).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["content-type"], "application/json");
    assert_eq!(body.as_bytes(), b"{\"value\":42}\n");
    assert_eq!(
        request(gateway.clone(), &path.to_lowercase(), GATEWAY_HOST)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    let head = gateway
        .clone()
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri(path)
                .header("host", GATEWAY_HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(head.status(), StatusCode::OK);
    assert!(head
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .is_empty());
    for forbidden in ["/app/request", "/open?u=oct://one/docs/", "/rpc"] {
        assert_eq!(
            request(gateway.clone(), forbidden, GATEWAY_HOST).await.0,
            StatusCode::NOT_FOUND
        );
    }
    let post = gateway
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("host", GATEWAY_HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(post.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn gateway_rejects_host_spoofing_stale_scopes_and_provenance_changes() {
    let resolver = fixture();
    let gateway = Gateway::new(resolver.clone(), GATEWAY_ORIGIN)
        .unwrap()
        .router();
    for host in [
        "evil.example",
        "127.0.0.1",
        "circles.example.ts.net.evil",
        "circles.example.ts.net:80",
    ] {
        let response = gateway
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/circles/two/about")
                    .header("host", host)
                    .header("x-forwarded-host", GATEWAY_HOST)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    let stale = format!("/snapshots/{}/two/about", "f".repeat(64));
    assert_eq!(
        request(gateway.clone(), &stale, GATEWAY_HOST).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(resolver.reads.load(Ordering::Relaxed), 0);
    let pinned = format!("/snapshots/{}/two/about", provenance().id());
    assert_eq!(
        request(gateway.clone(), &pinned, GATEWAY_HOST).await.0,
        StatusCode::OK
    );
    resolver.changed.store(true, Ordering::Relaxed);
    let (status, _, body) = request(gateway, "/circles/two/about", GATEWAY_HOST).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(!body.contains("Other Circle"));
}

#[test]
fn gateway_rejects_ambiguous_or_non_https_origins() {
    for origin in [
        "http://circles.example",
        "https://user@circles.example",
        "https://circles.example/",
        "https://circles.example/path",
        "https://circles.example?x=1",
        "https://circles.example#x",
        "https://circles.example:8443",
        "https://*.example",
        "https://circles.example\r\nInjected: yes",
    ] {
        assert!(Gateway::new(fixture(), origin).is_err(), "{origin}");
    }
}

struct Restricted {
    canonical: bool,
}
#[async_trait]
impl AssetResolver for Restricted {
    fn provenance(&self) -> Provenance {
        if self.canonical {
            provenance()
        } else {
            Provenance::UnpinnedRpc
        }
    }
    async fn resolve(&self, url: &OctUrl) -> Result<Asset, Error> {
        if url.path == "/sealed" {
            Err(Error::Sealed)
        } else {
            Err(Error::ApprovalRequired {
                approval_url: "/local-review".into(),
            })
        }
    }
}

#[tokio::test]
async fn gateway_cannot_publish_unverified_or_private_resources() {
    assert!(Gateway::new(Arc::new(Restricted { canonical: false }), GATEWAY_ORIGIN).is_err());
    let gateway = Gateway::new(Arc::new(Restricted { canonical: true }), GATEWAY_ORIGIN)
        .unwrap()
        .router();
    for path in ["/circles/one/sealed", "/circles/one/approval"] {
        assert_eq!(
            request(gateway.clone(), path, GATEWAY_HOST).await.0,
            StatusCode::PRECONDITION_FAILED
        );
    }
}
