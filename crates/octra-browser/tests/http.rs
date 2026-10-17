use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use http_body_util::BodyExt;
use octra_browser::{
    http::{Browser, Gateway, Portal},
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
        origin: octra_browser::ChainOrigin::Genesis {
            state_root: octra_browser::StateRoot([0; 32]),
        },
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

fn portal_fixture() -> Arc<Resolver> {
    Arc::new(Resolver {
        assets: [
            (("one".into(), "/index.html".into()), ("text/html".into(), br#"<h1>Join Octranet</h1><link rel="stylesheet" href="style.css"><a href="status.json">Account status</a><a href="oct://two/about">Other</a><script>fetch('https://evil/')</script>"#.to_vec())),
            (("one".into(), "/style.css".into()), ("text/css".into(), b"body{background-image:url('/logo.svg')}".to_vec())),
            (("one".into(), "/logo.svg".into()), ("image/svg+xml".into(), b"<svg xmlns='http://www.w3.org/2000/svg'/>".to_vec())),
            (("one".into(), "/status.json".into()), ("application/json".into(), br#"{"paid_admission":false}"#.to_vec())),
            (("one".into(), "/private.html".into()), ("text/html".into(), b"<h1>Not in the portal</h1>".to_vec())),
            (("one".into(), "/docs/index.html".into()), ("text/html".into(), b"<h1>No implicit directory grant</h1>".to_vec())),
            (("two".into(), "/index.html".into()), ("text/html".into(), b"<h1>Another Circle</h1>".to_vec())),
        ].into(),
        changed: AtomicBool::new(false),
        reads: AtomicUsize::new(0),
    })
}

fn portal() -> Portal {
    Portal::new(
        "one",
        [
            "/index.html",
            "/style.css",
            "/logo.svg",
            "/status.json",
            "/docs/index.html",
        ]
        .map(str::to_owned),
    )
    .unwrap()
}

#[test]
fn portal_configuration_is_bounded_canonical_and_immutable() {
    let configured = portal();
    assert_eq!(configured.circle(), "one");
    assert_eq!(configured.paths().len(), 5);
    let encoded = serde_json::to_vec(&configured).unwrap();
    let restored: Portal = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(restored.circle(), configured.circle());
    assert_eq!(restored.paths(), configured.paths());
    for path in [
        "/",
        "/docs/",
        "/../index.html",
        "/./index.html",
        "//index.html",
        "/a//index.html",
        "/index.html?proxy=1",
        "/index.html#fragment",
        "/%69ndex.html",
        "/%252e%252e/index.html",
        "/index%2ehtml",
        "/image*.png",
        "/rpc",
        "/app/request",
        "/snapshots/a/one/index.html",
        "/circles/one/index.html",
        "/view/a/one/index.html",
        "/o/oct://two/",
        "/site/two/index.html",
        "/back\\slash.css",
        "/café.css",
    ] {
        assert!(
            Portal::new("one", ["/index.html".into(), path.into()]).is_err(),
            "{path}"
        );
    }
    assert!(Portal::new("one", ["/style.css".into()]).is_err());
    assert!(Portal::new("one", ["/index.html".into(), "/index.html".into()]).is_err());
    assert!(Portal::new(
        "one",
        [
            "/index.html".into(),
            format!("/{}", "a".repeat(Portal::MAX_PATH_BYTES))
        ]
    )
    .is_err());
    assert!(Portal::new(
        "one",
        std::iter::once("/index.html".into())
            .chain((0..Portal::MAX_PATHS).map(|i| format!("/{i}.css")))
    )
    .is_err());
    for invalid in [
        serde_json::json!({"circle":"one","paths":["/index.html"],"proxy":true}),
        serde_json::json!({"circle":"one","paths":["/index.html","/%69ndex.html"]}),
        serde_json::json!({"circle":"one/docs","paths":["/index.html"]}),
    ] {
        assert!(serde_json::from_value::<Portal>(invalid).is_err());
    }
    assert!(Gateway::new(portal_fixture(), GATEWAY_ORIGIN)
        .unwrap()
        .with_site("one")
        .unwrap()
        .with_portal(portal())
        .is_err());
    assert!(Gateway::new(portal_fixture(), GATEWAY_ORIGIN)
        .unwrap()
        .with_portal(portal())
        .unwrap()
        .with_site("one")
        .is_err());
}

#[tokio::test]
async fn portal_serves_only_its_explicit_canonical_assets_and_pinned_subresources() {
    let gateway = Gateway::new(portal_fixture(), GATEWAY_ORIGIN)
        .unwrap()
        .with_portal(portal())
        .unwrap()
        .router();
    let (status, headers, html) = request(gateway.clone(), "/", GATEWAY_HOST).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["x-octra-epoch"], "3");
    assert!(html.contains("Join Octranet"));
    assert!(!html.contains("<script"));
    assert!(html.contains("/circles/one/status.json"));
    let stylesheet = format!("/snapshots/{}/one/style.css", provenance().id());
    assert!(html.contains(&stylesheet));
    let (status, _, css) = request(gateway.clone(), &stylesheet, GATEWAY_HOST).await;
    assert_eq!(status, StatusCode::OK);
    assert!(css.contains(&format!("/snapshots/{}/one/logo.svg", provenance().id())));
    for path in ["/status.json", "/circles/one/status.json"] {
        let (status, _, body) = request(gateway.clone(), path, GATEWAY_HOST).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, r#"{"paid_admission":false}"#);
    }
    let head = gateway
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri("/index.html")
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
}

#[tokio::test]
async fn portal_refuses_route_encoding_query_circle_and_scope_escapes_before_lookup() {
    let resolver = portal_fixture();
    let gateway = Gateway::new(resolver.clone(), GATEWAY_ORIGIN)
        .unwrap()
        .with_portal(portal())
        .unwrap()
        .router();
    for path in [
        "/private.html",
        "/docs/",
        "/circles/two/index.html",
        "/circles/one-other/index.html",
        "/circles/one/private.html",
        "/view/one/index.html",
        "/o/oct://two/",
        "/site/two/index.html",
        "/open?u=oct://two/",
        "/rpc",
        "/app/request",
        "/%69ndex.html",
        "/%252e%252e/index.html",
        "/%2e%2e/index.html",
        "/a/../index.html",
        "/a//index.html",
        "//index.html",
        "/index.html%3fproxy=1",
        "/index.html?proxy=oct://two/",
        "https://evil.example/index.html",
    ] {
        let (status, _, body) = request(gateway.clone(), path, GATEWAY_HOST).await;
        assert!(!status.is_success(), "{path}");
        assert!(!body.contains("Join Octranet"), "{path}");
    }
    for path in [
        format!("/snapshots/{}/one/index.html", "f".repeat(64)),
        format!("/snapshots/{}/two/index.html", provenance().id()),
        format!("/snapshots/{}/one/private.html", provenance().id()),
        format!("/snapshots/{}/one/index.html?x=1", provenance().id()),
    ] {
        assert!(
            !request(gateway.clone(), &path, GATEWAY_HOST)
                .await
                .0
                .is_success(),
            "{path}"
        );
    }
    assert_eq!(resolver.reads.load(Ordering::Relaxed), 0);
    for method in ["POST", "PUT", "DELETE", "OPTIONS", "CONNECT"] {
        let response = gateway
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri("/index.html")
                    .header("host", GATEWAY_HOST)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "{method}"
        );
    }
    assert_eq!(resolver.reads.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn portal_keeps_host_and_changed_provenance_fail_closed() {
    let resolver = portal_fixture();
    let gateway = Gateway::new(resolver.clone(), GATEWAY_ORIGIN)
        .unwrap()
        .with_portal(portal())
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
                    .uri("/index.html")
                    .header("host", host)
                    .header("x-forwarded-host", GATEWAY_HOST)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    assert_eq!(resolver.reads.load(Ordering::Relaxed), 0);
    resolver.changed.store(true, Ordering::Relaxed);
    let (status, _, body) = request(gateway, "/index.html", GATEWAY_HOST).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(!body.contains("Join Octranet"));
}

#[tokio::test]
async fn circle_website_paths_keep_host_snapshot_and_read_only_boundaries() {
    let resolver = fixture();
    let gateway = Gateway::new(resolver.clone(), GATEWAY_ORIGIN)
        .unwrap()
        .with_site("one")
        .unwrap()
        .router();
    let (status, headers, html) = request(gateway.clone(), "/docs/?mode=join", GATEWAY_HOST).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["x-octra-epoch"], "3");
    assert!(html.contains(&format!(
        "/snapshots/{}/one/docs/style.css",
        provenance().id()
    )));
    assert!(html.contains("/circles/two/about?q=1#section"));
    assert!(!html.contains("<script"));
    assert_eq!(
        request(gateway.clone(), "/unpublished", GATEWAY_HOST)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        request(gateway.clone(), "/docs/", "evil.example").await.0,
        StatusCode::BAD_REQUEST
    );
    let stale = format!("/snapshots/{}/one/docs/", "f".repeat(64));
    assert_eq!(
        request(gateway.clone(), &stale, GATEWAY_HOST).await.0,
        StatusCode::BAD_REQUEST
    );
    let response = gateway
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/docs/")
                .header("host", GATEWAY_HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    for invalid in ["one/docs", "one?x", "one#x", "", "..", "one:443"] {
        assert!(Gateway::validate_site(invalid).is_err(), "{invalid}");
    }
}

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
