use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use http_body_util::BodyExt;
use octra_browser::{
    http::{Gateway, Portal},
    Asset, AssetResolver, ChainOrigin, Error, OctUrl, Provenance, SnapshotIdentity, StateRoot,
};
use std::{collections::BTreeMap, sync::Arc};
use tower::ServiceExt;

const PORTAL_HOST: &str = "octra.to";
const PAID_HOST: &str = "circles.octra.to";
const PORTAL_CIRCLE: &str = "octC9XpV4K4LJWFzc16zvaS1Rk3z8nyiqS7xwswH84Tca7E";
const PORTAL_FILES: [(&str, &str, &[u8]); 6] = [
    (
        "/index.html",
        "text/html",
        include_bytes!("../../../sites/octra-to/index.html"),
    ),
    (
        "/join.html",
        "text/html",
        include_bytes!("../../../sites/octra-to/join.html"),
    ),
    (
        "/browse.html",
        "text/html",
        include_bytes!("../../../sites/octra-to/browse.html"),
    ),
    (
        "/operators.html",
        "text/html",
        include_bytes!("../../../sites/octra-to/operators.html"),
    ),
    (
        "/style.css",
        "text/css",
        include_bytes!("../../../sites/octra-to/style.css"),
    ),
    (
        "/logo.svg",
        "image/svg+xml",
        include_bytes!("../../../sites/octra-to/logo.svg"),
    ),
];

fn provenance() -> Provenance {
    Provenance::Canonical(SnapshotIdentity {
        chain_id: "octra-to-test".into(),
        origin: ChainOrigin::Genesis {
            state_root: StateRoot([0; 32]),
        },
        epoch: 8,
        state_root: "11".repeat(32),
        ledger_root: "22".repeat(64),
        irmin_commit: "33".repeat(64),
    })
}

struct Resolver {
    files: BTreeMap<(String, String), (&'static str, &'static [u8])>,
}

#[async_trait]
impl AssetResolver for Resolver {
    fn provenance(&self) -> Provenance {
        provenance()
    }
    async fn resolve(&self, url: &OctUrl) -> Result<Asset, Error> {
        let (content_type, bytes) = self
            .files
            .get(&(url.circle_id.clone(), url.path.clone()))
            .ok_or(Error::NotFound)?;
        Ok(Asset {
            bytes: Arc::from(*bytes),
            content_type: (*content_type).to_owned(),
            provenance: provenance(),
        })
    }
}

fn resolver() -> Arc<Resolver> {
    let mut files = PORTAL_FILES
        .iter()
        .map(|(path, typ, bytes)| ((PORTAL_CIRCLE.into(), (*path).into()), (*typ, *bytes)))
        .collect::<BTreeMap<_, _>>();
    files.insert(
        ("public".into(), "/index.html".into()),
        ("text/html", b"<h1>Public Circle</h1>"),
    );
    Arc::new(Resolver { files })
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
async fn circle_hosted_onboarding_is_bounded_and_navigable() {
    let portal = Portal::new(
        PORTAL_CIRCLE,
        PORTAL_FILES.iter().map(|(path, _, _)| (*path).to_owned()),
    )
    .unwrap();
    let app = Gateway::new(resolver(), "https://octra.to")
        .unwrap()
        .with_portal(portal)
        .unwrap()
        .router();
    let (status, headers, home) = request(app.clone(), "/", PORTAL_HOST).await;
    assert_eq!(status, StatusCode::OK);
    assert!(home.contains("Go where the"));
    assert!(home.contains(&format!("/circles/{PORTAL_CIRCLE}/join.html")));
    assert!(home.contains(&format!(
        "/snapshots/{}/{PORTAL_CIRCLE}/style.css",
        provenance().id(),
    )));
    assert!(headers["content-security-policy"]
        .to_str()
        .unwrap()
        .contains("form-action 'none'"));
    for (path, _, _) in PORTAL_FILES {
        assert_eq!(
            request(app.clone(), path, PORTAL_HOST).await.0,
            StatusCode::OK,
            "{path}"
        );
    }
    let css = request(app.clone(), "/style.css", PORTAL_HOST).await.2;
    assert!(css.contains(".mesh-card"));
    let browse = request(app.clone(), "/browse.html", PORTAL_HOST).await.2;
    assert!(browse.contains(&format!("/circles/{PORTAL_CIRCLE}/index.html")));
    assert!(!browse.contains("href=\"oct://"));
    for path in [
        "/resolve?u=oct%3A%2F%2Fpublic%2Findex.html",
        "/circles/public/index.html",
        "/unknown.html",
    ] {
        assert!(
            !request(app.clone(), path, PORTAL_HOST).await.0.is_success(),
            "{path}"
        );
    }
}

#[tokio::test]
async fn paid_https_gateway_resolves_valid_public_circle_urls_only() {
    let app = Gateway::new(resolver(), "https://circles.octra.to")
        .unwrap()
        .router();
    let (status, headers, _) = request(
        app.clone(),
        "/resolve?u=oct%3A%2F%2Fpublic%2Findex.html",
        PAID_HOST,
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers["location"], "/circles/public/index.html");
    let (status, _, body) = request(app.clone(), "/circles/public/index.html", PAID_HOST).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Public Circle"));
    for bad in [
        "/resolve?u=https%3A%2F%2Fevil.example%2F",
        "/resolve?u=oct%3A%2F%2Fevil.example%40public%2Findex.html",
        "/resolve?u=oct%3A%2F%2Fpublic%2F..%2Findex.html",
    ] {
        assert_eq!(
            request(app.clone(), bad, PAID_HOST).await.0,
            StatusCode::BAD_REQUEST,
            "{bad}"
        );
    }
    assert_eq!(
        request(
            app,
            "/resolve?u=oct%3A%2F%2Fpublic%2Findex.html",
            "evil.example"
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
}
