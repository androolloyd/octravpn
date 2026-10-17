//! Actual Node gateway: canonical publication between HTML and subresources.
use super::*;

const HOST: &str = "circles.example.ts.net";

fn put(state: &mut StateBatch, circle: &[u8], path: &str, typ: &str, body: &[u8]) {
    let key = circles::path_key(path.as_bytes());
    let meta = AssetMeta {
        path_key: key.as_bytes().to_vec(),
        canonical_path: path.as_bytes().to_vec(),
        content_type: typ.as_bytes().to_vec(),
        encoding: b"identity".to_vec(),
        size_bytes: body.len() as i64,
        blob_hash: hex::encode(Sha256::digest(body)).into_bytes(),
        body_mode: ResourceMode::Public,
        plaintext_hash: None,
        key_id: None,
        padding_class: None,
        resource_key: circles::resource_key(circle, path.as_bytes()).into_bytes(),
        locator_mode: LocatorMode::Path,
        slot_ref: None,
        activate_after_epoch: None,
        expire_after_epoch: None,
        metadata_mode: MetadataMode::Reveal,
    };
    let base = [
        b"circles".as_slice(),
        circle,
        b"assets",
        b"by_hash",
        key.as_bytes(),
    ];
    let mut path = base.to_vec();
    path.push(b"meta");
    state.set(&path, meta.to_json_bytes()).unwrap();
    path.pop();
    path.push(b"body_b64");
    state
        .set(&path, STANDARD.encode(body).into_bytes())
        .unwrap();
}
fn site(state: &mut StateBatch, color: &str) {
    let circle = b"MiXeD";
    put(state, circle, "/index.html", "text/html", br#"<h1>Octranet onboarding</h1><link rel="stylesheet" href="/docs/style.css"><a href="/status.json">Account status</a><a href="oct://Other/about">Another Circle</a>"#);
    put(
        state,
        circle,
        "/status.json",
        "application/json",
        br#"{"paid_admission":false}"#,
    );
    for (path,typ,body) in [
        ("/docs/index.html","text/html",br#"<!doctype html><html><head><link rel="stylesheet" href="style.css"><style>@import "inline.css"; #inline{background-image:url('/mark.svg')}</style></head><body><h1 id="title" style="background-image:url('/mark.svg')">Canonical gateway</h1><div id="inline">Inline</div><img id="image" src="/mark.svg"><a id="next" href="oct://Other/about">Other Circle</a><script>document.body.dataset.hacked='yes'</script></body></html>"#.as_slice()),
        ("/docs/inline.css","text/css",b"#inline{color:rgb(3,4,5)}".as_slice()),
        ("/theme.css","text/css",b"#title{border-top:3px solid rgb(7,8,9)}".as_slice()),
    ] { put(state,circle,path,typ,body); }
    put(
        state,
        circle,
        "/docs/style.css",
        "text/css",
        format!("@import '/theme.css';#title{{color:{color};background-image:url('/mark.svg')}}")
            .as_bytes(),
    );
    put(state,circle,"/mark.svg","image/svg+xml",format!(r#"<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16"><rect width="16" height="16" fill="{color}"/></svg>"#).as_bytes());
    circle_host::install_counter(state, b"Other", b"0");
    put(
        state,
        b"Other",
        "/about",
        "text/html",
        b"<h1 id='other'>Other Circle</h1>",
    );
}

struct Fixture {
    _dir: tempfile::TempDir,
    node: Arc<Node<Authority>>,
    authority: finality_host::Authority,
    endpoint: String,
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<Result<()>>,
}
impl Fixture {
    async fn new() -> Self {
        Self::with_portal(None).await
    }
    async fn with_portal(portal: Option<octra_browser::http::Portal>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut state = genesis(b"MiXeD");
        site(&mut state, "rgb(20,100,160)");
        let chain = ChainIdentity::genesis(
            "node-gateway-retention-fixture",
            StateRoot(finality_host::root(None, &state, &[])),
        );
        let path = dir.path().join("chain.db");
        CanonicalStore::create(&path, chain.clone(), state.snapshot(), 0)
            .await
            .unwrap()
            .close()
            .await;
        let checkpoints = Arc::new(
            SqliteCheckpoints::open(&dir.path().join("exex.db"))
                .await
                .unwrap(),
        );
        let node = Arc::new(open(&path, checkpoints, chain.clone(), Arc::default()).await);
        let service = node
            .bind_gateway(octra_node::gateway::Config {
                listen: "127.0.0.1:0".parse().unwrap(),
                origin: format!("https://{HOST}"),
                sites: if portal.is_some() {
                    std::collections::BTreeMap::default()
                } else {
                    [("octra.test".into(), "MiXeD".into())].into()
                },
                portal,
            })
            .await
            .unwrap();
        let endpoint = format!("http://{}", service.local_addr().unwrap());
        let (stop, shutdown) = watch::channel(false);
        let task = tokio::spawn(service.run(shutdown));
        Self {
            _dir: dir,
            node,
            authority: finality_host::Authority { seed: 1, chain },
            endpoint,
            stop,
            task,
        }
    }
    async fn advance(&self) {
        let view = self.node.snapshot().unwrap();
        let mut state = StateBatch::from_snapshot(view.state().clone());
        state.begin().unwrap();
        site(&mut state, "rgb(140,20,30)");
        let state = StateBatch::from_snapshot(state.snapshot());
        let executed =
            execute_received(view.head(), state, &[], &self.authority, None, None).unwrap();
        let certificate = finality_host::certificate(view.head(), &executed, &self.authority)
            .encode()
            .unwrap();
        self.node
            .publish(view.head(), &certificate, executed)
            .await
            .unwrap();
    }
    async fn get(&self, path: &str) -> reqwest::Response {
        reqwest::Client::new()
            .get(format!("{}{path}", self.endpoint))
            .header("host", HOST)
            .send()
            .await
            .unwrap()
    }
    async fn shutdown(self) {
        self.stop.send(true).unwrap();
        self.task.await.unwrap().unwrap();
        self.node.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn unpaid_portal_keeps_the_canonical_gateway_inside_its_asset_capability() {
    let portal = octra_browser::http::Portal::new(
        "MiXeD",
        [
            "/index.html",
            "/status.json",
            "/docs/style.css",
            "/theme.css",
            "/mark.svg",
        ]
        .map(str::to_owned),
    )
    .unwrap();
    let fixture = Fixture::with_portal(Some(portal.clone())).await;
    assert_eq!(fixture.get("/").await.status(), 503);
    fixture.node.resume().await.unwrap();
    let page = fixture.get("/").await;
    assert_eq!(page.status(), 200);
    let old = fixture.node.snapshot().unwrap().provenance().id();
    let html = page.text().await.unwrap();
    assert!(html.contains("Octranet onboarding"));
    assert!(html.contains(&format!("/snapshots/{old}/MiXeD/docs/style.css")));
    assert_eq!(
        fixture.get("/status.json").await.text().await.unwrap(),
        r#"{"paid_admission":false}"#
    );
    for path in [
        "/circles/Other/about",
        "/docs/",
        "/view/whatever/MiXeD/",
        "/open?u=oct://Other/about",
        "/rpc",
        "/status.json?proxy=1",
    ] {
        assert!(!fixture.get(path).await.status().is_success(), "{path}");
    }
    assert!(fixture
        .node
        .bind_gateway(octra_node::gateway::Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            origin: format!("https://{HOST}"),
            sites: [("octra.test".into(), "MiXeD".into())].into(),
            portal: Some(portal),
        })
        .await
        .is_err());
    fixture.advance().await;
    let css = fixture
        .get(&format!("/snapshots/{old}/MiXeD/docs/style.css"))
        .await;
    assert_eq!(css.status(), 200);
    assert!(css.text().await.unwrap().contains("rgb(20,100,160)"));
    assert_eq!(
        fixture
            .get(&format!("/snapshots/{old}/Other/about"))
            .await
            .status(),
        404
    );
    fixture.node.suspend("unpaid portal must not hide catch-up");
    assert_eq!(fixture.get("/index.html").await.status(), 503);
    assert_eq!(
        fixture
            .get(&format!("/snapshots/{old}/MiXeD/docs/style.css"))
            .await
            .status(),
        503
    );
    fixture.shutdown().await;
}

#[tokio::test]
async fn canonical_gateway_keeps_old_subresources_across_publication_and_refuses_suspended_reads() {
    let fixture = Fixture::new().await;
    assert_eq!(fixture.get("/circles/MiXeD/docs/").await.status(), 503);
    fixture.node.resume().await.unwrap();
    let site = reqwest::Client::new()
        .get(format!("{}/docs/", fixture.endpoint))
        .header("host", "octra.test")
        .send()
        .await
        .unwrap();
    assert_eq!(site.status(), 200);
    assert!(site.text().await.unwrap().contains("Canonical gateway"));
    let wrong_host = reqwest::Client::new()
        .get(format!("{}/docs/", fixture.endpoint))
        .header("host", "unconfigured.test")
        .send()
        .await
        .unwrap();
    assert_eq!(wrong_host.status(), 404);
    let response = fixture.get("/circles/MiXeD/docs/").await;
    assert_eq!(response.status(), 200);
    let old = fixture.node.snapshot().unwrap().provenance().id();
    let html = response.text().await.unwrap();
    assert!(html.contains(&format!("/snapshots/{old}/MiXeD/docs/style.css")));
    assert!(html.contains(&format!("/snapshots/{old}/MiXeD/mark.svg")));
    assert!(!html.contains("<script"));
    fixture.node.suspend("publishing canonical epoch");
    let during_publication = fixture.get("/circles/MiXeD/docs/").await;
    assert_eq!(during_publication.status(), 200);
    assert!(during_publication.text().await.unwrap().contains(&old));
    fixture.node.suspend("gateway fixture catch-up");
    assert_eq!(fixture.get("/circles/MiXeD/docs/").await.status(), 503);
    fixture.node.resume().await.unwrap();
    fixture.advance().await;
    let new = fixture.node.snapshot().unwrap().provenance().id();
    assert_ne!(new, old);
    let css = fixture
        .get(&format!("/snapshots/{old}/MiXeD/docs/style.css"))
        .await;
    assert_eq!(css.status(), 200);
    let css = css.text().await.unwrap();
    assert!(css.contains("rgb(20,100,160)"));
    assert!(css.contains(&format!("/snapshots/{old}/MiXeD/theme.css")));
    assert!(css.contains(&format!("/snapshots/{old}/MiXeD/mark.svg")));
    let old_image = fixture
        .get(&format!("/snapshots/{old}/MiXeD/mark.svg"))
        .await
        .text()
        .await
        .unwrap();
    assert!(old_image.contains("rgb(20,100,160)"));
    let latest = fixture
        .get("/circles/MiXeD/docs/")
        .await
        .text()
        .await
        .unwrap();
    assert!(latest.contains(&new));
    let css = fixture
        .get(&format!("/snapshots/{new}/MiXeD/docs/style.css"))
        .await
        .text()
        .await
        .unwrap();
    assert!(css.contains("rgb(140,20,30)"));
    assert_eq!(
        fixture
            .get(&format!(
                "/snapshots/{}/MiXeD/docs/style.css",
                "f".repeat(64)
            ))
            .await
            .status(),
        400
    );
    assert_eq!(fixture.get("/circles/mixed/docs/").await.status(), 404);
    for path in [
        "/rpc",
        "/app/request",
        "/app/review",
        "/open?u=oct://MiXeD/",
    ] {
        assert_eq!(fixture.get(path).await.status(), 404);
    }
    let post = reqwest::Client::new()
        .post(format!("{}/circles/MiXeD/docs/", fixture.endpoint))
        .header("host", HOST)
        .send()
        .await
        .unwrap();
    assert_eq!(post.status(), 405);
    fixture.node.suspend("gateway fixture catch-up");
    assert_eq!(
        fixture
            .get(&format!("/snapshots/{old}/MiXeD/mark.svg"))
            .await
            .status(),
        503
    );
    fixture.node.resume().await.unwrap();
    assert_eq!(
        fixture
            .get(&format!("/snapshots/{old}/MiXeD/mark.svg"))
            .await
            .status(),
        200
    );
    fixture.shutdown().await;
}

// Isolated qualification only. A CDP transport interceptor carries HTTPS-origin
// browser requests into this real Node's loopback HTTP backend; no TLS/tailnet
// admission is inferred from that renderer test.
#[tokio::test]
#[ignore = "launched by the isolated gateway Chromium qualification runner"]
async fn canonical_gateway_chromium_fixture() {
    let fixture = Arc::new(Fixture::new().await);
    fixture.node.resume().await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control = format!("http://{}", listener.local_addr().unwrap());
    let app = axum::Router::new().route(
        "/advance",
        axum::routing::post({
            let f = fixture.clone();
            move || {
                let f = f.clone();
                async move {
                    f.advance().await;
                    axum::Json(json!({"scope":f.node.snapshot().unwrap().provenance().id()}))
                }
            }
        }),
    );
    let report =
        std::env::var_os("OCTRA_GATEWAY_FIXTURE_FILE").expect("fixture output path required");
    std::fs::write(report,serde_json::to_vec(&json!({"gateway":fixture.endpoint,"control":control,"origin":format!("https://{HOST}"),"old_scope":fixture.node.snapshot().unwrap().provenance().id()})).unwrap()).unwrap();
    axum::serve(listener, app).await.unwrap();
}
