use base64::{engine::general_purpose::STANDARD, Engine};
use octra_browser::{AssetResolver, Error, OctUrl, Provenance, MAX_ASSET_BYTES};
use octra_exex::{ChainIdentity, StateRoot};
use octra_node_protocol::{
    circles::{self, AssetMeta, LocatorMode, MetadataMode, ResourceMode},
    epoch_index,
};
use octra_node_runtime::{
    canonical::{AppliedEpoch, CanonicalStore},
    circle_assets::CanonicalAssets,
    state_batch::StateBatch,
};
use serde_json::json;
use sha2::{Digest, Sha256};
#[path = "common/browser_host.rs"]
mod browser_host;
#[path = "common/circle_host.rs"]
mod circle_host;
#[path = "common/finality_host.rs"]
mod finality_host;
#[path = "canonical_assets/retained.rs"]
mod retained;

fn asset(state: &mut StateBatch, circle: &str, path: &str, body: &[u8]) -> AssetMeta {
    let circle = circle.as_bytes();
    state
        .set(
            &[b"circles", circle, b"browser", b"mode"],
            b"gateway_allowed".to_vec(),
        )
        .unwrap();
    state
        .set(
            &[b"circles", circle, b"resources", b"mode"],
            b"public_resources".to_vec(),
        )
        .unwrap();
    let meta = AssetMeta {
        path_key: circles::path_key(path.as_bytes()).into_bytes(),
        canonical_path: path.as_bytes().to_vec(),
        content_type: b"text/html".to_vec(),
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
    write_meta(state, circle, &meta);
    state
        .set(
            &[
                b"circles",
                circle,
                b"assets",
                b"by_hash",
                &meta.path_key,
                b"body_b64",
            ],
            STANDARD.encode(body).into_bytes(),
        )
        .unwrap();
    meta
}
fn write_meta(state: &mut StateBatch, circle: &[u8], meta: &AssetMeta) {
    state
        .set(
            &[
                b"circles",
                circle,
                b"assets",
                b"by_hash",
                &meta.path_key,
                b"meta",
            ],
            meta.to_json_bytes(),
        )
        .unwrap();
}
fn policy(state: &mut StateBatch, circle: &[u8], key: &str, value: &str) {
    let hash = circles::stable_key(key.as_bytes());
    state.set(&[b"circles",circle,b"stable",b"by_hash",hash.as_bytes()],serde_json::to_vec(&json!({"raw_key":key,"key_hash":hash,"value":{"value_kind":"inline","value_inline":value}})).unwrap()).unwrap();
}
fn initial() -> StateBatch {
    let mut state = StateBatch::default();
    state.begin().unwrap();
    state.set(&[b"meta", b"last_epoch"], b"0".to_vec()).unwrap();
    state
}
async fn create(path: &std::path::Path, state: &StateBatch) -> CanonicalStore {
    let root = epoch_index::folded_state_root(
        hex::encode(state.root().unwrap()).as_bytes(),
        hex::encode(
            epoch_index::next_root(hex::encode(epoch_index::genesis_root()).as_bytes(), 0, &[])
                .unwrap()
                .1,
        )
        .as_bytes(),
    )
    .unwrap();
    CanonicalStore::create(
        path,
        ChainIdentity::genesis("native-circle-browser-fixture", StateRoot(root)),
        state.snapshot(),
        0,
    )
    .await
    .unwrap()
}
#[tokio::test]
async fn reads_remain_on_one_committed_head_through_prepare_commit_and_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("chain.db");
    let mut state = initial();
    asset(&mut state, "first", "/index.html", b"old");
    asset(&mut state, "first", "/%2e", b"literal percent");
    asset(&mut state, "second", "/about", b"other circle");
    let store = create(&path, &state).await;
    let old = CanonicalAssets::capture(&store).await.unwrap();
    let url = OctUrl::parse("oct://first/index.html").unwrap();
    assert_eq!(&*old.resolve(&url).await.unwrap().bytes, b"old");
    assert_eq!(
        &*old
            .resolve(&OctUrl::parse("oct://first/%252e").unwrap())
            .await
            .unwrap()
            .bytes,
        b"literal percent"
    );
    assert_eq!(
        &*old
            .resolve(&OctUrl::parse("oct://second/about").unwrap())
            .await
            .unwrap()
            .bytes,
        b"other circle"
    );
    let (head, mut next) = store.snapshot().await.unwrap();
    next.begin().unwrap();
    next.set(&[b"meta", b"last_epoch"], b"1".to_vec()).unwrap();
    asset(&mut next, "first", "/index.html", b"new");
    let index = epoch_index::next_root(head.index_root.as_bytes(), 1, &[])
        .unwrap()
        .1;
    let root = epoch_index::folded_state_root(
        hex::encode(next.root().unwrap()).as_bytes(),
        hex::encode(index).as_bytes(),
    )
    .unwrap();
    let applied = AppliedEpoch {
        epoch: 1,
        state: next.snapshot(),
        expected_root: StateRoot(root),
        transactions: vec![],
        certificate: b"storage fixture only".to_vec(),
        date: 1,
        message: b"epoch 1".to_vec(),
    };
    let pending = store.prepare(&head, applied).await.unwrap();
    let during = CanonicalAssets::capture(&store).await.unwrap();
    assert_eq!(during.provenance(), old.provenance());
    pending.commit().await.unwrap();
    let new = CanonicalAssets::capture(&store).await.unwrap();
    assert_ne!(new.provenance().id(), old.provenance().id());
    assert_eq!(&*new.resolve(&url).await.unwrap().bytes, b"new");
    assert_eq!(&*old.resolve(&url).await.unwrap().bytes, b"old");
    let Provenance::Canonical(identity) = new.provenance() else {
        panic!("canonical provenance")
    };
    assert_eq!(identity.epoch, 1);
    assert_eq!(
        identity.ledger_root,
        store.head().await.unwrap().ledger_root
    );
    let chain = store.chain().clone();
    store.close().await;
    let reopened = CanonicalStore::open(&path, &chain).await.unwrap();
    let restored = CanonicalAssets::capture(&reopened).await.unwrap();
    assert_eq!(restored.provenance(), new.provenance());
    assert_eq!(&*restored.resolve(&url).await.unwrap().bytes, b"new");
    // A retained immutable read remains usable after its store is closed.
    assert_eq!(&*old.resolve(&url).await.unwrap().bytes, b"old");
    reopened.close().await;
}
#[tokio::test]
async fn public_browser_enforces_modes_visibility_binding_and_allocation_limits() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = initial();
    for variant in [
        "ok",
        "sealed",
        "opaque",
        "slot",
        "key",
        "encoding",
        "hash",
        "size",
        "inflated",
        "future",
        "expired",
        "tombstone",
        "revoked",
        "override",
        "fallback",
        "missing",
        "large_meta",
    ] {
        let path = format!("/{variant}");
        let mut m = asset(&mut state, "circle", &path, b"hello");
        match variant {
            "sealed" => m.body_mode = ResourceMode::Sealed,
            "opaque" => m.metadata_mode = MetadataMode::Opaque,
            "slot" => m.locator_mode = LocatorMode::Slot,
            "key" => m.key_id = Some(b"secret".to_vec()),
            "encoding" => m.encoding = b"gzip".to_vec(),
            "hash" => m.blob_hash = b"wrong".to_vec(),
            "size" => m.size_bytes = MAX_ASSET_BYTES as i64 + 1,
            "future" => m.activate_after_epoch = Some(2),
            "expired" => m.expire_after_epoch = Some(0),
            "tombstone" | "revoked" => policy(
                &mut state,
                b"circle",
                &format!(
                    "slot_policy:{}:{variant}",
                    String::from_utf8_lossy(&m.path_key)
                ),
                " YES\n",
            ),
            "override" => {
                m.activate_after_epoch = Some(2);
                policy(
                    &mut state,
                    b"circle",
                    &format!(
                        "slot_policy:{}:activate_after_epoch",
                        String::from_utf8_lossy(&m.path_key)
                    ),
                    "0",
                );
            }
            "fallback" => policy(
                &mut state,
                b"circle",
                &format!("mailbox:{}:revoked", String::from_utf8_lossy(&m.path_key)),
                "true",
            ),
            _ => (),
        }
        write_meta(&mut state, b"circle", &m);
        let path = [
            b"circles".as_slice(),
            b"circle",
            b"assets",
            b"by_hash",
            &m.path_key,
            b"body_b64",
        ];
        if variant == "inflated" {
            state.set(&path, vec![b'A'; 1024]).unwrap();
        }
        if variant == "missing" {
            state.remove(&path).unwrap();
        }
        if variant == "large_meta" {
            state
                .set(
                    &[
                        b"circles",
                        b"circle",
                        b"assets",
                        b"by_hash",
                        &m.path_key,
                        b"meta",
                    ],
                    vec![b' '; 65537],
                )
                .unwrap();
        }
    }
    let store = create(&dir.path().join("chain.db"), &state).await;
    let resolver = CanonicalAssets::capture(&store).await.unwrap();
    for variant in ["ok", "override"] {
        assert_eq!(
            &*resolver
                .resolve(&OctUrl::parse(&format!("oct://circle/{variant}")).unwrap())
                .await
                .unwrap()
                .bytes,
            b"hello"
        );
    }
    for variant in ["sealed", "opaque", "slot", "key"] {
        assert!(
            matches!(
                resolver
                    .resolve(&OctUrl::parse(&format!("oct://circle/{variant}")).unwrap())
                    .await,
                Err(Error::Sealed)
            ),
            "{variant}"
        );
    }
    for variant in [
        "future",
        "expired",
        "tombstone",
        "revoked",
        "fallback",
        "missing",
    ] {
        assert!(
            matches!(
                resolver
                    .resolve(&OctUrl::parse(&format!("oct://circle/{variant}")).unwrap())
                    .await,
                Err(Error::NotFound)
            ),
            "{variant}"
        );
    }
    for variant in ["size", "inflated", "large_meta"] {
        assert!(
            matches!(
                resolver
                    .resolve(&OctUrl::parse(&format!("oct://circle/{variant}")).unwrap())
                    .await,
                Err(Error::TooLarge)
            ),
            "{variant}"
        );
    }
    for variant in ["encoding", "hash"] {
        assert!(
            matches!(
                resolver
                    .resolve(&OctUrl::parse(&format!("oct://circle/{variant}")).unwrap())
                    .await,
                Err(Error::Invalid(_))
            ),
            "{variant}"
        );
    }
    store.close().await;
}
#[tokio::test]
async fn inconsistent_committed_epoch_cannot_issue_browser_provenance() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = initial();
    state.set(&[b"meta", b"last_epoch"], b"7".to_vec()).unwrap();
    let store = create(&dir.path().join("chain.db"), &state).await;
    assert!(CanonicalAssets::capture(&store).await.is_err());
    store.close().await;
}

fn application_browser(
    assets: CanonicalAssets,
    host: std::sync::Arc<browser_host::Host>,
) -> octra_browser::http::Browser {
    let chain = host.store.chain().clone();
    let profile = circle_host::view_profile(&assets, browser_host::profile());
    let execution = octra_node_runtime::circle_application::CanonicalApplications::new(
        assets.clone(),
        circle_host::runtime(),
        profile,
    )
    .with_wallet(std::sync::Arc::new(
        octra_node_runtime::browser_wallet::Wallet::new(
            host,
            std::sync::Arc::new(browser_host::DevelopmentSigner),
            octra_node_runtime::browser_wallet::Policy {
                chain,
                max_amount: 10.into(),
                max_ou: 1000.into(),
            },
        )
        .unwrap(),
    ));
    octra_browser::http::Browser::new(std::sync::Arc::new(assets), "/apps")
        .unwrap()
        .with_application(std::sync::Arc::new(execution))
        .unwrap()
}

// Served only by the explicit Chromium qualification runner. Never part of the
// default test run, and contains only public synthetic data in a temporary DB.
#[tokio::test]
#[ignore = "launched by scripts/node-port/test-circle-browser.mjs"]
async fn browser_fixture() {
    use octra_browser::http::Browser;
    use octra_node_protocol::consensus::codec::Wire;
    use octra_node_runtime::finality::{ExecutedEpoch, Publisher};
    use std::sync::Arc;
    let Some(report) = std::env::var_os("OCTRA_BROWSER_FIXTURE_FILE") else {
        panic!("fixture output path required")
    };
    let dir = tempfile::tempdir().unwrap();
    let mut state = initial();
    let circle = format!("oct{}", "1".repeat(44));
    let octb_circle = format!("oct{}", "3".repeat(44));
    browser_host::fund(&mut state);
    let page=br#"<!doctype html><html><head><link rel="stylesheet" href="style.css"></head><body><h1 id="title">Committed Circle</h1><img id="image" src="image.svg"><p><a id="next" href="oct://two/about#section">Visit second Circle</a></p><script>document.body.dataset.hacked='true'</script></body></html>"#;
    asset(&mut state, "one", "/docs/index.html", page);
    let mut style = asset(
        &mut state,
        "one",
        "/docs/style.css",
        b"h1{color:rgb(20,100,160)}",
    );
    style.content_type = b"text/css".to_vec();
    write_meta(&mut state, b"one", &style);
    let mut image=asset(&mut state,"one","/docs/image.svg",br#"<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24"><rect width="24" height="24" fill="green"/></svg>"#);
    image.content_type = b"image/svg+xml".to_vec();
    write_meta(&mut state, b"one", &image);
    asset(
        &mut state,
        "two",
        "/about",
        br#"<h1>Second Circle</h1><p id="section">Reached through oct://</p>"#,
    );
    if let Some(path) = std::env::var_os("OCTRA_BROWSER_NATIVE_SITE_FILE") {
        circle_host::install_counter(&mut state, circle.as_bytes(), b"4");
        circle_host::install_octb_counter(&mut state, octb_circle.as_bytes());
        let site: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        for (name, typ) in [
            ("index.html", "text/html"),
            ("app.js", "text/javascript"),
            ("style.css", "text/css"),
        ] {
            let bytes = STANDARD.decode(site[name].as_str().unwrap()).unwrap();
            for target in [&circle, &octb_circle] {
                let mut meta = asset(&mut state, target, &format!("/{name}"), &bytes);
                meta.content_type = typ.as_bytes().to_vec();
                write_meta(&mut state, target.as_bytes(), &meta);
            }
        }
    }
    let store = Arc::new(create(&dir.path().join("chain.db"), &state).await);
    let authority = finality_host::Authority {
        seed: 1,
        chain: store.chain().clone(),
    };
    let publisher = Publisher::open(store.clone(), authority.clone())
        .await
        .unwrap();
    let old = CanonicalAssets::capture(&store).await.unwrap();
    let (head, mut state) = store.snapshot().await.unwrap();
    state.begin().unwrap();
    state.set(&[b"meta", b"last_epoch"], b"1".to_vec()).unwrap();
    let mut style = asset(
        &mut state,
        "one",
        "/docs/style.css",
        b"h1{color:rgb(140,20,30)}",
    );
    style.content_type = b"text/css".to_vec();
    write_meta(&mut state, b"one", &style);
    let executed = ExecutedEpoch {
        epoch_observation: None,
        metrics: octra_node_protocol::metrics::Epoch::default(),
        vm_receipts: std::collections::BTreeMap::default(),
        reward_source: finality_host::reward_source(authority.seed),
        state: state.snapshot(),
        transactions: vec![],
        consensus_receipts: vec![],
        date: 1,
        message: b"browser fixture".to_vec(),
    };
    let certificate = finality_host::certificate(&head, &executed, &authority)
        .encode()
        .unwrap();
    publisher
        .prepare(&head, &certificate, executed)
        .await
        .unwrap()
        .commit()
        .await
        .unwrap();
    publisher.audit().await.unwrap();
    let new = CanonicalAssets::capture(&store).await.unwrap();
    let host = Arc::new(browser_host::Host {
        store: store.clone(),
        authority,
        writing: tokio::sync::Mutex::new(()),
        calls: std::sync::Mutex::default(),
        pending: std::sync::Mutex::default(),
    });
    let applications = application_browser(new.clone(), host.clone());
    let old = Browser::new(Arc::new(old), "/old").unwrap();
    let new = Browser::new(Arc::new(new), "/new").unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let home = OctUrl::parse("oct://one/docs/").unwrap();
    std::fs::write(report,serde_json::to_vec(&json!({"old":format!("{origin}{}",old.view_url(&home)),"new":format!("{origin}{}",new.view_url(&home)),"application":format!("{origin}{}", applications.view_url(&OctUrl::parse(&format!("oct://{circle}/")).unwrap())),"octb_application":format!("{origin}/fixture-octb"),"stats":format!("{origin}/fixture-stats"),"circle":circle,"octb_circle":octb_circle,"wallet":std::str::from_utf8(&browser_host::address()).unwrap()})).unwrap()).unwrap();
    let refresh_host = host.clone();
    let app = axum::Router::new()
        .nest("/old", old.router())
        .nest("/new", new.router())
        .nest("/apps", applications.router())
        .route("/fixture-octb", axum::routing::get(move || {
            let host = refresh_host.clone();
            async move {
                // Open another app at the current committed head. Retained
                // browser sessions keep their original snapshot and wallet guard.
                let assets = CanonicalAssets::capture(&host.store).await.unwrap();
                let browser = application_browser(assets, host);
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let url = format!("http://{}{}", listener.local_addr().unwrap(), browser.view_url(
                    &OctUrl::parse(&format!("oct://oct{}/", "3".repeat(44))).unwrap()));
                let _server = tokio::spawn(async move {
                    let app = axum::Router::new().nest("/apps", browser.router());
                    axum::serve(listener, app).await.unwrap();
                });
                axum::Json(json!({"url":url}))
            }
        }))
        .route(
            "/fixture-stats",
            axum::routing::get(move || {
                let host = host.clone();
                async move {
                    use octra_browser::application::{ApplicationHost, Context, ReadMethod, ReadRequest};
                    use octra_exex::{CommittedEpochSource, Sequence};
                    let assets = CanonicalAssets::capture(&host.store).await.unwrap();
                    let context = Context { circle_id:format!("oct{}", "1".repeat(44)),provenance:assets.provenance() };
                    let profile = circle_host::view_profile(&assets, browser_host::profile());
                    let applications = octra_node_runtime::circle_application::CanonicalApplications::new(assets,circle_host::runtime(),profile);
                    let count = applications.read(ReadRequest { context,method:ReadMethod::ProgramView,params:json!({"method":"get_counter","params":[]}) }).await;
                    let octb_count = applications.read(ReadRequest { context:Context {circle_id:format!("oct{}", "3".repeat(44)),provenance:applications.provenance()},method:ReadMethod::ProgramView,params:json!({"method":"get_counter","params":[]}) }).await;
                    let source = host.store.source();
                    let head = source.head().await.unwrap();
                    let events = source.load(Sequence(head.sequence.0)).await.unwrap().unwrap().events.clone();
                    let state = host.store.snapshot().await.unwrap().1;
                    let account = octra_node_runtime::account_store::load(&state,&browser_host::address()).unwrap().unwrap();
                    axum::Json(json!({"calls":*host.calls.lock().unwrap(),"count":count.ok(),"octb_count":octb_count.ok(),"epoch":head.epoch.0,"balance":account.balance.to_string(),"nonce":account.nonce.get(),"exex":events,"supply":octra_node_runtime::account_store::ledger(&state).unwrap().total_supply().to_string(),"proposer_reward":octra_node_runtime::account_store::load(&state,b"validator-0").unwrap().map(|a|a.balance.to_string())}))
                }
            }),
        );
    axum::serve(listener, app).await.unwrap();
}
