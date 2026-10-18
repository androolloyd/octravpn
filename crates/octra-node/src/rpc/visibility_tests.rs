//! Real canonical fixture plus the actual RPC/gRPC/HTTP dispatch boundaries.
//! The manually held visibility owner isolates the apply interval; it grants
//! neither a publication nor a transaction receipt.
use super::*;
use crate::rpc::{grpc, native};
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use octra_node_protocol::grpc::proto;
use tokio::sync::oneshot;

#[test]
fn read_inventory_excludes_effects_compute_unknown_and_fixture_aliases() {
    let methods = native::read_methods::METHODS;
    let fixture: Value =
        serde_json::from_str(include_str!("native/read_dispatch_native.json")).unwrap();
    assert_eq!(
        fixture["source_pin"],
        "7f9be4489870645cfcc95439638cde40f5da9f50"
    );
    assert_eq!(
        fixture["methods"]
            .as_array()
            .unwrap()
            .iter()
            .map(|name| name.as_str().unwrap().as_bytes())
            .collect::<Vec<_>>(),
        methods
    );
    assert_eq!(methods.len(), 205);
    assert!(methods.windows(2).all(|pair| pair[0] < pair[1]));
    for name in [
        b"node_version".as_slice(),
        b"contract_saveAbi",
        b"circle_storage_auth",
        b"octra_circleAssetCiphertextByStateRefAuth",
        b"octra_recommendedFee",
    ] {
        assert!(native::read_methods::contains(name));
    }
    for name in [
        b"octra_submit".as_slice(),
        b"octra_submitBatch",
        b"octra_privateTransfer",
        b"staging_remove",
        b"octra_registerPublicKey",
        b"octra_registerPvacPubkey",
        b"octra_circleComputeSubmit",
        b"octra_circleComputeStatus",
        b"octra_circleComputeCancel",
        b"not_a_method",
        b"circle_program",
        b"octra_head",
    ] {
        assert!(!native::read_methods::contains(name));
    }
}

#[tokio::test]
async fn actual_rpc_and_grpc_reads_wait_while_unknown_and_effects_do_not() {
    let fixture = Box::pin(Fixture::new(None)).await;
    let rpc = Rpc::open(&fixture, fixture.native.clone()).await;
    let context = rpc.context.clone();
    let visibility = fixture.node.shared.visibility();
    let apply = visibility.begin().unwrap();
    // Unknown names and malformed writes are dispatched once immediately,
    // even while a canonical apply is active.
    assert_eq!(
        native::invoke(&context, b"not_a_method", b"[]")
            .await
            .unwrap_err()
            .code,
        -32601
    );
    assert_eq!(
        native::invoke(&context, b"octra_submit", b"[]")
            .await
            .unwrap_err()
            .code,
        -32602
    );
    let reading = native::invoke(&context, b"node_version", b"[]");
    tokio::pin!(reading);
    tokio::select! {
        biased;
        _ = &mut reading => panic!("RPC read escaped visibility"),
        () = tokio::task::yield_now() => (),
    }
    // Empty protobuf Status request maps through the exact same native invoke.
    let grpc_read = grpc::invoke(&context, proto::STATUS, b"");
    tokio::pin!(grpc_read);
    tokio::select! {
        biased;
        _ = &mut grpc_read => panic!("gRPC read escaped visibility"),
        () = tokio::task::yield_now() => (),
    }
    drop(apply);
    assert!(reading.await.is_ok());
    assert!(grpc_read.await.is_ok());
    rpc.close().await;
}

#[tokio::test]
async fn real_http_stable_routes_wait_but_metrics_and_wrong_verb_do_not() {
    let fixture = Box::pin(Fixture::new(None)).await;
    let rpc = Rpc::open(&fixture, fixture.native.clone()).await;
    let apply = fixture.node.shared.visibility().begin().unwrap();
    for path in ["/", "/status", "/state-sync/head", "/state-sync/range"] {
        let reading = crate::rpc::http::handle(
            axum::extract::State(rpc.context.clone()),
            Request::builder().uri(path).body(Body::empty()).unwrap(),
        );
        tokio::pin!(reading);
        tokio::select! {
            biased;
            _ = &mut reading => panic!("stable HTTP read escaped visibility: {path}"),
            () = tokio::task::yield_now() => (),
        }
    }
    let metrics = crate::rpc::http::handle(
        axum::extract::State(rpc.context.clone()),
        Request::builder()
            .uri("/metrics")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(metrics.status(), StatusCode::OK);
    let wrong_verb = crate::rpc::http::handle(
        axum::extract::State(rpc.context.clone()),
        Request::builder()
            .method("POST")
            .uri("/status")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(wrong_verb.status(), StatusCode::NOT_FOUND);
    drop(apply);
    let response = crate::rpc::http::handle(
        axum::extract::State(rpc.context.clone()),
        Request::builder()
            .uri("/status")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    rpc.close().await;
}

#[tokio::test]
async fn real_tcp_rpc_waits_for_owned_apply() {
    let fixture = Box::pin(Fixture::new(None)).await;
    let rpc = Rpc::open(&fixture, fixture.native.clone()).await;
    let context = rpc.context.clone();
    let apply = fixture.node.shared.visibility().begin().unwrap();
    let (entered, entering) = oneshot::channel();
    let entered = Arc::new(std::sync::Mutex::new(Some(entered)));
    let app = crate::rpc::router(context).layer(axum::middleware::from_fn(
        move |request: Request<Body>, next: axum::middleware::Next| {
            let entered = entered.clone();
            async move {
                if let Some(entered) = entered.lock().unwrap().take() {
                    let _ = entered.send(());
                }
                next.run(request).await
            }
        },
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/rpc", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let response = tokio::spawn(async move {
        reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .post(url)
            .timeout(Duration::from_secs(10))
            .json(&json!({"jsonrpc":"2.0","id":99,"method":"node_version","params":[]}))
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap()
    });
    entering.await.unwrap();
    assert!(!response.is_finished());
    drop(apply);
    assert_eq!(response.await.unwrap()["id"], 99);
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
    rpc.close().await;
}
