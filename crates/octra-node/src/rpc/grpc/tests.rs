//! Real HTTP/2 flow control and trailers, without a wallet or public network.
use super::*;
use std::time::Duration;
use tokio::{sync::oneshot, task::JoinHandle};

struct Pair {
    send: h2::client::SendRequest<Bytes>,
    client: JoinHandle<()>,
    server: JoinHandle<()>,
    completed: oneshot::Receiver<std::result::Result<(), String>>,
}
impl Drop for Pair {
    fn drop(&mut self) {
        self.client.abort();
        self.server.abort();
    }
}
async fn pair(body: Option<Vec<u8>>, status: Status, deadline: Duration) -> Pair {
    let (client_io, server_io) = tokio::io::duplex(16_384);
    let (completed, done) = oneshot::channel();
    let server = tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_io).await.unwrap();
        let mut tasks = JoinSet::new();
        let mut first = Some((body, status, completed));
        loop {
            tokio::select! {
                Some(result)=tasks.join_next()=>{result.unwrap();},
                request=connection.accept()=>{
                    let Some(request)=request else {break};
                    let (_, respond)=request.unwrap();
                    let (body,status,completed)=first.take().expect("one request fixture");
                    let mut config=Config::capture(|name|(name=="OCTRA_GRPC_ENABLE").then(||b"1".to_vec())).unwrap().unwrap();
                    config.max_deadline=deadline;
                    tasks.spawn(async move {
                        let result=reply(respond,body,status,&config).await.map_err(|error|error.to_string());
                        let _=completed.send(result);
                    });
                }
            }
        }
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    });
    let (send, connection) = h2::client::Builder::new()
        .initial_window_size(1024)
        .handshake::<_, Bytes>(client_io)
        .await
        .unwrap();
    let client = tokio::spawn(async move {
        let _ = connection.await;
    });
    Pair {
        send,
        client,
        server,
        completed: done,
    }
}

#[tokio::test]
async fn unary_reply_honors_small_windows_and_delivers_exact_native_trailers() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let body = (0..131_072).map(|n| (n % 251) as u8).collect::<Vec<_>>();
        let mut pair = pair(
            Some(body.clone()),
            Status::new(0, b""),
            Duration::from_secs(3),
        )
        .await;
        let request = Request::builder()
            .method("POST")
            .uri("https://localhost/grpc.health.v1.Health/Check")
            .body(())
            .unwrap();
        let (response, _) = pair.send.send_request(request, true).unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-type"], "application/grpc+proto");
        let mut response = response.into_body();
        let mut raw = Vec::new();
        while let Some(part) = response.data().await {
            let part = part.unwrap();
            raw.extend_from_slice(&part);
            response
                .flow_control()
                .release_capacity(part.len())
                .unwrap();
        }
        assert_eq!(grpc::unframe(&raw, body.len()).unwrap(), body);
        let trailers = response.trailers().await.unwrap().unwrap();
        assert_eq!(trailers["grpc-status"], "0");
        assert!(!trailers.contains_key("grpc-message"));
        (&mut pair.completed).await.unwrap().unwrap();
    })
    .await
    .expect("bounded in-memory HTTP/2 exchange");
}

#[tokio::test]
async fn a_reader_that_never_releases_capacity_cannot_retain_the_response_worker() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut pair = pair(
            Some(vec![7; 262_144]),
            Status::new(0, b""),
            Duration::from_millis(100),
        )
        .await;
        let request = Request::builder()
            .method("POST")
            .uri("https://localhost/octra.node.v1.Node/Status")
            .body(())
            .unwrap();
        let (response, _) = pair.send.send_request(request, true).unwrap();
        let mut body = response.await.unwrap().into_body();
        // Do not consume DATA until the response worker has reached its bounded
        // deadline. The 1 KiB stream window cannot buffer the 256 KiB reply.
        (&mut pair.completed).await.unwrap().unwrap();
        let mut received = 0;
        let reset = loop {
            match body.data().await {
                Some(Ok(bytes)) => received += bytes.len(),
                Some(Err(error)) => break error.reason(),
                None => panic!("unread oversized response completed without a reset"),
            }
        };
        assert_eq!(reset, Some(Reason::CANCEL));
        assert!(received < 262_144);
    })
    .await
    .expect("slow reader must release server work");
}
