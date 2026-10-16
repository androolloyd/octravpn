// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Optional loopback native unary gRPC. HTTP/2 flow control and stream resets
//! remain explicit so slow response readers cannot retain an unbounded lease.
use super::{native, Context};
use anyhow::{Context as _, Result};
use axum::{
    body::Bytes,
    http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode},
};
use h2::{
    server::{self, SendResponse},
    Reason, RecvStream, SendStream,
};
use octra_node_protocol::{
    grpc::{self, proto, Config, Status},
    network::endpoint::native_trim,
};
use std::{future::poll_fn, sync::Arc};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{watch, Semaphore},
    task::JoinSet,
};
#[cfg(test)]
mod tests;

pub(crate) struct Service {
    listener: TcpListener,
    config: Config,
    host: Arc<Context>,
}
impl Service {
    pub(crate) async fn bind(config: Config, host: Arc<Context>) -> Result<Self> {
        anyhow::ensure!(config.listen.ip().is_loopback(), "gRPC requires loopback");
        Ok(Self {
            listener: TcpListener::bind(config.listen).await?,
            config,
            host,
        })
    }
    pub(crate) async fn run(self, mut stop: watch::Receiver<bool>) -> Result<()> {
        let connections = Arc::new(Semaphore::new(128));
        let submit = Arc::new(Semaphore::new(1));
        let mut tasks = JoinSet::new();
        let mut attempt = 0;
        let mut next_accept = tokio::time::Instant::now();
        loop {
            let connection_stop = stop.clone();
            tokio::select! {
                _=stop.wait_for(|value|*value)=>break,
                Some(_)=tasks.join_next()=>(),
                accepted=async {tokio::time::sleep_until(next_accept).await;self.listener.accept().await}=>{
                    let (socket,_)=match accepted {
                        Ok(socket)=>{attempt=0;next_accept=tokio::time::Instant::now();socket},
                        Err(error)=>match octra_node_protocol::network::accept::delay(attempt,&error) {
                            Some(delay)=>{attempt=(attempt+1).min(7);next_accept=tokio::time::Instant::now()+delay;continue;},
                            None=>return Err(error.into()),
                        },
                    };
                    let Ok(lease)=connections.clone().try_acquire_owned() else {drop(socket);continue;};
                    let (config,host,shutdown,submit)=(self.config.clone(),self.host.clone(),connection_stop,submit.clone());
                    tasks.spawn(async move{let _lease=lease;let _=connection(socket,host,config,submit,shutdown).await;});
                }
            }
        }
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        Ok(())
    }
}
async fn connection(
    socket: TcpStream,
    host: Arc<Context>,
    config: Config,
    submit: Arc<Semaphore>,
    mut stop: watch::Receiver<bool>,
) -> Result<()> {
    let mut builder = server::Builder::new();
    builder
        .max_concurrent_streams(config.streams)
        .initial_window_size(65_535)
        .max_send_buffer_size(4096);
    let mut connection = tokio::select! {
        _=stop.wait_for(|value|*value)=>return Ok(()),
        connection=builder.handshake::<_,Bytes>(socket)=>connection?,
    };
    let streams = Arc::new(Semaphore::new(config.streams as usize));
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            _=stop.wait_for(|value|*value)=>break,
            Some(_)=tasks.join_next()=>(),
            accepted=connection.accept()=>{
                let Some(accepted)=accepted else {break;};let (request,mut respond)=accepted?;
                let Ok(lease)=streams.clone().try_acquire_owned() else {respond.send_reset(Reason::REFUSED_STREAM);continue;};
                let (host,config,submit)=(host.clone(),config.clone(),submit.clone());
                tasks.spawn(async move{let _lease=lease;let _=handle(host,config,submit,request,respond).await;});
            }
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}
fn headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        "content-type",
        HeaderValue::from_static("application/grpc+proto"),
    );
    headers.insert("grpc-accept-encoding", HeaderValue::from_static("identity"));
    headers
}
fn header(headers: &HeaderMap, name: &str) -> Option<Vec<u8>> {
    headers
        .get(name)
        .map(|value| native_trim(value.as_bytes()).to_ascii_lowercase())
}
async fn deliver(
    stream: &mut SendStream<Bytes>,
    body: Option<Vec<u8>>,
    status: Status,
) -> Result<()> {
    if let Some(body) = body {
        let mut wire = Bytes::from(grpc::frame(&body));
        while !wire.is_empty() {
            stream.reserve_capacity(wire.len().min(4096));
            let capacity = poll_fn(|cx| stream.poll_capacity(cx))
                .await
                .context("gRPC stream closed")??;
            if capacity == 0 {
                continue;
            }
            let count = wire.len().min(capacity).min(4096);
            stream.send_data(wire.split_to(count), false)?;
        }
    }
    let mut trailers = HeaderMap::new();
    for (name, value) in status.trailers() {
        trailers.insert(name, HeaderValue::from_str(&value)?);
    }
    stream.send_trailers(trailers)?;
    Ok(())
}
async fn reply(
    mut respond: SendResponse<Bytes>,
    body: Option<Vec<u8>>,
    status: Status,
    config: &Config,
) -> Result<()> {
    let mut response = Response::new(());
    *response.headers_mut() = headers();
    let mut stream = respond.send_response(response, false)?;
    if let Ok(result) =
        tokio::time::timeout(config.max_deadline, deliver(&mut stream, body, status)).await
    {
        result
    } else {
        stream.send_reset(Reason::CANCEL);
        Ok(())
    }
}
async fn invoke(
    host: &Arc<Context>,
    path: &str,
    payload: &[u8],
) -> std::result::Result<Vec<u8>, Status> {
    let request = proto::decode(path, payload).map_err(|message| {
        Status::new(if proto::PATHS.contains(&path) { 3 } else { 12 }, message)
    })?;
    match request {
        proto::Request::Health(service) => {
            if service.is_empty()
                || service == b"grpc.health.v1.Health"
                || service == b"octra.node.v1.Node"
            {
                Ok(proto::serving())
            } else {
                Err(Status::new(5, b"service is not registered"))
            }
        }
        proto::Request::Call {
            method,
            params,
            page,
        } => {
            let result = native::invoke(host, method, &params)
                .await
                .map_err(Status::from_rpc)?;
            if page {
                proto::encode_page(&result).map_err(|reason| Status::new(13, reason))
            } else {
                Ok(proto::json(&result))
            }
        }
    }
}
async fn handle(
    host: Arc<Context>,
    config: Config,
    submit: Arc<Semaphore>,
    request: Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
) -> Result<()> {
    if request.method() != Method::POST {
        let mut response = Response::new(());
        *response.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
        respond.send_response(response, true)?;
        return Ok(());
    }
    let metadata = request.headers();
    let content_type = header(metadata, "content-type").unwrap_or_default();
    let media = native_trim(
        content_type
            .split(|b| *b == b';')
            .next()
            .unwrap_or_default(),
    );
    if !matches!(media, b"application/grpc" | b"application/grpc+proto") {
        let mut response = Response::new(());
        *response.status_mut() = StatusCode::UNSUPPORTED_MEDIA_TYPE;
        respond.send_response(response, true)?;
        return Ok(());
    }
    let path = request
        .uri()
        .path_and_query()
        .map_or("/", |value| value.as_str())
        .to_owned();
    let submitting = path == proto::SUBMIT;
    if submitting && config.submit_bytes.is_none() {
        return reply(
            respond,
            None,
            Status::new(12, b"submission is disabled"),
            &config,
        )
        .await;
    }
    let limit = if submitting {
        config.submit_bytes.unwrap_or(0)
    } else {
        config.request_bytes
    };
    let declared = metadata.get("content-length").map(|value| {
        value
            .to_str()
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
    });
    if declared.is_some_and(|length| length.is_none_or(|length| length > limit + 5)) {
        return reply(
            respond,
            None,
            Status::new(8, b"request body exceeds limit"),
            &config,
        )
        .await;
    }
    if !header(metadata, "te").is_some_and(|raw| {
        raw.split(|b| *b == b',')
            .any(|value| native_trim(value) == b"trailers")
    }) {
        return reply(
            respond,
            None,
            Status::new(3, b"te header must include trailers"),
            &config,
        )
        .await;
    }
    if header(metadata, "grpc-encoding").is_some_and(|value| value != b"identity") {
        return reply(
            respond,
            None,
            Status::new(12, b"message encoding is not supported"),
            &config,
        )
        .await;
    }
    let _submit = if submitting {
        match submit.try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(_) => {
                return reply(
                    respond,
                    None,
                    Status::new(8, b"submission is busy"),
                    &config,
                )
                .await
            }
        }
    } else {
        None
    };
    let deadline = match config.deadline(metadata.get("grpc-timeout").map(HeaderValue::as_bytes)) {
        Ok(value) => value,
        Err(status) => return reply(respond, None, status, &config).await,
    };
    let mut response = Response::new(());
    *response.headers_mut() = headers();
    let mut stream = respond.send_response(response, false)?;
    let work = async {
        let mut body = request.into_body();
        let mut raw = Vec::new();
        while let Some(bytes) = body.data().await {
            let bytes = bytes.map_err(|_| Status::new(13, b"request failed"))?;
            if bytes.len() > limit + 5 - raw.len() {
                return Err(Status::new(8, b"request body exceeds limit"));
            }
            raw.extend_from_slice(&bytes);
            body.flow_control()
                .release_capacity(bytes.len())
                .map_err(|_| Status::new(13, b"request failed"))?;
        }
        invoke(&host, &path, grpc::unframe(&raw, limit)?).await
    };
    let result = tokio::select! {
        _=poll_fn(|cx|stream.poll_reset(cx))=>return Ok(()),
        result=tokio::time::timeout(deadline,work)=>match result{Ok(result)=>result,Err(_)=>Err(Status::new(4,b"deadline exceeded"))},
    };
    let (body, status) = match result {
        Ok(body) if body.len() > config.response_bytes => {
            (None, Status::new(8, b"response message exceeds limit"))
        }
        Ok(body) => (Some(body), Status::new(0, b"")),
        Err(status) => (None, status),
    };
    if tokio::time::timeout(config.max_deadline, deliver(&mut stream, body, status))
        .await
        .is_err()
    {
        stream.send_reset(Reason::CANCEL);
    }
    Ok(())
}
