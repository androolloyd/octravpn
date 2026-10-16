//! Serve only manifest-committed files from a fully verified native package.
use super::{package, Authority};
use anyhow::{ensure, Result};
use axum::{
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, Query, State},
    http::{header, HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use octra_node_runtime::ledger_image::Limits;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{net::SocketAddr, path::Path, sync::Arc};
use tokio::sync::{watch, Semaphore};

struct Service {
    package: package::VerifiedPackage,
    raw: Bytes,
    capacity: Arc<Semaphore>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChunkQuery {
    snapshot: String,
    path: String,
    index: String,
    sha256: String,
}

/// The package is authenticated and all file commitments are checked before
/// binding. A reverse proxy can supply TLS; no unrelated local files are routed.
pub async fn serve(
    authority: &Authority,
    directory: &Path,
    limits: Limits,
    bind: SocketAddr,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let directory = std::fs::canonicalize(directory)?;
    let network = authority.network().clone();
    let mut package = tokio::task::spawn_blocking(move || {
        package::verify(&Authority::new(network)?, &directory, limits)
    })
    .await??;
    let raw = Bytes::from(std::mem::take(&mut package.raw));
    let service = Arc::new(Service {
        package,
        raw,
        capacity: Arc::new(Semaphore::new(8)),
    });
    let routes = Router::new()
        .route("/state-sync/manifest", get(manifest))
        .route("/state-sync/chunk", get(chunk))
        .layer(DefaultBodyLimit::max(0))
        .with_state(service);
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, routes)
        .with_graceful_shutdown(async move {
            let _ = shutdown.wait_for(|value| *value).await;
        })
        .await?;
    Ok(())
}
fn fresh(service: &Service) -> bool {
    super::super::now().is_ok_and(|now| service.package.certificate.certificate().fresh(now))
}
async fn manifest(State(service): State<Arc<Service>>) -> Response {
    if !fresh(&service) {
        return StatusCode::GONE.into_response();
    }
    let mut response = service.raw.clone().into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    let hash = &service.package.certificate.draft().manifest_hash;
    if insert(&mut response, "x-octra-manifest-sha256", hash).is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    response
}
async fn chunk(State(service): State<Arc<Service>>, Query(query): Query<ChunkQuery>) -> Response {
    if !fresh(&service) {
        return StatusCode::GONE.into_response();
    }
    let draft = service.package.certificate.draft();
    if query.snapshot.as_bytes() != draft.manifest.snapshot_id
        || query.path.len() > 1024
        || query.sha256.len() != 64
        || query.index.len() > 20
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Ok(index) = query.index.parse::<usize>() else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if index.to_string() != query.index {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let Some(file) = draft
        .manifest
        .files
        .iter()
        .find(|file| file.path == query.path.as_bytes())
    else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(descriptor) = file
        .chunks
        .get(index)
        .filter(|chunk| chunk.index == index as i64 && chunk.sha256 == query.sha256.as_bytes())
        .cloned()
    else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Ok(permit) = service.capacity.clone().try_acquire_owned() else {
        return (StatusCode::TOO_MANY_REQUESTS, [(header::RETRY_AFTER, "3")]).into_response();
    };
    let expected_size = file.size;
    let owned = service.clone();
    let path = file.path.clone();
    let chunk = descriptor.clone();
    let result = tokio::task::spawn_blocking(move || {
        let file = owned
            .package
            .files
            .get(&path)
            .ok_or_else(|| anyhow::anyhow!("verified snapshot file missing"))?;
        ensure!(
            file.metadata()?.len() == expected_size as u64,
            "snapshot file length changed"
        );
        let mut bytes = vec![0; usize::try_from(chunk.size)?];
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileExt;
            let mut offset = 0;
            while offset < bytes.len() {
                let n = file.read_at(&mut bytes[offset..], chunk.offset as u64 + offset as u64)?;
                ensure!(n != 0, "snapshot chunk truncated");
                offset += n;
            }
        }
        #[cfg(not(unix))]
        anyhow::bail!("positional snapshot reads require Unix");
        ensure!(
            hex::encode(Sha256::digest(&bytes)).as_bytes() == chunk.sha256,
            "snapshot chunk bytes changed"
        );
        Ok::<_, anyhow::Error>((Bytes::from(bytes), permit))
    })
    .await;
    let (bytes, permit) = match result {
        Ok(Ok(pair)) => pair,
        other => {
            let _ = other;
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    if !fresh(&service) {
        return StatusCode::GONE.into_response();
    }
    let length = bytes.len();
    // Keep the capacity lease until the body is consumed or disconnected,
    // rather than releasing it when response headers become ready.
    let stream =
        futures::stream::unfold((bytes, 0, permit), |(bytes, offset, permit)| async move {
            if offset == bytes.len() {
                return None;
            }
            let end = (offset + 65_536).min(bytes.len());
            Some((
                Ok::<_, std::io::Error>(bytes.slice(offset..end)),
                (bytes, end, permit),
            ))
        });
    let mut response = Body::from_stream(stream).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    let headers = [
        ("x-octra-chunk-sha256", descriptor.sha256.as_slice()),
        ("x-octra-manifest-sha256", draft.manifest_hash.as_slice()),
        ("x-octra-snapshot", draft.manifest.snapshot_id.as_slice()),
        ("x-octra-chunk-index", query.index.as_bytes()),
    ];
    for (name, value) in headers {
        if insert(&mut response, name, value).is_err() {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }
    if insert(
        &mut response,
        "content-length",
        length.to_string().as_bytes(),
    )
    .is_err()
    {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    response
}
fn insert(response: &mut Response, name: &'static str, value: &[u8]) -> Result<()> {
    response.headers_mut().insert(
        HeaderName::from_static(name),
        HeaderValue::from_bytes(value)?,
    );
    Ok(())
}
