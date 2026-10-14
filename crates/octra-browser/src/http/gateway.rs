//! Read-only HTTPS facade for ordinary tailnet HTTP clients. TLS and tailnet
//! admission belong to the reverse proxy; mount only on its loopback backend.
use super::{failure, resolved_asset, Browser};
use crate::{AssetResolver, Error, OctUrl, Provenance};
use axum::{
    extract::{OriginalUri, State},
    http::{header, HeaderMap, Uri},
    response::Response,
    routing::get,
    Router,
};
use std::sync::Arc;

#[derive(Clone)]
pub struct Gateway {
    browser: Browser,
    origin: String,
}

impl Gateway {
    pub fn validate_origin(origin: &str) -> Result<(), Error> {
        let uri: Uri = origin
            .parse()
            .map_err(|_| Error::Invalid("invalid gateway origin".into()))?;
        let authority = uri
            .authority()
            .ok_or_else(|| Error::Invalid("gateway host required".into()))?;
        let host = authority.host();
        if uri.scheme_str() != Some("https")
            || uri.path_and_query().is_some_and(|p| p.as_str() != "/")
            || origin != format!("https://{host}")
            || authority.port().is_some()
            || host.len() > 253
            || !host.contains('.')
            || host.split('.').any(|part| {
                part.is_empty()
                    || part.len() > 63
                    || part.starts_with('-')
                    || part.ends_with('-')
                    || !part
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            })
        {
            return Err(Error::Invalid(
                "gateway requires a canonical HTTPS DNS origin on port 443".into(),
            ));
        }
        Ok(())
    }

    pub fn new(resolver: Arc<dyn AssetResolver>, origin: &str) -> Result<Self, Error> {
        Self::validate_origin(origin)?;
        let browser = Browser::new(resolver, "")?;
        if !matches!(browser.provenance, Provenance::Canonical(_)) {
            return Err(Error::Invalid(
                "gateway requires a canonical snapshot".into(),
            ));
        }
        Ok(Self {
            browser,
            origin: origin.into(),
        })
    }

    pub fn router(self) -> Router {
        Router::new()
            .route("/circles/:circle", get(serve))
            .route("/circles/:circle/", get(serve))
            .route("/circles/:circle/*path", get(serve))
            .route("/snapshots/:scope/:circle/", get(serve))
            .route("/snapshots/:scope/:circle/*path", get(serve))
            .with_state(self)
    }
}

async fn serve(
    State(gateway): State<Gateway>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
) -> Response {
    // Never infer authority from Forwarded/X-Forwarded-* or the request URL.
    let expected = gateway
        .origin
        .strip_prefix("https://")
        .expect("validated origin");
    let hosts = headers.get_all(header::HOST).iter().collect::<Vec<_>>();
    if hosts.len() != 1
        || !hosts[0].to_str().is_ok_and(|host| {
            host.eq_ignore_ascii_case(expected)
                || host.eq_ignore_ascii_case(&format!("{expected}:443"))
        })
    {
        return failure(&Error::Invalid("unexpected gateway Host".into()));
    }
    let raw = uri.to_string();
    let pinned = format!("/snapshots/{}/", gateway.browser.scope);
    let Some(path) = raw
        .strip_prefix("/circles/")
        .or_else(|| raw.strip_prefix(&pinned))
    else {
        return failure(&Error::SnapshotChanged);
    };
    let url = match OctUrl::parse(&format!("oct://{path}")) {
        Ok(url) => url,
        Err(error) => return failure(&error),
    };
    resolved_asset(gateway.browser, gateway.origin, url, false, true).await
}
