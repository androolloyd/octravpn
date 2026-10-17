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
use serde::{Deserialize, Deserializer, Serialize};
use std::{collections::BTreeSet, sync::Arc};

/// A bounded read capability for the unpaid onboarding website. It grants no
/// network carriage or application execution, and never accepts a wildcard.
#[derive(Clone, Debug, Serialize)]
pub struct Portal {
    circle: String,
    paths: BTreeSet<String>,
}

impl Portal {
    pub const MAX_PATHS: usize = 128;
    pub const MAX_PATH_BYTES: usize = 1024;

    pub fn new(circle: &str, paths: impl IntoIterator<Item = String>) -> Result<Self, Error> {
        Gateway::validate_site(circle)?;
        let mut allowed = BTreeSet::new();
        for path in paths {
            if allowed.len() >= Self::MAX_PATHS
                || !Self::canonical_asset(&path)
                || !allowed.insert(path)
            {
                return Err(Error::Invalid(
                    "portal requires at most 128 distinct canonical asset paths".into(),
                ));
            }
        }
        if !allowed.contains("/index.html") {
            return Err(Error::Invalid(
                "portal must explicitly allow /index.html".into(),
            ));
        }
        Ok(Self {
            circle: circle.into(),
            paths: allowed,
        })
    }

    pub fn circle(&self) -> &str {
        &self.circle
    }

    pub fn paths(&self) -> &BTreeSet<String> {
        &self.paths
    }

    fn canonical_asset(path: &str) -> bool {
        path.len() <= Self::MAX_PATH_BYTES
            && path.starts_with('/')
            && !path.ends_with('/')
            && path
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"/-._~".contains(&byte))
            && path[1..]
                .split('/')
                .all(|part| !part.is_empty() && !matches!(part, "." | ".."))
            && !matches!(
                path[1..].split('/').next(),
                Some(
                    "circles"
                        | "snapshots"
                        | "view"
                        | "asset"
                        | "document"
                        | "o"
                        | "site"
                        | "open"
                        | "rpc"
                        | "app"
                        | "admin"
                )
            )
    }

    fn target(&self, scope: &str, uri: &Uri) -> Result<OctUrl, Error> {
        if uri.scheme().is_some() || uri.authority().is_some() || uri.query().is_some() {
            return Err(Error::Invalid(
                "portal requires a canonical local asset URL without query".into(),
            ));
        }
        let path = uri.path();
        let path = if let Some(pinned) = path.strip_prefix("/snapshots/") {
            let pinned = pinned
                .strip_prefix(scope)
                .and_then(|rest| rest.strip_prefix('/'))
                .ok_or(Error::SnapshotChanged)?;
            pinned
                .strip_prefix(&self.circle)
                .filter(|rest| rest.starts_with('/'))
                .ok_or(Error::NotFound)?
        } else if let Some(circle) = path.strip_prefix("/circles/") {
            circle
                .strip_prefix(&self.circle)
                .filter(|rest| rest.starts_with('/'))
                .ok_or(Error::NotFound)?
        } else {
            path
        };
        let path = if path == "/" { "/index.html" } else { path };
        if !Self::canonical_asset(path) || !self.paths.contains(path) {
            return Err(Error::NotFound);
        }
        OctUrl::parse(&format!("oct://{}{path}", self.circle))
    }
}

impl<'de> Deserialize<'de> for Portal {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            circle: String,
            paths: Vec<String>,
        }
        let fields = Fields::deserialize(deserializer)?;
        Self::new(&fields.circle, fields.paths).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone)]
pub struct Gateway {
    browser: Browser,
    origin: String,
    site: Option<String>,
    portal: Option<Portal>,
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
            site: None,
            portal: None,
        })
    }

    pub fn validate_site(circle: &str) -> Result<(), Error> {
        let url = OctUrl::parse(&format!("oct://{circle}/"))?;
        if url.circle_id != circle {
            return Err(Error::Invalid("site must name one Circle".into()));
        }
        Ok(())
    }

    /// Map ordinary website paths to published assets in this Circle. The
    /// canonical snapshot and resource isolation are shared with /circles/.
    pub fn with_site(mut self, circle: &str) -> Result<Self, Error> {
        Self::validate_site(circle)?;
        if self.portal.is_some() {
            return Err(Error::Invalid(
                "portal cannot grant broad site access".into(),
            ));
        }
        self.site = Some(circle.into());
        Ok(self)
    }

    /// Limit every gateway route to this portal's immutable asset capability.
    pub fn with_portal(mut self, portal: Portal) -> Result<Self, Error> {
        if self.site.is_some() {
            return Err(Error::Invalid(
                "portal cannot grant broad site access".into(),
            ));
        }
        self.portal = Some(portal);
        Ok(self)
    }

    pub fn router(self) -> Router {
        let router = Router::new()
            .route("/circles/:circle", get(serve))
            .route("/circles/:circle/", get(serve))
            .route("/circles/:circle/*path", get(serve))
            .route("/snapshots/:scope/:circle/", get(serve))
            .route("/snapshots/:scope/:circle/*path", get(serve));
        let router = if self.site.is_some() || self.portal.is_some() {
            router.fallback_service(get(serve).with_state(self.clone()))
        } else {
            router
        };
        router.with_state(self)
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
    if let Some(portal) = &gateway.portal {
        let target = match portal.target(&gateway.browser.scope, &uri) {
            Ok(url) => url,
            Err(error) => return failure(&error),
        };
        return resolved_asset(gateway.browser, gateway.origin, target, false, true).await;
    }
    let raw = uri.to_string();
    let pinned = format!("/snapshots/{}/", gateway.browser.scope);
    let path = raw
        .strip_prefix("/circles/")
        .or_else(|| raw.strip_prefix(&pinned));
    let target = match path {
        Some(path) => format!("oct://{path}"),
        None if uri.path().starts_with("/snapshots/") => {
            return failure(&Error::SnapshotChanged);
        }
        None => match &gateway.site {
            Some(circle) => format!("oct://{circle}{raw}"),
            None => return failure(&Error::NotFound),
        },
    };
    let url = match OctUrl::parse(&target) {
        Ok(url) => url,
        Err(error) => return failure(&error),
    };
    resolved_asset(gateway.browser, gateway.origin, url, false, true).await
}
