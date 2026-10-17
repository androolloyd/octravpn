//! Embeddable mesh enrollment, DNS, policy and DERP service.
use anyhow::{ensure, Context, Result};
use futures_util::{stream::FuturesUnordered, StreamExt};
use octravpn_mesh::{
    headscale_api::dns::{self, DnsConfigSpec, DnsStore},
    tailscale_wire::{
        derp_config::{empty_derp_map, load_derp_map},
        serve::{serve, ServeConfig, TrustedProxyConfig},
        tls::{SanConfig, TlsMaterialSource},
        KnockConfig,
    },
    MachineRegistry, ServerNoiseKey, TailnetIpAllocator, WireStateBuilder,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::{sync::watch, task::JoinHandle};
mod preauth;

#[derive(Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub state_dir: PathBuf,
    pub tailnet_id: String,
    pub http_addr: Option<SocketAddr>,
    pub https_addr: Option<SocketAddr>,
    pub hostname: String,
    pub control_url: Option<String>,
    pub admin_token_file: Option<PathBuf>,
    pub tls: Option<TlsFiles>,
    pub dns: Option<DnsConfigSpec>,
    pub serve_derp: bool,
    pub derp_map: Option<PathBuf>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsFiles {
    pub certificate: PathBuf,
    pub key: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            state_dir: "state/tailscale-wire".into(),
            tailnet_id: "octravpn-interop".into(),
            http_addr: Some("127.0.0.1:51821".parse().expect("static socket")),
            https_addr: None,
            hostname: "localhost".into(),
            control_url: None,
            admin_token_file: None,
            tls: None,
            dns: None,
            serve_derp: false,
            derp_map: None,
        }
    }
}

impl Config {
    pub fn resolve_paths(&mut self, directory: &Path) {
        let mut paths = vec![&mut self.state_dir];
        paths.extend(self.admin_token_file.as_mut());
        paths.extend(self.derp_map.as_mut());
        if let Some(tls) = &mut self.tls {
            paths.extend([&mut tls.certificate, &mut tls.key]);
        }
        if let Some(dns) = &mut self.dns {
            paths.extend(dns.extra_records_path.as_mut());
        }
        for path in paths {
            if path.is_relative() {
                *path = directory.join(&*path);
            }
        }
    }

    pub async fn bind(self) -> Result<Service> {
        let token = self
            .admin_token_file
            .as_ref()
            .map(|path| read_token(path))
            .transpose()?;
        bind(self, token, None, KnockConfig::disabled()).await
    }
}

pub struct Service {
    pub http_addr: Option<SocketAddr>,
    pub https_addr: Option<SocketAddr>,
    pub certificate: Option<PathBuf>,
    listeners: FuturesUnordered<JoinHandle<std::io::Result<()>>>,
    background: Vec<JoinHandle<()>>,
    _lock: File,
}

impl Service {
    pub async fn run(mut self, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        let result = if *shutdown.borrow_and_update() {
            Ok(())
        } else {
            tokio::select! {
                result = self.listeners.next() => match result {
                    Some(result) => {
                        match result.context("mesh listener task").and_then(|result| result.context("mesh listener")) {
                            Ok(()) => Err(anyhow::anyhow!("mesh listener stopped unexpectedly")),
                            Err(error) => Err(error),
                        }
                    },
                    None => Err(anyhow::anyhow!("mesh has no listeners")),
                },
                _ = shutdown.wait_for(|stop| *stop) => Ok(()),
            }
        };
        self.abort();
        while self.listeners.next().await.is_some() {}
        for task in self.background.drain(..) {
            let _ = task.await;
        }
        result
    }

    fn abort(&self) {
        for task in &self.listeners {
            task.abort();
        }
        for task in &self.background {
            task.abort();
        }
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        self.abort();
    }
}

pub(crate) async fn bind(
    config: Config,
    token: Option<Arc<str>>,
    members: Option<crate::members_policy::MembersPolicySync>,
    knock: KnockConfig,
) -> Result<Service> {
    ensure!(
        config.http_addr.is_some() || config.https_addr.is_some(),
        "mesh needs a listener"
    );
    ensure!(
        !config.serve_derp || config.https_addr.is_some_and(|addr| addr.port() != 0),
        "native DERP needs a fixed HTTPS port"
    );
    ensure!(
        config.tls.is_none() || config.https_addr.is_some(),
        "TLS files need an HTTPS listener"
    );
    let control_url = config
        .control_url
        .as_ref()
        .map(|raw| {
            let url = reqwest::Url::parse(raw).context("invalid mesh control URL")?;
            ensure!(
                url.scheme() == "https"
                    && url.host_str().is_some()
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.query().is_none()
                    && url.fragment().is_none()
                    && url.path() == "/",
                "mesh control URL must be an HTTPS origin"
            );
            Ok::<_, anyhow::Error>(raw.clone())
        })
        .transpose()?;
    let dns = config
        .dns
        .clone()
        .map(DnsStore::try_from_spec)
        .transpose()?;
    if let (Some(store), Some(path)) = (
        &dns,
        config
            .dns
            .as_ref()
            .and_then(|dns| dns.extra_records_path.as_ref()),
    ) {
        let mut bytes = Vec::new();
        File::open(path)?
            .take(1024 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= 1024 * 1024,
            "mesh DNS records file too large"
        );
        store.set_extra_records(
            dns::parse_extra_records(&bytes).context("invalid mesh DNS records")?,
        );
    }
    std::fs::create_dir_all(&config.state_dir)?;
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
    }
    let lock = options.open(config.state_dir.join("control.lock"))?;
    lock.try_lock()
        .context("mesh state directory already in use")?;
    let key = Arc::new(ServerNoiseKey::load_or_generate(&config.state_dir)?);
    let machines = Arc::new(MachineRegistry::new());
    let stores = crate::mesh_store::MeshStore::open(&config.state_dir, machines.clone())
        .await?
        .managed_policy(members.is_some());
    let policy = stores.policy.clone();
    if members.is_some() {
        crate::members_policy::install_boot_deny_all(&policy)?;
    }
    let native_derp = config
        .serve_derp
        .then(|| crate::native_derp::load_native_derp_runtime(&config.state_dir))
        .transpose()?;
    let derp_map = if config.serve_derp {
        crate::native_derp::self_derp_map(
            &config.hostname,
            config.https_addr.expect("validated HTTPS").port(),
        )
    } else if let Some(path) = &config.derp_map {
        load_derp_map(path)?
    } else {
        empty_derp_map()
    };
    let mut wire = WireStateBuilder::new(
        key,
        stores.redeemer(None),
        Arc::new(TailnetIpAllocator::new(config.tailnet_id)),
        machines.clone(),
        Arc::new(policy.clone()),
        octravpn_mesh::tailscale_wire::DerpMapStore::shared(derp_map),
    )
    .registration_store(Some(stores.machines.clone()))
    .registration_gate(
        members
            .as_ref()
            .and_then(crate::members_policy::MembersPolicySync::registration_gate),
    )
    .native_derp(native_derp)
    .knock(knock)
    .build();
    if let Some(dns) = dns {
        wire.dns = Arc::new(dns);
    }
    wire.public_control_url = control_url;
    let admin = preauth::router(stores.clone(), token.clone())
        .merge(stores.admin_router(policy.clone(), token));
    let sans = SanConfig::with_hostname(&config.hostname);
    let tls_source = match config.tls {
        Some(files) => TlsMaterialSource::Files {
            cert_path: files.certificate,
            key_path: files.key,
        },
        None => TlsMaterialSource::SelfSigned {
            state_dir: config.state_dir.clone(),
            sans: sans.clone(),
        },
    };
    let handle = serve(
        wire.clone(),
        ServeConfig {
            http_addr: config.http_addr,
            https_addr: config.https_addr,
            state_dir: config.state_dir,
            sans,
            tls_source,
            trusted_proxies: TrustedProxyConfig::default(),
            oidc: None,
            metrics_addr: None,
            acme_http01: None,
            acme_http01_host: None,
            acme_http01_addr: None,
        },
        admin,
    )
    .await?;
    let mut service = Service {
        http_addr: handle.http_addr,
        https_addr: handle.https_addr,
        certificate: handle.tls.map(|tls| tls.cert_path),
        listeners: [
            handle.http,
            handle.https,
            handle.metrics,
            handle.acme_http01,
        ]
        .into_iter()
        .flatten()
        .collect(),
        background: vec![],
        _lock: lock,
    };
    if let Some(path) = wire.dns.spec().extra_records_path.clone() {
        service.background.push(dns::spawn_extra_records_watcher(
            wire.dns.as_ref().clone(),
            path,
            None,
        ));
    }
    if let Some(sync) = members {
        service.background.push(tokio::spawn(sync.run(
            crate::members_policy::MembersPolicyWiring {
                machines,
                policy: Arc::new(policy),
                registration_store: Some(stores.machines.clone()),
            },
        )));
    }
    Ok(service)
}

fn read_token(path: &Path) -> Result<Arc<str>> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
    }
    let file = options.open(path).context("open mesh admin token")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            file.metadata()?.permissions().mode().trailing_zeros() >= 6,
            "mesh token must be readable only by its owner"
        );
    }
    let mut token = String::new();
    file.take(1025).read_to_string(&mut token)?;
    ensure!(
        token.len() <= 1024
            && !token.trim().is_empty()
            && token.trim().bytes().all(|byte| byte.is_ascii_graphic()),
        "invalid mesh admin token file"
    );
    Ok(Arc::from(token.trim()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn state_is_exclusive_and_released_on_shutdown() {
        let directory = tempfile::tempdir().unwrap();
        let config = Config {
            state_dir: directory.path().join("wire"),
            http_addr: Some("127.0.0.1:0".parse().unwrap()),
            ..Default::default()
        };
        let service = config.clone().bind().await.unwrap();
        let address = service.http_addr.unwrap();
        assert!(config.clone().bind().await.is_err());
        let (stop, shutdown) = watch::channel(false);
        let task = tokio::spawn(service.run(shutdown));
        let http = reqwest::Client::new();
        for path in ["/api/v1/machines", "/admin/", "/admin/preauth"] {
            let response = http
                .get(format!("http://{address}{path}"))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
            assert!(response.bytes().await.unwrap().is_empty());
        }
        stop.send_replace(true);
        task.await.unwrap().unwrap();
        assert!(std::net::TcpListener::bind(address).is_ok());
        let service = config.bind().await.unwrap();
        drop(service);
    }

    #[tokio::test]
    async fn corrupt_policy_prevents_the_service_from_binding() {
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("wire");
        let db = crate::mesh_store::database(&state).await.unwrap();
        headscale_db::policies::set(db.pool(), "invalid policy")
            .await
            .unwrap();
        let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = reserved.local_addr().unwrap();
        drop(reserved);
        let config = Config {
            state_dir: state,
            http_addr: Some(address),
            ..Default::default()
        };
        assert!(config.bind().await.is_err());
        assert!(std::net::TcpListener::bind(address).is_ok());
    }

    #[test]
    fn all_mesh_files_resolve_against_the_config_directory() {
        let mut config: Config = serde_json::from_value(serde_json::json!({
            "state_dir":"mesh", "admin_token_file":"admin.token", "derp_map":"derp.json",
            "tls":{"certificate":"cert.pem","key":"key.pem"},
            "dns":{"base_domain":"mesh.test", "override_local_dns":false, "extra_records_path":"records.json"}
        }))
        .unwrap();
        config.resolve_paths(Path::new("/operator"));
        assert_eq!(config.state_dir, Path::new("/operator/mesh"));
        assert_eq!(
            config.admin_token_file.as_deref(),
            Some(Path::new("/operator/admin.token"))
        );
        assert_eq!(
            config.derp_map.as_deref(),
            Some(Path::new("/operator/derp.json"))
        );
        let tls = config.tls.unwrap();
        assert_eq!(tls.certificate, Path::new("/operator/cert.pem"));
        assert_eq!(tls.key, Path::new("/operator/key.pem"));
        assert_eq!(
            config.dns.unwrap().extra_records_path.as_deref(),
            Some(Path::new("/operator/records.json"))
        );
    }
}
