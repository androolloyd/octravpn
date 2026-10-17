//! Shared durable enrollment handles for native mesh control services.
use anyhow::{Context, Result};
use octravpn_mesh::{
    headscale_api::admin::{
        PersistentApiKeyAdmin, PersistentMachineAdmin, PersistentPreauthAdmin, PersistentUserAdmin,
        PreauthAdmin, PreauthAdminKey, PreauthMintRequest, UserAdmin, UserRegistryError,
    },
    MachineRegistry,
};
use std::{path::Path, sync::Arc};

#[derive(Clone)]
pub struct MeshStore {
    pub machines: Arc<PersistentMachineAdmin>,
    pub users: Arc<PersistentUserAdmin>,
    pub preauth: Arc<PersistentPreauthAdmin>,
    pub api_keys: Arc<PersistentApiKeyAdmin>,
    pub policy: octravpn_mesh::policy::PolicyStore,
    policy_storage: Arc<dyn octravpn_mesh::policy::persistence::PolicyPersistence>,
    policy_managed: bool,
}

impl MeshStore {
    pub async fn open(directory: &Path, registry: Arc<MachineRegistry>) -> Result<Self> {
        let db = database(directory).await?;
        let users = Arc::new(PersistentUserAdmin::new(db.pool().clone()));
        let preauth =
            Arc::new(PersistentPreauthAdmin::new(db.pool().clone()).with_user_admin(users.clone()));
        let machines = Arc::new(
            PersistentMachineAdmin::new(db.pool().clone())
                .with_user_admin(users.clone())
                .with_wire_registry(registry.clone()),
        );
        machines.hydrate_wire_registry(&registry).await?;
        let api_keys = Arc::new(PersistentApiKeyAdmin::new(db.pool().clone()));
        let policy = octravpn_mesh::policy::PolicyStore::new();
        let policy_storage = Arc::new(db.pool().clone());
        octravpn_mesh::admin_surface::AdminState::builder()
            .policy(policy.clone())
            .policy_persistence(policy_storage.clone())
            .build()
            .load_policy_from_persistence()
            .await
            .map_err(anyhow::Error::msg)
            .context("load mesh policy")?;
        Ok(Self {
            machines,
            users,
            preauth,
            api_keys,
            policy,
            policy_storage,
            policy_managed: false,
        })
    }

    pub(crate) fn managed_policy(mut self, managed: bool) -> Self {
        self.policy_managed = managed;
        self
    }

    /// The legacy mint endpoint creates its named user as before, but its
    /// token now belongs to the same durable store as the wire/admin APIs.
    pub async fn mint_for_user(
        &self,
        user: String,
        ttl_secs: u64,
        reusable: bool,
    ) -> Result<PreauthAdminKey> {
        if self.users.get(&user).await?.is_none() {
            match self.users.create(&user).await {
                Ok(_) | Err(UserRegistryError::Exists(_)) => (),
                Err(error) => return Err(error.into()),
            }
        }
        self.preauth
            .mint(PreauthMintRequest {
                user,
                ttl_secs,
                reusable,
                ephemeral: false,
                tags: vec![],
            })
            .await
            .map_err(Into::into)
    }

    pub fn admin_router(
        &self,
        policy: octravpn_mesh::policy::PolicyStore,
        token: Option<Arc<str>>,
    ) -> axum::Router {
        let state = octravpn_mesh::admin_surface::AdminState::builder()
            .bearer_token(token.as_deref().unwrap_or(""))
            .users_arc(self.users.clone())
            .machines(self.machines.clone())
            .preauth(self.preauth.clone())
            .api_keys(self.api_keys.clone())
            .policy(policy)
            .policy_persistence(self.policy_storage.clone())
            .policy_read_only(self.policy_managed)
            .build();
        octravpn_mesh::admin_surface::build_admin_router(state, token)
    }

    pub fn redeemer(
        &self,
        metrics: Option<Arc<dyn octravpn_mesh::MetricsSink>>,
    ) -> Arc<dyn octravpn_mesh::tailscale_wire::PreauthRedeemer> {
        match metrics {
            Some(metrics) => Arc::new(MeteredRedeemer {
                store: self.preauth.clone(),
                metrics,
            }),
            None => self.preauth.clone(),
        }
    }
}

struct MeteredRedeemer {
    store: Arc<PersistentPreauthAdmin>,
    metrics: Arc<dyn octravpn_mesh::MetricsSink>,
}
#[async_trait::async_trait]
impl octravpn_mesh::tailscale_wire::PreauthRedeemer for MeteredRedeemer {
    async fn redeem(
        &self,
        key: &str,
    ) -> Result<octravpn_mesh::tailscale_wire::RedeemOk, octravpn_mesh::tailscale_wire::RedeemError>
    {
        let result = self.store.redeem(key).await?;
        self.metrics.record_event("preauth_redeem");
        Ok(result)
    }
    async fn lookup(&self, key: &str) -> Option<octravpn_mesh::tailscale_wire::RedeemOk> {
        self.store.lookup(key).await
    }
}

pub(crate) async fn database(directory: &Path) -> Result<headscale_db::Database> {
    std::fs::create_dir_all(directory).context("create mesh state directory")?;
    let path = directory.join("machines.sqlite");
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
    }
    options.open(&path).context("create mesh database")?;
    let db = headscale_db::Database::new(&format!("sqlite://{}", path.display())).await?;
    db.migrate().await.context("migrate mesh database")?;
    Ok(db)
}
