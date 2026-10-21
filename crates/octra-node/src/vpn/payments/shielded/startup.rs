//! Explicit private operator startup. Initialization never opens listeners;
//! ordinary startup only resumes an existing encrypted wallet.
pub mod offline;
use super::{
    wallet::{rpc::Policy, Wallet},
    Pool,
};
use crate::{Host, Node, Services};
use anyhow::{ensure, Context, Result};
use ed25519_dalek::SigningKey;
use octra_node_protocol::rules::IsolatedApplicationProfile;
use octravpn_core::{sealed::Key, Address, KeyPair};
use serde::{Deserialize, Serialize};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

/// Local initialization and consent share the same captured node authority as
/// ordinary startup. Applying an action never starts peers or listeners.
pub enum Action {
    Operator,
    Payer,
    Consent(Vec<super::payer::startup::Request>),
    RouteConsent {
        hops: Vec<super::payer::startup::route::Consent>,
        resume: bool,
    },
}
impl Action {
    pub(crate) async fn apply<A: Host>(
        self,
        node: &Node<A>,
        key: &SigningKey,
        operator: Option<&Config>,
        payer: Option<&super::payer::startup::Config>,
        route: Option<&super::payer::startup::route::Config>,
    ) -> Result<PathBuf> {
        match self {
            Self::Operator => {
                let config = operator.context("private operator configuration missing")?;
                config.initialize(node, key).await?;
                Ok(config.wallet.clone())
            }
            Self::Payer => {
                let config = payer.context("private payer configuration missing")?;
                config.initialize(node).await?;
                Ok(config.wallet.clone())
            }
            Self::Consent(requests) => {
                let config = payer.context("private payer configuration missing")?;
                config.consent(node, requests).await?;
                Ok(config.wallet.clone())
            }
            Self::RouteConsent { hops, resume } => {
                Box::pin(
                    route
                        .context("private route configuration missing")?
                        .consent(node, hops, resume),
                )
                .await
            }
        }
    }
}

/// This only selects supported service profiles. Each financial read still
/// authenticates native activation anchors and the current publication.
pub(crate) fn check_profile(graph: &octra_node_protocol::rules::Graph) -> Result<()> {
    ensure!(
        graph.application_fixture() == Some(IsolatedApplicationProfile::BftDevnet)
            || (graph.application_fixture().is_none()
                && graph.chain_id() == octra_node_protocol::consensus::policy::DEVNET),
        "private startup requires adopted public devnet or isolated BFT applications"
    );
    Ok(())
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub application: crate::vpn::payments::Config,
    pub pool: super::Config,
    pub wallet: PathBuf,
    pub master_key: PathBuf,
    pub purchases: Policy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_tunnel: Option<octravpn_node::embedded::IpTunnelConfig>,
}
#[derive(Clone, Copy)]
pub struct Listen {
    pub browser: SocketAddr,
    pub control: SocketAddr,
    pub tunnel: SocketAddr,
}
impl Config {
    pub(crate) fn resolve_paths(&mut self, parent: &Path) {
        for path in [&mut self.wallet, &mut self.master_key] {
            if path.is_relative() {
                *path = parent.join(&*path);
            }
        }
        if let Some(path) = self
            .ip_tunnel
            .as_mut()
            .and_then(|ip| ip.address_book.as_mut())
        {
            if path.is_relative() {
                *path = parent.join(&*path);
            }
        }
    }
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            self.application.application == crate::vpn::payments::Application::Circle,
            "private startup requires a Circle directory"
        );
        self.purchases.validate()?;
        if let Some(ip) = &self.ip_tunnel {
            ip.validate()?;
        }
        Ok(())
    }
    fn source<A: Host>(&self, node: &Node<A>, operator: &SigningKey) -> Result<Arc<Pool>> {
        self.validate()?;
        check_profile(&node.view_graph)?;
        let directory = node.payments(
            self.application.clone(),
            Address::from_pubkey(operator.verifying_key().as_bytes()),
        )?;
        Ok(Arc::new(Pool::new(Arc::new(directory), self.pool.clone())?))
    }
    fn key(&self, transport: Option<&Path>) -> Result<Key> {
        let key_path = std::fs::canonicalize(&self.master_key)?;
        let wallet = destination(&self.wallet)?;
        ensure!(
            !key_path.starts_with(&wallet),
            "master key must stay outside the encrypted wallet"
        );
        if let Some(transport) = transport {
            ensure!(
                !key_path.starts_with(destination(transport)?),
                "master key must stay outside transport recovery data"
            );
        }
        read_key(&self.master_key)
    }
    /// A new directory only. Never recreates a missing journal during resume.
    pub async fn initialize<A: Host>(&self, node: &Node<A>, operator: &SigningKey) -> Result<()> {
        let source = self.source(node, operator)?;
        let key = self.key(None)?;
        drop(Wallet::create(&self.wallet, key, source).await?);
        Ok(())
    }
    pub async fn resume<A: Host>(&self, node: &Node<A>, operator: &SigningKey) -> Result<Wallet> {
        let source = self.source(node, operator)?;
        Wallet::resume(&self.wallet, self.key(None)?, source).await
    }
    pub async fn bind<A: Host>(
        &self,
        node: &Node<A>,
        listen: Listen,
        data: &Path,
        operator: &SigningKey,
    ) -> Result<Services> {
        Ok(self.bind_with_wallet(node, listen, data, operator).await?.0)
    }
    /// Retain the same unlocked wallet for a local payer. The returned service
    /// and wallet share one lease; no second writer or key export is involved.
    pub async fn bind_with_wallet<A: Host>(
        &self,
        node: &Node<A>,
        listen: Listen,
        data: &Path,
        operator: &SigningKey,
    ) -> Result<(Services, Wallet)> {
        ensure!(
            listen.browser.ip().is_loopback() && listen.control.ip().is_loopback(),
            "private startup HTTP must bind loopback behind authenticated TLS"
        );
        let transport = data.join("private-payments-transport");
        let source = self.source(node, operator)?;
        let wallet = Wallet::resume(&self.wallet, self.key(Some(&transport))?, source).await?;
        let keys = crate::vpn::Keys::derive(operator);
        let service = node
            .bind_shielded_purchases(
                listen.browser,
                octravpn_node::payments::Config {
                    control_listen: listen.control,
                    tunnel_listen: listen.tunnel,
                    data_dir: transport,
                    operator_key: Arc::new(KeyPair::from_secret_bytes(&operator.to_bytes())),
                    wireguard_secret: keys.wireguard,
                    ip_tunnel: self.ip_tunnel.clone(),
                },
                &wallet,
                self.purchases,
            )
            .await?;
        Ok((service, wallet))
    }
}
fn destination(path: &Path) -> Result<PathBuf> {
    let parent = path.parent().context("private path has no parent")?;
    Ok(std::fs::canonicalize(parent)?.join(path.file_name().context("private path has no name")?))
}
pub(super) fn read_key(path: &Path) -> Result<Key> {
    Ok(Key::from_bytes(*read_secret(path)?))
}
pub(super) fn read_signing_key(path: &Path) -> Result<SigningKey> {
    Ok(SigningKey::from_bytes(&*read_secret(path)?))
}
#[cfg(unix)]
fn read_secret(path: &Path) -> Result<zeroize::Zeroizing<[u8; 32]>> {
    use rustix::fs::{open, Mode, OFlags};
    use std::{
        fs::File,
        io::Read,
        os::unix::fs::{MetadataExt, PermissionsExt},
    };
    let mut file: File = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?
    .into();
    let meta = file.metadata()?;
    #[expect(
        clippy::verbose_bit_mask,
        reason = "Explicit private POSIX permission mask"
    )]
    let private = meta.permissions().mode() & 0o077 == 0;
    ensure!(
        meta.is_file() && meta.len() == 32 && meta.nlink() == 1 && private,
        "wallet master key must be a private 32-byte regular file with one link"
    );
    let mut bytes = zeroize::Zeroizing::new([0; 32]);
    file.read_exact(bytes.as_mut())?;
    Ok(bytes)
}
#[cfg(not(unix))]
fn read_secret(_: &Path) -> Result<zeroize::Zeroizing<[u8; 32]>> {
    anyhow::bail!("private wallet keys require Unix permissions")
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    #[test]
    fn supported_profiles_do_not_activate_public_rules() {
        use octra_node_protocol::{
            rules::{Graph, Rule},
            transaction::RuleMode,
        };
        let graph = Graph::new(
            octra_node_protocol::consensus::policy::DEVNET.to_vec(),
            None,
        );
        check_profile(&graph).unwrap();
        let plan =
            octra_node_protocol::rules::activation(graph.chain_id(), Rule::ProofExecution).unwrap();
        assert_eq!(
            octra_node_protocol::rules::activation_mode(
                &|_| octra_node_protocol::rules::RootRead::Missing,
                Some(&plan),
                plan.activation_epoch - 1
            )
            .unwrap(),
            RuleMode::Prior
        );
        assert!(octra_node_protocol::rules::activation_mode(
            &|_| octra_node_protocol::rules::RootRead::Missing,
            Some(&plan),
            plan.activation_epoch
        )
        .is_err());
        assert!(octra_node_protocol::rules::activation_mode(
            &|_| octra_node_protocol::rules::RootRead::Root(b"wrong".to_vec()),
            Some(&plan),
            plan.activation_epoch
        )
        .is_err());
        assert_eq!(
            octra_node_protocol::rules::activation_mode(
                &|_| octra_node_protocol::rules::RootRead::Root(plan.anchor_state_root.clone()),
                Some(&plan),
                plan.activation_epoch
            )
            .unwrap(),
            RuleMode::Active
        );
        for chain in [
            b"octra-mainnet".as_slice(),
            b"unknown",
            b"octra-rust-local-0123456789abcdef",
        ] {
            assert!(check_profile(&Graph::new(chain.to_vec(), None)).is_err());
        }
        let local = b"octra-rust-local-0123456789abcdef".to_vec();
        check_profile(&Graph::isolated_applications(local, None, [7; 32]).unwrap()).unwrap();
        let single = Graph::isolated_single_applications(
            b"octra-single-local-0123456789abcdef".to_vec(),
            None,
            [7; 32],
        )
        .unwrap();
        assert!(check_profile(&single).is_err());
    }
    #[test]
    fn master_key_files_require_private_single_link_regular_material() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("master.key");
        crate::storage::publish(&key, &[7; 32]).unwrap();
        assert!(read_key(&key).is_ok());
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_key(&key).is_err());
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.path().join("linked");
        std::fs::hard_link(&key, &link).unwrap();
        assert!(read_key(&key).is_err());
        std::fs::remove_file(&link).unwrap();
        let alias = dir.path().join("symlink");
        symlink(&key, &alias).unwrap();
        assert!(read_key(&alias).is_err());
        std::fs::write(&key, [7; 31]).unwrap();
        assert!(read_key(&key).is_err());
    }
}
