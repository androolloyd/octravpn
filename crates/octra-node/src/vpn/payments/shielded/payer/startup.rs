//! Resume-only node startup; consent is imported explicitly while the node is
//! offline. Configuration contains public pins and local paths, never keys.
pub mod route;
use super::{funding, runner, service::Service, Payer};
use crate::{
    vpn::payments::shielded::{
        index::{Index, Limits, Seed},
        Pool,
    },
    Host, Node,
};
use anyhow::{ensure, Context, Result};
use ark_serialize::CanonicalDeserialize;
use base64::Engine;
use ed25519_dalek::SigningKey;
use octra_private_payments_experimental::pool::transaction::Prover;
use octravpn_core::{sealed::Key, Address};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub application: crate::vpn::payments::Config,
    pub pool: crate::vpn::payments::shielded::Config,
    pub operator_public: [u8; 32],
    pub wallet: PathBuf,
    pub index: PathBuf,
    pub master_key: PathBuf,
    pub relayer_key: PathBuf,
    pub proving_key: PathBuf,
    pub index_limits: Limits,
    /// Public leaf hints for an authenticated retained checkpoint. Read only
    /// during explicit initialization; startup never reseeds an existing book.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index_seed: Option<PathBuf>,
    pub control_url: String,
    pub control_ca_pem: String,
    pub control_spki: Vec<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_pin: Option<std::net::SocketAddrV4>,
    /// Attach this node's unlocked operator wallet to the payer book. This
    /// imports canonical earnings, never authorizes another purchase.
    #[serde(default)]
    pub spend_operator_income: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum Request {
    Deposit {
        id: [u8; 32],
        terms: funding::Terms,
    },
    Purchase {
        id: [u8; 32],
        terms: Box<runner::Terms>,
    },
}
impl Config {
    pub(crate) fn resolve_paths(&mut self, parent: &Path) {
        for path in [
            &mut self.wallet,
            &mut self.index,
            &mut self.master_key,
            &mut self.relayer_key,
            &mut self.proving_key,
        ] {
            if path.is_relative() {
                *path = parent.join(&*path);
            }
        }
        if let Some(path) = &mut self.index_seed {
            if path.is_relative() {
                *path = parent.join(&*path);
            }
        }
    }
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            self.application.application == crate::vpn::payments::Application::Circle,
            "private payer requires a Circle directory"
        );
        ensure!(
            !ed25519_dalek::VerifyingKey::from_bytes(&self.operator_public)?.is_weak(),
            "weak private operator key"
        );
        self.index_limits.check()?;
        Ok(())
    }
    fn source<A: Host>(&self, node: &Node<A>) -> Result<Arc<Pool>> {
        self.validate()?;
        super::super::startup::check_profile(&node.view_graph)?;
        let directory = node.payments(
            self.application.clone(),
            Address::from_pubkey(&self.operator_public),
        )?;
        Ok(Arc::new(Pool::new(Arc::new(directory), self.pool.clone())?))
    }
    fn key(&self) -> Result<Key> {
        let master = std::fs::canonicalize(&self.master_key)?;
        let relayer = std::fs::canonicalize(&self.relayer_key)?;
        let wallet = destination(&self.wallet)?;
        let index = destination(&self.index)?;
        ensure!(
            !wallet.starts_with(&index) && !index.starts_with(&wallet),
            "private payer stores overlap"
        );
        for key in [master, relayer] {
            ensure!(
                !key.starts_with(&wallet) && !key.starts_with(&index),
                "payer keys must stay outside recovery stores"
            );
        }
        super::super::startup::read_key(&self.master_key)
    }
    fn relayer(&self) -> Result<Arc<SigningKey>> {
        Ok(Arc::new(super::super::startup::read_signing_key(
            &self.relayer_key,
        )?))
    }
    fn control(&self, source: &Pool) -> Result<octravpn_client::PrivateControl> {
        let target = octravpn_core::payments::PrivateTarget {
            pool: octravpn_core::payments::Deployment {
                domain: hex::encode(source.domain.digest()),
                program: octravpn_core::parse_native_address(source.circle())?,
            },
            directory: octravpn_core::parse_native_address(&self.application.program)?,
            operator: octravpn_core::PublicKey(self.operator_public),
            chain_origin: source.origin,
        };
        if let Some(peer) = self.control_pin {
            return octravpn_client::PrivateControl::new_pinned(
                &self.control_url,
                target,
                &self.control_ca_pem,
                self.control_spki.clone(),
                peer,
            );
        }
        octravpn_client::PrivateControl::new(
            &self.control_url,
            target,
            &self.control_ca_pem,
            self.control_spki.clone(),
        )
    }
    /// Creates empty books only. Deployment and an authenticated retained pool
    /// baseline must already exist; initialization opens no network listeners.
    pub async fn initialize<A: Host>(&self, node: &Node<A>) -> Result<()> {
        let source = self.source(node)?;
        let key = self.key()?;
        ensure!(
            !self.wallet.exists() && !self.index.exists(),
            "private payer stores already exist"
        );
        let seed = self
            .index_seed
            .as_ref()
            .map(|path| {
                Seed::decode(
                    &crate::bootstrap::read_limited(path, 64 * 1024 * 1024)?,
                    self.index_limits,
                )
            })
            .transpose()?;
        let index = Index::initialize(
            &self.index,
            key.clone(),
            source.clone(),
            self.index_limits,
            seed.as_ref(),
            node,
        )
        .await?;
        let created = Payer::create(&self.wallet, key, source).await;
        index.close().await;
        drop(created?);
        Ok(())
    }
    /// Explicit offline consent. Each record commits atomically; an interrupted
    /// batch resumes with identical IDs and terms and never regenerates IDs.
    pub async fn consent<A: Host>(&self, node: &Node<A>, requests: Vec<Request>) -> Result<()> {
        ensure!(
            !requests.is_empty() && requests.len() <= 256,
            "private consent batch size refused"
        );
        let payer = Payer::resume(&self.wallet, self.key()?, self.source(node)?).await?;
        let public = self.relayer()?.verifying_key().to_bytes();
        for request in requests {
            match request {
                Request::Deposit { id, terms } => {
                    ensure!(
                        terms.relayer_public == public,
                        "funding relayer differs from configuration"
                    );
                    funding::Funding::create(payer.clone(), id, terms).await?;
                }
                Request::Purchase { id, terms } => {
                    ensure!(
                        terms.relayer_public == public,
                        "purchase relayer differs from configuration"
                    );
                    runner::Purchase::create(payer.clone(), id, *terms).await?;
                }
            }
        }
        Ok(())
    }
    async fn prover(&self) -> Result<Prover> {
        let verification =
            base64::engine::general_purpose::STANDARD.decode(&self.pool.verification_key_b64)?;
        let path = self.proving_key.clone();
        tokio::task::spawn_blocking(move || {
            let bytes = crate::bootstrap::read_limited(&path, 512 * 1024 * 1024)?;
            let mut input = bytes.as_slice();
            let pk =
                ark_groth16::ProvingKey::<ark_bn254::Bn254>::deserialize_compressed(&mut input)
                    .map_err(|_| anyhow::anyhow!("invalid private pool proving key"))?;
            ensure!(input.is_empty(), "trailing private pool proving material");
            Prover::new(Arc::new(pk), &verification)
        })
        .await?
    }
    pub async fn resume<A: Host>(
        &self,
        submission: Arc<crate::rpc::Submission<A>>,
    ) -> Result<Service<A>> {
        self.resume_with_income(submission, None).await
    }
    pub async fn resume_with_income<A: Host>(
        &self,
        submission: Arc<crate::rpc::Submission<A>>,
        income: Option<super::super::wallet::Wallet>,
    ) -> Result<Service<A>> {
        self.open_service(submission, income, false).await
    }
    /// Validate existing custody, jobs, fee consent and proving material before
    /// peer startup, but defer the spending index until fresh chain admission.
    pub async fn prepare_with_income<A: Host>(
        &self,
        submission: Arc<crate::rpc::Submission<A>>,
        income: Option<super::super::wallet::Wallet>,
    ) -> Result<Service<A>> {
        self.open_service(submission, income, true).await
    }
    async fn open_service<A: Host>(
        &self,
        submission: Arc<crate::rpc::Submission<A>>,
        income: Option<super::super::wallet::Wallet>,
        defer_index: bool,
    ) -> Result<Service<A>> {
        ensure!(
            !self.spend_operator_income || income.is_some(),
            "private payer requires its unlocked operator income wallet"
        );
        let source = self.source(&submission.node)?;
        let key = self.key()?;
        let relayer = self.relayer()?;
        let control = Arc::new(self.control(&source)?);
        let prover = self.prover().await?;
        let payer = Payer::resume(&self.wallet, key.clone(), source.clone()).await?;
        let index = if defer_index {
            super::super::index::Handle::resume(self.index.clone(), key, source)?
        } else {
            super::super::index::Handle::ready(
                Arc::new(Index::resume(&self.index, key, source.clone()).await?),
                source,
            )?
        };
        let service =
            Service::resume_handle(payer, index, submission, relayer, prover, control).await?;
        if self.spend_operator_income {
            service.with_income(income.context("operator income wallet is missing")?)
        } else {
            Ok(service)
        }
    }
}
fn destination(path: &Path) -> Result<PathBuf> {
    match std::fs::canonicalize(path) {
        Ok(path) => Ok(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(std::fs::canonicalize(
            path.parent().context("private store has no parent")?,
        )?
        .join(path.file_name().context("private store has no name")?)),
        Err(error) => Err(error.into()),
    }
}

/// Consent describes private relationships. Accept only bounded private files;
/// never print their contents, keys or invoices in CLI diagnostics.
#[cfg(unix)]
pub fn read_requests(path: &Path) -> Result<Vec<Request>> {
    read_private(path)
}
#[cfg(unix)]
pub(super) fn read_private<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
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
        reason = "Explicit private POSIX permissions"
    )]
    let private = meta.permissions().mode() & 0o077 == 0;
    ensure!(
        meta.is_file() && meta.nlink() == 1 && private && meta.len() <= 1024 * 1024,
        "private consent must be a bounded private single-link regular file"
    );
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    file.by_ref()
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 1024 * 1024,
        "private consent exceeds size limit"
    );
    serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("invalid private consent file"))
}
#[cfg(not(unix))]
pub fn read_requests(path: &Path) -> Result<Vec<Request>> {
    read_private(path)
}
#[cfg(not(unix))]
pub(super) fn read_private<T: serde::de::DeserializeOwned>(_: &Path) -> Result<T> {
    anyhow::bail!("private consent requires Unix permissions")
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    #[test]
    fn private_consent_rejects_public_linked_and_non_regular_inputs() {
        let root = tempfile::tempdir().unwrap();
        let input = root.path().join("requests.json");
        crate::storage::publish(&input, b"[]").unwrap();
        assert!(read_requests(&input).unwrap().is_empty());
        std::fs::set_permissions(&input, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_requests(&input).is_err());
        std::fs::set_permissions(&input, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = root.path().join("linked");
        std::fs::hard_link(&input, &link).unwrap();
        assert!(read_requests(&input).is_err());
        std::fs::remove_file(&link).unwrap();
        symlink(&input, &link).unwrap();
        assert!(read_requests(&link).is_err());
        assert!(read_requests(root.path()).is_err());
        std::fs::write(&input, b"[{\"kind\":\"secret-invalid-value\"}]").unwrap();
        let error = read_requests(&input).err().unwrap();
        assert!(!error.to_string().contains("secret-invalid-value"));
    }
}
