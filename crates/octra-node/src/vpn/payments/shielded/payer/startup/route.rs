//! Resume an existing complete route before starting the node's P2P actor.
//! Startup accepts no fresh purchase terms and creates no replacement stores.
use super::{Config as PayerConfig, Payer};
use crate::{
    rpc::Submission,
    vpn::payments::shielded::{
        payer::runner::{route, Terms},
        wallet::Wallet,
        Pool,
    },
    Host,
};
use anyhow::{ensure, Result};
use octra_node_protocol::network::swarm::TransportScope;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::sync::watch;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub id: [u8; 32],
    pub hops: Vec<PayerConfig>,
    #[serde(default)]
    pub chain_dns: BTreeMap<String, Ipv4Addr>,
}
/// Explicit offline finite consent; never read by the running service.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Consent {
    pub purchase_id: [u8; 32],
    pub terms: Terms,
    pub tariff: octravpn_core::payments::Tariff,
    pub endpoint: octravpn_client::PrivateEndpoint,
    pub journal: PathBuf,
    pub interface_name: String,
}
pub fn read_consent(path: &Path) -> Result<Vec<Consent>> {
    super::read_private(path)
}
pub struct Prepared<A: Host> {
    route: Arc<route::Route>,
    resources: Vec<route::driver::Resources<A>>,
    chain_dns: BTreeMap<String, Ipv4Addr>,
    income: Income,
}
#[derive(Clone)]
pub(crate) struct Income {
    sender: watch::Sender<Option<Wallet>>,
    sources: Vec<Arc<Pool>>,
}
impl Income {
    pub(crate) fn attach(&self, wallet: Wallet) -> Result<()> {
        ensure!(
            self.sources
                .iter()
                .all(|source| source.same_custody(wallet.income_pool())),
            "route income wallet belongs to another custody source"
        );
        self.sender.send_replace(Some(wallet));
        Ok(())
    }
}
impl Config {
    pub(crate) fn resolve_paths(&mut self, parent: &Path) {
        for hop in &mut self.hops {
            hop.resolve_paths(parent);
        }
    }
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            self.id != [0; 32] && (2..=octravpn_core::onion::MAX_HOPS).contains(&self.hops.len()),
            "route startup requires its identity and two or three configured books"
        );
        for hop in &self.hops {
            hop.validate()?;
        }
        Ok(())
    }
    pub async fn consent<A: Host>(
        &self,
        node: &crate::Node<A>,
        intents: Vec<Consent>,
        resume: bool,
    ) -> Result<PathBuf> {
        self.validate()?;
        ensure!(
            intents.len() == self.hops.len(),
            "route consent differs from configured hop count"
        );
        let mut books = Vec::<([PathBuf; 5], Payer)>::new();
        let mut hops = Vec::new();
        for (config, intent) in self.hops.iter().zip(intents) {
            let source = config.source(node)?;
            let paths = paths(config)?;
            let payer =
                if let Some((original, payer)) = books.iter().find(|(p, _)| p[0] == paths[0]) {
                    ensure!(
                        *original == paths,
                        "shared route consent changes key or index authority"
                    );
                    payer.for_operator(source)?
                } else {
                    let payer = Payer::resume(&config.wallet, config.key()?, source).await?;
                    books.push((paths, payer.clone()));
                    payer
                };
            ensure!(
                intent.terms.relayer_public == config.relayer()?.verifying_key().to_bytes(),
                "route consent relayer differs from configuration"
            );
            check_endpoint(config, &intent.endpoint)?;
            hops.push(route::Hop {
                payer,
                purchase_id: intent.purchase_id,
                terms: intent.terms,
                tariff: intent.tariff,
                endpoint: intent.endpoint,
                journal: intent.journal,
                interface_name: intent.interface_name,
            });
        }
        if resume {
            route::Route::resume(self.id, hops).await?;
        } else {
            route::Route::create(self.id, hops).await?;
        }
        Ok(self.hops[0].wallet.clone())
    }
    /// All custody leases and immutable consent are checked before P2P starts.
    /// The spending indexes stay unopened until fresh chain access is restored.
    pub async fn prepare<A: Host>(&self, submission: Arc<Submission<A>>) -> Result<Prepared<A>> {
        self.validate()?;
        let mut books = Vec::<Book>::new();
        let mut payers = Vec::new();
        let mut resources = Vec::new();
        let (sender, _) = watch::channel(None);
        let mut income = Income {
            sender,
            sources: Vec::new(),
        };
        for config in &self.hops {
            let source = config.source(&submission.node)?;
            let paths = paths(config)?;
            let existing = books.iter().position(|book| book.paths[0] == paths[0]);
            let book = if let Some(position) = existing {
                let book = &books[position];
                ensure!(
                    book.paths == paths,
                    "shared route book changes index or key authority"
                );
                book
            } else {
                let key = config.key()?;
                let payer = Payer::resume(&config.wallet, key.clone(), source.clone()).await?;
                books.push(Book {
                    paths,
                    payer,
                    index: route::index::IndexHandle::resume(
                        config.index.clone(),
                        key,
                        source.clone(),
                    )?,
                    relayer: config.relayer()?,
                    prover: config.prover().await?,
                });
                books.last().expect("book was inserted")
            };
            payers.push(book.payer.for_operator(source.clone())?);
            if config.spend_operator_income {
                income.sources.push(source);
            }
            resources.push(route::driver::Resources {
                index: book.index.clone(),
                submission: submission.clone(),
                relayer: book.relayer.clone(),
                prover: book.prover.clone(),
                income: config
                    .spend_operator_income
                    .then(|| income.sender.subscribe()),
            });
        }
        let route = Arc::new(route::Route::resume_stored(self.id, payers).await?);
        let profiles = route.profiles();
        for (profile, config) in profiles.iter().zip(&self.hops) {
            check_endpoint(config, &profile.endpoint)?;
        }
        submission
            .swarm
            .validate_scope(&TransportScope::Interface {
                name: profiles[0].interface_name.clone(),
                pins: self.chain_dns.clone(),
                mark: route::driver::SOCKET_MARK,
            })?;
        route.configure_chain(&submission.swarm).await?;
        Ok(Prepared {
            route,
            resources,
            chain_dns: self.chain_dns.clone(),
            income,
        })
    }
}
fn check_endpoint(config: &PayerConfig, endpoint: &octravpn_client::PrivateEndpoint) -> Result<()> {
    ensure!(
        endpoint.control_url == config.control_url
            && endpoint.control_ca_pem == config.control_ca_pem
            && endpoint.control_spki == config.control_spki
            && Some(endpoint.pins.control) == config.control_pin,
        "configured control transport differs from sealed route consent"
    );
    Ok(())
}
impl<A: Host> Prepared<A> {
    pub(crate) fn income(&self) -> Income {
        self.income.clone()
    }
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        let swarm = self.resources[0].submission.swarm.clone();
        while !swarm.connection_diagnostics().running {
            tokio::select! {
                _=shutdown.wait_for(|v| *v)=>return Ok(()),
                ()=tokio::time::sleep(Duration::from_millis(10))=>{},
            }
        }
        let opened = route::driver::open(self.route, self.resources, self.chain_dns);
        let client = tokio::select! {
            _=shutdown.wait_for(|v| *v)=>return Ok(()),
            result=opened=>result?,
        };
        client
            .run(async move {
                shutdown.wait_for(|v| *v).await?;
                Ok(())
            })
            .await?;
        Ok(())
    }
}
struct Book {
    paths: [PathBuf; 5],
    payer: Payer,
    index: route::index::IndexHandle,
    relayer: Arc<ed25519_dalek::SigningKey>,
    prover: octra_private_payments_experimental::pool::transaction::Prover,
}
fn paths(config: &PayerConfig) -> Result<[PathBuf; 5]> {
    Ok([
        std::fs::canonicalize(&config.wallet)?,
        std::fs::canonicalize(&config.index)?,
        std::fs::canonicalize(&config.master_key)?,
        std::fs::canonicalize(&config.relayer_key)?,
        std::fs::canonicalize(&config.proving_key)?,
    ])
}
