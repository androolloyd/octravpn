//! Complete finite route consent, durable before any operator is contacted.
//! Ownership and each purchase are committed together in its custody book.
mod consent;
pub mod driver;
pub mod index;
mod storage;
#[cfg(test)]
mod tests;
#[cfg(test)]
pub(crate) use tests::qualification;

use super::{Payer, Purchase, Terms};
use anyhow::{ensure, Result};
use octravpn_client::PrivateEndpoint;
use octravpn_core::payments::Tariff;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

const OWNER: u8 = 14;
const INTENT: u8 = 15;

/// Fresh job identities and independently accepted transport/price consent.
/// Credentials stay in the caller's unlocked books, never in this record.
pub struct Hop {
    pub payer: Payer,
    pub purchase_id: [u8; 32],
    pub terms: Terms,
    pub tariff: Tariff,
    pub endpoint: PrivateEndpoint,
    pub journal: PathBuf,
    pub interface_name: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredHop {
    book: PathBuf,
    wallet: [u8; 32],
    receipt_key: [u8; 32],
    purchase: [u8; 32],
    terms: Terms,
    tariff: Tariff,
    endpoint: PrivateEndpoint,
    journal: PathBuf,
    interface_name: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Consent {
    version: u8,
    id: [u8; 32],
    hops: Vec<StoredHop>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Saved {
    consent: Consent,
    ready: bool,
    #[serde(default)]
    network_armed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    network: Option<octravpn_client::PrivateRouteNetwork>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Owner {
    version: u8,
    route: [u8; 32],
    coordinator: [u8; 32],
    digest: [u8; 32],
    position: usize,
    count: usize,
}

/// Holds every original custody lease. This record authorizes no network path
/// or payment: the ordered route owner must still fund and admit each carrier.
pub struct Route {
    root: Payer,
    consent: Consent,
    digest: [u8; 32],
    purchases: Vec<Purchase>,
}
impl Route {
    pub async fn create(id: [u8; 32], hops: Vec<Hop>) -> Result<Self> {
        Self::open(id, hops, false).await
    }
    /// Requires the existing intent. A partial first initialization can finish
    /// only its missing, never-started jobs; admitted jobs cannot be recreated.
    pub async fn resume(id: [u8; 32], hops: Vec<Hop>) -> Result<Self> {
        Self::open(id, hops, true).await
    }
    /// Startup restores consent from the original encrypted coordinator book.
    /// Supplied books must match every stored identity, source and position;
    /// no missing route, job or child journal is replaced.
    pub async fn resume_stored(id: [u8; 32], payers: Vec<Payer>) -> Result<Self> {
        ensure!(
            id != [0; 32] && (2..=octravpn_core::onion::MAX_HOPS).contains(&payers.len()),
            "private route requires its identity and original books"
        );
        let disk = &payers[0].0.disk;
        disk.check()?;
        let mut tx = disk.begin().await?;
        let saved: Saved = disk
            .load(&mut tx, INTENT, &disk.tag(INTENT, &id)?)
            .await?
            .ok_or_else(|| anyhow::anyhow!("private route intent missing; refusing recreation"))?;
        tx.rollback().await?;
        ensure!(
            saved.consent.id == id && saved.consent.hops.len() == payers.len(),
            "stored route identity or count differs"
        );
        let hops = saved
            .consent
            .hops
            .into_iter()
            .zip(payers)
            .map(|(hop, payer)| Hop {
                payer,
                purchase_id: hop.purchase,
                terms: hop.terms,
                tariff: hop.tariff,
                endpoint: hop.endpoint,
                journal: hop.journal,
                interface_name: hop.interface_name,
            })
            .collect();
        Self::resume(id, hops).await
    }
    pub fn profiles(&self) -> Vec<octravpn_client::PrivateRouteProfile> {
        self.consent
            .hops
            .iter()
            .map(|hop| octravpn_client::PrivateRouteProfile {
                endpoint: hop.endpoint.clone(),
                target: hop.terms.target.clone(),
                interface_name: hop.interface_name.clone(),
            })
            .collect()
    }
    async fn open(id: [u8; 32], hops: Vec<Hop>, resume: bool) -> Result<Self> {
        let route = Self::prepare(id, hops)?;
        if !resume {
            route.require_fresh_jobs().await?;
        }
        let ready = route.initialize(resume).await?;
        for (position, purchase) in route.purchases.iter().enumerate() {
            route.claim(purchase, position, ready, resume).await?;
        }
        if !ready {
            route.mark_ready().await?;
        }
        route.check().await?;
        Ok(route)
    }
    fn prepare(id: [u8; 32], hops: Vec<Hop>) -> Result<Self> {
        let (consent, purchases) = consent::validate(id, hops)?;
        let mut hash = Sha256::new();
        hash.update(b"Octranet private route consent v1\0");
        hash.update(serde_json::to_vec(&consent)?);
        Ok(Self {
            root: purchases[0].payer.clone(),
            consent,
            digest: hash.finalize().into(),
            purchases,
        })
    }
    pub fn hop_count(&self) -> usize {
        self.purchases.len()
    }
    pub(super) async fn require_armed_entry(&self, purchase: &Purchase) -> Result<()> {
        self.check().await?;
        let entry = &self.purchases[0];
        ensure!(
            self.load().await?.network_armed
                && entry.id == purchase.id
                && std::sync::Arc::ptr_eq(&entry.payer.0, &purchase.payer.0),
            "retained reconnection requires the original armed route entry"
        );
        Ok(())
    }
    /// Call before P2P startup when restoring a previously armed route.
    pub async fn configure_chain(
        &self,
        swarm: &octra_node_protocol::network::swarm::Swarm,
    ) -> Result<()> {
        self.check().await?;
        if self.load().await?.network_armed {
            swarm.configure_scope(octra_node_protocol::network::swarm::TransportScope::Paused)?;
        }
        Ok(())
    }
    pub(super) fn accepts(
        &self,
        purchase: &Purchase,
        transport: &super::client::Transport,
    ) -> Result<()> {
        let position = self
            .purchases
            .iter()
            .position(|p| {
                p.id == purchase.id && std::sync::Arc::ptr_eq(&p.payer.0, &purchase.payer.0)
            })
            .ok_or_else(|| anyhow::anyhow!("purchase belongs to another route"))?;
        let hop = &self.consent.hops[position];
        let actual = &transport.plan;
        ensure!(
            actual.target == hop.terms.target
                && actual.tariff == hop.tariff
                && actual.control_url == hop.endpoint.control_url
                && actual.control_ca_pem == hop.endpoint.control_ca_pem
                && actual.control_spki == hop.endpoint.control_spki
                && actual.wireguard_endpoint == hop.endpoint.wireguard_endpoint
                && super::client::canonical_parent(&transport.journal)? == hop.journal
                && transport.interface_name == hop.interface_name
                && transport
                    .hop
                    .as_ref()
                    .is_some_and(|p| p.position == position
                        && p.count == self.hop_count()
                        && p.pins.control == hop.endpoint.pins.control
                        && p.pins.wireguard == hop.endpoint.pins.wireguard),
            "private client differs from complete route consent"
        );
        Ok(())
    }
    /// Verify all books, complete consent and every ownership marker together
    /// before the controller advances a route phase. No state is reconstructed.
    pub async fn check(&self) -> Result<()> {
        let saved = self.load().await?;
        same(&saved.consent, &self.consent)?;
        ensure!(saved.ready, "private route initialization is incomplete");
        ensure!(
            saved.network_armed == saved.network.is_some(),
            "armed route lost its sealed kernel plan"
        );
        if let Some(network) = &saved.network {
            network.validate(&self.profiles())?;
        }
        for (position, purchase) in self.purchases.iter().enumerate() {
            purchase.validate()?;
            let disk = &purchase.payer.0.disk;
            let mut tx = disk.begin().await?;
            let owner: Option<Owner> = disk.load(&mut tx, OWNER, &purchase.tag(OWNER, 0)?).await?;
            ensure!(
                purchase.check_stored(&mut tx).await? == Some(self.owner(position)),
                "private route purchase ownership differs"
            );
            tx.rollback().await?;
            let owner = owner.ok_or_else(|| anyhow::anyhow!("private route owner disappeared"))?;
            same(&owner, &self.owner(position))?;
        }
        Ok(())
    }
    fn owner(&self, position: usize) -> Owner {
        Owner {
            version: 1,
            route: self.consent.id,
            coordinator: self.root.0.wallet,
            digest: self.digest,
            position,
            count: self.purchases.len(),
        }
    }
}

#[async_trait::async_trait]
impl octravpn_client::PrivateRouteJournal for Route {
    async fn check(&self) -> Result<()> {
        Self::check(self).await
    }
    async fn network(&self) -> Result<Option<octravpn_client::PrivateRouteNetwork>> {
        self.check().await?;
        Ok(self.load().await?.network)
    }
    async fn armed(&self, network: &octravpn_client::PrivateRouteNetwork) -> Result<()> {
        self.network_state(Some(network)).await
    }
    async fn released(&self) -> Result<()> {
        self.network_state(None).await
    }
}

pub(super) async fn require_unowned(purchase: &Purchase) -> Result<()> {
    let disk = &purchase.payer.0.disk;
    let mut tx = disk.begin().await?;
    let owner: Option<Owner> = disk.load(&mut tx, OWNER, &purchase.tag(OWNER, 0)?).await?;
    let embedded = purchase.check_stored(&mut tx).await?;
    tx.rollback().await?;
    ensure!(
        owner.is_none() && embedded.is_none(),
        "private purchase belongs to an ordered route"
    );
    Ok(())
}

fn same<T: Serialize>(saved: &T, expected: &T) -> Result<()> {
    ensure!(
        serde_json::to_vec(saved)? == serde_json::to_vec(expected)?,
        "private route changes accepted consent or ownership"
    );
    Ok(())
}
