//! Ordered native funding hooks around the shared paid route supervisor.
//! The host supplies its canonical payer and actual chain socket scope owner.
use super::{service, Pins};
use crate::{
    paid_routes::CompositeRouteGuard, Interface, PrivateEndpoint, PrivatePaymentClient,
    PrivatePaymentSummary,
};
use anyhow::{ensure, Result};
use octravpn_core::payments::PrivateTarget;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

#[derive(Clone)]
pub struct Profile {
    pub endpoint: PrivateEndpoint,
    pub target: PrivateTarget,
    pub interface_name: String,
}
#[async_trait::async_trait]
pub trait Hop: Send {
    fn profile(&self) -> Profile;
    /// Canonical payment only. Must be durable and idempotent across retries;
    /// an operator acknowledgement alone cannot establish this state.
    async fn fund(&mut self) -> Result<()>;
    async fn open(self: Box<Self>) -> Result<PrivatePaymentClient>;
}
#[async_trait::async_trait]
pub trait Journal: Send + Sync {
    async fn check(&self) -> Result<()>;
    async fn network(&self) -> Result<Option<crate::PrivateRouteNetwork>>;
    /// Persist before kernel changes, so restart cannot select direct bootstrap.
    async fn armed(&self, network: &crate::PrivateRouteNetwork) -> Result<()>;
    async fn released(&self) -> Result<()>;
}
#[async_trait::async_trait]
pub trait Chain: Send + Sync {
    fn socket_mark(&self) -> u32;
    async fn pause(&mut self) -> Result<()>;
    async fn activate(&mut self, entry: &Interface) -> Result<()>;
    fn check(&self) -> Result<()>;
    /// Called only after successful explicit disconnect and route removal.
    async fn release(&mut self) -> Result<()>;
}

pub struct Client(service::Route<PrivatePaymentSummary>);
impl Client {
    pub async fn open(
        mut hops: Vec<Box<dyn Hop>>,
        journal: Arc<dyn Journal>,
        mut chain: Box<dyn Chain>,
    ) -> Result<Self> {
        ensure!(
            cfg!(target_os = "linux"),
            "coordinated paid routes require Linux"
        );
        let profiles = hops.iter().map(|hop| hop.profile()).collect::<Vec<_>>();
        let pins = validate(&profiles)?;
        journal.check().await?;
        let entry = pins[0].wireguard;
        let controls = pins.iter().map(|pin| pin.control).collect::<Vec<_>>();
        let peers = pins[1..]
            .iter()
            .map(|pin| pin.wireguard)
            .collect::<Vec<_>>();
        let names = profiles
            .iter()
            .map(|p| p.interface_name.clone())
            .collect::<Vec<_>>();
        let mark = chain.socket_mark();
        ensure!(
            mark != 0,
            "chain route requires a privileged nonzero socket mark"
        );
        let previous = journal.network().await?;
        let mut routes = tokio::task::spawn_blocking(move || {
            CompositeRouteGuard::reserve_chain(
                entry,
                &controls,
                &peers,
                &names,
                mark,
                previous.as_ref(),
            )
        })
        .await??;
        // Reserve the host namespace and check all pins before spending, while
        // authenticated bootstrap chain access is still available for entry.
        hops[0].fund().await?;
        journal.check().await?;
        journal.armed(&routes.network()?).await?;
        chain.pause().await?;
        routes.activate()?;
        let mut chain = Some(chain);
        let mut route = service::Route::new(routes, journal.clone());
        for (position, (mut hop, profile)) in hops.into_iter().zip(profiles).enumerate() {
            route.next(pins[position])?;
            let opened = async move {
                if position != 0 {
                    hop.fund().await?;
                }
                let client = hop.open().await?;
                let actual = client.accepted();
                ensure!(
                    client.interface().name == profile.interface_name
                        && client.peer_addr()
                            == std::net::SocketAddr::V4(profile.endpoint.pins.wireguard)
                        && client.control_pin() == Some(profile.endpoint.pins.control)
                        && actual.target == profile.target
                        && actual.control_url == profile.endpoint.control_url
                        && actual.control_ca_pem == profile.endpoint.control_ca_pem
                        && actual.control_spki == profile.endpoint.control_spki
                        && actual.wireguard_endpoint == profile.endpoint.wireguard_endpoint,
                    "funded client differs from accepted route transport"
                );
                Ok(client)
            };
            route.admit(opened).await?;
            if position == 0 {
                let entry = route.interfaces()[0].clone();
                route.routes_chain(&entry)?;
                let mut scoped = chain
                    .take()
                    .ok_or_else(|| anyhow::anyhow!("chain owner missing"))?;
                scoped.activate(&entry).await?;
                scoped.check()?;
                route.chain = Some(scoped);
            }
        }
        route.finish().await?;
        Ok(Self(route))
    }
    pub fn interfaces(&self) -> &[Interface] {
        self.0.interfaces()
    }
    pub async fn run(
        self,
        shutdown: impl std::future::Future<Output = Result<()>>,
    ) -> Result<Vec<PrivatePaymentSummary>> {
        self.0.run(shutdown).await
    }
}

fn validate(profiles: &[Profile]) -> Result<Vec<Pins>> {
    ensure!(
        (2..=octravpn_core::onion::MAX_HOPS).contains(&profiles.len()),
        "funded route requires two or three hops"
    );
    let mut names = BTreeSet::new();
    let mut addresses = BTreeMap::new();
    let mut pins = Vec::new();
    let origin = profiles[0].target.chain_origin;
    for (i, p) in profiles.iter().enumerate() {
        ensure!(
            p.target.chain_origin == origin,
            "funded route crosses chain origins"
        );
        p.endpoint.control(p.target.clone())?;
        super::super::paid_routes::validate_interface(&p.interface_name)?;
        ensure!(
            p.interface_name != "tailscale0" && names.insert(p.interface_name.clone()),
            "duplicate or reserved route interface"
        );
        for ip in [p.endpoint.pins.control.ip(), p.endpoint.pins.wireguard.ip()] {
            ensure!(
                addresses.insert(*ip, i).is_none_or(|prior| prior == i),
                "route endpoint IP belongs to several hops"
            );
        }
        pins.push(Pins {
            control: p.endpoint.pins.control,
            wireguard: p.endpoint.pins.wireguard,
        });
    }
    Ok(pins)
}
