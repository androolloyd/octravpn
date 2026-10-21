//! Native payer adapter for the owned, ordered client route supervisor.
use super::super::{
    client::{self, Prepared, Transport},
    Services, State,
};
use super::Route;
use crate::{rpc::Submission, vpn::payments::shielded::wallet::Wallet, Host};
use anyhow::{ensure, Context, Result};
use ed25519_dalek::SigningKey;
use octra_node_protocol::network::swarm::{ScopeLease, Swarm, TransportScope};
use octra_private_payments_experimental::pool::transaction::Prover;
use octravpn_client::{
    FundedPrivateRoute, PrivateControl, PrivatePaymentClient, PrivateRouteChain, PrivateRouteHop,
    PrivateRouteProfile,
};
use octravpn_core::payments::PlanBinding;
use std::{collections::BTreeMap, net::Ipv4Addr, sync::Arc, time::Duration};
pub const SOCKET_MARK: u32 = 0x4f43_544e;

pub struct Resources<A: Host> {
    pub index: super::index::IndexHandle,
    pub submission: Arc<Submission<A>>,
    pub relayer: Arc<SigningKey>,
    pub prover: Prover,
    pub income: Option<tokio::sync::watch::Receiver<Option<Wallet>>>,
}

/// The node and its canonical indexes must already be running. On restart,
/// configure_chain() must have selected Paused before P2P startup if armed.
pub async fn open<A: Host>(
    route: Arc<Route>,
    resources: Vec<Resources<A>>,
    chain_dns: BTreeMap<String, Ipv4Addr>,
) -> Result<FundedPrivateRoute> {
    route.check().await?;
    ensure!(
        resources.len() == route.hop_count(),
        "route resources differ from consent"
    );
    let swarm = resources[0].submission.swarm.clone();
    for (purchase, service) in route.purchases.iter().zip(&resources) {
        ensure!(
            service.index.belongs_to(&purchase.payer.1)
                && Arc::ptr_eq(
                    &purchase.payer.1.directory.shared,
                    &service.submission.node.shared
                )
                && swarm.same_instance(&service.submission.swarm)
                && service.relayer.verifying_key().to_bytes() == purchase.terms.relayer_public,
            "route resources belong to another node, pool or relayer"
        );
    }
    let scope = TransportScope::Interface {
        name: route.consent.hops[0].interface_name.clone(),
        pins: chain_dns.clone(),
        mark: SOCKET_MARK,
    };
    // Validate both platform and proxy compatibility before any purchase.
    swarm.validate_scope(&scope)?;
    if route.load().await?.network_armed {
        ensure!(
            matches!(swarm.transport_scope(), TransportScope::Paused)
                || swarm.transport_scope() == scope,
            "armed route restart requires paused or original-entry chain transport before startup"
        );
    }
    let mut hops = Vec::<Box<dyn PrivateRouteHop>>::new();
    for (position, resources) in resources.into_iter().enumerate() {
        let accepted = &route.consent.hops[position];
        let control = accepted.endpoint.control(accepted.terms.target.clone())?;
        hops.push(Box::new(Hop {
            route: route.clone(),
            position,
            resources,
            control,
            prepared: None,
        }));
    }
    Box::pin(FundedPrivateRoute::open(
        hops,
        route,
        Box::new(Chain {
            swarm,
            pins: chain_dns,
            lease: None,
        }),
    ))
    .await
}

struct Hop<A: Host> {
    route: Arc<Route>,
    position: usize,
    resources: Resources<A>,
    control: PrivateControl,
    prepared: Option<Prepared>,
}
impl<A: Host> Hop<A> {
    async fn channel(&self) -> Result<PlanBinding> {
        let purchase = &self.route.purchases[self.position];
        if let Some(reply) = purchase.reply(0).await? {
            return purchase.opened(&reply);
        }
        ensure!(
            self.position != 0 || !self.route.load().await?.network_armed,
            "armed entry lost its authenticated channel; refusing new bootstrap"
        );
        loop {
            self.route.check().await?;
            let result = async {
                let index = self.resources.index.get().await.context("resume route pool index")?;
                let _purchases = purchase.payer.0.purchases.lock().await;
                if index.sync(128).await.context("sync route pool index")?.complete {
                    let view = index.view().await?;
                    let (_, now) = purchase.payer.current(view.index()).await?;
                    let (binding, _) = purchase.open_at(now, &self.control).await?;
                    view.with_current(|_| Ok(()))?;
                    return Ok(Some(binding));
                }
                Ok::<_, anyhow::Error>(None)
            }
            .await;
            match result {
                Ok(Some(binding)) => return Ok(binding),
                Err(error) if !error.is::<crate::published::Unavailable>() => return Err(error),
                _ => {}
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }
    fn transport(&self, binding: PlanBinding) -> Result<Transport> {
        let hop = &self.route.consent.hops[self.position];
        let bytes = hop.terms.prepaid(&hop.tariff)?;
        Ok(Transport {
            plan: octravpn_client::AcceptedPrivatePlan {
                target: hop.terms.target.clone(),
                binding,
                tariff: hop.tariff.clone(),
                operator_generation: hop.terms.operator_generation,
                quote_ceiling_ou: hop.terms.ceiling_ou,
                prepaid_bytes: bytes,
                control_url: hop.endpoint.control_url.clone(),
                control_ca_pem: hop.endpoint.control_ca_pem.clone(),
                control_spki: hop.endpoint.control_spki.clone(),
                wireguard_endpoint: hop.endpoint.wireguard_endpoint.clone(),
            },
            journal: hop.journal.clone(),
            interface_name: hop.interface_name.clone(),
            hop: Some(client::Hop {
                pins: hop.endpoint.pins,
                position: self.position,
                count: self.route.hop_count(),
            }),
        })
    }
}
#[async_trait::async_trait]
impl<A: Host> PrivateRouteHop for Hop<A> {
    fn profile(&self) -> PrivateRouteProfile {
        let hop = &self.route.consent.hops[self.position];
        PrivateRouteProfile {
            endpoint: hop.endpoint.clone(),
            target: hop.terms.target.clone(),
            interface_name: hop.interface_name.clone(),
        }
    }
    async fn fund(&mut self) -> Result<()> {
        self.route.check().await?;
        if self.prepared.is_some() {
            return Ok(());
        }
        let binding = self.channel().await.context("open private route channel")?;
        let transport = self.transport(binding)?;
        let purchase = &self.route.purchases[self.position];
        let mut prepared = Box::pin(purchase.prepare_guarded(transport, Some(self.route.clone())))
            .await
            .context("prepare private route client")?;
        if self.position == 0 && self.route.load().await?.network_armed {
            prepared
                .resume_entry(&self.resources.submission.node)
                .await?;
        } else if !loop {
            match prepared.resume_credit().await {
                Ok(credited) => break credited,
                Err(error) if !error.is::<crate::published::Unavailable>() => return Err(error),
                Err(_) => tokio::time::sleep(Duration::from_millis(250)).await,
            }
        } {
            let index = self.resources.index.get().await?;
            loop {
                let result = async {
                    if let Some(income) = &mut self.resources.income {
                        let wallet = income
                            .wait_for(Option::is_some)
                            .await?
                            .as_ref()
                            .context("route income wallet unavailable")?
                            .clone();
                        if index.sync(128).await?.complete {
                            let view = index.view().await?;
                            purchase.payer.attach_income(&wallet, view.index()).await?;
                            view.with_current(|_| Ok(()))?;
                        }
                    }
                    Box::pin(prepared.step(Services {
                        index: &index,
                        submission: &self.resources.submission,
                        control: &self.control,
                        relayer: &self.resources.relayer,
                        prover: &self.resources.prover,
                    }))
                    .await
                }
                .await;
                match result {
                    Ok(State::Credited { .. }) => break,
                    Err(error) if !error.is::<crate::published::Unavailable>() => {
                        return Err(error.context("fund private route hop"))
                    }
                    _ => {}
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
        self.prepared = Some(prepared);
        Ok(())
    }
    async fn open(mut self: Box<Self>) -> Result<PrivatePaymentClient> {
        self.route.check().await?;
        let prepared = self
            .prepared
            .take()
            .context("private hop has no canonical funding")?;
        Box::pin(prepared.open())
            .await
            .context("open funded private route hop")
    }
}

struct Chain {
    swarm: Swarm,
    pins: BTreeMap<String, Ipv4Addr>,
    lease: Option<ScopeLease>,
}
#[async_trait::async_trait]
impl PrivateRouteChain for Chain {
    fn socket_mark(&self) -> u32 {
        SOCKET_MARK
    }
    async fn pause(&mut self) -> Result<()> {
        self.lease = Some(self.swarm.change_scope(TransportScope::Paused).await?);
        Ok(())
    }
    async fn activate(&mut self, entry: &octravpn_client::Interface) -> Result<()> {
        self.lease = Some(
            self.swarm
                .change_scope(TransportScope::Interface {
                    name: entry.name.clone(),
                    pins: self.pins.clone(),
                    mark: SOCKET_MARK,
                })
                .await?,
        );
        Ok(())
    }
    fn check(&self) -> Result<()> {
        self.lease
            .as_ref()
            .context("chain scope has not activated")?
            .check()
            .map_err(Into::into)
    }
    async fn release(&mut self) -> Result<()> {
        self.lease = Some(self.swarm.change_scope(TransportScope::Public).await?);
        Ok(())
    }
}
