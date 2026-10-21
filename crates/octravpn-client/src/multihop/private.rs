//! Explicit private paid routes. Funding is provisioned by the native payer
//! service; this transport cannot buy capacity or fall back to public payments.
use super::{
    absolute, journal, mtu, service, validate_layout, validate_pins, Layout, Pins, RoutePins,
};
use crate::{
    paid_routes::CompositeRouteGuard, private_runner, JournalMode, PrivatePaymentOptions,
    PrivatePaymentSummary,
};
use anyhow::{ensure, Result};
use octravpn_core::sealed::{Key, Protection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::Read as _,
    path::{Path, PathBuf},
    sync::Arc,
};

/// Each hop uses a separate receipt key, encrypted journal and accepted plan.
/// Mandatory IP pins prevent bootstrap DNS from disclosing downstream names.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RoutePlan {
    pub journal: PathBuf,
    pub hops: Vec<HopPlan>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HopPlan {
    pub plan: crate::AcceptedPrivatePlan,
    pub journal: PathBuf,
    pub receipt_key: PathBuf,
    pub interface_name: String,
    pub pins: RoutePins,
}
impl RoutePlan {
    pub fn load(path: &Path) -> Result<Self> {
        let mut bytes = Vec::new();
        std::fs::File::open(path)?
            .take(524_289)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= 524_288,
            "accepted private route exceeds byte bound"
        );
        let mut route: Self = serde_json::from_slice(&bytes)?;
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        route.journal = absolute(&parent.join(&route.journal))?;
        for hop in &mut route.hops {
            hop.journal = absolute(&parent.join(&hop.journal))?;
            hop.receipt_key = absolute(&parent.join(&hop.receipt_key))?;
        }
        Ok(route)
    }
    pub fn options(self, mode: JournalMode) -> Result<Options> {
        ensure!(
            (2..=octravpn_core::onion::MAX_HOPS).contains(&self.hops.len()),
            "a composite route requires two or three hops"
        );
        // Validate every transport pin before loading any secret or journal.
        for hop in &self.hops {
            transport(&hop.plan, hop.pins)?;
        }
        let mut hops = Vec::new();
        let mut pins = Vec::new();
        for hop in self.hops {
            let key = hop
                .receipt_key
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("receipt key path is not UTF-8"))?;
            hops.push(PrivatePaymentOptions {
                plan: hop.plan,
                journal: hop.journal,
                receipt_key: Arc::new(crate::wallet::load_keypair(key)?),
                interface_name: hop.interface_name,
                mode,
            });
            pins.push(hop.pins);
        }
        let options = Options {
            journal: self.journal,
            hops,
            pins,
            mode,
        };
        validate(&options)?;
        Ok(options)
    }
}
pub struct Options {
    pub journal: PathBuf,
    pub hops: Vec<PrivatePaymentOptions>,
    pub pins: Vec<RoutePins>,
    pub mode: JournalMode,
}

/// Experimental Linux nested transport. Each operator independently enforces
/// canonical private funding. This API submits no public or private payment.
pub struct Client(service::Route<PrivatePaymentSummary>);
impl Client {
    pub async fn open(options: Options) -> Result<Self> {
        let pins = validate(&options)?;
        let mtus = mtu::route_mtus(options.hops.len())?;
        let journal = lease(&options, &pins, &mtus)?;
        let entry = pins[0].wireguard;
        let controls = pins.iter().map(|pin| pin.control).collect::<Vec<_>>();
        let peers = pins[1..]
            .iter()
            .map(|pin| pin.wireguard)
            .collect::<Vec<_>>();
        let names = options
            .hops
            .iter()
            .map(|hop| hop.interface_name.clone())
            .collect::<Vec<_>>();
        let routes = tokio::task::spawn_blocking(move || {
            CompositeRouteGuard::arm(entry, &controls, &peers, &names)
        })
        .await??;
        let mut prepared = Vec::new();
        for ((hop, pin), mtu) in options.hops.into_iter().zip(pins.iter().copied()).zip(mtus) {
            prepared.push(private_runner::Local::new(hop, Some(pin), mtu).await?);
        }
        Ok(Self(
            service::Route::open(prepared, &pins, routes, journal).await?,
        ))
    }
    pub fn interfaces(&self) -> &[crate::Interface] {
        self.0.interfaces()
    }
    pub async fn run(
        self,
        shutdown: impl std::future::Future<Output = Result<()>>,
    ) -> Result<Vec<PrivatePaymentSummary>> {
        self.0.run(shutdown).await
    }
}
pub(crate) fn transport(plan: &crate::AcceptedPrivatePlan, pin: RoutePins) -> Result<()> {
    plan.validate()?;
    crate::PrivateEndpoint {
        control_url: plan.control_url.clone(),
        control_ca_pem: plan.control_ca_pem.clone(),
        control_spki: plan.control_spki.clone(),
        wireguard_endpoint: plan.wireguard_endpoint.clone(),
        pins: pin,
    }
    .control(plan.target.clone())?;
    Ok(())
}
fn validate(options: &Options) -> Result<Vec<Pins>> {
    ensure!(
        options.pins.len() == options.hops.len(),
        "private route pin count differs from hop count"
    );
    validate_layout(
        &options.journal,
        options.mode,
        options.hops.iter().map(|hop| Layout {
            binding: &hop.plan.binding,
            journal: &hop.journal,
            receipt_key: &hop.receipt_key,
            interface_name: &hop.interface_name,
            mode: hop.mode,
        }),
    )?;
    let mut pins = Vec::new();
    let mut chain = None;
    for (hop, pin) in options.hops.iter().zip(&options.pins) {
        ensure!(
            hop.plan.binding.payer
                == octravpn_core::Address::from_pubkey(&hop.receipt_key.public.0),
            "private route receipt identity differs"
        );
        transport(&hop.plan, *pin)?;
        let identity = hop.plan.target.chain_origin;
        ensure!(
            chain.is_none_or(|accepted| accepted == identity),
            "private route chain differs between hops"
        );
        chain = Some(identity);
        pins.push(Pins {
            wireguard: pin.wireguard,
            control: pin.control,
        });
    }
    validate_pins(&pins)?;
    Ok(pins)
}
fn lease(options: &Options, pins: &[Pins], mtus: &[u16]) -> Result<journal::Lease> {
    ensure!(
        options.hops.len() == pins.len() && pins.len() == mtus.len(),
        "private route identity lengths differ"
    );
    let identity = options.hops.iter().zip(pins).zip(mtus).map(|((hop, pin), mtu)| {
        Ok(serde_json::json!({"plan":hop.plan,"journal":absolute(&hop.journal)?,
            "interface":hop.interface_name,"receipt_key":hop.receipt_key.public.0,"pin":pin,"mtu":mtu}))
    }).collect::<Result<Vec<_>>>()?;
    let identity = serde_json::to_value(identity)?;
    let mut hash = Sha256::new();
    hash.update(b"Octranet private nested prepaid route v1\0");
    hash.update(serde_json::to_vec(&identity)?);
    let scope: [u8; 32] = hash.finalize().into();
    let first = options
        .hops
        .first()
        .ok_or_else(|| anyhow::anyhow!("private route has no entry"))?;
    let protection = Protection::new(
        Key::from_bytes(*first.receipt_key.secret_bytes())
            .derive(b"private route journal", &scope)?,
        scope,
    );
    journal::Lease::identity(&options.journal, options.mode, identity, Some(protection))
}

#[cfg(test)]
mod tests;
