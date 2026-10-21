//! Experimental private prepaid transport. Native note purchasing is a separate
//! service; this client holds only its receipt key and never submits payments.
mod monitor;
use crate::{
    payment_runner::{self, accounting::Accounting, Interface, Pins},
    payments::{Journal, OpenMode},
    wireguard, PrivateControl,
};
use anyhow::{ensure, Result};
use octravpn_core::{
    ip_tunnel,
    payments::{PlanBinding, PrivateTarget, SignedConnect, SignedShieldedStatus, Tariff},
    Address, KeyPair,
};
use octravpn_tun::{amnezia::WireTransport, Tun, TunAddress, TunConfig};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, sync::Arc};

/// Independently accepted private channel and finite class caps. A signed
/// operator status is an observation, never proof of canonical note funding.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub target: PrivateTarget,
    pub binding: PlanBinding,
    pub tariff: Tariff,
    pub operator_generation: u64,
    /// Allocation/price ceiling, not available or withdrawable channel OCT.
    pub quote_ceiling_ou: u64,
    pub prepaid_bytes: Vec<u64>,
    pub control_url: String,
    pub control_ca_pem: String,
    pub control_spki: Vec<[u8; 32]>,
    pub wireguard_endpoint: String,
}
impl Plan {
    pub(crate) fn validate(&self) -> Result<()> {
        self.target.pool.validate()?;
        self.binding.validate()?;
        octravpn_core::parse_native_address(self.target.directory.display())?;
        ensure!(
            self.target.chain_origin != [0; 32]
                && self.binding.deployment == self.target.pool
                && self.binding.generation == 1
                && self.binding.plan > 0
                && self.operator_generation > 0
                && self.quote_ceiling_ou > 0
                && Address::from_pubkey(&self.target.operator.0) == *self.tariff.operator()
                && self.tariff.hash_hex()? == self.binding.manifest_hash
                && i64::try_from(self.quote_ceiling_ou).is_ok(),
            "private plan identity differs"
        );
        ensure!(
            !ed25519_dalek::VerifyingKey::from_bytes(&self.target.operator.0)?.is_weak(),
            "weak private operator key"
        );
        crate::payments::validate_purchase(
            &self.tariff,
            self.quote_ceiling_ou,
            &self.prepaid_bytes,
        )?;
        wireguard::validate_endpoint(&self.wireguard_endpoint)?;
        Ok(())
    }
    pub(crate) fn control(&self, pins: Option<Pins>) -> Result<PrivateControl> {
        self.validate()?;
        PrivateControl::at(
            &self.control_url,
            self.target.clone(),
            &self.control_ca_pem,
            self.control_spki.clone(),
            pins.map(|p| p.control),
        )
    }
}

pub struct Options {
    pub plan: Plan,
    pub journal: PathBuf,
    pub receipt_key: Arc<KeyPair>,
    pub interface_name: String,
    pub mode: OpenMode,
}
pub struct Summary {
    pub confirmed_bytes: Vec<u64>,
    pub held_bytes: Vec<u64>,
    pub authorized_bytes: Vec<u64>,
}

/// Offline, encrypted client preparation. This reserves a connection sequence
/// without contacting the operator, buying capacity, or creating a payload path.
/// Keep the journal after cancellation; open() still requires canonical funding.
pub struct Pending(Local);
impl Pending {
    pub async fn new(options: Options) -> Result<Self> {
        Ok(Self(
            Local::new(options, None, ip_tunnel::MTU as u16).await?,
        ))
    }
    pub async fn for_hop(
        options: Options,
        pins: crate::MultiRoutePins,
        position: usize,
        hops: usize,
    ) -> Result<Self> {
        crate::multihop::private::transport(&options.plan, pins)?;
        ensure!(
            options.interface_name != "tailscale0",
            "reserved composite TUN name"
        );
        let mtus = crate::multihop::mtu::route_mtus(hops)?;
        let mtu = *mtus
            .get(position)
            .ok_or_else(|| anyhow::anyhow!("private hop position exceeds route"))?;
        Ok(Self(
            Local::new(
                options,
                Some(Pins {
                    wireguard: pins.wireguard,
                    control: pins.control,
                }),
                mtu,
            )
            .await?,
        ))
    }
    /// Recheck the held writer and encrypted snapshot before native payment.
    /// A removed, replaced or ambiguously written journal cannot be reset here.
    pub async fn check(&self) -> Result<()> {
        self.0.journal.with(|journal| journal.ready()).await
    }
    /// Authenticate current funded capacity without opening a tunnel or route.
    pub async fn admit(self) -> Result<Prepared> {
        self.0.connect().await
    }
    pub async fn open(self) -> Result<Client> {
        Box::pin(self.admit().await?.open()).await
    }
}

/// Owns the encrypted journal and an authenticated admission snapshot. No UDP,
/// TUN or routes exist until open(). Preserve the journal after cancellation.
pub struct Prepared {
    plan: Plan,
    journal: Accounting,
    key: Arc<KeyPair>,
    control: PrivateControl,
    connect: SignedConnect,
    status: monitor::Observation,
    name: String,
    pins: Option<Pins>,
    mtu: u16,
}
impl Prepared {
    pub async fn new(options: Options) -> Result<Self> {
        Local::new(options, None, ip_tunnel::MTU as u16)
            .await?
            .connect()
            .await
    }
}

/// Local encrypted state only. Composite routes prepare every hop before any
/// control request, then admit downstream hops through their paid predecessor.
pub(crate) struct Local {
    plan: Plan,
    journal: Accounting,
    key: Arc<KeyPair>,
    control: PrivateControl,
    connect: SignedConnect,
    name: String,
    pins: Option<Pins>,
    mtu: u16,
}
impl Local {
    pub(crate) async fn new(options: Options, pins: Option<Pins>, mtu: u16) -> Result<Self> {
        let Options {
            plan,
            journal: path,
            receipt_key: key,
            interface_name: name,
            mode,
        } = options;
        let control = plan.control(pins)?;
        ensure!(
            (68..=ip_tunnel::MTU as u16).contains(&mtu),
            "invalid private IPv4 MTU"
        );
        ensure!(
            plan.binding.payer == Address::from_pubkey(&key.public.0),
            "private receipt identity differs"
        );
        ensure!(
            !name.is_empty()
                && name.len() <= 15
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
            "invalid TUN name"
        );
        let accepted = plan.clone();
        let stored_key = key.clone();
        let journal = Accounting::new(
            tokio::task::spawn_blocking(move || {
                Journal::open_private(&path, &accepted, stored_key, mode)
            })
            .await??,
        );
        let public = wireguard::public_key(&key);
        let connect = journal.with(move |j| j.connect(public)).await?;
        Ok(Self {
            plan,
            journal,
            key,
            control,
            connect,
            name,
            pins,
            mtu,
        })
    }
    async fn connect(self) -> Result<Prepared> {
        let Self {
            plan,
            journal,
            key,
            control,
            connect,
            name,
            pins,
            mtu,
        } = self;
        let status = monitor::initial(&control, &connect, &plan, &journal).await?;
        ensure!(
            monitor::purchased(&status.signed, &plan),
            "private canonical prepaid capacity missing"
        );
        // This is only a durable local cap. No public usage or native call is
        // sent, and the remote meter still requires its canonical funded floor.
        journal.with(Journal::purchases).await?;
        Ok(Prepared {
            plan,
            journal,
            key,
            control,
            connect,
            status,
            name,
            pins,
            mtu,
        })
    }
    pub(crate) async fn open(self) -> Result<Client> {
        Box::pin(self.connect().await?.open()).await
    }
}
impl Prepared {
    pub fn status(&self) -> &SignedShieldedStatus {
        &self.status.signed
    }
    pub async fn open(self) -> Result<Client> {
        let Self {
            plan,
            journal,
            key,
            control,
            connect,
            status: _,
            name,
            pins,
            mtu,
        } = self;
        // Recheck after any caller delay before creating a payload path.
        let status = monitor::poll(&control, &connect, &plan, &journal).await?;
        ensure!(
            monitor::purchased(&status.signed, &plan),
            "private prepaid capacity regressed"
        );
        let session = plan.binding.session_id()?;
        let server = status.signed.status.server_wireguard_key;
        let tunnel = if let Some(pins) = pins {
            wireguard::Tunnel::connect_to_addr(
                session.clone(),
                &key,
                &plan.wireguard_endpoint,
                pins.wireguard,
                server,
                None,
                WireTransport::default(),
            )
            .await?
        } else {
            wireguard::Tunnel::connect(
                session.clone(),
                &key,
                &plan.wireguard_endpoint,
                server,
                None,
                WireTransport::default(),
            )
            .await?
        };
        let address = ip_tunnel::address(&session, &wireguard::public_key(&key));
        let device = tokio::task::spawn_blocking(move || {
            Tun::open(&TunConfig {
                name,
                address: TunAddress::new(address, 32),
                mtu,
                up_at_open: true,
            })
        })
        .await??;
        let interface = Interface {
            name: device.name().to_owned(),
            address,
            mtu,
        };
        Ok(Client {
            plan,
            journal,
            control,
            connect,
            status,
            tunnel,
            device,
            interface,
        })
    }
}

/// Opens one explicitly provisioned private prepaid interface. Host routing
/// remains caller-owned; this does not enable the released multihop CLI mode.
pub struct Client {
    plan: Plan,
    journal: Accounting,
    control: PrivateControl,
    connect: SignedConnect,
    status: monitor::Observation,
    tunnel: wireguard::Tunnel,
    device: Tun,
    interface: Interface,
}
impl Client {
    pub(crate) fn accepted(&self) -> &Plan {
        &self.plan
    }
    pub(crate) fn peer_addr(&self) -> std::net::SocketAddr {
        self.tunnel.peer_addr()
    }
    pub(crate) fn control_pin(&self) -> Option<std::net::SocketAddrV4> {
        self.control.peer_pin()
    }
    pub async fn open(options: Options) -> Result<Self> {
        let prepared = Box::pin(Prepared::new(options)).await?;
        Box::pin(prepared.open()).await
    }
    pub const fn interface(&self) -> &Interface {
        &self.interface
    }
    pub async fn run(
        self,
        shutdown: impl std::future::Future<Output = Result<()>>,
    ) -> Result<Summary> {
        let Self {
            plan,
            journal,
            control,
            connect,
            status,
            tunnel,
            device,
            interface,
        } = self;
        status.freshness.ensure_live()?;
        let (stop, stopped) = tokio::sync::watch::channel(false);
        let driver = payment_runner::drive(tunnel, device, interface, journal.clone());
        let monitoring = monitor::run(control, connect, plan, journal.clone(), status, stopped);
        let result = payment_runner::supervise(journal, driver, monitoring, stop, shutdown).await?;
        Ok(Summary {
            confirmed_bytes: result.confirmed_bytes,
            held_bytes: result.held_bytes,
            authorized_bytes: result.authorized_bytes,
        })
    }
}

#[cfg(test)]
mod tests;
