//! Separate durable preparation from network startup, so every accepted hop
//! journal exists before a composite route makes its first purchase.
use super::{Accounting, Client, Interface, Observation, Options, Plan};
use crate::{payments::Journal, wireguard};
use anyhow::{ensure, Result};
use octravpn_core::{ip_tunnel, payments::SignedConnect, KeyPair};
use octravpn_tun::{amnezia::WireTransport, Tun, TunAddress, TunConfig};
use std::{net::SocketAddrV4, sync::Arc};

#[derive(Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub(crate) struct Pins {
    pub(crate) wireguard: SocketAddrV4,
    pub(crate) control: SocketAddrV4,
}

pub(crate) struct Prepared {
    plan: Plan,
    journal: Accounting,
    origin: reqwest::Url,
    connect: SignedConnect,
    http: reqwest::Client,
    key: Arc<KeyPair>,
    name: String,
    pins: Option<Pins>,
    mtu: u16,
}
impl Prepared {
    pub(crate) async fn new(options: Options, pins: Option<Pins>, mtu: u16) -> Result<Self> {
        let Options {
            plan,
            journal: path,
            receipt_key: key,
            interface_name: name,
            mode,
        } = options;
        let origin = plan.origin()?;
        ensure!(
            (68..=ip_tunnel::MTU as u16).contains(&mtu),
            "invalid paid IPv4 MTU"
        );
        ensure!(
            !name.is_empty()
                && name.len() <= 15
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
            "invalid TUN name"
        );
        let wg = wireguard::public_key(&key);
        let mut builder = plan.control_http()?;
        if let Some(pins) = pins {
            let host = origin
                .host_str()
                .ok_or_else(|| anyhow::anyhow!("missing control host"))?;
            ensure!(
                origin.port_or_known_default() == Some(pins.control.port()),
                "control pin port differs"
            );
            builder = builder.resolve(host, pins.control.into());
        }
        // Build TLS trust before any journal or authorization is created.
        let http = builder.build()?;
        let binding = plan.binding.clone();
        let tariff = plan.tariff.clone();
        let journal_key = key.clone();
        let budget = plan.original_budget_ou;
        let prepaid = plan.prepaid_bytes.clone();
        let journal = Accounting::new(
            tokio::task::spawn_blocking(move || {
                Journal::open(&path, binding, tariff, budget, prepaid, journal_key, mode)
            })
            .await??,
        );
        let connect = journal.with(move |journal| journal.connect(wg)).await?;
        Ok(Self {
            plan,
            journal,
            origin,
            connect,
            http,
            key,
            name,
            pins,
            mtu,
        })
    }

    pub(crate) async fn open(self) -> Result<Client> {
        let Self {
            plan,
            journal,
            origin,
            connect,
            http,
            key,
            name,
            pins,
            mtu,
        } = self;
        let initial =
            Observation::new(super::status(&http, &origin, &connect, &plan, &journal).await?);
        // No payload path exists until the exact finite purchases are canonical.
        let initial = super::prepay(&http, &origin, &connect, &plan, &journal, initial).await?;
        let session = plan.binding.session_id()?;
        let server = initial.signed.status.server_wireguard_key;
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
        let assigned = ip_tunnel::address(&session, &wireguard::public_key(&key));
        let device = tokio::task::spawn_blocking(move || {
            Tun::open(&TunConfig {
                name,
                address: TunAddress::new(assigned, 32),
                mtu,
                up_at_open: true,
            })
        })
        .await??;
        let interface = Interface {
            name: device.name().to_owned(),
            address: assigned,
            mtu,
        };
        Ok(Client {
            plan,
            journal,
            origin,
            connect,
            http,
            initial,
            tunnel,
            device,
            interface,
        })
    }
}
