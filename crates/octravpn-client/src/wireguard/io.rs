//! Prepare local resources before escrow, bind the canonical session later.
use anyhow::Result;
use octravpn_core::session::SessionId;

use super::{forward::PreparedForward, ip::Ip, Forward, Traffic, Tunnel};

#[derive(Clone, Debug)]
pub(crate) enum Mode {
    Udp(Forward),
    Ip { name: String },
}

pub(crate) enum Prepared {
    Udp(PreparedForward),
    Ip { name: String },
}

pub(crate) enum Ready {
    Udp(PreparedForward),
    Ip(Ip),
}

impl Mode {
    pub(crate) async fn prepare(self) -> Result<Prepared> {
        match self {
            Self::Udp(forward) => Ok(Prepared::Udp(forward.prepare().await?)),
            Self::Ip { name } => {
                Ip::preflight(&name)?;
                Ok(Prepared::Ip { name })
            }
        }
    }
}

impl Prepared {
    pub(crate) fn raw_ip(&self) -> bool {
        matches!(self, Self::Ip { .. })
    }

    pub(crate) fn bind(self, session: &SessionId, wireguard_key: &[u8; 32]) -> Result<Ready> {
        match self {
            Self::Udp(forward) => Ok(Ready::Udp(forward)),
            Self::Ip { name } => Ok(Ready::Ip(Ip::open(&name, session, wireguard_key)?)),
        }
    }
}

impl Ready {
    pub(crate) async fn run(
        self,
        mut tunnel: Tunnel,
        heartbeat: impl std::future::Future<Output = Result<()>>,
    ) -> (Traffic, Result<()>) {
        // Borrow the tunnel inside this scope so cancellation of either path
        // retains all counters before the authenticated socket is dropped.
        let result = {
            let forwarding = async {
                match self {
                    Self::Udp(forward) => forward.drive(&mut tunnel).await,
                    Self::Ip(ip) => ip.drive(&mut tunnel).await,
                }
            };
            tokio::pin!(forwarding);
            tokio::pin!(heartbeat);
            tokio::select! {result=&mut forwarding=>result,result=&mut heartbeat=>result}
        };
        (tunnel.traffic(), result)
    }
}
