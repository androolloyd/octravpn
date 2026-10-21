//! Host-only chain socket policy. Peer identity, frames and finality are
//! unchanged. A transition acknowledges only after the old IO tasks stop.
use super::{Error, Swarm, TcpListener, TcpStream};
use std::{collections::BTreeMap, net::Ipv4Addr};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scope {
    Public,
    Paused,
    Interface {
        name: String,
        /// Accepted hostname pins; bound mode never consults host DNS.
        pins: BTreeMap<String, Ipv4Addr>,
        /// Nonzero privileged socket mark accepted by the host's chain policy.
        mark: u32,
    },
}
#[derive(Clone)]
pub(super) struct Request {
    pub revision: u64,
    pub scope: Scope,
}
pub struct Lease {
    swarm: Swarm,
    scope_revision: u64,
    scope: Scope,
}
impl Scope {
    pub(super) fn validate(&self, proxy: bool) -> Result<(), Error> {
        if let Self::Interface { name, pins, mark } = self {
            if !cfg!(target_os = "linux") {
                return Err("interface-bound P2P requires Linux".into());
            }
            if proxy
                || *mark == 0
                || name.is_empty()
                || name.len() > 15
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
                || pins.len() > 1024
                || pins.keys().any(|host| {
                    host.is_empty()
                        || host.len() > 253
                        || !host
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"-.".contains(&b))
                })
            {
                return Err("invalid interface-bound P2P policy or proxy conflict".into());
            }
        }
        Ok(())
    }
    pub(super) fn paused(&self) -> bool {
        matches!(self, Self::Paused)
    }
    pub(super) fn listener(&self, listener: &TcpListener) -> Result<(), Error> {
        #[cfg(target_os = "linux")]
        {
            let socket = socket2::SockRef::from(listener);
            match self {
                Self::Interface { name, mark, .. } => socket
                    .set_mark(*mark)
                    .and_then(|()| socket.bind_device(Some(name.as_bytes()))),
                Self::Public => {
                    if socket.mark().map_err(|e| Error::from(e.to_string()))? != 0 {
                        socket.set_mark(0).map_err(|e| Error::from(e.to_string()))?;
                    }
                    if socket
                        .device()
                        .map_err(|e| Error::from(e.to_string()))?
                        .is_some()
                    {
                        socket.bind_device(None)
                    } else {
                        Ok(())
                    }
                }
                Self::Paused => return Ok(()),
            }
            .map_err(|e| Error::from(format!("P2P listener scope: {e}")))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = listener;
            if matches!(self, Self::Interface { .. }) {
                Err("interface-bound P2P requires Linux".into())
            } else {
                Ok(())
            }
        }
    }
    /// A pre-transition connection can remain in the listener backlog. Never
    /// authenticate it under a newer interface policy merely because accepted
    /// after that policy was installed.
    pub(super) fn accepts(&self, stream: &TcpStream) -> Result<bool, Error> {
        match self {
            Self::Paused => Ok(false),
            Self::Public => Ok(true),
            Self::Interface { name, mark, .. } => {
                #[cfg(target_os = "linux")]
                {
                    Ok(socket2::SockRef::from(stream)
                        .device()
                        .map_err(|e| Error::from(e.to_string()))?
                        .as_deref()
                        == Some(name.as_bytes())
                        && socket2::SockRef::from(stream)
                            .mark()
                            .map_err(|e| Error::from(e.to_string()))?
                            == *mark)
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = (stream, name, mark);
                    Err("interface-bound P2P requires Linux".into())
                }
            }
        }
    }
    pub(super) async fn connect(
        &self,
        endpoint: &super::Endpoint,
        proxy: Option<std::net::SocketAddr>,
    ) -> Result<TcpStream, super::super::proxy::Failure> {
        match self {
            Self::Public => super::super::proxy::connect_diagnosed(endpoint, proxy).await,
            Self::Paused => Err(failure("P2P transport is paused")),
            Self::Interface { name, pins, mark } => {
                self.validate(proxy.is_some())
                    .map_err(|error| super::super::proxy::Failure {
                        error,
                        socks_reply: None,
                    })?;
                let host = std::str::from_utf8(&endpoint.host)
                    .map_err(|_| failure("invalid peer host"))?;
                let ip = host
                    .parse::<Ipv4Addr>()
                    .ok()
                    .or_else(|| pins.get(host).copied())
                    .ok_or_else(|| {
                        failure("bound P2P peer requires an IPv4 address or accepted DNS pin")
                    })?;
                bound(name, *mark, std::net::SocketAddrV4::new(ip, endpoint.port)).await
            }
        }
    }
}

fn failure(message: &str) -> super::super::proxy::Failure {
    super::super::proxy::Failure {
        error: message.into(),
        socks_reply: None,
    }
}
async fn bound(
    name: &str,
    mark: u32,
    peer: std::net::SocketAddrV4,
) -> Result<TcpStream, super::super::proxy::Failure> {
    #[cfg(target_os = "linux")]
    {
        let result = async {
            let socket = tokio::net::TcpSocket::new_v4()?;
            socket2::SockRef::from(&socket).set_mark(mark)?;
            socket.bind_device(Some(name.as_bytes()))?;
            socket.connect(peer.into()).await
        };
        match tokio::time::timeout(std::time::Duration::from_secs(10), result).await {
            Ok(result) => result.map_err(|e| failure(&format!("bound P2P connect: {e}"))),
            Err(_) => Err(failure("bound P2P connect timeout")),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (name, mark, peer);
        Err(failure("interface-bound P2P requires Linux"))
    }
}

impl Lease {
    /// Dropping a lease deliberately retains its scope. Only an explicit host
    /// transition can restore public networking after a clean disconnect.
    pub fn check(&self) -> Result<(), Error> {
        let requested = self.swarm.0.scope.borrow().revision;
        let state = self.swarm.state();
        if !state.running
            || requested != self.scope_revision
            || state.scope_revision != self.scope_revision
            || state.scope != self.scope
        {
            return Err("P2P scope lease is no longer active".into());
        }
        Ok(())
    }
}
impl Swarm {
    pub fn same_instance(&self, other: &Self) -> bool {
        std::sync::Arc::ptr_eq(&self.0, &other.0)
    }
    pub fn validate_scope(&self, scope: &Scope) -> Result<(), Error> {
        scope.validate(self.state().proxy.is_some())?;
        #[cfg(target_os = "linux")]
        if let Scope::Interface { mark, .. } = scope {
            let probe = socket2::Socket::new(
                socket2::Domain::IPV4,
                socket2::Type::STREAM,
                Some(socket2::Protocol::TCP),
            )
            .map_err(|e| Error::from(e.to_string()))?;
            probe.bind_device(Some(b"lo")).map_err(|e| {
                Error::from(format!("P2P interface binding capability unavailable: {e}"))
            })?;
            probe.set_mark(*mark).map_err(|e| {
                Error::from(format!("P2P socket marking capability unavailable: {e}"))
            })?;
        }
        Ok(())
    }
    /// Before startup only. A restart may select Paused until its recorded paid
    /// entry is reconstructed; it need not open any physical chain connection.
    pub fn configure_scope(&self, scope: Scope) -> Result<(), Error> {
        let mut state = self.state();
        scope.validate(state.proxy.is_some())?;
        if state.started {
            return Err("P2P scope configuration requires stopped swarm".into());
        }
        let revision = self
            .0
            .scope
            .borrow()
            .revision
            .checked_add(1)
            .ok_or_else(|| Error::from("P2P scope revision exhausted"))?;
        state.scope = scope.clone();
        state.scope_revision = revision;
        self.0.scope.send_replace(Request { revision, scope });
        Ok(())
    }
    pub async fn change_scope(&self, scope: Scope) -> Result<Lease, Error> {
        let _transition = self.0.scope_transition.lock().await;
        let mut applied = self.0.scope_applied.subscribe();
        let revision = {
            let state = self.state();
            scope.validate(state.proxy.is_some())?;
            if !state.running {
                return Err("P2P scope transition requires running swarm".into());
            }
            let revision = self
                .0
                .scope
                .borrow()
                .revision
                .checked_add(1)
                .ok_or_else(|| Error::from("P2P scope revision exhausted"))?;
            self.0.scope.send_replace(Request {
                revision,
                scope: scope.clone(),
            });
            revision
        };
        loop {
            let done = *applied.borrow_and_update() == revision;
            if done {
                let lease = Lease {
                    swarm: self.clone(),
                    scope_revision: revision,
                    scope,
                };
                lease.check()?;
                return Ok(lease);
            }
            if !self.state().running {
                return Err("P2P stopped during scope transition".into());
            }
            applied
                .changed()
                .await
                .map_err(|e| Error::from(e.to_string()))?;
        }
    }
    pub(super) fn scope(&self) -> Scope {
        self.state().scope.clone()
    }
    pub fn transport_scope(&self) -> Scope {
        self.scope()
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    #[tokio::test]
    #[ignore = "Requires isolated Linux NET_RAW; explicit network-scope qualification"]
    async fn bound_dials_use_only_the_device_and_accepted_dns_pin() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer = listener.local_addr().unwrap();
        let endpoint = super::super::Endpoint {
            host: b"chain-peer.invalid".to_vec(),
            port: peer.port(),
        };
        let mut scope = Scope::Interface {
            name: "lo".into(),
            pins: BTreeMap::new(),
            mark: 0x4f43_544e,
        };
        assert!(scope.connect(&endpoint, None).await.is_err());
        let Scope::Interface { pins, .. } = &mut scope else {
            unreachable!()
        };
        pins.insert("chain-peer.invalid".into(), Ipv4Addr::LOCALHOST);
        let missing = Scope::Interface {
            name: "octra_missing".into(),
            pins: pins.clone(),
            mark: 0x4f43_544e,
        };
        assert!(missing.connect(&endpoint, None).await.is_err());
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
        let mut stream = scope
            .connect(&endpoint, None)
            .await
            .map_err(|e| e.error)
            .unwrap();
        assert_eq!(socket2::SockRef::from(&stream).mark().unwrap(), 0x4f43_544e);
        assert_eq!(
            socket2::SockRef::from(&stream).device().unwrap().as_deref(),
            Some(b"lo".as_slice())
        );
        let (mut incoming, _) = listener.accept().await.unwrap();
        stream.write_all(b"bound").await.unwrap();
        let mut bytes = [0; 5];
        incoming.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"bound");
    }
}
