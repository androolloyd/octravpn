// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Shared native P2p_conn / gRPC listener retry policy.
use std::time::Duration;
use std::{net::SocketAddr, sync::Arc};

pub const LIMIT: usize = 136;
pub const RESERVE: usize = 8;
pub const WAIT: Duration = Duration::from_secs(5);

#[derive(Default)]
pub(crate) struct Slots(Vec<Slot>);
struct Slot {
    token: Arc<()>,
    host: Vec<u8>,
    network: Vec<u8>,
    grant: Option<Vec<u8>>,
}
fn bootstrap(grant: Option<&[u8]>) -> bool {
    grant.is_some_and(|grant| grant.starts_with(b"boot:"))
}
pub(crate) fn address(address: SocketAddr) -> (Vec<u8>, Vec<u8>) {
    let host = address.ip().to_string().into_bytes();
    let network = match address.ip() {
        std::net::IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            format!("{a}.{b}.{c}").into_bytes()
        }
        std::net::IpAddr::V6(_) => b"ipv6".to_vec(),
    };
    (host, network)
}
impl Slots {
    pub(crate) fn select(&self, grant: Option<Vec<u8>>) -> Option<Vec<u8>> {
        if bootstrap(grant.as_deref())
            && self
                .0
                .iter()
                .filter(|slot| bootstrap(slot.grant.as_deref()))
                .count()
                >= RESERVE
        {
            None
        } else {
            grant
        }
    }
    pub(crate) fn acquire(
        &mut self,
        host: Vec<u8>,
        network: Vec<u8>,
        grant: Option<Vec<u8>>,
    ) -> Option<Arc<()>> {
        let known = grant.is_some();
        let boot = bootstrap(grant.as_deref());
        let limit = if !known {
            LIMIT - 2 * RESERVE
        } else if boot {
            LIMIT - RESERVE
        } else {
            LIMIT
        };
        if self.0.len() >= limit
            || self
                .0
                .iter()
                .filter(|s| s.grant.is_some() == known && s.host == host)
                .count()
                >= 4
            || self
                .0
                .iter()
                .filter(|s| s.grant.is_some() == known && s.network == network)
                .count()
                >= 16
            || (boot
                && self
                    .0
                    .iter()
                    .filter(|s| bootstrap(s.grant.as_deref()))
                    .count()
                    >= RESERVE)
            || (known && self.0.iter().filter(|s| s.grant == grant).count() >= 4)
        {
            return None;
        }
        let token = Arc::new(());
        self.0.push(Slot {
            token: token.clone(),
            host,
            network,
            grant,
        });
        Some(token)
    }
    pub(crate) fn release(&mut self, token: &Arc<()>) {
        self.0.retain(|slot| !Arc::ptr_eq(&slot.token, token));
    }
    pub(crate) fn clear(&mut self) {
        self.0.clear();
    }
}
pub fn delay(attempt: u32, error: &std::io::Error) -> Option<Duration> {
    use rustix::io::Errno as E;
    let code = error.raw_os_error()?;
    let retry = [
        E::INTR,
        E::AGAIN,
        E::CONNABORTED,
        E::NETDOWN,
        E::NETUNREACH,
        E::HOSTDOWN,
        E::HOSTUNREACH,
        E::NOPROTOOPT,
        E::OPNOTSUPP,
        E::MFILE,
        E::NFILE,
        E::NOBUFS,
        E::NOMEM,
        E::PROTO,
    ]
    .iter()
    .any(|error| error.raw_os_error() == code);
    #[cfg(target_os = "linux")]
    let retry = retry || code == E::NONET.raw_os_error();
    retry.then(|| Duration::from_secs_f64((0.01 * f64::from(1_u32 << attempt.min(7))).min(1.0)))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_pressure_preserves_bootstrap_and_validator_reservations() {
        let mut slots = Slots::default();
        for n in 0..120 {
            assert!(slots
                .acquire(n.to_string().into_bytes(), n.to_string().into_bytes(), None)
                .is_some());
        }
        assert!(slots
            .acquire(b"new".to_vec(), b"new".to_vec(), None)
            .is_none());
        for n in 0..8 {
            assert!(slots
                .acquire(
                    n.to_string().into_bytes(),
                    n.to_string().into_bytes(),
                    Some(format!("boot:{n}").into_bytes())
                )
                .is_some());
        }
        assert_eq!(slots.select(Some(b"boot:extra".to_vec())), None);
        for n in 0..8 {
            assert!(slots
                .acquire(
                    n.to_string().into_bytes(),
                    n.to_string().into_bytes(),
                    Some(format!("peer:{n}").into_bytes())
                )
                .is_some());
        }
        assert!(slots
            .acquire(
                b"new".to_vec(),
                b"new".to_vec(),
                Some(b"peer:extra".to_vec())
            )
            .is_none());
    }
    #[test]
    fn host_network_and_grant_caps_are_independent_and_release_is_exact() {
        let mut slots = Slots::default();
        let first = slots
            .acquire(b"host".to_vec(), b"net".to_vec(), None)
            .unwrap();
        for _ in 1..4 {
            assert!(slots
                .acquire(b"host".to_vec(), b"net".to_vec(), None)
                .is_some());
        }
        assert!(slots
            .acquire(b"host".to_vec(), b"net".to_vec(), None)
            .is_none());
        assert!(slots
            .acquire(b"host".to_vec(), b"net".to_vec(), Some(b"peer:1".to_vec()))
            .is_some());
        slots.release(&Arc::new(()));
        assert!(slots
            .acquire(b"host".to_vec(), b"net".to_vec(), None)
            .is_none());
        slots.release(&first);
        assert!(slots
            .acquire(b"host".to_vec(), b"net".to_vec(), None)
            .is_some());
        for n in 0..12 {
            assert!(slots
                .acquire(n.to_string().into_bytes(), b"net".to_vec(), None)
                .is_some());
        }
        assert!(slots
            .acquire(b"fifth".to_vec(), b"net".to_vec(), None)
            .is_none());
        for n in 0..3 {
            assert!(slots
                .acquire(
                    n.to_string().into_bytes(),
                    b"another".to_vec(),
                    Some(b"peer:1".to_vec())
                )
                .is_some());
        }
        assert!(slots
            .acquire(
                b"fifth".to_vec(),
                b"other".to_vec(),
                Some(b"peer:1".to_vec())
            )
            .is_none());
    }
}
