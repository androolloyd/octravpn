//! Subnet routing bookkeeping.
//!
//! A tailnet member can advertise a subnet (CIDR) — typically a private
//! office LAN behind their device — so the rest of the tailnet can reach
//! it through them. The bookkeeping here is the off-chain registry; the
//! data-plane (kernel routes / WG `AllowedIPs`) is wired by the
//! consumer.

use std::{
    collections::HashMap,
    net::Ipv4Addr,
};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::MeshError;

/// An IPv4 CIDR.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct Cidr {
    pub network: Ipv4Addr,
    pub prefix_len: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Result<Self, MeshError> {
        let (net, plen) = s
            .split_once('/')
            .ok_or_else(|| MeshError::InvalidSubnet(format!("missing /: {s}")))?;
        let network: Ipv4Addr = net
            .parse()
            .map_err(|e| MeshError::InvalidSubnet(format!("bad ip: {e}")))?;
        let prefix_len: u8 = plen
            .parse()
            .map_err(|e| MeshError::InvalidSubnet(format!("bad prefix: {e}")))?;
        if prefix_len > 32 {
            return Err(MeshError::InvalidSubnet(format!(
                "prefix>32: {prefix_len}"
            )));
        }
        // Canonicalize: zero out host bits.
        let raw = u32::from_be_bytes(network.octets());
        let mask = if prefix_len == 0 {
            0
        } else {
            !0u32 << (32 - prefix_len)
        };
        let canonical = Ipv4Addr::from((raw & mask).to_be_bytes());
        Ok(Self {
            network: canonical,
            prefix_len,
        })
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        if self.prefix_len == 0 {
            return true;
        }
        let mask = !0u32 << (32 - self.prefix_len);
        let net_raw = u32::from_be_bytes(self.network.octets()) & mask;
        let ip_raw = u32::from_be_bytes(ip.octets()) & mask;
        net_raw == ip_raw
    }
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix_len)
    }
}

/// A subnet advertisement from a tailnet member.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SubnetAdvertisement {
    pub tailnet_id: String,
    pub advertiser_addr: String,
    pub cidr: Cidr,
}

/// Registry of all known subnet advertisements in a tailnet. Lookup
/// returns the addresses that have advertised a route covering `ip`.
#[derive(Default)]
pub struct SubnetRouter {
    /// tailnet_id → list of advertisements.
    inner: RwLock<HashMap<String, Vec<SubnetAdvertisement>>>,
}

impl SubnetRouter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn advertise(&self, ad: SubnetAdvertisement) {
        let mut m = self.inner.write();
        let v = m.entry(ad.tailnet_id.clone()).or_default();
        if !v.contains(&ad) {
            v.push(ad);
        }
    }

    pub fn withdraw(&self, tailnet_id: &str, advertiser_addr: &str, cidr: Cidr) {
        if let Some(v) = self.inner.write().get_mut(tailnet_id) {
            v.retain(|a| !(a.advertiser_addr == advertiser_addr && a.cidr == cidr));
        }
    }

    /// Return all advertisements covering `ip` inside `tailnet_id`.
    /// The most-specific (longest prefix) advertisement is first.
    pub fn route(&self, tailnet_id: &str, ip: Ipv4Addr) -> Vec<SubnetAdvertisement> {
        let m = self.inner.read();
        let Some(ads) = m.get(tailnet_id) else {
            return Vec::new();
        };
        let mut hits: Vec<_> = ads
            .iter()
            .filter(|a| a.cidr.contains(ip))
            .cloned()
            .collect();
        hits.sort_by(|a, b| b.cidr.prefix_len.cmp(&a.cidr.prefix_len));
        hits
    }

    pub fn list(&self, tailnet_id: &str) -> Vec<SubnetAdvertisement> {
        self.inner
            .read()
            .get(tailnet_id)
            .cloned()
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_parse_canonicalizes_host_bits() {
        // 192.168.1.7/24 → network bits 192.168.1.0
        let c = Cidr::parse("192.168.1.7/24").unwrap();
        assert_eq!(c.network, Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(c.prefix_len, 24);
    }

    #[test]
    fn cidr_contains_works_for_in_and_out_of_range() {
        let c = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(c.contains(Ipv4Addr::new(10, 5, 6, 7)));
        assert!(!c.contains(Ipv4Addr::new(11, 0, 0, 1)));
    }

    #[test]
    fn most_specific_advertisement_wins() {
        let r = SubnetRouter::new();
        r.advertise(SubnetAdvertisement {
            tailnet_id: "t".into(),
            advertiser_addr: "octA".into(),
            cidr: Cidr::parse("10.0.0.0/8").unwrap(),
        });
        r.advertise(SubnetAdvertisement {
            tailnet_id: "t".into(),
            advertiser_addr: "octB".into(),
            cidr: Cidr::parse("10.1.0.0/16").unwrap(),
        });
        let hits = r.route("t", Ipv4Addr::new(10, 1, 2, 3));
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].advertiser_addr, "octB"); // most-specific first
    }

    #[test]
    fn withdraw_removes_advertisement() {
        let r = SubnetRouter::new();
        let cidr = Cidr::parse("172.16.0.0/12").unwrap();
        r.advertise(SubnetAdvertisement {
            tailnet_id: "t".into(),
            advertiser_addr: "octA".into(),
            cidr,
        });
        assert_eq!(r.list("t").len(), 1);
        r.withdraw("t", "octA", cidr);
        assert!(r.list("t").is_empty());
    }
}
