//! Deterministic tailnet IP allocation.
//!
//! Every member of a given tailnet gets a stable IPv4 address in the
//! CGNAT range (100.64.0.0/10, RFC 6598) computed as a function of
//! (tailnet_id, member_addr). Determinism matters: any node in the
//! tailnet can compute every other node's address without coordination.
//!
//! The /10 range gives us 2^22 = 4M addresses per tailnet — enough that
//! collisions inside a reasonable tailnet (≤ 1000 devices) are
//! astronomically unlikely.

use std::net::Ipv4Addr;

use sha2::{Digest, Sha256};

/// Base of the CGNAT range: 100.64.0.0/10.
const CGNAT_BASE: u32 = 0x6440_0000;
/// Bits 0..=21 inside CGNAT are split: 12 bits select the per-tailnet
/// /22 sub-network; the remaining 10 bits identify the host within it.
/// That gives 4096 tailnets × ~1022 usable hosts per tailnet — plenty.
const TAILNET_BITS: u32 = 12;
const HOST_BITS: u32 = 10;
const HOST_MASK: u32 = (1u32 << HOST_BITS) - 1;
const TAILNET_MASK: u32 = (1u32 << TAILNET_BITS) - 1;
/// Reserved low host addresses (.0 network, .1 router/DNS).
const RESERVED_LOW: u32 = 2;
/// Reserved top host addresses (broadcast).
const RESERVED_HIGH: u32 = 1;

#[derive(Clone)]
pub struct TailnetIpAllocator {
    tailnet_id: String,
}

impl TailnetIpAllocator {
    pub fn new(tailnet_id: impl Into<String>) -> Self {
        Self {
            tailnet_id: tailnet_id.into(),
        }
    }

    /// The tailnet's "router" / magic-DNS IP. Conventionally 100.64.0.1
    /// scoped under the tailnet's network prefix (which is the first 22
    /// bits of the hashed tailnet_id, masked into CGNAT). The router IP
    /// is the first usable host inside the tailnet's /22.
    pub fn router_ip(&self) -> Ipv4Addr {
        let net = self.network_prefix();
        Ipv4Addr::from((net | 0x1).to_be_bytes())
    }

    /// Allocate `member_addr`'s IPv4 inside this tailnet.
    pub fn allocate(&self, member_addr: &str) -> Ipv4Addr {
        let net = self.network_prefix();
        let host = self.hashed_host(member_addr);
        Ipv4Addr::from((net | host).to_be_bytes())
    }

    fn network_prefix(&self) -> u32 {
        // sha256 the tailnet id, take 12 bits as the sub-network selector,
        // shift into bits 10..22 of the address. Each tailnet gets its
        // own /22.
        let mut h = Sha256::new();
        h.update(b"octravpn-mesh/tailnet-prefix-v1");
        h.update(self.tailnet_id.as_bytes());
        let digest = h.finalize();
        let raw = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
        let tailnet_bits = raw & TAILNET_MASK;
        CGNAT_BASE | (tailnet_bits << HOST_BITS)
    }

    fn hashed_host(&self, member_addr: &str) -> u32 {
        let mut h = Sha256::new();
        h.update(b"octravpn-mesh/host-v1");
        h.update(self.tailnet_id.as_bytes());
        h.update(b"::");
        h.update(member_addr.as_bytes());
        let digest = h.finalize();
        let raw = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
        // Map into [RESERVED_LOW, 2^HOST_BITS - RESERVED_HIGH) so we never
        // hand out the network, broadcast, or router IP.
        let usable = (1u32 << HOST_BITS) - RESERVED_LOW - RESERVED_HIGH;
        RESERVED_LOW + (raw & HOST_MASK) % usable
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocations_are_deterministic_per_member() {
        let a = TailnetIpAllocator::new("tailnet-A");
        let one = a.allocate("octCLIENT001");
        let two = a.allocate("octCLIENT001");
        assert_eq!(one, two, "same input must yield same IP");
    }

    #[test]
    fn allocations_differ_across_members() {
        let a = TailnetIpAllocator::new("tailnet-A");
        let one = a.allocate("octCLIENT001");
        let two = a.allocate("octCLIENT002");
        assert_ne!(one, two, "different members must get different IPs");
    }

    #[test]
    fn allocations_differ_across_tailnets() {
        let a = TailnetIpAllocator::new("tailnet-A");
        let b = TailnetIpAllocator::new("tailnet-B");
        let m = "octCLIENT";
        assert_ne!(a.allocate(m), b.allocate(m), "tailnet scope must matter");
    }

    #[test]
    fn allocated_addresses_are_in_cgnat_range() {
        let a = TailnetIpAllocator::new("any-tid");
        for i in 0..1000 {
            let ip = a.allocate(&format!("oct{i}"));
            let oct = ip.octets();
            assert!(
                oct[0] == 100 && (oct[1] & 0xC0) == 0x40,
                "got {ip} outside 100.64/10"
            );
        }
    }

    #[test]
    fn router_ip_is_inside_tailnet_prefix() {
        let a = TailnetIpAllocator::new("tid");
        let r = a.router_ip();
        let m = a.allocate("oct1");
        // Same /22 prefix (top 22 bits identical).
        let prefix_mask = !((1u32 << HOST_BITS) - 1);
        let rb = u32::from_be_bytes(r.octets());
        let mb = u32::from_be_bytes(m.octets());
        assert_eq!(rb & prefix_mask, mb & prefix_mask);
    }

    #[test]
    fn router_ip_does_not_collide_with_member() {
        let a = TailnetIpAllocator::new("tid");
        for i in 0..200 {
            let m = a.allocate(&format!("oct{i}"));
            assert_ne!(m, a.router_ip(), "member {i} collided with router");
        }
    }
}
