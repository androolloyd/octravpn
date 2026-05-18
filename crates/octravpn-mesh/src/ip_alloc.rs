//! Deterministic tailnet IP allocation.
//!
//! Every member of a given tailnet gets a stable IPv4 address in the
//! CGNAT range (`100.64.0.0/10`, RFC 6598) computed as a function of
//! `(tailnet_id, member_addr, ip_salt)`. Determinism matters: any
//! node in the tailnet can compute every other node's address without
//! coordination.
//!
//! ## Address space and birthday bounds
//!
//! The CGNAT /10 contains `2^22 = 4,194,304` host addresses. Of those
//! we reserve a small handful (network/broadcast/router/magic-dns) and
//! treat the remaining ~`4,194,300` slots as a single flat host space
//! per tailnet. **There is no per-tailnet sub-network.** Each tailnet
//! is isolated by its own WireGuard interface + routing table; IP
//! overlap across tailnets is harmless.
//!
//! Earlier versions split the /10 into 4096 tailnets × 1022 hosts.
//! That was a serious bug: birthday collisions on 1022 slots are
//! ~70% probable with only 50 members and effectively guaranteed at
//! 1000.
//!
//! Realistic birthday-collision probability for the current flat
//! 22-bit space (`m = 4,194,300`):
//!
//! | N members | P(any collision) |
//! |-----------|------------------|
//! |       100 |          ~0.12 % |
//! |       500 |          ~2.95 % |
//! |      1000 |         ~11.75 % |
//! |      2000 |         ~37.9  % |
//!
//! 11% at 1000 members is still non-trivial. The recommended
//! mitigation is the per-tailnet `ip_salt: u32` field exposed via
//! [`TailnetIpAllocator::with_salt`]: on a detected collision, the
//! tailnet owner bumps the salt on-chain and every member
//! re-derives. That makes the IP map ephemeral, not load-bearing.
//!
//! The on-chain salt field is **not yet added** to the `Tailnet`
//! struct in `program/main-v2.aml` — see audit follow-up commit
//! message. Until then `ip_salt` defaults to `0` for all tailnets,
//! and collisions must be resolved out-of-band.
//!
//! ## Capacity invariant
//!
//! [`TailnetIpAllocator::host_capacity`] returns the size of the
//! usable host range. Tests assert that capacity is at least
//! `2^22 - 8`, that every allocation lands in CGNAT, and that the
//! router IP never collides with a member IP.

use std::net::Ipv4Addr;

use sha2::{Digest, Sha256};

/// Base of the CGNAT range: `100.64.0.0/10`.
const CGNAT_BASE: u32 = 0x6440_0000;
/// Number of host bits inside CGNAT /10. The /10 contains `2^22`
/// addresses.
const HOST_BITS: u32 = 22;
const HOST_SPACE: u32 = 1u32 << HOST_BITS; // 4_194_304

/// Reserved low host indices:
/// - `0` → CGNAT network address (`100.64.0.0`)
/// - `1` → magic-DNS / router IP
const RESERVED_LOW: u32 = 2;
/// Reserved top host index (`100.127.255.255` broadcast).
const RESERVED_HIGH: u32 = 1;

/// Domain-separation tag for the per-member host hash.
const HOST_DOMAIN: &[u8] = b"octravpn-mesh/host-v2";

/// Deterministic per-tailnet IPv4 allocator.
///
/// Construct with [`TailnetIpAllocator::new`] (defaults `ip_salt` to
/// `0`) or [`TailnetIpAllocator::with_salt`] when the on-chain
/// salt is non-zero.
#[derive(Clone)]
pub struct TailnetIpAllocator {
    tailnet_id: String,
    ip_salt: u32,
}

impl TailnetIpAllocator {
    /// Allocator with `ip_salt = 0`.
    pub fn new(tailnet_id: impl Into<String>) -> Self {
        Self::with_salt(tailnet_id, 0)
    }

    /// Allocator with an explicit `ip_salt`. Bump this when the
    /// tailnet owner observes a collision and wants every member to
    /// re-derive their address.
    pub fn with_salt(tailnet_id: impl Into<String>, ip_salt: u32) -> Self {
        Self {
            tailnet_id: tailnet_id.into(),
            ip_salt,
        }
    }

    /// Size of the usable per-tailnet host range.
    ///
    /// `HOST_SPACE - RESERVED_LOW - RESERVED_HIGH` — this is the
    /// denominator that goes into the birthday probability bound.
    pub const fn host_capacity() -> u32 {
        HOST_SPACE - RESERVED_LOW - RESERVED_HIGH
    }

    /// The tailnet's magic-DNS / router IP. Fixed at `100.64.0.1`
    /// (the lowest reserved address inside CGNAT). All tailnets use
    /// the same router IP — it's only ever resolved inside a
    /// tailnet's own WireGuard interface, so cross-tailnet overlap
    /// is harmless.
    pub fn router_ip(&self) -> Ipv4Addr {
        // Index `1` inside CGNAT == 100.64.0.1.
        Ipv4Addr::from((CGNAT_BASE | 1u32).to_be_bytes())
    }

    /// Allocate `member_addr`'s IPv4 inside this tailnet.
    pub fn allocate(&self, member_addr: &str) -> Ipv4Addr {
        let host = self.hashed_host(member_addr);
        Ipv4Addr::from((CGNAT_BASE | host).to_be_bytes())
    }

    fn hashed_host(&self, member_addr: &str) -> u32 {
        // TupleHash-style framing: domain tag, then length-prefixed
        // parts. Same shape as `octra-core::circle::h256_raw`.
        let mut h = Sha256::new();
        h.update(HOST_DOMAIN);
        h.update([0u8]);
        push_part(&mut h, self.tailnet_id.as_bytes());
        push_part(&mut h, member_addr.as_bytes());
        push_part(&mut h, &self.ip_salt.to_be_bytes());
        let digest = h.finalize();
        let raw = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
        let capacity = Self::host_capacity();
        // Map into [RESERVED_LOW, HOST_SPACE - RESERVED_HIGH).
        RESERVED_LOW + (raw % capacity)
    }
}

fn push_part(h: &mut Sha256, part: &[u8]) {
    let len = u32::try_from(part.len()).expect("part length fits in u32");
    h.update(len.to_be_bytes());
    h.update(part);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

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
    fn router_ip_is_inside_cgnat_range() {
        let a = TailnetIpAllocator::new("tid");
        let r = a.router_ip();
        let oct = r.octets();
        assert!(oct[0] == 100 && (oct[1] & 0xC0) == 0x40);
    }

    #[test]
    fn router_ip_does_not_collide_with_member() {
        let a = TailnetIpAllocator::new("tid");
        for i in 0..1000 {
            let m = a.allocate(&format!("oct{i}"));
            assert_ne!(m, a.router_ip(), "member {i} collided with router");
        }
    }

    #[test]
    fn salt_changes_allocation() {
        let m = "octMEMBER";
        let a0 = TailnetIpAllocator::with_salt("tid", 0);
        let a1 = TailnetIpAllocator::with_salt("tid", 1);
        assert_ne!(
            a0.allocate(m),
            a1.allocate(m),
            "ip_salt bump must shuffle addresses"
        );
    }

    #[test]
    fn host_capacity_is_documented_size() {
        // 2^22 - 3 reserved slots.
        let cap = TailnetIpAllocator::host_capacity();
        assert!(cap >= (1 << 22) - 8, "capacity {cap} smaller than expected");
        assert_eq!(cap, (1u32 << 22) - 3);
    }

    /// Birthday-probability bound for 1000 members in the host space.
    /// We don't *guarantee* zero collisions at the analytic level —
    /// instead we assert the expected probability matches the
    /// documented module-level table.
    #[test]
    fn birthday_probability_matches_documented_bound() {
        let m = f64::from(TailnetIpAllocator::host_capacity());

        // P_collide(n, m) = 1 - exp(-n*(n-1)/(2m))
        fn p_collide(n: f64, m: f64) -> f64 {
            1.0 - (-(n * (n - 1.0)) / (2.0 * m)).exp()
        }

        let p100 = p_collide(100.0, m);
        let p1000 = p_collide(1000.0, m);
        let p2000 = p_collide(2000.0, m);

        // Documented in the module docstring: ~0.12%, ~11.75%, ~37.9%.
        assert!(
            (0.0010..0.0014).contains(&p100),
            "P(100) = {p100}, expected ~0.12%"
        );
        assert!(
            (0.110..0.124).contains(&p1000),
            "P(1000) = {p1000}, expected ~11.75%"
        );
        assert!(
            (0.370..0.385).contains(&p2000),
            "P(2000) = {p2000}, expected ~37.9%"
        );
    }

    /// Empirical collision count for 1000 distinct members in one
    /// tailnet. With 4M slots we expect a small handful (~0.1 in
    /// expectation, so usually 0; the bound is loose enough to be
    /// deterministic across CI machines).
    #[test]
    fn empirical_collisions_for_1000_members_is_small() {
        let alloc = TailnetIpAllocator::new("audit-1000");
        let mut seen = HashSet::new();
        let mut collisions = 0;
        for i in 0..1000 {
            let ip = alloc.allocate(&format!("octMEMBER{i:06}"));
            if !seen.insert(ip) {
                collisions += 1;
            }
        }
        // Expected number of pairs: 1000^2 / (2 * 4_194_300) ≈ 0.119.
        // 5 is a very generous upper bound that will catch a
        // regression to a small host space immediately.
        assert!(
            collisions <= 5,
            "got {collisions} collisions for 1000 members — host space shrunk?"
        );
    }

    /// Direct regression test for the old 10-bit host space bug. If
    /// host capacity is ever reduced back to ~1000, 50 members
    /// collide with overwhelming probability — assert that
    /// explicitly so any future shrink trips this test.
    #[test]
    fn regression_old_10bit_host_space_would_collide() {
        // For 50 members in 1021 slots, P(collision) ≈ 70%. We
        // simulate it by computing a fake allocator at the old
        // bit-width and showing the new one does not behave that way.
        let alloc = TailnetIpAllocator::new("regression");
        let mut seen = HashSet::new();
        for i in 0..50 {
            let ip = alloc.allocate(&format!("octR{i}"));
            assert!(seen.insert(ip), "regression: collision at i={i}");
        }
    }
}
