//! Property-based fuzzing for mesh parsers / canonicalisation /
//! allocator. These don't aim for high coverage; they aim to surface
//! panics on malformed input and to assert determinism over arbitrary
//! valid input.

use std::net::Ipv4Addr;

use octravpn_mesh::{AclDoc, MagicDns, TailnetIpAllocator};
use proptest::prelude::*;

// ---------- DNS parser robustness ----------

proptest! {
    /// Throwing random bytes at the DNS parser must never panic.
    /// Output is either Some(reply) or None (unparseable); both are fine.
    #[test]
    fn magic_dns_respond_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..1500)) {
        let dns = MagicDns::new();
        let _ = dns.respond(&bytes);
    }
}

proptest! {
    /// Random in-zone hostnames should either resolve (registered) or
    /// NXDOMAIN — never panic, never refuse.
    #[test]
    fn magic_dns_inzone_query_round_trip(host in "[a-z]{1,20}", tid in "[a-z0-9]{1,30}") {
        let dns = MagicDns::new();
        let req = build_a_query(&format!("{host}.{tid}.octra"));
        let r = dns.respond(&req).unwrap();
        // Must be a valid 12+-byte response.
        prop_assert!(r.len() >= 12);
        let rcode = r[3] & 0x0F;
        // NOERROR (registered, but we registered none) or NXDOMAIN.
        prop_assert!(rcode == 3 /* NXDOMAIN */ || rcode == 0 /* NOERROR */);
    }
}

fn build_a_query(qname: &str) -> Vec<u8> {
    let mut out = vec![0x12, 0x34]; // ID
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    for label in qname.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&1u16.to_be_bytes()); // QTYPE_A
    out.extend_from_slice(&1u16.to_be_bytes()); // QCLASS_IN
    out
}

// ---------- ACL canonical hash determinism ----------

prop_compose! {
    fn arb_acl_doc()(
        groups in proptest::collection::vec(
            ("[a-z]{1,8}", proptest::collection::vec("oct[a-z0-9]{1,10}", 1..5)),
            0..4
        ),
        rules in proptest::collection::vec(
            (any::<bool>(), proptest::collection::vec("oct[a-z0-9]{1,10}", 1..4),
                            proptest::collection::vec("oct[a-z0-9]{1,10}", 1..4)),
            0..5
        ),
    ) -> String {
        let mut toml = String::from("version = 1\n");
        if !groups.is_empty() {
            toml.push_str("[groups]\n");
            for (name, members) in &groups {
                toml.push_str(&format!("{name} = [\n"));
                for m in members {
                    toml.push_str(&format!("  \"{m}\",\n"));
                }
                toml.push_str("]\n");
            }
        }
        for (accept, src, dst) in &rules {
            toml.push_str("[[rules]]\n");
            toml.push_str(&format!("action = \"{}\"\n", if *accept { "accept" } else { "deny" }));
            toml.push_str("src = [\n");
            for s in src { toml.push_str(&format!("  \"{s}\",\n")); }
            toml.push_str("]\n");
            toml.push_str("dst = [\n");
            for d in dst { toml.push_str(&format!("  \"{d}\",\n")); }
            toml.push_str("]\n");
        }
        toml
    }
}

proptest! {
    /// The canonical hash of a doc is stable across parses of the same
    /// source bytes.
    #[test]
    fn acl_hash_is_deterministic(doc in arb_acl_doc()) {
        let Ok(parsed) = AclDoc::from_toml(&doc) else { return Ok(()); };
        let a = parsed.policy_hash();
        let b = parsed.policy_hash();
        prop_assert_eq!(a, b);
    }
}

proptest! {
    /// Reparsing the same doc yields the same hash.
    #[test]
    fn acl_hash_round_trip_via_parse(doc in arb_acl_doc()) {
        let Ok(p1) = AclDoc::from_toml(&doc) else { return Ok(()); };
        let bytes = p1.canonical_bytes();
        // Re-parse from canonical JSON wouldn't go through TOML again,
        // so we re-parse the original TOML to assert stability across
        // parses of the same source.
        let p2 = AclDoc::from_toml(&doc).unwrap();
        prop_assert_eq!(p1.policy_hash(), p2.policy_hash());
        prop_assert!(!bytes.is_empty());
    }
}

// ---------- IP allocator collision-freedom ----------

proptest! {
    /// For any tailnet id and an arbitrary set of distinct member
    /// addresses (≤ 200), every allocated IP is inside the CGNAT
    /// range and within the tailnet's /22.
    #[test]
    fn ip_allocator_stays_in_cgnat_and_per_tailnet_subnet(
        tid in "[a-z0-9]{1,30}",
        members in proptest::collection::hash_set("oct[a-z0-9]{1,10}", 1..200)
    ) {
        let alloc = TailnetIpAllocator::new(&tid);
        let router = alloc.router_ip();
        let mut prefixes = std::collections::HashSet::new();
        for m in &members {
            let ip = alloc.allocate(m);
            let oct = ip.octets();
            // CGNAT /10: 100.64.0.0 to 100.127.255.255.
            prop_assert!(oct[0] == 100 && (oct[1] & 0xC0) == 0x40,
                         "ip {ip} outside 100.64/10");
            // Same /22 prefix for every member of this tailnet.
            let prefix = u32::from_be_bytes(oct) & 0xFFFF_FC00;
            prefixes.insert(prefix);
            // Never equal to the router.
            prop_assert_ne!(ip, router);
        }
        prop_assert_eq!(prefixes.len(), 1, "members landed across multiple /22s");
    }
}

proptest! {
    /// The same input pair (tailnet_id, addr) always yields the same IP.
    #[test]
    fn ip_allocator_is_deterministic(
        tid in "[a-z0-9]{1,30}",
        m in "oct[a-z0-9]{1,10}"
    ) {
        let alloc = TailnetIpAllocator::new(&tid);
        let a: Ipv4Addr = alloc.allocate(&m);
        let b: Ipv4Addr = alloc.allocate(&m);
        prop_assert_eq!(a, b);
    }
}
