//! Property-based fuzzing for mesh parsers / canonicalisation /
//! allocator. These don't aim for high coverage; they aim to surface
//! panics on malformed input and to assert determinism over arbitrary
//! valid input.

use std::net::Ipv4Addr;
use std::time::Instant;

use octravpn_core::sig::KeyPair;
use octravpn_mesh::{
    AclDoc, MagicDns, PeerCandidate, PeerSnapshot, SignedPeerSnapshot, TailnetIpAllocator,
    PEER_SNAPSHOT_MAX_AGE_SECS,
};
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
        use std::fmt::Write;
        let mut toml = String::from("version = 1\n");
        if !groups.is_empty() {
            toml.push_str("[groups]\n");
            for (name, members) in &groups {
                let _ = writeln!(toml, "{name} = [");
                for m in members {
                    let _ = writeln!(toml, "  \"{m}\",");
                }
                toml.push_str("]\n");
            }
        }
        for (accept, src, dst) in &rules {
            toml.push_str("[[rules]]\n");
            let _ = writeln!(toml, "action = \"{}\"", if *accept { "accept" } else { "deny" });
            toml.push_str("src = [\n");
            for s in src { let _ = writeln!(toml, "  \"{s}\","); }
            toml.push_str("]\n");
            toml.push_str("dst = [\n");
            for d in dst { let _ = writeln!(toml, "  \"{d}\","); }
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
    /// /10 range and never collides with the router IP. v2 of the
    /// allocator no longer carves out a per-tailnet /22 — the full
    /// /10 is the host space.
    #[test]
    fn ip_allocator_stays_in_cgnat(
        tid in "[a-z0-9]{1,30}",
        members in proptest::collection::hash_set("oct[a-z0-9]{1,10}", 1..200)
    ) {
        let alloc = TailnetIpAllocator::new(&tid);
        let router = alloc.router_ip();
        for m in &members {
            let ip = alloc.allocate(m);
            let oct = ip.octets();
            // CGNAT /10: 100.64.0.0 to 100.127.255.255.
            prop_assert!(oct[0] == 100 && (oct[1] & 0xC0) == 0x40,
                         "ip {ip} outside 100.64/10");
            // Never equal to the router.
            prop_assert_ne!(ip, router);
        }
    }
}

proptest! {
    /// ip_salt bumping must change the IP for at least *some*
    /// members. (For any given member there's a 1/capacity chance
    /// of accidentally re-hashing to the same slot; we test the
    /// population property.)
    #[test]
    fn ip_allocator_salt_reshuffles_population(
        tid in "[a-z0-9]{1,30}",
        members in proptest::collection::hash_set("oct[a-z0-9]{1,10}", 5..50)
    ) {
        let a0 = TailnetIpAllocator::with_salt(&tid, 0);
        let a1 = TailnetIpAllocator::with_salt(&tid, 1);
        let mut changed = 0;
        for m in &members {
            if a0.allocate(m) != a1.allocate(m) {
                changed += 1;
            }
        }
        prop_assert!(changed >= members.len() - 1,
            "salt bump barely moved anyone: {changed}/{}", members.len());
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

// ---------- ACL canonical-bytes stability ----------

proptest! {
    /// `canonical_bytes` is a function of the document — same parse
    /// twice, identical bytes both times.
    #[test]
    fn acl_canonical_bytes_stable(doc in arb_acl_doc()) {
        let Ok(parsed) = AclDoc::from_toml(&doc) else { return Ok(()); };
        prop_assert_eq!(parsed.canonical_bytes(), parsed.canonical_bytes());
    }
}

// ---------- SignedPeerSnapshot verify success + tamper rejection ----------

fn arb_candidate() -> impl Strategy<Value = PeerCandidate> {
    prop_oneof![
        any::<u8>().prop_map(|p| PeerCandidate::Lan(
            format!("10.0.0.1:{}", u16::from(p) + 1).parse().unwrap()
        )),
        any::<u16>().prop_map(|p| PeerCandidate::Stun(
            format!("203.0.113.4:{}", p.saturating_add(1))
                .parse()
                .unwrap()
        )),
        "[a-z0-9]{4,16}".prop_map(|v| PeerCandidate::Relay { validator_addr: v }),
    ]
}

prop_compose! {
    fn arb_snapshot()(
        tid in "[a-z0-9]{1,30}",
        addr in "oct[a-z0-9]{1,10}",
        host in proptest::option::of("[a-z]{1,12}"),
        wg in any::<[u8; 32]>(),
        cands in proptest::collection::vec(arb_candidate(), 0..4),
    ) -> PeerSnapshot {
        PeerSnapshot {
            tailnet_id: tid,
            addr,
            wg_pubkey: wg,
            candidates: cands,
            hostname: host,
            last_refresh: Instant::now(),
        }
    }
}

proptest! {
    #[test]
    fn signed_peer_snapshot_round_trip_verifies(snap in arb_snapshot()) {
        let kp = KeyPair::generate();
        let signed = SignedPeerSnapshot::sign(snap, &kp);
        prop_assert!(signed.verify(&kp.public, PEER_SNAPSHOT_MAX_AGE_SECS).is_ok());
    }
}

proptest! {
    /// Tamper path 1: flip a byte in `wg_pubkey`.
    #[test]
    fn signed_peer_snapshot_rejects_wg_tamper(snap in arb_snapshot(), idx in 0usize..32) {
        let kp = KeyPair::generate();
        let mut signed = SignedPeerSnapshot::sign(snap, &kp);
        signed.snapshot.wg_pubkey[idx] ^= 0xFF;
        prop_assert!(signed.verify(&kp.public, PEER_SNAPSHOT_MAX_AGE_SECS).is_err());
    }
}

proptest! {
    /// Tamper path 2: mutate `addr`.
    #[test]
    fn signed_peer_snapshot_rejects_addr_tamper(snap in arb_snapshot()) {
        let kp = KeyPair::generate();
        let mut signed = SignedPeerSnapshot::sign(snap, &kp);
        signed.snapshot.addr.push('!');
        prop_assert!(signed.verify(&kp.public, PEER_SNAPSHOT_MAX_AGE_SECS).is_err());
    }
}

proptest! {
    /// Tamper path 3: swap the candidate list.
    #[test]
    fn signed_peer_snapshot_rejects_candidate_tamper(snap in arb_snapshot()) {
        let kp = KeyPair::generate();
        let mut signed = SignedPeerSnapshot::sign(snap, &kp);
        signed.snapshot.candidates.push(PeerCandidate::Relay {
            validator_addr: "octINJECTED".into(),
        });
        prop_assert!(signed.verify(&kp.public, PEER_SNAPSHOT_MAX_AGE_SECS).is_err());
    }
}
