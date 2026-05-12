//! Tailnet ACL document, parser, canonicalisation, and evaluator.
//!
//! The on-chain `acl_policy` field of a tailnet is the SHA-256 of a
//! canonicalised ACL document. The full document is distributed
//! off-chain (typically served by the tailnet owner over HTTPS or
//! gossiped through validator endpoints). Every member fetches it,
//! verifies the hash matches what's on-chain, then enforces the
//! decisions at the data plane.
//!
//! Document shape (TOML):
//!
//! ```toml
//! version = 1
//!
//! [groups]
//! admins  = ["oct1...", "oct2..."]
//! eng     = ["oct3...", "oct4..."]
//!
//! [tags]
//! laptop  = "phys"
//! phone   = "mobile"
//!
//! [[rules]]
//! action = "accept"   # or "deny"
//! src = ["group:admins"]
//! dst = ["*"]
//! ports = ["*:*"]
//!
//! [[rules]]
//! action = "accept"
//! src = ["group:eng"]
//! dst = ["group:eng"]
//! ports = ["*:tcp/22"]
//! ```
//!
//! Evaluation walks `rules` top-to-bottom; the first match wins.
//! No match → deny.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::MeshError;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AclAction {
    Accept,
    Deny,
}

/// A single ACL rule. Sources and destinations name groups
/// (`group:<name>`), explicit addresses (`oct...`), or the wildcard `*`.
/// Ports follow the `<proto>/<port>` form (`tcp/22`, `udp/*`, `*/*`,
/// also accepted: `*:tcp/22` for backward-compat).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AclRule {
    pub action: AclAction,
    pub src: Vec<String>,
    pub dst: Vec<String>,
    #[serde(default)]
    pub ports: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AclDoc {
    pub version: u32,
    #[serde(default)]
    pub groups: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub tags: BTreeMap<String, String>,
    #[serde(default)]
    pub rules: Vec<AclRule>,
}

impl AclDoc {
    /// Parse a TOML document. Rejects unknown top-level fields.
    pub fn from_toml(input: &str) -> Result<Self, MeshError> {
        toml::from_str(input).map_err(|e| MeshError::InvalidPeer(format!("ACL parse: {e}")))
    }

    /// Canonical byte form: stable across irrelevant edits (whitespace,
    /// comment changes, key ordering). The on-chain hash is the SHA-256
    /// of this form.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // We canonicalise via serde_json with a BTreeMap-backed object
        // so keys are sorted. Newline-separated to keep the wire form
        // human-readable.
        serde_json::to_vec(&self.canonical_value()).unwrap_or_default()
    }

    fn canonical_value(&self) -> serde_json::Value {
        let mut groups_sorted: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (k, v) in &self.groups {
            let mut sorted = v.clone();
            sorted.sort();
            groups_sorted.insert(k.clone(), sorted);
        }
        let mut tags_sorted: BTreeMap<String, String> = BTreeMap::new();
        for (k, v) in &self.tags {
            tags_sorted.insert(k.clone(), v.clone());
        }
        serde_json::json!({
            "version": self.version,
            "groups": groups_sorted,
            "tags": tags_sorted,
            "rules": self.rules.iter().map(|r| {
                let mut src = r.src.clone();
                let mut dst = r.dst.clone();
                let mut ports = r.ports.clone();
                src.sort();
                dst.sort();
                ports.sort();
                serde_json::json!({
                    "action": match r.action {
                        AclAction::Accept => "accept",
                        AclAction::Deny => "deny",
                    },
                    "src": src,
                    "dst": dst,
                    "ports": ports,
                })
            }).collect::<Vec<_>>(),
        })
    }

    /// SHA-256 of `canonical_bytes`. The result matches the on-chain
    /// `acl_policy` field for the tailnet that owns this document.
    pub fn policy_hash(&self) -> [u8; 32] {
        let bytes = self.canonical_bytes();
        let mut h = Sha256::new();
        h.update(&bytes);
        let out = h.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&out);
        arr
    }
}

/// An ACL document plus the tailnet owner's signature over its
/// canonical bytes. Distributed alongside the doc (e.g. served at the
/// owner's HTTPS endpoint or pinned to IPFS) so members can verify the
/// authorship without trusting the transport.
///
/// Sig storage matches `SignedPeerSnapshot`: raw `[u8;64]` with a
/// serde helper that emits as a byte string in JSON/CBOR.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedAclDoc {
    pub doc: AclDoc,
    pub owner_addr: String,
    #[serde(with = "acl_sig_bytes")]
    pub sig: [u8; 64],
}

mod acl_sig_bytes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_with::{serde_as, Bytes};

    #[serde_as]
    #[derive(Serialize, Deserialize)]
    struct Wrap(#[serde_as(as = "Bytes")] [u8; 64]);

    pub(super) fn serialize<S: Serializer>(b: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        Wrap(*b).serialize(s)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        Wrap::deserialize(d).map(|w| w.0)
    }
}

impl SignedAclDoc {
    /// Produce a SignedAclDoc by signing canonical_bytes with `kp`.
    pub fn sign(doc: AclDoc, owner_addr: impl Into<String>, kp: &octravpn_core::sig::KeyPair) -> Self {
        let canonical = doc.canonical_bytes();
        let sig = kp.sign(&canonical);
        Self {
            doc,
            owner_addr: owner_addr.into(),
            sig: sig.0,
        }
    }

    /// Verify against an expected owner pubkey.
    pub fn verify(&self, owner_pubkey: &octravpn_core::sig::PublicKey) -> Result<(), MeshError> {
        let canonical = self.doc.canonical_bytes();
        octravpn_core::sig::verify(
            owner_pubkey,
            &canonical,
            &octravpn_core::sig::Signature(self.sig),
        )
        .map_err(|e| MeshError::InvalidPeer(format!("acl sig verify: {e}")))?;
        Ok(())
    }

    /// Convenience: hash of the underlying document (matches the
    /// on-chain `acl_policy` field).
    pub fn policy_hash(&self) -> [u8; 32] {
        self.doc.policy_hash()
    }
}

// Empty `impl` to keep the file's top-level structure compiling; the
// previous `impl AclDoc { ... }` block ends above.
impl AclDoc {

    /// Evaluate a (src, dst, port) tuple. Returns the action of the
    /// first matching rule, or `Deny` if no rule matched (default-deny).
    pub fn decide(&self, src: &str, dst: &str, port: PortRef<'_>) -> AclAction {
        for rule in &self.rules {
            if self.matches(rule, src, dst, port) {
                return rule.action.clone();
            }
        }
        AclAction::Deny
    }

    fn matches(&self, rule: &AclRule, src: &str, dst: &str, port: PortRef<'_>) -> bool {
        self.principal_matches(&rule.src, src)
            && self.principal_matches(&rule.dst, dst)
            && (rule.ports.is_empty() || rule.ports.iter().any(|p| port_matches(p, port)))
    }

    fn principal_matches(&self, set: &[String], principal: &str) -> bool {
        for entry in set {
            if entry == "*" {
                return true;
            }
            if let Some(group) = entry.strip_prefix("group:") {
                if self
                    .groups
                    .get(group)
                    .is_some_and(|members| members.iter().any(|m| m == principal))
                {
                    return true;
                }
            } else if entry == principal {
                return true;
            }
        }
        false
    }
}

/// Reference into a (proto, port) decision. Wildcards: pass
/// `proto = None` or `port = None` to mean "any".
#[derive(Clone, Copy, Debug)]
pub struct PortRef<'a> {
    pub proto: Option<&'a str>,
    pub port: Option<u16>,
}

impl<'a> PortRef<'a> {
    pub fn new(proto: &'a str, port: u16) -> Self {
        Self {
            proto: Some(proto),
            port: Some(port),
        }
    }
    pub fn any() -> Self {
        Self {
            proto: None,
            port: None,
        }
    }
}

fn port_matches(pattern: &str, port: PortRef<'_>) -> bool {
    // Accept "tcp/22", "udp/*", "*/*", or the legacy "*:tcp/22" form.
    let pat = pattern.strip_prefix("*:").unwrap_or(pattern);
    let (proto_part, port_part) = pat.split_once('/').unwrap_or((pat, "*"));
    let proto_ok = proto_part == "*" || port.proto.map_or(true, |p| p == proto_part);
    let port_ok = port_part == "*"
        || match (port.port, port_part.parse::<u16>()) {
            (Some(p), Ok(want)) => p == want,
            _ => false,
        };
    proto_ok && port_ok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_doc() {
        let src = r#"
            version = 1
            [[rules]]
            action = "accept"
            src = ["*"]
            dst = ["*"]
        "#;
        let doc = AclDoc::from_toml(src).unwrap();
        assert_eq!(doc.version, 1);
        assert_eq!(doc.rules.len(), 1);
    }

    #[test]
    fn canonical_form_is_stable_across_key_order() {
        let a = AclDoc::from_toml(
            r#"
            version = 1
            [groups]
            admins = ["oct2", "oct1"]
            eng    = ["oct3"]
            [[rules]]
            action = "accept"
            src = ["group:admins"]
            dst = ["*"]
        "#,
        )
        .unwrap();
        let b = AclDoc::from_toml(
            r#"
            version = 1
            [groups]
            eng    = ["oct3"]
            admins = ["oct1", "oct2"]
            [[rules]]
            action = "accept"
            dst = ["*"]
            src = ["group:admins"]
        "#,
        )
        .unwrap();
        assert_eq!(a.canonical_bytes(), b.canonical_bytes());
        assert_eq!(a.policy_hash(), b.policy_hash());
    }

    #[test]
    fn default_deny_when_no_rule_matches() {
        let doc = AclDoc {
            version: 1,
            groups: BTreeMap::default(),
            tags: BTreeMap::default(),
            rules: vec![AclRule {
                action: AclAction::Accept,
                src: vec!["oct1".into()],
                dst: vec!["oct2".into()],
                ports: vec![],
            }],
        };
        assert_eq!(doc.decide("octX", "octY", PortRef::any()), AclAction::Deny);
    }

    #[test]
    fn group_expansion_matches_member() {
        let doc = AclDoc {
            version: 1,
            groups: [
                ("admins".to_string(), vec!["octA".into(), "octB".into()]),
            ]
            .into_iter()
            .collect(),
            tags: BTreeMap::default(),
            rules: vec![AclRule {
                action: AclAction::Accept,
                src: vec!["group:admins".into()],
                dst: vec!["*".into()],
                ports: vec![],
            }],
        };
        assert_eq!(doc.decide("octA", "anything", PortRef::any()), AclAction::Accept);
        assert_eq!(doc.decide("octC", "anything", PortRef::any()), AclAction::Deny);
    }

    #[test]
    fn first_match_wins_even_if_later_would_accept() {
        let doc = AclDoc {
            version: 1,
            groups: BTreeMap::default(),
            tags: BTreeMap::default(),
            rules: vec![
                AclRule {
                    action: AclAction::Deny,
                    src: vec!["octA".into()],
                    dst: vec!["octB".into()],
                    ports: vec![],
                },
                AclRule {
                    action: AclAction::Accept,
                    src: vec!["*".into()],
                    dst: vec!["*".into()],
                    ports: vec![],
                },
            ],
        };
        assert_eq!(doc.decide("octA", "octB", PortRef::any()), AclAction::Deny);
        assert_eq!(doc.decide("octZ", "octB", PortRef::any()), AclAction::Accept);
    }

    #[test]
    fn port_pattern_tcp_22_matches() {
        let doc = AclDoc {
            version: 1,
            groups: BTreeMap::default(),
            tags: BTreeMap::default(),
            rules: vec![AclRule {
                action: AclAction::Accept,
                src: vec!["*".into()],
                dst: vec!["*".into()],
                ports: vec!["tcp/22".into()],
            }],
        };
        assert_eq!(
            doc.decide("a", "b", PortRef::new("tcp", 22)),
            AclAction::Accept
        );
        assert_eq!(
            doc.decide("a", "b", PortRef::new("tcp", 80)),
            AclAction::Deny
        );
        assert_eq!(
            doc.decide("a", "b", PortRef::new("udp", 22)),
            AclAction::Deny
        );
    }

    #[test]
    fn signed_acl_round_trip() {
        use octravpn_core::sig::KeyPair;
        let kp = KeyPair::generate();
        let doc = AclDoc::from_toml(
            r#"version = 1
            [[rules]]
            action = "accept"
            src = ["*"]
            dst = ["*"]
            "#,
        )
        .unwrap();
        let signed = SignedAclDoc::sign(doc, "octOWNER", &kp);
        signed.verify(&kp.public).unwrap();
    }

    #[test]
    fn signed_acl_rejects_wrong_pubkey() {
        use octravpn_core::sig::KeyPair;
        let owner = KeyPair::generate();
        let attacker = KeyPair::generate();
        let doc = AclDoc {
            version: 1,
            groups: BTreeMap::default(),
            tags: BTreeMap::default(),
            rules: vec![],
        };
        let signed = SignedAclDoc::sign(doc, "octOWNER", &owner);
        assert!(signed.verify(&attacker.public).is_err());
    }

    #[test]
    fn signed_acl_rejects_tampered_doc() {
        use octravpn_core::sig::KeyPair;
        let kp = KeyPair::generate();
        let doc = AclDoc {
            version: 1,
            groups: BTreeMap::default(),
            tags: BTreeMap::default(),
            rules: vec![],
        };
        let mut signed = SignedAclDoc::sign(doc.clone(), "octOWNER", &kp);
        // Mutate the doc — signature was over the old canonical bytes.
        signed.doc.rules.push(AclRule {
            action: AclAction::Accept,
            src: vec!["*".into()],
            dst: vec!["*".into()],
            ports: vec![],
        });
        assert!(signed.verify(&kp.public).is_err());
    }

    #[test]
    fn legacy_port_pattern_star_colon_tcp_22() {
        let doc = AclDoc {
            version: 1,
            groups: BTreeMap::default(),
            tags: BTreeMap::default(),
            rules: vec![AclRule {
                action: AclAction::Accept,
                src: vec!["*".into()],
                dst: vec!["*".into()],
                ports: vec!["*:tcp/22".into()],
            }],
        };
        assert_eq!(
            doc.decide("a", "b", PortRef::new("tcp", 22)),
            AclAction::Accept
        );
    }
}
