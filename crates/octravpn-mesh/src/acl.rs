//! Tailnet ACL document — thin facade over `headscale-api-acl`.
//!
//! Before the 2026-05-20 consolidation this module carried the full
//! ACL implementation (51 tests, parser, evaluator). The canonical
//! types + eval engine now live in the shared `headscale-api-acl`
//! crate so `octravpn-mesh` and `headscale-api` share one
//! battle-tested code path. This file:
//!
//! * Re-exports the canonical types ([`AclAction`], [`AclDoc`],
//!   [`AclRule`], [`NodeView`], [`PortRef`], [`NodeAttrGrant`],
//!   [`AutoApprovers`], [`SshRule`]) under their octravpn-mesh-side
//!   names so every existing caller compiles unchanged.
//! * Adds the OctraVPN-only [`SignedAclDoc`] — an ed25519
//!   owner-signed wrapper around the canonical doc. The on-chain
//!   `acl_policy` field of a tailnet is the SHA-256 of the
//!   document's canonical bytes; this signature binds the off-chain
//!   distribution to the on-chain owner pubkey.
//!
//! Distribution model: the doc is published off-chain (typically
//! HTTPS or IPFS by the tailnet owner). Every member fetches it,
//! verifies the signature against `circle.owner`, then checks the
//! `policy_hash` matches what's on-chain before enforcing rules at
//! the data plane.

pub use headscale_api_acl::{
    parse_cidr, parse_hujson_policy, strip_hujson, AclAction, AclDoc, AclRule, AutoApprovers,
    NodeAttrGrant, NodeView, PolicyParseError, PortRef, SshRule,
};

use serde::{Deserialize, Serialize};

use crate::MeshError;

/// An ACL document plus the tailnet owner's signature over its
/// canonical bytes. Distributed alongside the doc (HTTPS, IPFS,
/// validator endpoints) so members can verify the authorship without
/// trusting the transport.
///
/// Signature storage matches `SignedPeerSnapshot`: raw `[u8;64]`
/// with a serde helper that emits as a byte string in JSON/CBOR.
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
    /// Produce a `SignedAclDoc` by signing `doc.canonical_bytes()`
    /// with `kp`. Pair with [`Self::verify`] against the owner's
    /// public key.
    pub fn sign(
        doc: AclDoc,
        owner_addr: impl Into<String>,
        kp: &octravpn_core::sig::KeyPair,
    ) -> Self {
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

#[cfg(test)]
mod tests {
    use super::*;

    // Coverage for the canonical types lives in `headscale-api-acl`
    // (58 tests, ported from the pre-consolidation 51 + the
    // headscale-api unit blocks). This module owns only the
    // OctraVPN extension: ed25519 owner-signed doc round-trip.

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
            ..Default::default()
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
            ..Default::default()
        };
        let mut signed = SignedAclDoc::sign(doc, "octOWNER", &kp);
        signed.doc.rules.push(AclRule {
            action: AclAction::Accept,
            src: vec!["*".into()],
            dst: vec!["*".into()],
            ports: vec![],
        });
        assert!(signed.verify(&kp.public).is_err());
    }

    #[test]
    fn policy_hash_matches_canonical_bytes_sha256() {
        // Sanity: the SignedAclDoc shortcut returns the same hash
        // the doc's canonical_bytes would.
        use octravpn_core::sig::KeyPair;
        let kp = KeyPair::generate();
        let doc = AclDoc {
            version: 1,
            ..Default::default()
        };
        let expect = doc.policy_hash();
        let signed = SignedAclDoc::sign(doc, "octOWNER", &kp);
        assert_eq!(signed.policy_hash(), expect);
    }
}
