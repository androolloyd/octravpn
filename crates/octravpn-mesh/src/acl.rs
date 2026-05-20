//! Tailnet ACL document, parser, canonicalisation, and evaluator.
//!
//! The on-chain `acl_policy` field of a tailnet is the SHA-256 of a
//! canonicalised ACL document. The full document is distributed
//! off-chain (typically served by the tailnet owner over HTTPS or
//! gossiped through validator endpoints). Every member fetches it,
//! verifies the hash matches what's on-chain, then enforces the
//! decisions at the data plane.
//!
//! ## Headscale-go compatibility
//!
//! This evaluator mirrors features of upstream `juanfont/headscale`
//! `hscontrol/policy/v2/`:
//!
//! * `groups` / `tagOwners` / `hosts` / `ipsets` definitions.
//! * `autogroup:*` expansion — `internet`, `member`, `nonroot`,
//!   `tagged`, `tag:<x>`, `self`.
//! * `nodeAttrs` — per-target capability flags (`funnel`,
//!   `exit-node`, …) returned by [`AclDoc::attrs_for`].
//! * `autoApprovers` — route + exit-node auto-approval queried via
//!   [`AclDoc::auto_approves_route`] / [`AclDoc::auto_approves_exit_node`].
//!
//! Document shape (TOML; HuJSON is parsed upstream of this crate by
//! `headscale-api::policy::hujson`):
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
//! [tag_owners]
//! "tag:router" = ["group:admins"]
//!
//! [hosts]
//! office = "10.0.0.0/8"
//!
//! [ipsets]
//! office = ["10.0.0.0/8", "10.1.0.0/16"]
//!
//! [auto_approvers]
//! exit_node = ["tag:exit"]
//! [auto_approvers.routes]
//! "10.0.0.0/8" = ["tag:router"]
//!
//! [[node_attrs]]
//! target = ["tag:exit"]
//! attr   = ["funnel", "exit-node"]
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
use std::net::IpAddr;

use ipnet::IpNet;
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
///
/// `#[serde(deny_unknown_fields)]`: a misspelled rule field is a
/// loud error, not a silently permissive ACL.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AclRule {
    pub action: AclAction,
    pub src: Vec<String>,
    pub dst: Vec<String>,
    #[serde(default)]
    pub ports: Vec<String>,
}

/// One `nodeAttrs` grant. Mirrors upstream
/// `juanfont/headscale@main:hscontrol/policy/v2/types.go::NodeAttrGrant`.
///
/// `target` lists principal tokens (the same vocabulary as rule `src`/
/// `dst`) the attrs apply to. `attr` is the list of capability flags
/// the matching nodes receive — strings like `"funnel"`, `"exit-node"`,
/// `"ssh"`. The client-side daemon honours these per
/// `tailcfg.NodeCapability`.
#[derive(Clone, Debug, Eq, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeAttrGrant {
    pub target: Vec<String>,
    #[serde(default)]
    pub attr: Vec<String>,
}

/// `autoApprovers` block — route + exit-node auto-approval. Upstream
/// `policy/v2/types.go::AutoApproverPolicy`.
///
/// * `routes` keys are CIDR strings, values are principal-token lists
///   (`tag:<name>` / `group:<name>` / username / `*`). If a node that
///   matches one of the principals advertises a route covered by the
///   key prefix, the route is auto-approved.
/// * `exit_node` is a flat list of principals. Matching nodes become
///   auto-approved exit nodes.
#[derive(Clone, Debug, Eq, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutoApprovers {
    #[serde(default)]
    pub routes: BTreeMap<String, Vec<String>>,
    #[serde(default, rename = "exit_node", alias = "exitNode")]
    pub exit_node: Vec<String>,
}

/// SSH grant. Minimal mirror of upstream `SSH` rule — `action: accept|check`,
/// `src`, `dst`, `users` list. The full upstream surface is broader;
/// this carries what the parser must round-trip.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshRule {
    /// Upstream allows `accept` or `check`. We keep the literal for
    /// round-trip purposes; semantics aren't enforced at this layer.
    pub action: String,
    pub src: Vec<String>,
    pub dst: Vec<String>,
    #[serde(default)]
    pub users: Vec<String>,
}

/// Top-level ACL document.
///
/// `#[serde(deny_unknown_fields)]`: unknown top-level keys are
/// rejected. Forward-compat is handled explicitly via the `version`
/// field — bump that and the parser plus this struct in lockstep.
#[derive(Clone, Debug, Eq, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AclDoc {
    pub version: u32,
    #[serde(default)]
    pub groups: BTreeMap<String, Vec<String>>,
    /// `tags` is the legacy short-form alias (tag_name → description).
    /// Kept for backward compatibility with v1 docs. Upstream stores
    /// tag ownership in `tag_owners` instead.
    #[serde(default)]
    pub tags: BTreeMap<String, String>,
    /// `tag_owners` mirrors upstream `tagOwners`: a tag name → list of
    /// principals (groups/users) allowed to claim that tag.
    #[serde(default, alias = "tagOwners")]
    pub tag_owners: BTreeMap<String, Vec<String>>,
    /// `hosts`: named single-CIDR aliases. Used as `host:office` (or
    /// the bare name) in rule src/dst.
    #[serde(default)]
    pub hosts: BTreeMap<String, String>,
    /// `ipsets`: named lists of CIDRs. Used as `ipset:office` in
    /// src/dst. Distinct from `hosts` so the same name can carry
    /// multiple prefixes.
    #[serde(default)]
    pub ipsets: BTreeMap<String, Vec<String>>,
    /// `auto_approvers`: routes + exit-node auto-approval. See
    /// [`AutoApprovers`].
    #[serde(default, alias = "autoApprovers")]
    pub auto_approvers: AutoApprovers,
    /// `node_attrs`: per-target capability flags. See [`NodeAttrGrant`].
    #[serde(default, alias = "nodeAttrs")]
    pub node_attrs: Vec<NodeAttrGrant>,
    /// `ssh`: SSH grants. Carried as a list of [`SshRule`].
    #[serde(default)]
    pub ssh: Vec<SshRule>,
    #[serde(default)]
    pub rules: Vec<AclRule>,
}

/// A node's identity facets used during principal / autogroup
/// matching. Constructed by the caller and passed into matching
/// helpers like [`AclDoc::attrs_for`] / [`AclDoc::evaluate_with`].
///
/// All fields are optional because the caller may not know every
/// facet at every call site — e.g. NodeAttrs only needs `user` + `tags`,
/// route approval only needs `tags`. An empty `NodeView` matches only
/// `*` / `autogroup:member` (and `autogroup:nonroot` if no tags).
#[derive(Clone, Debug, Default)]
pub struct NodeView<'a> {
    /// Node's tailnet IPv4 / IPv6 / `oct…` identity. Compared with
    /// rule literal sources and dest tokens.
    pub addr: Option<&'a str>,
    /// Owning user label.
    pub user: Option<&'a str>,
    /// Tags currently bound to the node. Each entry is the bare tag
    /// name without the `tag:` prefix (so `["router", "exit"]`).
    pub tags: &'a [String],
}

impl<'a> NodeView<'a> {
    pub fn new(addr: &'a str) -> Self {
        Self {
            addr: Some(addr),
            user: None,
            tags: &[],
        }
    }
    pub fn with_user(mut self, user: &'a str) -> Self {
        self.user = Some(user);
        self
    }
    pub fn with_tags(mut self, tags: &'a [String]) -> Self {
        self.tags = tags;
        self
    }
}

impl AclDoc {
    /// Parse a TOML document.
    ///
    /// Unknown top-level fields **and** unknown rule fields are
    /// rejected — see `#[serde(deny_unknown_fields)]` on [`AclDoc`]
    /// and [`AclRule`]. A misspelled `action` or stray `accept_all`
    /// flag will fail this call with a parse error rather than
    /// silently becoming a permissive policy.
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
        let groups_sorted = sort_map_of_vecs(&self.groups);
        let mut tags_sorted: BTreeMap<String, String> = BTreeMap::new();
        for (k, v) in &self.tags {
            tags_sorted.insert(k.clone(), v.clone());
        }
        let tag_owners_sorted = sort_map_of_vecs(&self.tag_owners);
        let mut hosts_sorted: BTreeMap<String, String> = BTreeMap::new();
        for (k, v) in &self.hosts {
            hosts_sorted.insert(k.clone(), v.clone());
        }
        let ipsets_sorted = sort_map_of_vecs(&self.ipsets);
        let auto_approver_routes = sort_map_of_vecs(&self.auto_approvers.routes);
        let mut exit_node_sorted = self.auto_approvers.exit_node.clone();
        exit_node_sorted.sort();
        let node_attrs_sorted: Vec<serde_json::Value> = self
            .node_attrs
            .iter()
            .map(|n| {
                let mut tgt = n.target.clone();
                let mut atr = n.attr.clone();
                tgt.sort();
                atr.sort();
                serde_json::json!({ "target": tgt, "attr": atr })
            })
            .collect();
        let ssh_sorted: Vec<serde_json::Value> = self
            .ssh
            .iter()
            .map(|s| {
                let mut src = s.src.clone();
                let mut dst = s.dst.clone();
                let mut users = s.users.clone();
                src.sort();
                dst.sort();
                users.sort();
                serde_json::json!({
                    "action": s.action,
                    "src": src,
                    "dst": dst,
                    "users": users,
                })
            })
            .collect();
        serde_json::json!({
            "version": self.version,
            "groups": groups_sorted,
            "tags": tags_sorted,
            "tag_owners": tag_owners_sorted,
            "hosts": hosts_sorted,
            "ipsets": ipsets_sorted,
            "auto_approvers": {
                "routes": auto_approver_routes,
                "exit_node": exit_node_sorted,
            },
            "node_attrs": node_attrs_sorted,
            "ssh": ssh_sorted,
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

fn sort_map_of_vecs(m: &BTreeMap<String, Vec<String>>) -> BTreeMap<String, Vec<String>> {
    let mut out = BTreeMap::new();
    for (k, v) in m {
        let mut sorted = v.clone();
        sorted.sort();
        out.insert(k.clone(), sorted);
    }
    out
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

// Empty `impl` to keep the file's top-level structure compiling; the
// previous `impl AclDoc { ... }` block ends above.
impl AclDoc {
    /// Evaluate a (src, dst, port) tuple. Returns the action of the
    /// first matching rule, or `Deny` if no rule matched (default-deny).
    ///
    /// Equivalent to [`Self::evaluate_with`] with empty NodeViews —
    /// autogroup tokens that depend on per-node context will not match.
    pub fn decide(&self, src: &str, dst: &str, port: PortRef<'_>) -> AclAction {
        let src_view = NodeView::new(src);
        let dst_view = NodeView::new(dst);
        self.evaluate_with(&src_view, &dst_view, port)
    }

    /// Evaluate a (src, dst, port) tuple using full NodeViews so the
    /// matcher can resolve `autogroup:self`, `autogroup:member`,
    /// `autogroup:nonroot`, `autogroup:tagged`, `autogroup:tag:<x>`,
    /// and `host:` / `ipset:` aliases.
    pub fn evaluate_with(
        &self,
        src: &NodeView<'_>,
        dst: &NodeView<'_>,
        port: PortRef<'_>,
    ) -> AclAction {
        for rule in &self.rules {
            if self.matches(rule, src, dst, port) {
                return rule.action.clone();
            }
        }
        AclAction::Deny
    }

    fn matches(
        &self,
        rule: &AclRule,
        src: &NodeView<'_>,
        dst: &NodeView<'_>,
        port: PortRef<'_>,
    ) -> bool {
        self.principal_matches(&rule.src, src, Some(dst))
            && self.principal_matches(&rule.dst, dst, Some(src))
            && (rule.ports.is_empty() || rule.ports.iter().any(|p| port_matches(p, port)))
    }

    /// Returns the list of NodeAttr capability flags that apply to
    /// `node`. Merges every matching [`NodeAttrGrant`] target with
    /// dedupe; output is stable (sorted) so it's safe to compare
    /// across calls.
    ///
    /// Mirrors upstream `policy.compileNodeAttrs` — every grant whose
    /// `target` resolves to include `node` contributes its `attr`
    /// list to the result.
    pub fn attrs_for(&self, node: &NodeView<'_>) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for grant in &self.node_attrs {
            if self.principal_matches(&grant.target, node, None) {
                for a in &grant.attr {
                    if !out.contains(a) {
                        out.push(a.clone());
                    }
                }
            }
        }
        out.sort();
        out
    }

    /// True if `node` should have a route covering `prefix`
    /// auto-approved per the `autoApprovers.routes` map.
    ///
    /// Walks every key in `auto_approvers.routes` whose CIDR covers
    /// (or equals) `prefix`; if at least one of the principals listed
    /// against that key resolves to include `node`, the route is
    /// auto-approved.
    pub fn auto_approves_route(&self, node: &NodeView<'_>, prefix: &str) -> bool {
        let Some(advertised) = parse_cidr(prefix) else {
            return false;
        };
        for (key, principals) in &self.auto_approvers.routes {
            let Some(approver_net) = parse_cidr(key) else {
                continue;
            };
            if !covers(&approver_net, &advertised) {
                continue;
            }
            if self.principal_matches(principals, node, None) {
                return true;
            }
        }
        false
    }

    /// True if `node` should be auto-approved as an exit-node per
    /// `autoApprovers.exit_node`.
    pub fn auto_approves_exit_node(&self, node: &NodeView<'_>) -> bool {
        if self.auto_approvers.exit_node.is_empty() {
            return false;
        }
        self.principal_matches(&self.auto_approvers.exit_node, node, None)
    }

    /// Match `set` (a rule's `src` or `dst`) against a `principal`
    /// NodeView. `peer` is the *other* side of the connection — required
    /// by `autogroup:self` which checks src == dst.
    fn principal_matches(
        &self,
        set: &[String],
        principal: &NodeView<'_>,
        peer: Option<&NodeView<'_>>,
    ) -> bool {
        for entry in set {
            if self.principal_matches_one(entry, principal, peer) {
                return true;
            }
        }
        false
    }

    fn principal_matches_one(
        &self,
        entry: &str,
        principal: &NodeView<'_>,
        peer: Option<&NodeView<'_>>,
    ) -> bool {
        // `*` — always matches.
        if entry == "*" {
            return true;
        }

        // `group:<name>` — member literal match.
        if let Some(group) = entry.strip_prefix("group:") {
            if let Some(members) = self.groups.get(group) {
                return members.iter().any(|m| identity_matches(m, principal));
            }
            return false;
        }

        // `tag:<name>` — principal has this tag bound.
        if let Some(tag) = entry.strip_prefix("tag:") {
            // `autogroup:tag:<name>` is handled in the autogroup branch;
            // a bare `tag:foo` checks the principal's tag list. Empty tag
            // list ⇒ never matches `tag:*`.
            return principal.tags.iter().any(|t| t == tag);
        }

        // `autogroup:<kind>` — see expansion table below.
        if let Some(ag) = entry.strip_prefix("autogroup:") {
            return autogroup_matches(ag, principal, peer);
        }

        // `host:<name>` — single-CIDR alias from `hosts` table.
        if let Some(host) = entry.strip_prefix("host:") {
            if let Some(cidr) = self.hosts.get(host) {
                return addr_in_cidr(principal.addr, cidr);
            }
            return false;
        }

        // `ipset:<name>` — multi-CIDR alias from `ipsets` table.
        if let Some(ipset) = entry.strip_prefix("ipset:") {
            if let Some(cidrs) = self.ipsets.get(ipset) {
                return cidrs.iter().any(|c| addr_in_cidr(principal.addr, c));
            }
            return false;
        }

        // Plain CIDR / single address literal.
        if entry.contains('/') {
            return addr_in_cidr(principal.addr, entry);
        }

        // Bare literal — must match either addr or user.
        identity_matches(entry, principal)
    }
}

/// True if `entry` matches the principal's address or user label.
fn identity_matches(entry: &str, principal: &NodeView<'_>) -> bool {
    if let Some(addr) = principal.addr {
        if entry == addr {
            return true;
        }
    }
    if let Some(user) = principal.user {
        if entry == user {
            return true;
        }
    }
    false
}

/// Expand an `autogroup:<kind>` token.
///
/// Supported kinds:
///
/// * `internet` — matches any traffic (used to express exit-node-style
///   "the public internet" destination). Match-all; equivalent to `*`.
/// * `member` — matches any tailnet member (presence is enough — caller
///   has already vouched for the principal being in the tailnet by
///   constructing the NodeView).
/// * `nonroot` — member with no bound tags.
/// * `tagged` — member with at least one tag.
/// * `tag:<name>` — member with the named tag bound.
/// * `self` — the principal is the same node as the peer on the other
///   side of the connection. Compares `addr` first, falls back to `user`.
///
/// Unknown autogroup kinds: returns false. Upstream rejects at parse
/// time; we tolerate at evaluate time to keep evaluation infallible.
fn autogroup_matches(kind: &str, principal: &NodeView<'_>, peer: Option<&NodeView<'_>>) -> bool {
    if kind == "internet" {
        return true;
    }
    if kind == "member" {
        return true;
    }
    if kind == "nonroot" {
        return principal.tags.is_empty();
    }
    if kind == "tagged" {
        return !principal.tags.is_empty();
    }
    if let Some(tag) = kind.strip_prefix("tag:") {
        return principal.tags.iter().any(|t| t == tag);
    }
    if kind == "self" {
        let Some(peer) = peer else {
            return false;
        };
        if let (Some(a), Some(b)) = (principal.addr, peer.addr) {
            return a == b;
        }
        if let (Some(a), Some(b)) = (principal.user, peer.user) {
            return a == b;
        }
        return false;
    }
    false
}

/// Parse a CIDR or bare-address string into an `IpNet`. A bare address
/// is treated as a /32 (v4) or /128 (v6).
pub(crate) fn parse_cidr(s: &str) -> Option<IpNet> {
    if let Ok(n) = s.parse::<IpNet>() {
        return Some(n);
    }
    if let Ok(addr) = s.parse::<IpAddr>() {
        return IpNet::new(addr, if addr.is_ipv4() { 32 } else { 128 }).ok();
    }
    None
}

/// `outer` covers `inner` iff they're the same family and every host
/// in `inner` is also in `outer`. Uses `ipnet::IpNet::contains` for the
/// prefix-cover check.
fn covers(outer: &IpNet, inner: &IpNet) -> bool {
    match (outer, inner) {
        (IpNet::V4(o), IpNet::V4(i)) => {
            if o.prefix_len() > i.prefix_len() {
                return false;
            }
            o.contains(&i.network())
        }
        (IpNet::V6(o), IpNet::V6(i)) => {
            if o.prefix_len() > i.prefix_len() {
                return false;
            }
            o.contains(&i.network())
        }
        _ => false,
    }
}

/// True if `addr` (an IP-like string) falls inside `cidr`.
fn addr_in_cidr(addr: Option<&str>, cidr: &str) -> bool {
    let Some(addr) = addr else {
        return false;
    };
    let Some(net) = parse_cidr(cidr) else {
        return false;
    };
    let Ok(parsed) = addr.parse::<IpAddr>() else {
        return false;
    };
    net.contains(&parsed)
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

    // --- Original P0 tests (preserved) ---------------------------------

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
            rules: vec![AclRule {
                action: AclAction::Accept,
                src: vec!["oct1".into()],
                dst: vec!["oct2".into()],
                ports: vec![],
            }],
            ..Default::default()
        };
        assert_eq!(doc.decide("octX", "octY", PortRef::any()), AclAction::Deny);
    }

    #[test]
    fn group_expansion_matches_member() {
        let doc = AclDoc {
            version: 1,
            groups: std::iter::once(("admins".to_string(), vec!["octA".into(), "octB".into()]))
                .collect(),
            rules: vec![AclRule {
                action: AclAction::Accept,
                src: vec!["group:admins".into()],
                dst: vec!["*".into()],
                ports: vec![],
            }],
            ..Default::default()
        };
        assert_eq!(
            doc.decide("octA", "anything", PortRef::any()),
            AclAction::Accept
        );
        assert_eq!(
            doc.decide("octC", "anything", PortRef::any()),
            AclAction::Deny
        );
    }

    #[test]
    fn first_match_wins_even_if_later_would_accept() {
        let doc = AclDoc {
            version: 1,
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
            ..Default::default()
        };
        assert_eq!(doc.decide("octA", "octB", PortRef::any()), AclAction::Deny);
        assert_eq!(
            doc.decide("octZ", "octB", PortRef::any()),
            AclAction::Accept
        );
    }

    #[test]
    fn port_pattern_tcp_22_matches() {
        let doc = AclDoc {
            version: 1,
            rules: vec![AclRule {
                action: AclAction::Accept,
                src: vec!["*".into()],
                dst: vec!["*".into()],
                ports: vec!["tcp/22".into()],
            }],
            ..Default::default()
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
    fn rejects_unknown_top_level_field() {
        let src = r#"
            version = 1
            policy_owner = "octATTACKER"
            [[rules]]
            action = "accept"
            src = ["*"]
            dst = ["*"]
        "#;
        let err = AclDoc::from_toml(src).expect_err("unknown top-level key must reject");
        let msg = format!("{err}");
        assert!(
            msg.contains("policy_owner") || msg.contains("unknown field"),
            "error should name the offending field, got: {msg}"
        );
    }

    #[test]
    fn rejects_unknown_rule_field() {
        let src = r#"
            version = 1
            [[rules]]
            action = "accept"
            src = ["*"]
            dst = ["*"]
            permit_all = true
        "#;
        let err = AclDoc::from_toml(src).expect_err("unknown rule key must reject");
        let msg = format!("{err}");
        assert!(
            msg.contains("permit_all") || msg.contains("unknown field"),
            "error should name the offending field, got: {msg}"
        );
    }

    #[test]
    fn rejects_misspelled_action_field() {
        let src = r#"
            version = 1
            [[rules]]
            actoin = "accept"
            src = ["*"]
            dst = ["*"]
        "#;
        let err = AclDoc::from_toml(src).expect_err("typo'd action must reject");
        let msg = format!("{err}");
        assert!(
            msg.contains("actoin") || msg.contains("action") || msg.contains("unknown field"),
            "error should reference the typo or missing field, got: {msg}"
        );
    }

    #[test]
    fn legacy_port_pattern_star_colon_tcp_22() {
        let doc = AclDoc {
            version: 1,
            rules: vec![AclRule {
                action: AclAction::Accept,
                src: vec!["*".into()],
                dst: vec!["*".into()],
                ports: vec!["*:tcp/22".into()],
            }],
            ..Default::default()
        };
        assert_eq!(
            doc.decide("a", "b", PortRef::new("tcp", 22)),
            AclAction::Accept
        );
    }

    // --- New tests: autogroup expansion -------------------------------

    fn doc_with_rule(src: &[&str], dst: &[&str]) -> AclDoc {
        AclDoc {
            version: 1,
            rules: vec![AclRule {
                action: AclAction::Accept,
                src: src.iter().map(|s| (*s).to_string()).collect(),
                dst: dst.iter().map(|s| (*s).to_string()).collect(),
                ports: vec![],
            }],
            ..Default::default()
        }
    }

    #[test]
    fn autogroup_internet_matches_anything() {
        let doc = doc_with_rule(&["*"], &["autogroup:internet"]);
        let s = NodeView::new("100.64.0.1");
        let d = NodeView::new("8.8.8.8");
        assert_eq!(
            doc.evaluate_with(&s, &d, PortRef::any()),
            AclAction::Accept
        );
    }

    #[test]
    fn autogroup_member_matches_any_node() {
        let doc = doc_with_rule(&["autogroup:member"], &["*"]);
        let s = NodeView::new("100.64.0.1");
        let d = NodeView::new("100.64.0.2");
        assert_eq!(
            doc.evaluate_with(&s, &d, PortRef::any()),
            AclAction::Accept
        );
    }

    #[test]
    fn autogroup_nonroot_only_matches_untagged() {
        let doc = doc_with_rule(&["autogroup:nonroot"], &["*"]);
        let tagged: Vec<String> = vec!["router".into()];
        let untagged = NodeView::new("100.64.0.1");
        let tagged_view = NodeView::new("100.64.0.2").with_tags(&tagged);
        let dst = NodeView::new("100.64.0.5");
        assert_eq!(
            doc.evaluate_with(&untagged, &dst, PortRef::any()),
            AclAction::Accept
        );
        assert_eq!(
            doc.evaluate_with(&tagged_view, &dst, PortRef::any()),
            AclAction::Deny
        );
    }

    #[test]
    fn autogroup_tagged_only_matches_tagged() {
        let doc = doc_with_rule(&["autogroup:tagged"], &["*"]);
        let tags: Vec<String> = vec!["exit".into()];
        let tagged_view = NodeView::new("100.64.0.1").with_tags(&tags);
        let untagged = NodeView::new("100.64.0.2");
        let dst = NodeView::new("100.64.0.5");
        assert_eq!(
            doc.evaluate_with(&tagged_view, &dst, PortRef::any()),
            AclAction::Accept
        );
        assert_eq!(
            doc.evaluate_with(&untagged, &dst, PortRef::any()),
            AclAction::Deny
        );
    }

    #[test]
    fn autogroup_tag_specific_matches_only_that_tag() {
        let doc = doc_with_rule(&["autogroup:tag:router"], &["*"]);
        let router_tags = vec!["router".into()];
        let exit_tags = vec!["exit".into()];
        let router = NodeView::new("100.64.0.1").with_tags(&router_tags);
        let exit = NodeView::new("100.64.0.2").with_tags(&exit_tags);
        let dst = NodeView::new("100.64.0.5");
        assert_eq!(
            doc.evaluate_with(&router, &dst, PortRef::any()),
            AclAction::Accept
        );
        assert_eq!(
            doc.evaluate_with(&exit, &dst, PortRef::any()),
            AclAction::Deny
        );
    }

    #[test]
    fn autogroup_self_matches_same_addr() {
        let doc = doc_with_rule(&["autogroup:member"], &["autogroup:self"]);
        let alice = NodeView::new("100.64.0.1");
        let bob = NodeView::new("100.64.0.2");
        assert_eq!(
            doc.evaluate_with(&alice, &alice.clone(), PortRef::any()),
            AclAction::Accept,
            "self-traffic must match autogroup:self"
        );
        assert_eq!(
            doc.evaluate_with(&alice, &bob, PortRef::any()),
            AclAction::Deny,
            "peer-traffic must not match autogroup:self"
        );
    }

    #[test]
    fn autogroup_self_matches_same_user_when_addr_unknown() {
        let doc = doc_with_rule(&["autogroup:member"], &["autogroup:self"]);
        let user = "alice".to_string();
        let s = NodeView {
            addr: None,
            user: Some(&user),
            tags: &[],
        };
        let d = NodeView {
            addr: None,
            user: Some(&user),
            tags: &[],
        };
        let s2 = NodeView {
            addr: None,
            user: Some("bob"),
            tags: &[],
        };
        assert_eq!(
            doc.evaluate_with(&s, &d, PortRef::any()),
            AclAction::Accept
        );
        assert_eq!(
            doc.evaluate_with(&s, &s2, PortRef::any()),
            AclAction::Deny
        );
    }

    // --- New tests: bare tag: prefix on principals --------------------

    #[test]
    fn bare_tag_prefix_matches_tagged_principal() {
        let doc = doc_with_rule(&["tag:router"], &["*"]);
        let tags: Vec<String> = vec!["router".into()];
        let router = NodeView::new("100.64.0.1").with_tags(&tags);
        let plain = NodeView::new("100.64.0.2");
        let dst = NodeView::new("100.64.0.5");
        assert_eq!(
            doc.evaluate_with(&router, &dst, PortRef::any()),
            AclAction::Accept
        );
        assert_eq!(
            doc.evaluate_with(&plain, &dst, PortRef::any()),
            AclAction::Deny
        );
    }

    // --- New tests: hosts / ipsets ------------------------------------

    #[test]
    fn host_alias_matches_address_inside_cidr() {
        let mut doc = doc_with_rule(&["*"], &["host:office"]);
        doc.hosts.insert("office".into(), "10.0.0.0/8".into());
        let s = NodeView::new("100.64.0.1");
        let inside = NodeView::new("10.5.5.5");
        let outside = NodeView::new("8.8.8.8");
        assert_eq!(
            doc.evaluate_with(&s, &inside, PortRef::any()),
            AclAction::Accept
        );
        assert_eq!(
            doc.evaluate_with(&s, &outside, PortRef::any()),
            AclAction::Deny
        );
    }

    #[test]
    fn ipset_alias_matches_any_member_cidr() {
        let mut doc = doc_with_rule(&["*"], &["ipset:office"]);
        doc.ipsets
            .insert("office".into(), vec!["10.0.0.0/8".into(), "192.168.0.0/16".into()]);
        let s = NodeView::new("100.64.0.1");
        let in1 = NodeView::new("10.1.2.3");
        let in2 = NodeView::new("192.168.4.5");
        let out = NodeView::new("172.16.0.1");
        assert_eq!(
            doc.evaluate_with(&s, &in1, PortRef::any()),
            AclAction::Accept
        );
        assert_eq!(
            doc.evaluate_with(&s, &in2, PortRef::any()),
            AclAction::Accept
        );
        assert_eq!(
            doc.evaluate_with(&s, &out, PortRef::any()),
            AclAction::Deny
        );
    }

    #[test]
    fn unknown_host_alias_is_deny() {
        let doc = doc_with_rule(&["*"], &["host:noexist"]);
        let s = NodeView::new("100.64.0.1");
        let d = NodeView::new("10.0.0.5");
        assert_eq!(doc.evaluate_with(&s, &d, PortRef::any()), AclAction::Deny);
    }

    #[test]
    fn unknown_ipset_alias_is_deny() {
        let doc = doc_with_rule(&["*"], &["ipset:noexist"]);
        let s = NodeView::new("100.64.0.1");
        let d = NodeView::new("10.0.0.5");
        assert_eq!(doc.evaluate_with(&s, &d, PortRef::any()), AclAction::Deny);
    }

    #[test]
    fn cidr_literal_in_dst_matches_address_inside() {
        let doc = doc_with_rule(&["*"], &["10.0.0.0/8"]);
        let s = NodeView::new("100.64.0.1");
        let d_in = NodeView::new("10.5.5.5");
        let d_out = NodeView::new("8.8.8.8");
        assert_eq!(
            doc.evaluate_with(&s, &d_in, PortRef::any()),
            AclAction::Accept
        );
        assert_eq!(
            doc.evaluate_with(&s, &d_out, PortRef::any()),
            AclAction::Deny
        );
    }

    // --- New tests: NodeAttrs -----------------------------------------

    #[test]
    fn attrs_for_collects_matching_grants() {
        let mut doc = AclDoc {
            version: 1,
            ..Default::default()
        };
        doc.node_attrs.push(NodeAttrGrant {
            target: vec!["*".into()],
            attr: vec!["funnel".into()],
        });
        doc.node_attrs.push(NodeAttrGrant {
            target: vec!["tag:exit".into()],
            attr: vec!["exit-node".into()],
        });
        let exit_tags = vec!["exit".into()];
        let exit_node = NodeView::new("100.64.0.1").with_tags(&exit_tags);
        let plain = NodeView::new("100.64.0.2");
        let exit_attrs = doc.attrs_for(&exit_node);
        let plain_attrs = doc.attrs_for(&plain);
        assert_eq!(exit_attrs, vec!["exit-node", "funnel"]);
        assert_eq!(plain_attrs, vec!["funnel"]);
    }

    #[test]
    fn attrs_for_dedupes_repeated_capabilities() {
        let mut doc = AclDoc {
            version: 1,
            ..Default::default()
        };
        doc.node_attrs.push(NodeAttrGrant {
            target: vec!["*".into()],
            attr: vec!["ssh".into()],
        });
        doc.node_attrs.push(NodeAttrGrant {
            target: vec!["autogroup:member".into()],
            attr: vec!["ssh".into(), "funnel".into()],
        });
        let n = NodeView::new("100.64.0.1");
        let out = doc.attrs_for(&n);
        assert_eq!(out, vec!["funnel", "ssh"]);
    }

    #[test]
    fn attrs_for_empty_when_no_grant_matches() {
        let mut doc = AclDoc {
            version: 1,
            ..Default::default()
        };
        doc.node_attrs.push(NodeAttrGrant {
            target: vec!["tag:exit".into()],
            attr: vec!["exit-node".into()],
        });
        let n = NodeView::new("100.64.0.1");
        assert!(doc.attrs_for(&n).is_empty());
    }

    #[test]
    fn attrs_for_user_target() {
        let mut doc = AclDoc {
            version: 1,
            ..Default::default()
        };
        doc.node_attrs.push(NodeAttrGrant {
            target: vec!["alice".into()],
            attr: vec!["funnel".into()],
        });
        let alice = NodeView::new("100.64.0.1").with_user("alice");
        let bob = NodeView::new("100.64.0.2").with_user("bob");
        assert_eq!(doc.attrs_for(&alice), vec!["funnel"]);
        assert!(doc.attrs_for(&bob).is_empty());
    }

    // --- New tests: autoApprovers -------------------------------------

    #[test]
    fn auto_approve_route_matches_exact_prefix() {
        let mut doc = AclDoc {
            version: 1,
            ..Default::default()
        };
        doc.auto_approvers
            .routes
            .insert("10.0.0.0/8".into(), vec!["tag:router".into()]);
        let tags = vec!["router".into()];
        let router = NodeView::new("100.64.0.1").with_tags(&tags);
        let plain = NodeView::new("100.64.0.2");
        assert!(doc.auto_approves_route(&router, "10.0.0.0/8"));
        assert!(!doc.auto_approves_route(&plain, "10.0.0.0/8"));
    }

    #[test]
    fn auto_approve_route_matches_subprefix() {
        // A node advertising 10.5.0.0/16 should be approved when the
        // policy permits 10.0.0.0/8 — the advertised prefix is a
        // subset of the approver key.
        let mut doc = AclDoc {
            version: 1,
            ..Default::default()
        };
        doc.auto_approvers
            .routes
            .insert("10.0.0.0/8".into(), vec!["tag:router".into()]);
        let tags = vec!["router".into()];
        let router = NodeView::new("100.64.0.1").with_tags(&tags);
        assert!(doc.auto_approves_route(&router, "10.5.0.0/16"));
    }

    #[test]
    fn auto_approve_route_rejects_superprefix() {
        // A node advertising 10.0.0.0/4 (superset) when the policy
        // permits only 10.0.0.0/8 must NOT be auto-approved.
        let mut doc = AclDoc {
            version: 1,
            ..Default::default()
        };
        doc.auto_approvers
            .routes
            .insert("10.0.0.0/8".into(), vec!["tag:router".into()]);
        let tags = vec!["router".into()];
        let router = NodeView::new("100.64.0.1").with_tags(&tags);
        assert!(!doc.auto_approves_route(&router, "10.0.0.0/4"));
    }

    #[test]
    fn auto_approve_route_rejects_outside_prefix() {
        let mut doc = AclDoc {
            version: 1,
            ..Default::default()
        };
        doc.auto_approvers
            .routes
            .insert("10.0.0.0/8".into(), vec!["tag:router".into()]);
        let tags = vec!["router".into()];
        let router = NodeView::new("100.64.0.1").with_tags(&tags);
        assert!(!doc.auto_approves_route(&router, "8.8.8.0/24"));
    }

    #[test]
    fn auto_approve_route_via_group_member() {
        let mut doc = AclDoc {
            version: 1,
            ..Default::default()
        };
        doc.groups
            .insert("admins".into(), vec!["alice".into(), "bob".into()]);
        doc.auto_approvers
            .routes
            .insert("172.16.0.0/12".into(), vec!["group:admins".into()]);
        let alice = NodeView::new("100.64.0.1").with_user("alice");
        let carol = NodeView::new("100.64.0.2").with_user("carol");
        assert!(doc.auto_approves_route(&alice, "172.16.0.0/16"));
        assert!(!doc.auto_approves_route(&carol, "172.16.0.0/16"));
    }

    #[test]
    fn auto_approve_exit_node_matches_tag() {
        let mut doc = AclDoc {
            version: 1,
            ..Default::default()
        };
        doc.auto_approvers.exit_node.push("tag:exit".into());
        let exit_tags = vec!["exit".into()];
        let exit = NodeView::new("100.64.0.1").with_tags(&exit_tags);
        let plain = NodeView::new("100.64.0.2");
        assert!(doc.auto_approves_exit_node(&exit));
        assert!(!doc.auto_approves_exit_node(&plain));
    }

    #[test]
    fn auto_approve_exit_node_empty_list_is_no() {
        let doc = AclDoc {
            version: 1,
            ..Default::default()
        };
        let n = NodeView::new("100.64.0.1");
        assert!(!doc.auto_approves_exit_node(&n));
    }

    // --- New tests: TOML round-trip -----------------------------------

    #[test]
    fn parses_node_attrs_from_toml() {
        let doc = AclDoc::from_toml(
            r#"
            version = 1
            [[node_attrs]]
            target = ["*"]
            attr = ["funnel"]

            [[node_attrs]]
            target = ["tag:exit"]
            attr = ["exit-node"]
        "#,
        )
        .unwrap();
        assert_eq!(doc.node_attrs.len(), 2);
        assert_eq!(doc.node_attrs[0].attr, vec!["funnel"]);
        assert_eq!(doc.node_attrs[1].target, vec!["tag:exit"]);
    }

    #[test]
    fn parses_auto_approvers_from_toml() {
        let doc = AclDoc::from_toml(
            r#"
            version = 1
            [auto_approvers]
            exit_node = ["tag:exit", "tag:router"]
            [auto_approvers.routes]
            "10.0.0.0/8" = ["tag:router"]
            "172.16.0.0/12" = ["group:admins"]
        "#,
        )
        .unwrap();
        assert_eq!(doc.auto_approvers.exit_node.len(), 2);
        assert_eq!(doc.auto_approvers.routes.len(), 2);
        assert!(doc.auto_approvers.routes.contains_key("10.0.0.0/8"));
    }

    #[test]
    fn parses_ipsets_from_toml() {
        let doc = AclDoc::from_toml(
            r#"
            version = 1
            [ipsets]
            office = ["10.0.0.0/8", "192.168.0.0/16"]
        "#,
        )
        .unwrap();
        assert_eq!(doc.ipsets["office"].len(), 2);
    }

    #[test]
    fn parses_hosts_from_toml() {
        let doc = AclDoc::from_toml(
            r#"
            version = 1
            [hosts]
            office = "10.0.0.0/8"
        "#,
        )
        .unwrap();
        assert_eq!(doc.hosts["office"], "10.0.0.0/8");
    }

    #[test]
    fn parses_tag_owners_from_toml() {
        let doc = AclDoc::from_toml(
            r#"
            version = 1
            [tag_owners]
            "tag:router" = ["group:admins"]
        "#,
        )
        .unwrap();
        assert_eq!(doc.tag_owners["tag:router"], vec!["group:admins"]);
    }

    #[test]
    fn parses_ssh_block_from_toml() {
        let doc = AclDoc::from_toml(
            r#"
            version = 1
            [[ssh]]
            action = "accept"
            src = ["group:admins"]
            dst = ["autogroup:tagged"]
            users = ["root"]
        "#,
        )
        .unwrap();
        assert_eq!(doc.ssh.len(), 1);
        assert_eq!(doc.ssh[0].action, "accept");
        assert_eq!(doc.ssh[0].users, vec!["root"]);
    }

    #[test]
    fn canonical_form_includes_new_fields() {
        let mut a = AclDoc {
            version: 1,
            ..Default::default()
        };
        a.ipsets
            .insert("o".into(), vec!["10.0.0.0/8".into(), "192.168.0.0/16".into()]);
        let mut b = AclDoc {
            version: 1,
            ..Default::default()
        };
        b.ipsets
            .insert("o".into(), vec!["192.168.0.0/16".into(), "10.0.0.0/8".into()]);
        // Same set, different declared order ⇒ same canonical hash.
        assert_eq!(a.policy_hash(), b.policy_hash());
    }

    #[test]
    fn camelcase_alias_for_auto_approvers_accepted() {
        // Upstream policy/v2 uses camelCase keys. Our parser accepts
        // both — the serde alias makes `autoApprovers` interchangeable
        // with `auto_approvers`.
        let doc = AclDoc::from_toml(
            r#"
            version = 1
            [autoApprovers]
            exitNode = ["tag:exit"]
            "#,
        )
        .unwrap();
        assert_eq!(doc.auto_approvers.exit_node, vec!["tag:exit"]);
    }

    #[test]
    fn camelcase_alias_for_node_attrs_accepted() {
        let doc = AclDoc::from_toml(
            r#"
            version = 1
            [[nodeAttrs]]
            target = ["*"]
            attr = ["funnel"]
            "#,
        )
        .unwrap();
        assert_eq!(doc.node_attrs.len(), 1);
    }

    // --- Existing rule semantics with NodeView paths ------------------

    #[test]
    fn evaluate_with_user_principal_match() {
        let doc = doc_with_rule(&["alice"], &["*"]);
        let alice = NodeView {
            addr: None,
            user: Some("alice"),
            tags: &[],
        };
        let bob = NodeView {
            addr: None,
            user: Some("bob"),
            tags: &[],
        };
        let dst = NodeView::new("100.64.0.5");
        assert_eq!(
            doc.evaluate_with(&alice, &dst, PortRef::any()),
            AclAction::Accept
        );
        assert_eq!(
            doc.evaluate_with(&bob, &dst, PortRef::any()),
            AclAction::Deny
        );
    }

    #[test]
    fn evaluate_with_group_referring_to_user_matches() {
        let mut doc = doc_with_rule(&["group:admins"], &["*"]);
        doc.groups
            .insert("admins".into(), vec!["alice".into()]);
        let alice = NodeView {
            addr: None,
            user: Some("alice"),
            tags: &[],
        };
        let dst = NodeView::new("100.64.0.5");
        assert_eq!(
            doc.evaluate_with(&alice, &dst, PortRef::any()),
            AclAction::Accept
        );
    }

    #[test]
    fn parse_cidr_handles_bare_address() {
        let n = parse_cidr("10.0.0.5").unwrap();
        assert_eq!(n.prefix_len(), 32);
    }

    #[test]
    fn parse_cidr_handles_ipv6_bare_address() {
        let n = parse_cidr("::1").unwrap();
        assert_eq!(n.prefix_len(), 128);
    }

    #[test]
    fn parse_cidr_rejects_garbage() {
        assert!(parse_cidr("not-an-ip").is_none());
    }
}
