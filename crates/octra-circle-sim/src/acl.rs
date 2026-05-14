//! Access contract logic — who may open which class of exit, at
//! what tariff. Lives inside the Circle in the v2 design (litepaper
//! §4.2); here it's a plain Rust evaluator.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// Two exit classes per the v2 design — `shared` is public-internet
/// egress (metered), `internal` is intra-tailnet-only (commonly free
/// when the tailnet sets `charge_internal_traffic = 0`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ExitClass {
    Shared,
    Internal,
}

impl ExitClass {
    pub fn as_aml_int(self) -> u64 {
        match self {
            Self::Shared => 0,
            Self::Internal => 1,
        }
    }
}

/// A free-form tag attached to a tailnet member by the tailnet
/// owner. Tags drive ACL evaluation. Mirrors Tailscale's tag model.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct MemberTag(pub String);

impl MemberTag {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

/// One row of the access contract. The Circle's effective ACL is the
/// union of all matching rules.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AclRule {
    /// Member must hold *all* of these tags. Empty = matches every
    /// member.
    pub require_tags: BTreeSet<MemberTag>,
    /// Class this rule grants access to.
    pub class: ExitClass,
    /// Price (OU per MB) at which this rule offers the class. Captured
    /// at `open_session` time so the AML can settle without
    /// consulting the proxy.
    pub price_per_mb: u64,
}

impl AclRule {
    pub fn applies(&self, member_tags: &BTreeSet<MemberTag>) -> bool {
        self.require_tags.is_subset(member_tags)
    }
}

/// In-memory evaluator. The Circle holds one per tailnet it serves.
#[derive(Clone, Debug, Default)]
pub struct AccessContract {
    rules: Vec<AclRule>,
    members: BTreeMap<String, BTreeSet<MemberTag>>,
}

impl AccessContract {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_rule(&mut self, rule: AclRule) {
        self.rules.push(rule);
    }

    pub fn set_member_tags<I>(&mut self, member: &str, tags: I)
    where
        I: IntoIterator<Item = MemberTag>,
    {
        self.members
            .insert(member.to_string(), tags.into_iter().collect());
    }

    pub fn member_tags(&self, member: &str) -> Option<&BTreeSet<MemberTag>> {
        self.members.get(member)
    }

    /// Resolve the best matching rule for (member, class). "Best" =
    /// lowest `price_per_mb` among applicable rules; ties broken by
    /// insertion order.
    pub fn quote(&self, member: &str, class: ExitClass) -> Option<&AclRule> {
        let tags = self.members.get(member)?;
        self.rules
            .iter()
            .filter(|r| r.class == class && r.applies(tags))
            .min_by_key(|r| r.price_per_mb)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tag(s: &str) -> MemberTag {
        MemberTag::new(s)
    }

    #[test]
    fn untagged_member_only_matches_unconditional_rules() {
        let mut ac = AccessContract::new();
        ac.set_member_tags("alice", []);
        ac.add_rule(AclRule {
            require_tags: BTreeSet::new(),
            class: ExitClass::Shared,
            price_per_mb: 100,
        });
        ac.add_rule(AclRule {
            require_tags: std::iter::once(tag("user")).collect(),
            class: ExitClass::Shared,
            price_per_mb: 50,
        });
        let q = ac.quote("alice", ExitClass::Shared).unwrap();
        assert_eq!(q.price_per_mb, 100);
    }

    #[test]
    fn tagged_member_gets_cheaper_rule() {
        let mut ac = AccessContract::new();
        ac.set_member_tags("alice", [tag("user")]);
        ac.add_rule(AclRule {
            require_tags: BTreeSet::new(),
            class: ExitClass::Shared,
            price_per_mb: 100,
        });
        ac.add_rule(AclRule {
            require_tags: std::iter::once(tag("user")).collect(),
            class: ExitClass::Shared,
            price_per_mb: 50,
        });
        let q = ac.quote("alice", ExitClass::Shared).unwrap();
        assert_eq!(q.price_per_mb, 50);
    }

    #[test]
    fn internal_class_separate_from_shared() {
        let mut ac = AccessContract::new();
        ac.set_member_tags("alice", [tag("user")]);
        ac.add_rule(AclRule {
            require_tags: BTreeSet::new(),
            class: ExitClass::Shared,
            price_per_mb: 100,
        });
        // No internal rule → no quote.
        assert!(ac.quote("alice", ExitClass::Internal).is_none());
        ac.add_rule(AclRule {
            require_tags: BTreeSet::new(),
            class: ExitClass::Internal,
            price_per_mb: 0,
        });
        assert_eq!(
            ac.quote("alice", ExitClass::Internal).unwrap().price_per_mb,
            0
        );
    }

    #[test]
    fn unknown_member_yields_none() {
        let ac = AccessContract::new();
        assert!(ac.quote("ghost", ExitClass::Shared).is_none());
    }
}
