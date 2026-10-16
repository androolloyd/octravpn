// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Anchored native rule activation. Epoch-only predicates are intentionally
//! separate from authenticated execution rules.
use crate::{consensus::policy, transaction::RuleMode};
pub const PROGRAM_OVERLAP: i64 = 64;
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(usize)]
pub enum Rule {
    Circle,
    WasmCompute,
    ValidatorQuorum,
    EpochTime,
    OwnerMigration,
    PrivatePayload,
    SetFold,
    ValidatorReady,
    ReadyReference,
    LiveSet,
    SeatCap,
    OpenSet,
    ObjectCost,
    AccountPack,
    Standard,
    SetPlan,
    Math,
    Exit,
    ReadyExecution,
    ProgramSource,
    TxEnvelope,
    FheWork,
    WasmFloat,
    CircleBatch,
    ProofExecution,
    VmBytes,
    CipherMigration,
    Settle,
}
pub const ALL: [Rule; 28] = [
    Rule::Circle,
    Rule::WasmCompute,
    Rule::ValidatorQuorum,
    Rule::EpochTime,
    Rule::OwnerMigration,
    Rule::PrivatePayload,
    Rule::SetFold,
    Rule::ValidatorReady,
    Rule::ReadyReference,
    Rule::LiveSet,
    Rule::SeatCap,
    Rule::OpenSet,
    Rule::ObjectCost,
    Rule::AccountPack,
    Rule::Standard,
    Rule::SetPlan,
    Rule::Math,
    Rule::Exit,
    Rule::ReadyExecution,
    Rule::ProgramSource,
    Rule::TxEnvelope,
    Rule::FheWork,
    Rule::WasmFloat,
    Rule::CircleBatch,
    Rule::ProofExecution,
    Rule::VmBytes,
    Rule::CipherMigration,
    Rule::Settle,
];
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Activation {
    pub anchor_epoch: i64,
    pub anchor_state_root: Vec<u8>,
    pub activation_epoch: i64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RootRead {
    Missing,
    Root(Vec<u8>),
    Unreadable(Vec<u8>),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fault {
    Missing(i64),
    Mismatch {
        epoch: i64,
        expected: Vec<u8>,
        actual: Vec<u8>,
    },
    Unreadable {
        epoch: i64,
        reason: Vec<u8>,
    },
}
impl Fault {
    pub fn message(&self) -> Vec<u8> {
        match self {
            Self::Missing(epoch) => format!("rule anchor missing epoch = {epoch}").into_bytes(),
            Self::Mismatch {
                epoch,
                expected,
                actual,
            } => [
                format!("rule anchor mismatch epoch = {epoch} expected = ").as_bytes(),
                expected,
                b" actual = ",
                actual,
            ]
            .concat(),
            Self::Unreadable { epoch, reason } => [
                format!("rule anchor unreadable epoch = {epoch} reason = ").as_bytes(),
                reason,
            ]
            .concat(),
        }
    }
}
impl std::fmt::Display for Fault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(&self.message()))
    }
}
impl std::error::Error for Fault {}
pub fn activation(chain: &[u8], rule: Rule) -> Option<Activation> {
    if chain != policy::DEVNET {
        return None;
    }
    let (anchor, root, epoch) = match rule {
        Rule::Circle => (
            1_293_376,
            "564797e4554eece839e606a431c3f1251679949c48dea039270dd8c6e706aab9",
            1_299_000,
        ),
        Rule::ValidatorQuorum => (
            1_306_321,
            "c19278aec1ff53c4796aea354c9cc7845d8421fc7d6ffe971b5fecea29299a04",
            1_306_547,
        ),
        Rule::EpochTime => (
            1_311_424,
            "e70bf274a6590f859d72bd2da171193b99d79e5ff44e78bb91f6cad3cc65fdc6",
            1_320_000,
        ),
        Rule::WasmCompute | Rule::OwnerMigration | Rule::PrivatePayload | Rule::SetFold => (
            1_325_398,
            "257254d363a6864cb28461d80b0d40885e561ee3d17a97bfccb3af906a010229",
            if rule == Rule::SetFold {
                1_334_000
            } else {
                1_330_000
            },
        ),
        Rule::ValidatorReady | Rule::SeatCap | Rule::ObjectCost => (
            1_353_962,
            "1def67e4c5886e28f648972ab3275901e66def42147b1b8b0d57a7578d19dec4",
            1_380_000,
        ),
        Rule::ReadyReference
        | Rule::LiveSet
        | Rule::OpenSet
        | Rule::AccountPack
        | Rule::Standard => (
            1_380_960,
            "20de716a0d578300de77508718d213db14c4164e229a5850eb0595324566c90e",
            match rule {
                Rule::OpenSet => 1_425_040,
                Rule::AccountPack => 1_480_000,
                Rule::Standard => 1_500_000,
                _ => 1_450_000,
            },
        ),
        Rule::SetPlan
        | Rule::Math
        | Rule::Exit
        | Rule::ReadyExecution
        | Rule::ProgramSource
        | Rule::TxEnvelope
        | Rule::FheWork
        | Rule::WasmFloat
        | Rule::CircleBatch
        | Rule::ProofExecution
        | Rule::VmBytes
        | Rule::CipherMigration => (
            1_504_440,
            "8e7f0e5a6e582070c040a07e7439caf532973fa09cddc79357a5ed964468065d",
            match rule {
                Rule::SetPlan | Rule::Math => 1_510_000,
                Rule::Exit | Rule::ReadyExecution | Rule::ProgramSource => 1_572_000,
                Rule::TxEnvelope | Rule::FheWork | Rule::WasmFloat => 1_614_500,
                Rule::CircleBatch | Rule::ProofExecution => 1_663_000,
                _ => 1_688_734,
            },
        ),
        Rule::Settle => return None,
    };
    Some(Activation {
        anchor_epoch: anchor,
        anchor_state_root: root.as_bytes().to_vec(),
        activation_epoch: epoch,
    })
}
pub fn activation_id(value: Option<&Activation>) -> Vec<u8> {
    value.map_or_else(
        || b"none".to_vec(),
        |v| {
            [
                v.anchor_epoch.to_string().as_bytes(),
                b":",
                &v.anchor_state_root,
                b":",
                v.activation_epoch.to_string().as_bytes(),
            ]
            .concat()
        },
    )
}
pub fn profile_epochs(chain: &[u8]) -> Vec<i64> {
    let mut epochs = ALL[14..]
        .iter()
        .filter_map(|r| activation(chain, *r).map(|v| v.activation_epoch))
        .collect::<Vec<_>>();
    epochs.sort_unstable();
    epochs.dedup();
    epochs
}
pub fn live_chain(chain: &[u8]) -> bool {
    ALL[..21].iter().all(|r| activation(chain, *r).is_some())
}
pub fn consensus_id(chain: &[u8], epoch: i64) -> Vec<u8> {
    let values = ALL
        .iter()
        .enumerate()
        .filter_map(|(i, r)| {
            let p = activation(chain, *r);
            (i < 15 || p.as_ref().is_some_and(|p| epoch >= p.activation_epoch))
                .then(|| activation_id(p.as_ref()))
        })
        .collect::<Vec<_>>();
    values.join(&b'|')
}
/// These are native epoch-only profile predicates; they do not verify an anchor.
pub fn at(chain: &[u8], rule: Rule, epoch: i64) -> RuleMode {
    if activation(chain, rule).is_some_and(|p| epoch >= p.activation_epoch) {
        RuleMode::Active
    } else {
        RuleMode::Prior
    }
}
/// Native trusted-history floor fallback. Callers must authenticate that floor.
pub fn root_after_floor(chain: &[u8], floor: i64, epoch: i64) -> Option<Vec<u8>> {
    let circle = activation(chain, Rule::Circle);
    if let Some(p) = circle.filter(|p| epoch == p.anchor_epoch && floor >= p.activation_epoch) {
        return Some(p.anchor_state_root);
    }
    // Order is observable if a future profile reuses an epoch with a new root.
    [
        Rule::ValidatorQuorum,
        Rule::EpochTime,
        Rule::OwnerMigration,
        Rule::WasmCompute,
        Rule::PrivatePayload,
        Rule::SetFold,
        Rule::ValidatorReady,
        Rule::ReadyReference,
        Rule::LiveSet,
        Rule::SeatCap,
        Rule::OpenSet,
        Rule::ObjectCost,
        Rule::AccountPack,
        Rule::Standard,
        Rule::SetPlan,
        Rule::Math,
        Rule::Exit,
        Rule::ReadyExecution,
        Rule::ProgramSource,
        Rule::TxEnvelope,
        Rule::FheWork,
        Rule::WasmFloat,
        Rule::CircleBatch,
        Rule::ProofExecution,
        Rule::VmBytes,
        Rule::CipherMigration,
        Rule::Settle,
    ]
    .iter()
    .filter_map(|r| activation(chain, *r))
    .find(|p| epoch == p.anchor_epoch && floor >= p.anchor_epoch)
    .map(|p| p.anchor_state_root)
}
pub fn verify_anchor(root_at: &impl Fn(i64) -> RootRead, plan: &Activation) -> Result<(), Fault> {
    match root_at(plan.anchor_epoch) {
        RootRead::Missing => Err(Fault::Missing(plan.anchor_epoch)),
        RootRead::Unreadable(reason) => Err(Fault::Unreadable {
            epoch: plan.anchor_epoch,
            reason,
        }),
        RootRead::Root(actual) if actual == plan.anchor_state_root => Ok(()),
        RootRead::Root(actual) => Err(Fault::Mismatch {
            epoch: plan.anchor_epoch,
            expected: plan.anchor_state_root.clone(),
            actual,
        }),
    }
}
pub fn activation_mode(
    root_at: &impl Fn(i64) -> RootRead,
    plan: Option<&Activation>,
    epoch: i64,
) -> Result<RuleMode, Fault> {
    match plan {
        None => Ok(RuleMode::Prior),
        Some(p) if epoch < p.activation_epoch => Ok(RuleMode::Prior),
        Some(p) => verify_anchor(root_at, p).map(|()| RuleMode::Active),
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Graph {
    chain_id: Vec<u8>,
    ready_config_hash: Option<Vec<u8>>,
    /// Native cached slots in ALL order, ending at ProgramSource. The
    /// later profile rules are derived from chain identity, as in Rule_graph.
    plans: [Option<Activation>; 20],
    isolated_applications: Option<Activation>,
}
impl Graph {
    pub fn new(chain_id: Vec<u8>, ready_config_hash: Option<Vec<u8>>) -> Self {
        let plans = std::array::from_fn(|i| activation(&chain_id, ALL[i]));
        Self {
            chain_id,
            ready_config_hash,
            plans,
            isolated_applications: None,
        }
    }
    /// Explicit application-only qualification profile for a new isolated
    /// genesis. Public network selection and native consensus rules are never
    /// overridden. The caller must commit this opt-in in its genesis state;
    /// every active lookup independently checks the retained epoch-zero root.
    pub fn isolated_applications(
        chain_id: Vec<u8>,
        ready_config_hash: Option<Vec<u8>>,
        genesis_root: [u8; 32],
    ) -> Result<Self, &'static str> {
        let Some(identity) = chain_id.strip_prefix(b"octra-rust-local-") else {
            return Err("application fixture requires an isolated local chain");
        };
        if identity.len() != 16
            || !identity
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        {
            return Err("invalid isolated local chain identity");
        }
        let mut graph = Self::new(chain_id, ready_config_hash);
        graph.isolated_applications = Some(Activation {
            anchor_epoch: 0,
            anchor_state_root: hex::encode(genesis_root).into_bytes(),
            activation_epoch: 0,
        });
        Ok(graph)
    }
    pub fn isolated_application_anchor(&self) -> Option<&[u8]> {
        self.isolated_applications
            .as_ref()
            .map(|plan| plan.anchor_state_root.as_slice())
    }
    pub fn chain_id(&self) -> &[u8] {
        &self.chain_id
    }
    pub fn ready_config_hash(&self) -> Option<&[u8]> {
        self.ready_config_hash.as_deref()
    }
    pub fn activation(&self, rule: Rule) -> Option<Activation> {
        if matches!(
            rule,
            Rule::Circle
                | Rule::OwnerMigration
                | Rule::ObjectCost
                | Rule::AccountPack
                | Rule::Standard
                | Rule::Math
                | Rule::ProgramSource
                | Rule::FheWork
                | Rule::ProofExecution
                | Rule::VmBytes
        ) {
            if let Some(plan) = &self.isolated_applications {
                return Some(plan.clone());
            }
        }
        self.plans
            .get(rule as usize)
            .cloned()
            .unwrap_or_else(|| activation(&self.chain_id, rule))
    }
    pub fn mode(
        &self,
        rule: Rule,
        epoch: i64,
        root_at: &impl Fn(i64) -> RootRead,
    ) -> Result<RuleMode, Fault> {
        let plan = self.activation(rule);
        if plan.is_some() {
            return activation_mode(root_at, plan.as_ref(), epoch);
        }
        let active = match rule {
            Rule::WasmCompute | Rule::PrivatePayload => true,
            Rule::ValidatorQuorum => policy::quorum_active(&self.chain_id, epoch),
            Rule::EpochTime => {
                policy::time_rule(&self.chain_id, epoch) == policy::TimeRule::Uniform
            }
            _ => false,
        };
        Ok(if active {
            RuleMode::Active
        } else {
            RuleMode::Prior
        })
    }
    pub fn program_overlap(
        &self,
        epoch: i64,
        root_at: &impl Fn(i64) -> RootRead,
    ) -> Result<bool, Fault> {
        let mode = self.mode(Rule::ProgramSource, epoch, root_at)?;
        Ok(mode == RuleMode::Active
            && self.activation(Rule::ProgramSource).is_some_and(|p| {
                ((epoch.wrapping_sub(p.activation_epoch) << 1) >> 1) < PROGRAM_OVERLAP
            }))
    }
}

#[cfg(test)]
mod isolated_tests {
    use super::*;

    #[test]
    fn isolated_applications_require_identity_and_matching_retained_genesis() {
        let chain = b"octra-rust-local-0123456789abcdef".to_vec();
        let graph = Graph::isolated_applications(chain.clone(), None, [7; 32]).unwrap();
        let read = |height| {
            if height == 0 {
                RootRead::Root(hex::encode([7; 32]).into_bytes())
            } else {
                RootRead::Missing
            }
        };
        for rule in [
            Rule::Standard,
            Rule::Math,
            Rule::ProgramSource,
            Rule::FheWork,
            Rule::ProofExecution,
            Rule::VmBytes,
            Rule::ObjectCost,
        ] {
            assert_eq!(graph.mode(rule, 1, &read).unwrap(), RuleMode::Active);
            assert!(matches!(
                graph.mode(rule, 1, &|_| RootRead::Root(
                    hex::encode([8; 32]).into_bytes()
                )),
                Err(Fault::Mismatch { epoch: 0, .. })
            ));
        }
        assert!(graph.program_overlap(63, &read).unwrap());
        assert!(!graph.program_overlap(64, &read).unwrap());
        for rule in [
            Rule::ValidatorQuorum,
            Rule::EpochTime,
            Rule::ValidatorReady,
            Rule::ReadyReference,
            Rule::LiveSet,
            Rule::SeatCap,
            Rule::OpenSet,
        ] {
            assert_eq!(
                graph.mode(rule, 1, &read),
                Graph::new(chain.clone(), None).mode(rule, 1, &read)
            );
            assert_eq!(
                graph.activation(rule),
                Graph::new(chain.clone(), None).activation(rule)
            );
        }
        for chain in [
            policy::DEVNET,
            b"mainnet",
            b"octra-rust-local-",
            b"octra-rust-local-arbitrary",
        ] {
            assert!(Graph::isolated_applications(chain.to_vec(), None, [7; 32]).is_err());
        }
    }

    #[test]
    fn public_and_default_local_graphs_have_no_fixture_rules() {
        for chain in [policy::DEVNET, b"octra-rust-local-0123456789abcdef"] {
            let graph = Graph::new(chain.to_vec(), None);
            assert!(graph.isolated_application_anchor().is_none());
            for rule in ALL {
                assert_eq!(graph.activation(rule), activation(chain, rule));
            }
        }
    }
}
