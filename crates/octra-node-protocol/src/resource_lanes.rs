// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native transaction resource lanes. Declared fee, execution allowance and
//! serialized byte cost are distinct quantities with native rejection ordering.
use crate::{
    transaction::{Error, Nonce, OpType, RuleMode, Transaction},
    transaction_policy,
};
use num_bigint::BigInt;
use num_traits::ToPrimitive;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Lane {
    Standard,
    ProgramDeploy,
    Program,
    CircleCompute,
    CircleMetadata,
    CircleAssets,
    Pvac,
    Fhe,
}
pub const LANES: [Lane; 8] = [
    Lane::Standard,
    Lane::ProgramDeploy,
    Lane::Program,
    Lane::CircleCompute,
    Lane::CircleMetadata,
    Lane::CircleAssets,
    Lane::Pvac,
    Lane::Fhe,
];
pub const PREVERIFY_REQUIRED_QUEUE: i64 = 128;
pub const PREVERIFY_SPECULATIVE_QUEUE: i64 = 6;
pub const PREVERIFY_REQUIRED_BURST: i64 = 4;
pub const VM_FLOOR: i64 = 1_000_000;

/// Signed native machine counters; `add` preserves OCaml int63 arithmetic.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    pub transactions: i64,
    pub bytes: i64,
    pub ou: BigInt,
    pub proofs: i64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Budget {
    pub transactions: i64,
    pub bytes: i64,
    pub ou: BigInt,
    pub proofs: i64,
}
impl Lane {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::ProgramDeploy => "program_deploy",
            Self::Program => "program",
            Self::CircleCompute => "circle_compute",
            Self::CircleMetadata => "circle_metadata",
            Self::CircleAssets => "circle_assets",
            Self::Pvac => "pvac",
            Self::Fhe => "fhe",
        }
    }
    pub const fn of(op: OpType) -> Self {
        use OpType::{
            CircleAssetPut, CircleAssetPutEncrypted, CircleBalanceCellPut, CircleCall,
            CircleDeploy, CircleHfhePolicyPut, CircleIngressCommit, CircleKeyErase,
            CircleKeyExtend, CircleKeyGrant, CircleKeyPolicyPut, CircleKeyRevoke, CircleOutboxOpen,
            CircleProgramUpdate, CircleRegisterCellPut, CircleRelayCancel, CircleRelayClaim,
            CircleSealedSlotPut, CircleSlotPolicyPut, CircleStateDescriptorPut,
            CircleTransportPolicyPut, Claim, ComputeFund, ComputeReturn, ComputeSettle,
            ContractCall, ContractDeploy, ContractUpgrade, Decrypt, Encrypt, KeySwitch, MultiExec,
            Op01Burn, Private, ProgramDeploy, ProgramExec, Recrypt, Standard, Stealth,
            ValidatorBond, ValidatorEvidence, ValidatorExit, ValidatorReady, ValidatorSetUpdate,
            ValidatorWithdraw,
        };
        match op {
            Standard | ValidatorSetUpdate | ValidatorReady | ValidatorBond | ValidatorExit
            | ValidatorWithdraw | ValidatorEvidence | ComputeReturn | Op01Burn => Self::Standard,
            ComputeFund | ComputeSettle | ContractDeploy | ContractCall | ProgramExec
            | MultiExec | ContractUpgrade => Self::Program,
            ProgramDeploy => Self::ProgramDeploy,
            CircleCall => Self::CircleCompute,
            CircleAssetPut | CircleAssetPutEncrypted | CircleSealedSlotPut => Self::CircleAssets,
            CircleBalanceCellPut | CircleRegisterCellPut | Recrypt | KeySwitch => Self::Fhe,
            Encrypt | Decrypt | Private | Stealth | Claim => Self::Pvac,
            CircleDeploy
            | CircleProgramUpdate
            | CircleSlotPolicyPut
            | CircleStateDescriptorPut
            | CircleTransportPolicyPut
            | CircleHfhePolicyPut
            | CircleKeyPolicyPut
            | CircleKeyGrant
            | CircleKeyExtend
            | CircleKeyRevoke
            | CircleKeyErase
            | CircleOutboxOpen
            | CircleRelayClaim
            | CircleRelayCancel
            | CircleIngressCommit => Self::CircleMetadata,
        }
    }
    pub const fn preverify_queue(self) -> i64 {
        match self {
            Self::CircleCompute => 1,
            Self::Pvac | Self::Fhe => 6,
            _ => 0,
        }
    }
    pub fn budget(self) -> Budget {
        let (transactions, mib, ou, proofs) = match self {
            Self::Standard => (2048, 8, 2_000_000, 0),
            Self::ProgramDeploy => (1, 4, 5_000_000, 0),
            Self::Program => (128, 4, 10_000_000, 16),
            Self::CircleCompute => (1, 4, 20_000_000, 1),
            Self::CircleMetadata => (256, 2, 5_000_000, 0),
            Self::CircleAssets => (16, 64, 10_000_000, 0),
            Self::Pvac => (64, 16, 20_000_000, 64),
            Self::Fhe => (32, 16, 20_000_000, 32),
        };
        Budget {
            transactions,
            bytes: mib * 1024 * 1024,
            ou: ou.into(),
            proofs,
        }
    }
}
impl Budget {
    pub fn over(&self, used: &Usage) -> Option<&'static str> {
        if used.transactions > self.transactions {
            Some("tx_count")
        } else if used.bytes > self.bytes {
            Some("bytes")
        } else if used.ou > self.ou {
            Some("ou")
        } else if used.proofs > self.proofs {
            Some("proof")
        } else {
            None
        }
    }
}
impl Usage {
    pub fn add(&self, other: &Self) -> Self {
        let add = |a: i64, b: i64| (a.wrapping_add(b) << 1) >> 1;
        Self {
            transactions: add(self.transactions, other.transactions),
            bytes: add(self.bytes, other.bytes),
            ou: &self.ou + &other.ou,
            proofs: add(self.proofs, other.proofs),
        }
    }
}
pub fn cost(tx: &Transaction, minimum: &BigInt) -> Result<Usage, Error> {
    let lane = Lane::of(tx.op_type);
    let ou = if matches!(lane, Lane::Program | Lane::CircleCompute) {
        tx.ou.clone()
    } else {
        transaction_policy::ou_cost(tx, minimum)
    };
    let bytes = i64::try_from(tx.to_json_bytes()?.len())
        .map_err(|_| Error("transaction byte count overflow".into()))?;
    Ok(Usage {
        transactions: 1,
        bytes,
        ou,
        proofs: i64::from(matches!(lane, Lane::CircleCompute | Lane::Pvac | Lane::Fhe)),
    })
}
pub fn vm_limit(ou: &BigInt) -> i64 {
    ou.to_i64()
        .filter(|v| (Nonce::MIN.get()..=Nonce::MAX.get()).contains(v))
        .unwrap_or(VM_FLOOR)
        .max(VM_FLOOR)
}
pub fn work(tx: &Transaction, minimum: &BigInt) -> Result<Usage, Error> {
    let mut declared = cost(tx, minimum)?;
    let allowance = match Lane::of(tx.op_type) {
        Lane::Program | Lane::CircleCompute => vm_limit(&tx.ou),
        Lane::ProgramDeploy => VM_FLOOR,
        _ => 0,
    };
    declared.ou = declared.ou.max(allowance.into());
    Ok(declared)
}
pub fn queue_check(tx: &Transaction, mode: RuleMode, minimum: &BigInt) -> Result<(), Error> {
    let lane = Lane::of(tx.op_type);
    let used = if mode == RuleMode::Active
        && matches!(
            lane,
            Lane::Program | Lane::ProgramDeploy | Lane::CircleMetadata
        ) {
        work(tx, minimum)?
    } else if lane == Lane::CircleCompute {
        cost(tx, minimum)?
    } else {
        return Ok(());
    };
    match lane.budget().over(&used) {
        None => Ok(()),
        Some(reason) => Err(Error(format!(
            "{} resource limit: {reason}",
            if lane == Lane::CircleCompute {
                "circle"
            } else {
                lane.as_str()
            }
        ))),
    }
}
pub fn admit(
    budget: &Budget,
    used: &Usage,
    tx: &Transaction,
    minimum: &BigInt,
) -> Result<Usage, Error> {
    let next = used.add(&cost(tx, minimum)?);
    budget
        .over(&next)
        .map_or(Ok(next), |reason| Err(Error(reason.into())))
}
