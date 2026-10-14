//! Native transaction operation profiles, fee schedules and amount semantics.
//! Configuration is explicit so replay never depends on the process environment.
use crate::{
    native_integer::parse_integer,
    native_json::{Document, Value},
    oce1::Reader,
    transaction::{decode_base64, OpType, Transaction},
};
use num_bigint::BigInt;
use num_traits::{Signed, Zero};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ReleaseProfile {
    #[default]
    Off,
    DevnetPrivateV1,
    DevnetFullV1,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Profile {
    pub release: ReleaseProfile,
    pub private_v1: bool,
    pub admit_ops: Vec<u8>,
}
impl Profile {
    pub fn from_values(
        release: Option<&[u8]>,
        crypto: Option<&[u8]>,
        admit_ops: Option<&[u8]>,
    ) -> Self {
        let release = match release {
            Some(b"devnet_private_v1") => ReleaseProfile::DevnetPrivateV1,
            Some(b"devnet_full_v1") => ReleaseProfile::DevnetFullV1,
            _ => ReleaseProfile::Off,
        };
        Self {
            private_v1: release != ReleaseProfile::Off || crypto == Some(b"private_v1"),
            release,
            admit_ops: admit_ops.unwrap_or_default().to_vec(),
        }
    }
    pub fn admits(&self, op: OpType) -> bool {
        if op == OpType::Standard {
            return true;
        }
        let crypto = is_crypto(op);
        match self.release {
            ReleaseProfile::DevnetPrivateV1 => crypto,
            ReleaseProfile::DevnetFullV1 => {
                crypto
                    || is_circle_noncall(op)
                    || matches!(
                        op,
                        OpType::ContractDeploy
                            | OpType::ProgramDeploy
                            | OpType::ContractCall
                            | OpType::ProgramExec
                            | OpType::MultiExec
                            | OpType::ContractUpgrade
                            | OpType::ComputeFund
                            | OpType::ComputeReturn
                            | OpType::ComputeSettle
                            | OpType::CircleCall
                    )
            }
            ReleaseProfile::Off => {
                self.private_v1 && crypto
                    || (is_circle_noncall(op)
                        || self.private_v1 && crypto
                        || op == OpType::CircleCall)
                        && self.admit_ops.split(|v| *v == b',').any(|v| {
                            let token = trim(v);
                            !token.is_empty()
                                && (token == op.as_str().as_bytes()
                                    || token == b"circle_noncall" && is_circle_noncall(op))
                        })
            }
        }
    }
    pub fn consensus_admits(&self, op: OpType) -> bool {
        is_validator(op) || self.admits(op)
    }
}
fn trim(mut bytes: &[u8]) -> &[u8] {
    // OCaml String.trim excludes vertical tab.
    let space = |v: u8| matches!(v, b' ' | b'\t' | b'\n' | b'\r' | 12);
    while bytes.first().is_some_and(|v| space(*v)) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(|v| space(*v)) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}
pub const fn is_crypto(op: OpType) -> bool {
    matches!(
        op,
        OpType::Encrypt | OpType::Decrypt | OpType::Stealth | OpType::Claim | OpType::KeySwitch
    )
}
pub const fn is_validator(op: OpType) -> bool {
    matches!(
        op,
        OpType::ValidatorSetUpdate
            | OpType::ValidatorReady
            | OpType::ValidatorBond
            | OpType::ValidatorExit
            | OpType::ValidatorWithdraw
            | OpType::ValidatorEvidence
    )
}
pub const fn is_circle_noncall(op: OpType) -> bool {
    matches!(
        op,
        OpType::CircleDeploy
            | OpType::CircleProgramUpdate
            | OpType::CircleAssetPut
            | OpType::CircleAssetPutEncrypted
            | OpType::CircleSealedSlotPut
            | OpType::CircleSlotPolicyPut
            | OpType::CircleStateDescriptorPut
            | OpType::CircleBalanceCellPut
            | OpType::CircleRegisterCellPut
            | OpType::CircleTransportPolicyPut
            | OpType::CircleHfhePolicyPut
            | OpType::CircleKeyPolicyPut
            | OpType::CircleKeyGrant
            | OpType::CircleKeyExtend
            | OpType::CircleKeyRevoke
            | OpType::CircleKeyErase
            | OpType::CircleOutboxOpen
            | OpType::CircleRelayClaim
            | OpType::CircleRelayCancel
            | OpType::CircleIngressCommit
    )
}
pub const fn is_asset_body(op: OpType) -> bool {
    matches!(
        op,
        OpType::CircleAssetPut
            | OpType::CircleAssetPutEncrypted
            | OpType::CircleSealedSlotPut
            | OpType::CircleBalanceCellPut
            | OpType::CircleRegisterCellPut
    )
}

pub fn semantic_check(tx: &Transaction) -> Result<(), &'static str> {
    if tx.amount.is_negative() {
        return Err("amount must not be negative");
    }
    if tx.ou.is_negative() {
        return Err("ou must not be negative");
    }
    let reason = match tx.op_type {
        OpType::Standard | OpType::Encrypt | OpType::Decrypt if !tx.amount.is_positive() => {
            Some("amount must be positive")
        }
        OpType::ComputeFund if !tx.amount.is_positive() => Some("compute reserve must be positive"),
        OpType::ValidatorBond if !tx.amount.is_positive() => {
            Some("validator bond must be positive")
        }
        OpType::Op01Burn if !tx.amount.is_positive() => {
            Some("amount must be positive for op01_burn")
        }
        OpType::Standard
        | OpType::Encrypt
        | OpType::Decrypt
        | OpType::ComputeFund
        | OpType::ValidatorBond
        | OpType::Op01Burn
        | OpType::ContractCall
        | OpType::ProgramExec
        | OpType::CircleCall => None,
        _ if tx.amount.is_zero() => None,
        OpType::ComputeReturn | OpType::ComputeSettle => Some("compute return amount must be zero"),
        OpType::MultiExec => Some("amount must be zero for multi_exec"),
        OpType::Stealth => Some("amount must be zero for stealth transfer"),
        OpType::Claim => Some("amount must be zero for claim"),
        OpType::Recrypt => Some("amount must be zero for recrypt"),
        OpType::KeySwitch => Some("amount must be zero for key_switch"),
        _ => Some("amount must be zero for this operation"),
    };
    reason.map_or(Ok(()), Err)
}
pub fn stealth_min_ou(raw: Option<&[u8]>) -> BigInt {
    raw.and_then(parse_integer)
        .filter(|v| v.is_positive() && v <= &BigInt::from(10_000_000_000u64))
        .unwrap_or_else(|| 5000.into())
}
pub fn circle_asset_fee(wire_len: usize) -> BigInt {
    let size = wire_len.saturating_add(3) / 4 * 3;
    let fee = match size {
        0..=4096 => 5000,
        4097..=16_384 => 10_000,
        16_385..=32_768 => 20_000,
        32_769..=131_072 => 40_000,
        131_073..=524_288 => 80_000,
        524_289..=2_097_152 => 160_000,
        2_097_153..=8_388_608 => 320_000,
        _ => 640_000,
    };
    fee.into()
}
/// Decode the native compute settlement's bounded OCE1 request, including its
/// signed 32-bit fuel and exact end-of-message check.
pub fn compute_request(raw: &[u8]) -> Result<(u32, Vec<Vec<u8>>), &'static str> {
    if raw.len() > 262_144 {
        return Err("compute payment size");
    }
    let decoded = decode_base64(raw).map_err(|_| "compute payment encoding")?;
    let mut reader = Reader::new(&decoded);
    let fuel = reader.get_u32().map_err(|_| "compute payment encoding")?;
    let count = reader.get_u16().map_err(|_| "compute payment encoding")?;
    // Invalid limits are returned before any records are consumed, but OCE1's
    // outer decoder still requires an exhausted input.
    if fuel == 0 || fuel > 5_000_000 || count == 0 || count > 64 {
        reader.finish().map_err(|_| "compute payment encoding")?;
        return Err("compute payment limits");
    }
    let mut records = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        records.push(
            reader
                .get_bytes_bounded(262_144)
                .map_err(|_| "compute payment encoding")?
                .to_vec(),
        );
    }
    reader.finish().map_err(|_| "compute payment encoding")?;
    Ok((fuel, records))
}
pub fn compute_fee(raw: &[u8]) -> BigInt {
    compute_request(raw).map_or_else(
        |_| 10_000_000.into(),
        |(fuel, _)| {
            BigInt::from(4_194_304 + 10_000 + u64::from(fuel)) + BigInt::from(raw.len()) * 2
        },
    )
}
pub fn ou_cost(tx: &Transaction, stealth_minimum: &BigInt) -> BigInt {
    use OpType::{
        CircleDeploy, CircleIngressCommit, CircleOutboxOpen, CircleProgramUpdate,
        CircleRelayCancel, CircleRelayClaim, Claim, ComputeFund, ComputeSettle, ContractDeploy,
        ContractUpgrade, Decrypt, Encrypt, KeySwitch, MultiExec, Private, ProgramDeploy, Recrypt,
        Stealth, ValidatorEvidence,
    };
    let amount = match tx.op_type {
        Encrypt | Decrypt | Claim | KeySwitch | CircleOutboxOpen | CircleRelayClaim
        | CircleRelayCancel | CircleIngressCommit => 3000,
        Private | Stealth => return stealth_minimum.clone(),
        Recrypt | ValidatorEvidence => 5000,
        ContractDeploy | ContractUpgrade | CircleDeploy | CircleProgramUpdate => 200_000,
        ProgramDeploy => {
            return BigInt::from(200_000)
                + BigInt::from(
                    tx.encrypted_data
                        .as_ref()
                        .map_or(0, Vec::len)
                        .div_ceil(1024),
                ) * 1000
        }
        MultiExec => {
            let count = tx
                .message
                .as_deref()
                .and_then(|v| Document::parse(v).ok())
                .map_or(1, |doc| {
                    let value = match doc.root() {
                        Value::Object(_) => doc.field(doc.root(), b"calls"),
                        value => Some(value),
                    };
                    match value {
                        Some(Value::List(items)) => items.len(),
                        _ => 1,
                    }
                });
            return BigInt::from(1000) + BigInt::from(count.max(1)) * 1000;
        }
        op if is_asset_body(op) => {
            return circle_asset_fee(tx.encrypted_data.as_ref().map_or(0, Vec::len))
        }
        ComputeFund => 10_000,
        ComputeSettle => return compute_fee(tx.message.as_deref().unwrap_or_default()),
        _ => 1000,
    };
    amount.into()
}
pub fn staging_admission(
    tx: &Transaction,
    minimum: &BigInt,
    relay_fee: &BigInt,
) -> Result<(), String> {
    if matches!(
        tx.op_type,
        OpType::Stealth | OpType::Encrypt | OpType::Decrypt | OpType::Recrypt | OpType::KeySwitch
    ) && tx.ou < *minimum
    {
        return Err(format!(
            "fee too low: stealth requires ou >= {minimum}, got {}",
            tx.ou
        ));
    }
    semantic_check(tx).map_err(str::to_owned)?;
    let required = ou_cost(tx, minimum).max(relay_fee.clone());
    if tx.ou < required {
        Err(format!("fee too low (min: {required})"))
    } else {
        Ok(())
    }
}
