// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{Constant, Cursor, Error, Pool, Value};
use num_bigint::BigInt;
use std::sync::Arc;

macro_rules! byte_type {
    ($name:ident) => {
        u8
    };
}
// One table gives each fixed-byte instruction its wire tag and ordered operands.
// XCALL/SPAWN2 include an argument count; admission checks their spans separately.
macro_rules! instructions {
    ($($name:ident($($reg:ident),*) = $tag:literal, $active:literal;)*) => {
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub enum Instruction {
            $($name($(byte_type!($reg)),*),)*
            Ldi(u8, Arc<Value>), Sload(u8, Arc<[u8]>), Sstore(Arc<[u8]>, u8),
            Sdel(Arc<[u8]>), CapCheck(Arc<BigInt>, u8), CapClose(Arc<BigInt>, u8),
            Mload(u8, u16), Mstore(u16, u8), Jmp(u32), Jif(u8, u32),
            Jdest(u32), CallInt(u8, u32), Emit(Arc<[u8]>, Vec<u8>),
        }
        impl Instruction {
            pub(super) fn fixed_arity(tag: u8) -> Option<usize> {
                match tag {
                    $($tag => { let args: &[&str] = &[$(stringify!($reg)),*]; Some(args.len()) },)*
                    _ => None,
                }
            }
            pub(super) fn from_fixed(tag: u8, values: &[u8]) -> Option<Self> {
                match (tag, values) {
                    $(($tag, [$($reg),*]) => Some(Self::$name($(*$reg),*)),)*
                    _ => None,
                }
            }
            pub(super) fn fixed_bytes(&self) -> Option<Vec<u8>> {
                match self {
                    $(Self::$name($($reg),*) => Some(vec![$(*$reg),*]),)*
                    _ => None,
                }
            }
            pub(super) fn first_invalid_byte(&self) -> Option<u8> {
                match self {
                    $(Self::$name($($reg),*) => { $(if *$reg > 63 { return Some(*$reg); })* None },)*
                    _ => None,
                }
            }
            pub fn opcode(&self) -> u8 {
                match self {
                    $(Self::$name(..) => $tag,)*
                    Self::Ldi(..)=>0x0b,Self::Sload(..)=>0x0d,Self::Sstore(..)=>0x0e,
                    Self::Sdel(..)=>0x0f,Self::CapCheck(..)=>0x89,Self::CapClose(..)=>0x8a,
                    Self::Mload(..)=>0x12,Self::Mstore(..)=>0x13,Self::Jmp(..)=>0x14,
                    Self::Jif(..)=>0x15,Self::Jdest(..)=>0x16,Self::CallInt(..)=>0x2d,
                    Self::Emit(..)=>0x27,
                }
            }
            pub(super) fn decode(r: &mut Cursor<'_>, pool: &mut super::Constants<'_>) -> Result<Self, Error> {
                let at = r.at;
                let tag = r.u8()?;
                Ok(match tag {
                    $($tag if !$active || pool.active => { $(let $reg=r.u8()?;)* Self::$name($($reg),*) },)*
                    0x0b => { let reg=r.u8()?;let ci=r.u16()?;Self::Ldi(reg,pool.value(ci)?) },
                    0x0d => {let reg=r.u8()?;let ci=r.u16()?;Self::Sload(reg,pool.string(ci)?)},
                    0x0e => {let ci=r.u16()?;let reg=r.u8()?;Self::Sstore(pool.string(ci)?,reg)},
                    0x0f => Self::Sdel(pool.string(r.u16()?)?),
                    0x89|0x8a if pool.active => {
                        let value=pool.value(r.u16()?)?;
                        let kind=if let Value::Int(kind)=value.as_ref() { kind.clone() } else {Arc::new(BigInt::from(-1))};
                        let reg=r.u8()?;
                        if tag==0x89 {Self::CapCheck(kind,reg)} else {Self::CapClose(kind,reg)}
                    },
                    0x12=>Self::Mload(r.u8()?,r.u16()?),0x13=>Self::Mstore(r.u16()?,r.u8()?),
                    0x14=>Self::Jmp(r.u32()?),0x15=>Self::Jif(r.u8()?,r.u32()?),
                    0x16=>Self::Jdest(r.u32()?),0x2d=>Self::CallInt(r.u8()?,r.u32()?),
                    0x27=>{let name=pool.string(r.u16()?)?;let count=r.u8()?;Self::Emit(name,r.take(count.into())?.to_vec())},
                    _=>return Err(Error::message(if pool.active {format!("unknown opcode 0x{tag:02x} at pc {}",pool.pc)} else {format!("unknown opcode 0x{tag:02x} at {at}")})),
                })
            }
            pub(super) fn encode(&self, out:&mut Vec<u8>, pool:&mut Pool) {
                out.push(self.opcode());
                match self {
                    $(Self::$name($($reg),*)=> { $(out.push(*$reg);)* },)*
                    Self::Ldi(reg,value)=>{out.push(*reg);out.extend(pool.intern(Constant::from_value(value)).to_le_bytes())},
                    Self::Sload(reg,key)=>{out.push(*reg);out.extend(pool.intern(Constant::Str(key.clone())).to_le_bytes())},
                    Self::Sstore(key,reg)=>{out.extend(pool.intern(Constant::Str(key.clone())).to_le_bytes());out.push(*reg)},
                    Self::Sdel(key)=>out.extend(pool.intern(Constant::Str(key.clone())).to_le_bytes()),
                    Self::CapCheck(kind,reg)|Self::CapClose(kind,reg)=>{out.extend(pool.intern(Constant::Int(kind.to_string().into_bytes().into())).to_le_bytes());out.push(*reg)},
                    Self::Mload(reg,index)=>{out.push(*reg);out.extend(index.to_le_bytes())},
                    Self::Mstore(index,reg)=>{out.extend(index.to_le_bytes());out.push(*reg)},
                    Self::Jmp(dest)|Self::Jdest(dest)=>out.extend(dest.to_le_bytes()),
                    Self::Jif(reg,dest)|Self::CallInt(reg,dest)=>{out.push(*reg);out.extend(dest.to_le_bytes())},
                    Self::Emit(name,regs)=>{out.extend(pool.intern(Constant::Str(name.clone())).to_le_bytes());out.push(regs.len() as u8);out.extend(regs)},
                }
            }
            #[cfg(test)]
            pub(super) fn signature(&self)->serde_json::Value {
                use serde_json::json;
                use base64::Engine;
                let bytes=|v:&[u8]|json!({"bytes":base64::engine::general_purpose::STANDARD.encode(v)});
                let args=match self {
                    $(Self::$name($($reg),*)=>json!([$($reg),*]),)*
                    Self::Ldi(reg,value)=>json!([reg,super::tests::value(value)]),
                    Self::Sload(reg,key)=>json!([reg,bytes(key)]),Self::Sstore(key,reg)=>json!([bytes(key),reg]),
                    Self::Sdel(key)=>json!([bytes(key)]),
                    Self::CapCheck(kind,reg)|Self::CapClose(kind,reg)=>json!([{"int":kind.to_string()},reg]),
                    Self::Mload(reg,index)=>json!([reg,index]),Self::Mstore(index,reg)=>json!([index,reg]),
                    Self::Jmp(dest)|Self::Jdest(dest)=>json!([dest]),
                    Self::Jif(reg,dest)|Self::CallInt(reg,dest)=>json!([reg,dest]),
                    Self::Emit(name,regs)=>json!([bytes(name),regs]),
                };
                json!({"opcode":self.opcode(),"args":args})
            }
        }
    }
}
instructions! {
    Add(r0,r1,r2) = 0x00, false;
    Sub(r0,r1,r2) = 0x01, false;
    Mul(r0,r1,r2) = 0x02, false;
    Div(r0,r1,r2) = 0x03, false;
    Mod(r0,r1,r2) = 0x04, false;
    Neg(r0,r1) = 0x05, false;
    Abs(r0,r1) = 0x06, false;
    Eq(r0,r1,r2) = 0x07, false;
    Lt(r0,r1,r2) = 0x08, false;
    Gt(r0,r1,r2) = 0x09, false;
    Neq(r0,r1,r2) = 0x0a, false;
    Mov(r0,r1) = 0x0c, false;
    Sloadk(r0,r1) = 0x10, false;
    Sstorek(r0,r1) = 0x11, false;
    Stop() = 0x17, false;
    Revert() = 0x18, false;
    Caller(r0) = 0x19, false;
    Origin(r0) = 0x1a, false;
    SelfAddr(r0) = 0x1b, false;
    Epoch(r0) = 0x1c, false;
    Value(r0) = 0x1d, false;
    Balance(r0,r1) = 0x1e, false;
    Treehash(r0) = 0x1f, false;
    Nodeid(r0) = 0x20, false;
    Xcall(r0,r1,r2,r3,r4) = 0x21, false;
    Spawn(r0,r1) = 0x22, false;
    Transfer(r0,r1,r2) = 0x23, false;
    Checkpoint() = 0x24, false;
    Rollback() = 0x25, false;
    Commit() = 0x26, false;
    Concat(r0,r1,r2) = 0x28, false;
    Assert(r0) = 0x29, false;
    Effort(r0) = 0x2a, false;
    Nop() = 0x2b, false;
    Strlen(r0,r1) = 0x2c, false;
    Mloadr(r0,r1) = 0x2e, false;
    Mstorer(r0,r1) = 0x2f, false;
    FheLoadPk(r0,r1) = 0x30, false;
    FheAdd(r0,r1,r2,r3) = 0x31, false;
    FheSub(r0,r1,r2,r3) = 0x32, false;
    FheScale(r0,r1,r2,r3) = 0x33, false;
    FheAddConst(r0,r1,r2,r3) = 0x34, false;
    FheSubConst(r0,r1,r2,r3) = 0x35, false;
    FheVerifyZero(r0,r1,r2,r3) = 0x36, false;
    FheVerifyRange(r0,r1,r2,r3) = 0x37, false;
    FheVerifyBound(r0,r1,r2,r3,r4) = 0x38, false;
    FheCommit(r0,r1,r2) = 0x39, false;
    FhePedersen(r0,r1,r2) = 0x3a, false;
    FheSer(r0,r1) = 0x3b, false;
    FheDeser(r0,r1) = 0x3c, false;
    FheSerPk(r0,r1) = 0x3d, false;
    FheDeserPk(r0,r1) = 0x3e, false;
    Groth16VerifyBn254(r0,r1,r2,r3) = 0x3f, false;
    ParseInts(r0,r1,r2) = 0x40, false;
    Isaddr(r0,r1) = 0x41, false;
    AssertAddr(r0) = 0x42, false;
    Substr(r0,r1,r2,r3) = 0x43, false;
    Indexof(r0,r1,r2) = 0x44, false;
    Sha256(r0,r1) = 0x45, false;
    Keccak256(r0,r1) = 0x46, false;
    Bitand(r0,r1,r2) = 0x47, false;
    Bitor(r0,r1,r2) = 0x48, false;
    Bitxor(r0,r1,r2) = 0x49, false;
    Bitshl(r0,r1,r2) = 0x4a, false;
    Bitshr(r0,r1,r2) = 0x4b, false;
    Skeys(r0,r1,r2) = 0x4c, false;
    Sloadn(r0,r1,r2) = 0x4d, false;
    Sstoren(r0,r1,r2) = 0x4e, false;
    Fstore(r0,r1) = 0x4f, false;
    Fload(r0,r1) = 0x50, false;
    SkeysPage(r0,r1,r2,r3,r4) = 0x51, false;
    Ishex(r0,r1) = 0x52, false;
    Spawn2(r0,r1,r2,r3) = 0x53, false;
    Sdelk(r0) = 0x54, false;
    Ed25519Ok(r0,r1,r2,r3) = 0x55, false;
    StatePathKey(r0,r1) = 0x56, false;
    ObjectTransitionApply(r0,r1,r2,r3,r4,r5,r6,r7,r8,r9,r10) = 0x57, false;
    ObjectMemberCount(r0,r1) = 0x58, false;
    ObjectHasMember(r0,r1,r2) = 0x59, false;
    ObjectMemberRefAt(r0,r1,r2) = 0x5a, false;
    FheMul(r0,r1,r2,r3) = 0x5b, false;
    FheDivConst(r0,r1,r2,r3) = 0x5c, false;
    FhePedersenAdd(r0,r1,r2) = 0x5d, true;
    FhePedersenSub(r0,r1,r2) = 0x5e, true;
    FhePedersenIdentity(r0) = 0x5f, true;
    Matmul(r0,r1,r2,r3,r4,r5) = 0x60, false;
    Vecdot(r0,r1,r2,r3) = 0x61, false;
    ExpLut(r0,r1) = 0x62, false;
    SoftmaxInplace(r0,r1) = 0x63, false;
    LayernormInplace(r0,r1,r2,r3) = 0x64, false;
    ReluInplace(r0,r1) = 0x65, false;
    RmsnormInplace(r0,r1,r2) = 0x66, false;
    SiluInplace(r0,r1) = 0x67, false;
    ElemwiseMulInplace(r0,r1,r2) = 0x68, false;
    LoadInt8BytesToMem(r0,r1,r2,r3,r4) = 0x69, false;
    ResidualAdd(r0,r1,r2) = 0x6a, false;
    RopeApply(r0,r1,r2,r3) = 0x6b, false;
    LoadInt8B64ToMem(r0,r1,r2,r3,r4) = 0x6c, false;
    MatmulQ16(r0,r1,r2,r3,r4,r5) = 0x6d, false;
    ShiftRoundInplace(r0,r1,r2) = 0x6e, false;
    MatmulFp(r0,r1,r2,r3,r4,r5) = 0x6f, false;
    RmsnormFp(r0,r1,r2) = 0x70, false;
    SiluFp(r0,r1) = 0x71, false;
    ElemwiseMulFp(r0,r1,r2) = 0x72, false;
    ResidualAddFp(r0,r1,r2) = 0x73, false;
    RopeApplyFp(r0,r1,r2,r3) = 0x74, false;
    LoadInt8Fp(r0,r1,r2,r3,r4) = 0x75, false;
    VecdotFp(r0,r1,r2,r3) = 0x76, false;
    ArgmaxFp(r0,r1,r2) = 0x77, false;
    AttentionKvFp(r0,r1,r2,r3,r4,r5,r6,r7) = 0x78, false;
    AppendVecFp(r0,r1,r2,r3) = 0x79, false;
    Txhash(r0) = 0x7a, false;
    EpochTime(r0) = 0x7b, false;
    ExpQ16(r0,r1) = 0x7c, false;
    SoftmaxQ16Inplace(r0,r1) = 0x7d, false;
    LayernormQ16Inplace(r0,r1,r2,r3) = 0x7e, false;
    RmsnormQ16Inplace(r0,r1,r2) = 0x7f, false;
    SiluQ16Inplace(r0,r1) = 0x80, false;
    RopeApplyQ16(r0,r1,r2,r3) = 0x81, false;
    AttentionKvQ16(r0,r1,r2,r3,r4,r5,r6,r7) = 0x82, false;
    VecdotQ16(r0,r1,r2,r3) = 0x83, false;
    ElemwiseMulQ16(r0,r1,r2) = 0x84, false;
    ResidualAddQ16(r0,r1,r2) = 0x85, false;
    LoadInt8Q16(r0,r1,r2,r3,r4) = 0x86, false;
    AppendVecQ16(r0,r1,r2,r3) = 0x87, false;
    ArgmaxQ16(r0,r1,r2) = 0x88, false;
}
