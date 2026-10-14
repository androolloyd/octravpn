// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Payload decoding and byte budgets. Validator-control semantic admission is a
//! separate check, as it is in the native `Bft_control_admission` module.
use crate::transaction::{Error, OpType, Transaction};
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub encrypted_data: usize,
    pub message: usize,
    pub message_zkp: usize,
    pub message_validator: usize,
    pub message_program: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            encrypted_data: 50_000_000,
            message: 256,
            message_zkp: 50_000,
            message_validator: 16_384,
            message_program: 10_000_000,
        }
    }
}
impl Limits {
    pub const fn message_limit(self, op: OpType) -> usize {
        use OpType::{
            CircleAssetPut, CircleAssetPutEncrypted, CircleBalanceCellPut, CircleCall,
            CircleDeploy, CircleHfhePolicyPut, CircleIngressCommit, CircleKeyErase,
            CircleKeyExtend, CircleKeyGrant, CircleKeyPolicyPut, CircleKeyRevoke, CircleOutboxOpen,
            CircleProgramUpdate, CircleRegisterCellPut, CircleRelayCancel, CircleRelayClaim,
            CircleSealedSlotPut, CircleSlotPolicyPut, CircleStateDescriptorPut,
            CircleTransportPolicyPut, Claim, ComputeFund, ComputeReturn, ComputeSettle,
            ContractCall, ContractDeploy, MultiExec, ProgramDeploy, ProgramExec, Recrypt,
            ValidatorBond, ValidatorEvidence, ValidatorReady, ValidatorSetUpdate,
        };
        match op {
            ComputeReturn => 64,
            ComputeSettle => 262_144,
            Recrypt | Claim => self.message_zkp,
            ComputeFund | CircleAssetPut | CircleAssetPutEncrypted | CircleSealedSlotPut => 8192,
            ContractCall
            | ProgramExec
            | MultiExec
            | CircleCall
            | CircleSlotPolicyPut
            | CircleStateDescriptorPut
            | CircleBalanceCellPut
            | CircleRegisterCellPut
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
            | CircleIngressCommit
            | ContractDeploy
            | ProgramDeploy
            | CircleDeploy
            | CircleProgramUpdate => self.message_program,
            ValidatorSetUpdate | ValidatorReady | ValidatorBond | ValidatorEvidence => {
                self.message_validator
            }
            _ => self.message,
        }
    }
    pub const fn encrypted_data_limit(self, op: OpType) -> usize {
        if matches!(
            op,
            OpType::CircleAssetPut
                | OpType::CircleAssetPutEncrypted
                | OpType::CircleSealedSlotPut
                | OpType::CircleBalanceCellPut
                | OpType::CircleRegisterCellPut
        ) {
            44_739_244
        } else {
            self.encrypted_data
        }
    }
    pub fn check(self, tx: &Transaction) -> Result<(), Error> {
        if tx
            .encrypted_data
            .as_ref()
            .is_some_and(|value| value.len() > self.encrypted_data_limit(tx.op_type))
            || tx
                .message
                .as_ref()
                .is_some_and(|value| value.len() > self.message_limit(tx.op_type))
        {
            Err(Error("encrypted_data or message exceeds size limit".into()))
        } else {
            Ok(())
        }
    }
}

/// Complete native Tx_payload.admit ordering: byte budgets first, then validator
/// control-message parsing. Signature, account and operation admission follow.
pub fn admit(limits: Limits, tx: &Transaction) -> Result<(), Error> {
    limits.check(tx)?;
    crate::control_payload::validate_message(tx.op_type, tx.message.as_deref())
        .map(|_| ())
        .map_err(|error| Error(error.to_string()))
}
