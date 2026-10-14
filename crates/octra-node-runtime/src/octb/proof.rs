// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{Budget, Exec, Host, Machine, Trap, Value};
use octra_node_protocol::transaction::decode_base64;

impl Machine {
    pub(super) fn verify_groth16(
        &mut self,
        dest: u8,
        key: u8,
        proof: u8,
        inputs: u8,
        host: &mut impl Host,
        budget: &mut Option<&mut Budget>,
    ) -> Exec {
        let enabled = self.options.proof_exec && self.options.fhe_work && self.options.math;
        if !self.options.is_view && !enabled {
            return Err(Trap::Refused);
        }
        let decode = |reg| -> Exec<Vec<u8>> {
            let raw = self.get(reg)?.bytes().ok_or(Trap::Refused)?;
            Ok(decode_base64(raw).unwrap_or_else(|_| raw.to_vec()))
        };
        let (key, proof, inputs) = (decode(key)?, decode(proof)?, decode(inputs)?);
        let Some(count) = crate::groth16::shape(&key, &proof, &inputs) else {
            return self.set(dest, Value::Bool(false));
        };
        // Native insufficient dynamic effort returns false without reverting or
        // consuming that effort. The already-paid fixed opcode cost remains.
        if self.charge(count as i64 * 20_000).is_err() {
            return self.set(dest, Value::Bool(false));
        }
        let valid = if enabled {
            match host.groth16(&key, &proof, &inputs) {
                Ok(value) => value,
                Err(error) if !self.options.is_view => {
                    if self.options.async_exec {
                        self.reverted = true;
                        self.closes.clear();
                    }
                    return Err(error.into());
                }
                Err(_) => {
                    let _ = self.emit(
                        b"Require".to_vec(),
                        vec![Value::string(b"fhe verifier unavailable".to_vec())],
                        budget,
                    );
                    // A resumed native host refusal leaves pc after the opcode.
                    return Err(if self.options.async_exec {
                        Trap::HostRefused
                    } else {
                        Trap::Refused
                    });
                }
            }
        } else {
            crate::groth16::verify(&key, &proof, &inputs)
        };
        self.set(dest, Value::Bool(valid))
    }
}
