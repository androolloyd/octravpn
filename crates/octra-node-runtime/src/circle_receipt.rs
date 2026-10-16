// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! The outer VM's shared event/return budget, separate from WASM instruction fuel.
use octra_node_protocol::{
    circle_wasm::codec::Scalar,
    native_integer::parse_integer,
    octb::work::{self, Budget, Request},
};
/// Native ContractVM.output_work on the caller's existing byte budget.
pub(crate) fn output_value(
    budget: &mut Budget,
    value: &crate::octb::Value,
    mut used: i64,
    limit: i64,
) -> Option<i64> {
    let left = budget.event_left() - 16;
    if value.numeric() {
        let size = i64::try_from(value.number().bits() / 3 + 2).ok()?;
        if size > budget.event_left() {
            return None;
        }
        used = budget.charge(used, limit, 0, &[Request::Allocate(size)])?;
    }
    let text = value.text();
    let mut size = work::text_size(left, &text)?;
    if matches!(
        value,
        crate::octb::Value::Bytes(_) | crate::octb::Value::Bytes32(_)
    ) {
        size = size.max(work::encoded_size(text.len() as i64)? + 2);
    }
    budget.output(used, limit, size + 16)
}

#[derive(Clone, Debug, Default)]
pub struct ReceiptBudget {
    pub(crate) work: Budget,
}
/// Converts the native scalar to the VM's return representation, including
/// arbitrary precision integers. A null scalar becomes an empty VM string.
pub fn vm_scalar(value: &Scalar) -> Option<Scalar> {
    Some(match value {
        Scalar::Null => Scalar::String(Vec::new()),
        Scalar::Integer(raw) => Scalar::Integer(parse_integer(raw)?.to_string().into_bytes()),
        v => v.clone(),
    })
}
impl ReceiptBudget {
    /// Lend the very same native budget across a VM host boundary. Failed child
    /// calls retain their consumed budget even when all journal effects revert.
    pub(crate) fn with_work<T>(
        work: Option<&mut Budget>,
        run: impl FnOnce(Option<&mut Self>) -> T,
    ) -> T {
        let Some(work) = work else { return run(None) };
        let mut receipt = Self {
            work: std::mem::take(work),
        };
        let result = run(Some(&mut receipt));
        *work = receipt.work;
        result
    }
    pub fn output(&mut self, value: &Scalar, mut used: i64, limit: i64) -> Option<i64> {
        let left = self.work.event_left() - 16;
        let number;
        let bytes = match value {
            Scalar::Null => b"".as_slice(),
            Scalar::Bool(true) => b"true",
            Scalar::Bool(false) => b"false",
            Scalar::String(v) => v,
            Scalar::Integer(v) => {
                let parsed = parse_integer(v)?;
                let size = i64::try_from(parsed.bits() / 3 + 2).ok()?;
                if size > self.work.event_left() {
                    return None;
                }
                used = self
                    .work
                    .charge(used, limit, 0, &[Request::Allocate(size)])?;
                number = parsed.to_string().into_bytes();
                &number
            }
        };
        let size = work::text_size(left, bytes)?;
        self.work.output(used, limit, size + 16)
    }
    pub fn event(
        &mut self,
        address: &[u8],
        depth: i64,
        name: &[u8],
        data: &[u8],
        used: i64,
        limit: i64,
    ) -> Option<i64> {
        let size = work::event_size(self.work.event_left() - 1, address, depth, name, &[data])?;
        self.work.emit(used, limit, size + 1)
    }
}
