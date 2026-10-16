// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Read-only Program RPC plans retain their native JSON arena and one snapshot.
use crate::{circle_call::VmReceipt, state_batch::Snapshot};
use octra_node_protocol::{
    native_json::{Document, Value},
    rpc::{param, param_id, require_address, require_string, Fault},
    transaction::json_string,
};

const DEFAULT_CALLER: &[u8] = b"oct00000000000000000000000000000000000000000000";
pub const EFFORT_LIMIT: i64 = 10_000_000;
pub struct Plan {
    document: Document,
    arguments: Document,
    address: Vec<u8>,
    method: usize,
    caller: Option<usize>,
    include_storage: bool,
}
impl Plan {
    pub fn prepare(document: &Document, params: &Value) -> Result<Self, Fault> {
        let address = require_address(document, params, 0, "address")?.to_vec();
        require_string(document, params, 1, "method")?;
        let method = param_id(params, 1).expect("validated method");
        let arguments = match param(document, params, 2) {
            Some(Value::List(_)) => document
                .rooted(param_id(params, 2).expect("validated arguments"))
                .expect("arena member"),
            _ => Document::parse(b"[]").map_err(|_| resources())?,
        };
        let caller = matches!(param(document, params, 3), Some(Value::String(_)))
            .then(|| param_id(params, 3).expect("validated caller"));
        Ok(Self {
            document: document.clone(),
            arguments,
            address,
            method,
            caller,
            include_storage: matches!(param(document, params, 4), Some(Value::Bool(true))),
        })
    }
    pub fn address(&self) -> &[u8] {
        &self.address
    }
    pub fn method(&self) -> &[u8] {
        let Some(Value::String(value)) = self.document.get(self.method) else {
            unreachable!("validated method remains in immutable arena")
        };
        value
    }
    pub fn caller(&self) -> &[u8] {
        match self.caller.and_then(|id| self.document.get(id)) {
            Some(Value::String(value)) => value,
            _ => DEFAULT_CALLER,
        }
    }
    pub fn arguments(&self) -> &Document {
        &self.arguments
    }
    // Preserve the native owned-input and typed diagnostic interface.
    #[allow(clippy::needless_pass_by_value)]
    pub fn response(&self, state: &Snapshot, receipt: VmReceipt) -> Result<Vec<u8>, Fault> {
        if !receipt.success {
            return Err(Fault::new(
                -32000,
                receipt.error.as_deref().unwrap_or(b"execution failed"),
            ));
        }
        let mut out = b"{\"result\":".to_vec();
        out.extend_from_slice(
            &receipt
                .response
                .as_ref()
                .map_or_else(|| b"null".to_vec(), crate::octb::Value::result_json),
        );
        if self.include_storage {
            let names = state
                .child_names(&[b"contracts", self.address(), b"storage"])
                .take(65)
                .collect::<Vec<_>>();
            out.extend_from_slice(b",\"storage\":{");
            let mut first = true;
            for name in names.iter().take(64) {
                if let Some(value) = state.get(&[b"contracts", self.address(), b"storage", name]) {
                    if !first {
                        out.push(b',');
                    }
                    first = false;
                    json_string(&mut out, name);
                    out.push(b':');
                    json_string(&mut out, &value[..value.len().min(4096)]);
                }
            }
            out.extend_from_slice(if names.len() > 64 {
                b"},\"storage_more\":true,\"storage_limit\":64"
            } else {
                b"},\"storage_more\":false,\"storage_limit\":64"
            });
        }
        out.push(b'}');
        Ok(out)
    }
}
pub fn resources() -> Fault {
    Fault::new(-32005, b"Program view resources unavailable")
}
pub fn time_limit() -> Fault {
    Fault::new(-32005, b"Program view time limit exceeded")
}
