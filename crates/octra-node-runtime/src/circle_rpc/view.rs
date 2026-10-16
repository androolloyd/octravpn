// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{error, load};
use crate::{circle_call::VmReceipt, circle_query::Query, circle_store, state_batch::Snapshot};
use octra_node_protocol::{
    circle_auth::{self, Auth, Gate},
    native_json::{Document, Value},
    rpc::{param, param_id, require_string, Fault},
    transaction::json_string,
};

pub struct Plan {
    circle: Vec<u8>,
    method: Vec<u8>,
    arguments: Document,
    caller: Vec<u8>,
    include_storage: bool,
}
impl Plan {
    pub fn prepare(
        state: &Snapshot,
        doc: &Document,
        params: &Value,
        authenticated: bool,
    ) -> Result<Self, Fault> {
        let circle = require_string(doc, params, 0, "circle_id")?;
        let method = require_string(doc, params, 1, "method")?;
        if circle.len() > 128 {
            return Err(Fault::invalid(b"circle id exceeds limit"));
        }
        if method.len() > 64 {
            return Err(Fault::invalid(b"circle view method exceeds limit"));
        }
        let arguments = match param(doc, params, 2) {
            Some(Value::List(_)) => doc
                .rooted(param_id(params, 2).expect("list parameter"))
                .expect("arena member"),
            _ => Document::parse(b"[]").map_err(|_| resources())?,
        };
        if arguments
            .measure(arguments.root(), 65_536)
            .map_err(|_| resources())?
            .is_none()
        {
            return Err(Fault::invalid(b"circle view params exceed limit"));
        }
        let info = load(state, circle)?;
        let include_storage =
            authenticated && matches!(param(doc, params, 6), Some(Value::Bool(true)));
        let caller = if authenticated {
            let subject = circle_auth::view_subject(method, &arguments, include_storage)
                .map_err(|_| resources())?;
            Auth::parse(doc, params, [3, 4, 5])?
                .authorize(
                    &info.privacy,
                    &info.owner,
                    if include_storage {
                        Gate::StorageOwner
                    } else {
                        Gate::PrivateOwner
                    },
                    b"octra_circle_view",
                    circle,
                    &subject,
                )?
                .to_vec()
        } else {
            if circle_auth::private_view_required(&info.privacy) {
                return Err(error(b"authenticated circle view required"));
            }
            b"oct00000000000000000000000000000000000000000000".to_vec()
        };
        Ok(Self {
            circle: circle.to_vec(),
            method: method.to_vec(),
            arguments,
            caller,
            include_storage,
        })
    }
    pub fn execute(&self, query: &Query<'_>, state: &Snapshot) -> Result<Vec<u8>, Fault> {
        let receipt = query
            .circle(
                &self.circle,
                &self.method,
                &self.arguments,
                &self.caller,
                2_000_000_000,
            )
            .map_err(|failure| match failure {
                octra_node_protocol::circle_wasm::Error::Rejected(reason) => error(reason),
                octra_node_protocol::circle_wasm::Error::Unavailable(_) => resources(),
            })?;
        self.response(state, receipt)
    }
    // Preserve the native owned-input and typed diagnostic interface.
    #[allow(clippy::needless_pass_by_value)]
    fn response(&self, state: &Snapshot, receipt: VmReceipt) -> Result<Vec<u8>, Fault> {
        if !receipt.success {
            return Err(error(
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
            let storage =
                circle_store::load_storage(state, &self.circle, None).map_err(|e| error(&e.0))?;
            // Native Hashtbl.fold prepends each pair; preserve that field order.
            let pairs = storage.iter().collect::<Vec<_>>();
            out.extend_from_slice(b",\"storage\":{");
            for (index, (key, value)) in pairs.into_iter().rev().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                json_string(&mut out, key);
                out.push(b':');
                json_string(&mut out, value);
            }
            out.push(b'}');
        }
        out.push(b'}');
        Ok(out)
    }
}
pub fn resources() -> Fault {
    Fault::new(-32005, b"circle view resources unavailable")
}
pub fn time_limit() -> Fault {
    Fault::new(-32005, b"circle view time limit exceeded")
}
