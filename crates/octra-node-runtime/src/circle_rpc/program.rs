// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{error, load, optional};
use crate::{circle::CircleRuntime, circle_view::Profile, state_batch::Snapshot};
use octra_node_protocol::{
    circle_auth::{self, Auth, Gate},
    native_json::{Document, Value},
    rpc::{require_string, Fault},
    transaction::json_string,
};

#[derive(Clone, Copy)]
pub enum Read {
    Code,
    Descriptor,
}
pub fn read(
    kind: Read,
    authenticated: bool,
    runtime: &CircleRuntime,
    state: &Snapshot,
    profile: &Profile,
    doc: &Document,
    params: &Value,
) -> Result<Vec<u8>, Fault> {
    let circle = require_string(doc, params, 0, "circle_id")?;
    let info = load(state, circle)?;
    let (op, denial) = match kind {
        Read::Code => (
            b"octra_circle_program".as_slice(),
            b"authenticated circle program read required".as_slice(),
        ),
        Read::Descriptor => (
            b"octra_circle_program_info".as_slice(),
            b"authenticated circle program info required".as_slice(),
        ),
    };
    if authenticated {
        Auth::parse(doc, params, [1, 2, 3])?.authorize(
            &info.privacy,
            &info.owner,
            Gate::PrivateOwner,
            op,
            circle,
            b"",
        )?;
    } else if circle_auth::private_view_required(&info.privacy) {
        return Err(error(denial));
    }
    if matches!(kind, Read::Descriptor) {
        return crate::circle_program::describe(runtime, state, profile, &info)
            .map(|descriptor| descriptor.encode())
            .map_err(|failure| match failure {
                octra_node_protocol::circle_wasm::Error::Rejected(reason) => error(reason),
                octra_node_protocol::circle_wasm::Error::Unavailable(_) => {
                    Fault::new(110, b"service unavailable")
                }
            });
    }
    let code = state.get(&[b"circles", circle, b"program", b"code_b64"]);
    let size = code.map_or(0, |raw| {
        let mut tail = [0; 2];
        let mut length: usize = 0;
        for byte in raw.iter().filter(|byte| **byte != b'\n') {
            tail = [tail[1], *byte];
            length += 1;
        }
        let padding = if length >= 2 && tail == *b"==" {
            2
        } else {
            usize::from(length >= 1 && tail[1] == b'=')
        };
        (length * 3 / 4).saturating_sub(padding)
    });
    let mut out = b"{\"circle_id\":".to_vec();
    json_string(&mut out, circle);
    out.extend_from_slice(if code.is_some() {
        b",\"has_program\":true,\"code_b64\":"
    } else {
        b",\"has_program\":false,\"code_b64\":"
    });
    optional(&mut out, code);
    out.extend_from_slice(format!(",\"code_bytes\":{size},\"code_hash\":").as_bytes());
    json_string(&mut out, &info.code_hash);
    out.extend_from_slice(b",\"runtime\":");
    json_string(&mut out, &info.runtime);
    out.push(b'}');
    Ok(out)
}
