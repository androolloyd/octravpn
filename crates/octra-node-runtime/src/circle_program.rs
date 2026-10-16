// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Snapshot-bound Circle descriptors shared by browser clients and native RPC.
use crate::{
    circle::CircleRuntime, circle_store::Info, circle_view::Profile, state_batch::Snapshot,
};
use octra_node_protocol::{
    circle_wasm::{self, Error, Execution, Method},
    transaction::{decode_base64, json_string},
};
use sha2::{Digest, Sha256};

pub struct Descriptor {
    pub info: Info,
    pub has_code: bool,
    pub code_bytes: usize,
    pub methods: Vec<Method>,
}
pub fn describe(
    runtime: &CircleRuntime,
    state: &Snapshot,
    profile: &Profile,
    info: &Info,
) -> Result<Descriptor, Error> {
    let Some(encoded) = state.get(&[b"circles", &info.circle_id, b"program", b"code_b64"]) else {
        return Ok(Descriptor {
            info: info.clone(),
            has_code: false,
            code_bytes: 0,
            methods: vec![],
        });
    };
    let raw = decode_base64(encoded).map_err(|error| {
        Error::Rejected(format!("invalid circle code: Invalid_argument(\"{error}\")").into_bytes())
    })?;
    if hex::encode(Sha256::digest(&raw)).as_bytes() != info.code_hash {
        return Err(Error::Rejected(b"circle code hash mismatch".to_vec()));
    }
    let code_bytes = raw.len();
    let methods = if info.runtime == b"octb" {
        crate::circle_octb::methods(crate::circle_query::admit(&raw, true, None)?.code())
    } else {
        // Base64 input is ASCII after successful decoding; retain an explicit
        // resource refusal rather than silently replacing stored string bytes.
        let code = std::str::from_utf8(encoded)
            .map_err(|_| Error::Unavailable(b"non-UTF-8 Circle engine field".to_vec()))?;
        let input = serde_json::to_vec(&serde_json::json!({"action":"describe","is_view":true,"float_mode":profile.wasm().wasm_float,"code_b64":code,"execution_profile":"manifest","inspect_policy":true}))
            .map_err(|error| Error::Unavailable(error.to_string().into_bytes()))?;
        let reply = runtime.execute(&input).map_err(|error| match error {
            crate::circle::Error::Rejected(reason) => {
                Error::Rejected([b"invalid circle wasm: ".as_slice(), reason.as_bytes()].concat())
            }
            crate::circle::Error::Unavailable(reason) => Error::Unavailable(reason.into_bytes()),
        })?;
        circle_wasm::methods(reply.as_ref()).map_err(|error| match error {
            Error::Rejected(reason) => {
                Error::Rejected([b"invalid circle wasm manifest: ".as_slice(), &reason].concat())
            }
            other @ Error::Unavailable(_) => other,
        })?
    };
    Ok(Descriptor {
        info: info.clone(),
        has_code: true,
        code_bytes,
        methods,
    })
}
fn string(out: &mut Vec<u8>, key: &[u8], value: &[u8]) {
    json_string(out, key);
    out.push(b':');
    json_string(out, value);
}
impl Descriptor {
    pub fn encode(&self) -> Vec<u8> {
        let info = &self.info;
        let mut out = vec![b'{'];
        for (index, (key, value)) in [
            (b"circle_id".as_slice(), info.circle_id.as_slice()),
            (b"runtime", &info.runtime),
            (b"version", info.version.to_string().as_bytes()),
            (b"owner", &info.owner),
            (b"code_hash", &info.code_hash),
        ]
        .into_iter()
        .enumerate()
        {
            if index > 0 {
                out.push(b',');
            }
            string(&mut out, key, value);
        }
        out.extend_from_slice(
            format!(
                ",\"has_program\":{},\"code_bytes\":{},\"code_b64\":null,\"methods\":[",
                self.has_code, self.code_bytes
            )
            .as_bytes(),
        );
        for (index, method) in self.methods.iter().enumerate() {
            if index > 0 {
                out.push(b',');
            }
            out.push(b'{');
            string(&mut out, b"name", &method.name);
            out.extend_from_slice(format!(",\"view\":{},", method.view).as_bytes());
            string(
                &mut out,
                b"execution",
                match method.execution {
                    Execution::Standard => b"standard",
                    Execution::Compute => b"compute",
                },
            );
            out.push(b'}');
        }
        out.push(b']');
        for (key, value) in [
            (b"stable_root".as_slice(), info.stable_root.as_slice()),
            (b"assets_root", &info.assets_root),
            (b"privacy_class", &info.privacy),
            (b"browser_mode", &info.browser),
            (b"resource_mode", &info.resource),
        ] {
            out.push(b',');
            string(&mut out, key, value);
        }
        out.extend_from_slice(b",\"limits\":{");
        for (index, (key, value)) in crate::circle_store::LIMIT_NAMES
            .iter()
            .zip(info.limits)
            .enumerate()
        {
            if index > 0 {
                out.push(b',');
            }
            string(&mut out, key, value.to_string().as_bytes());
        }
        out.extend_from_slice(b"}}");
        out
    }
}
