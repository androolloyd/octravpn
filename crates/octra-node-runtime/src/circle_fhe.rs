// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native direct-call HFHE policy. Scoped receipt/key-policy capabilities are
//! explicit host inputs; ordinary calls have no live scoped key or active relay.
use crate::octb::FheCapability;
use crate::{circle::CircleRuntime, state_batch::Snapshot};
use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::circle_policy::hfhe;
pub(crate) struct Context<'a> {
    pub epoch: i64,
    pub scope: Option<&'a crate::circle_scope::Scope>,
    pub receipt_linked: bool,
}
#[derive(Clone, Debug)]
pub(crate) struct Policy {
    owner: Vec<u8>,
    caller: Vec<u8>,
    modes: [hfhe::Access; 12],
    allowlist: Option<Vec<Vec<u8>>>,
    key_live: bool,
    proof_bound: bool,
    relays: Vec<Vec<u8>>,
    verifiers: bool,
}
impl Policy {
    fn receipt_linked(mut self, linked: bool) -> Self {
        self.proof_bound |= linked;
        self
    }
    pub(crate) fn without_verifiers(mut self) -> Self {
        self.verifiers = false;
        self
    }
    pub(crate) fn scoped(
        state: &Snapshot,
        circle: &[u8],
        owner: &[u8],
        caller: &[u8],
        epoch: i64,
        scope: Option<&crate::circle_scope::Scope>,
    ) -> Result<Self, crate::execution::Error> {
        use crate::{circle_error::Failure, circle_transport_store as transport};
        let error = |failure| match failure {
            Failure::Unavailable(error) => error,
            Failure::Refused(error) => {
                crate::execution::Error(String::from_utf8_lossy(&error.reason).into_owned())
            }
        };
        let policy = crate::circle_store::hfhe_policy(state, circle)
            .map_err(|e| crate::execution::Error(e.to_string()))?;
        let transport_policy = transport::policy(state, circle).map_err(error)?;
        let mut out = Self::from_policy(policy, owner, caller);
        let Some(scope) = scope else {
            return Ok(out);
        };
        if let (Some(intent), Some(relay)) = (&scope.intent, &scope.relay) {
            let active = transport::active_claims(state, circle, intent, epoch).map_err(error)?;
            if active.iter().any(|claim| claim.relay == *relay)
                && transport_policy.ingress_relay_allowed(&active, relay)
            {
                out.relays.push(relay.clone());
            }
        }
        if let Some(key) = &scope.key {
            out.key_live |= transport::key_policy(state, circle, key)
                .map_err(error)?
                .state(epoch)
                == octra_node_protocol::circle_policy::key::State::Live;
        }
        Ok(out)
    }
    fn from_policy(policy: hfhe::Policy, owner: &[u8], caller: &[u8]) -> Self {
        Self {
            owner: owner.to_vec(),
            caller: caller.to_vec(),
            modes: policy.modes,
            allowlist: policy.pk_allowlist,
            key_live: !policy.require_live_key,
            proof_bound: !policy.require_transport_binding,
            relays: vec![],
            verifiers: true,
        }
    }
    fn index(cap: FheCapability) -> usize {
        match cap {
            FheCapability::LoadKey => 0,
            FheCapability::Encrypt => 1,
            FheCapability::Decrypt => 2,
            FheCapability::Arithmetic => 3,
            FheCapability::VerifyZero => 8,
            FheCapability::VerifyRange => 9,
            FheCapability::VerifyBound => 10,
            FheCapability::Commit => 4,
            FheCapability::Pedersen => 5,
            FheCapability::CipherSerde => 6,
            FheCapability::KeySerde => 7,
        }
    }
    pub(crate) fn allows(&self, cap: FheCapability) -> bool {
        let index = Self::index(cap);
        self.key_live
            && (!matches!(
                cap,
                FheCapability::VerifyZero | FheCapability::VerifyRange | FheCapability::VerifyBound
            ) || (self.proof_bound && self.verifiers))
            && (index == 0
                || self.modes[index].allows(&self.owner, &self.caller, &self.caller, &self.relays))
    }
    pub(crate) fn key(&self, address: &[u8]) -> bool {
        self.key_live
            && self
                .allowlist
                .as_ref()
                .is_none_or(|list| list.iter().any(|v| v == address))
            && self.modes[0].allows(&self.owner, &self.caller, address, &self.relays)
    }
}

#[derive(Default)]
pub(crate) struct Wasm {
    pub caps: Vec<&'static str>,
    pub public: Vec<(Vec<u8>, Vec<u8>)>,
    pub effort: i64,
    active: Option<Active>,
}
struct Active {
    id: Vec<u8>,
    public: Vec<u8>,
    secret: zeroize::Zeroizing<String>,
}
impl Wasm {
    pub(crate) fn active_key_id(&self) -> Option<&[u8]> {
        self.active.as_ref().map(|key| key.id.as_slice())
    }
    #[allow(clippy::too_many_arguments)]
    // Preserve the native owned-input and typed diagnostic interface.
    #[allow(clippy::needless_pass_by_value)]
    pub(crate) fn prepare(
        runtime: &CircleRuntime,
        state: &Snapshot,
        circle: &[u8],
        owner: &[u8],
        caller: &[u8],
        method: &[u8],
        limit: i64,
        view: bool,
        proof: bool,
        context: Context<'_>,
        memory: Option<&octra_node_protocol::octb::fhe_work::Memory>,
    ) -> Result<Self, octra_node_protocol::circle_wasm::Error> {
        use octra_node_protocol::circle_wasm::Error;
        use octra_node_protocol::octb::fhe_work as work;
        let unavailable = |e: crate::execution::Error| Error::Unavailable(e.0.into_bytes());
        if !method.starts_with(b"fhe_") {
            return Ok(Self::default());
        }
        let policy = Policy::scoped(state, circle, owner, caller, context.epoch, context.scope)
            .map_err(unavailable)?
            .receipt_linked(context.receipt_linked);
        let active = context
            .scope
            .and_then(|scope| scope.key.as_ref().zip(scope.pair.as_ref()))
            .filter(|_| {
                policy.key_live
                    && (policy.allows(FheCapability::Encrypt)
                        || policy.allows(FheCapability::Decrypt))
            });
        let mut caps = vec![];
        if policy.allows(FheCapability::LoadKey) && policy.allows(FheCapability::KeySerde) {
            caps.push("fhe_load_pk");
        }
        for (cap, name) in [
            (FheCapability::Encrypt, "fhe_encrypt"),
            (FheCapability::Decrypt, "fhe_decrypt"),
        ] {
            if active.is_some() && policy.allows(cap) && policy.allows(FheCapability::CipherSerde) {
                caps.push(name);
            }
        }
        let pairs =
            policy.allows(FheCapability::KeySerde) && policy.allows(FheCapability::CipherSerde);
        for (cap, name) in [
            (FheCapability::Arithmetic, "fhe_cipher_arithmetic"),
            (FheCapability::Commit, "fhe_commit"),
        ] {
            if pairs && policy.allows(cap) {
                caps.push(name);
            }
        }
        if policy.allows(FheCapability::Pedersen) {
            caps.push("fhe_pedersen");
        }
        for (cap, name) in [
            (FheCapability::VerifyZero, "fhe_verify_zero"),
            (FheCapability::VerifyRange, "fhe_verify_range"),
            (FheCapability::VerifyBound, "fhe_verify_bound"),
        ] {
            if pairs && policy.allows(cap) {
                caps.push(name);
            }
        }
        let mut sources = vec![];
        if policy.allows(FheCapability::LoadKey) && policy.allows(FheCapability::KeySerde) {
            let addresses = policy
                .relays
                .iter()
                .cloned()
                .chain(std::iter::once(owner.to_vec()))
                .chain(std::iter::once(caller.to_vec()))
                .chain(policy.allowlist.clone().unwrap_or_default());
            let mut seen = std::collections::BTreeSet::new();
            for address in addresses {
                if !seen.insert(address.clone()) || !policy.key(&address) {
                    continue;
                }
                if let Some(raw) = runtime.public_key(state, &address).map_err(unavailable)? {
                    sources.push((address, raw));
                }
            }
        }
        let invalid = || Error::Rejected(b"wasm key size invalid".to_vec());
        let mut effort = 0i64;
        let secret = active.map(|(_, pair)| pair.secret.to_bytes());
        if view || proof {
            if let Some((_, pair)) = active {
                let image = pair
                    .public
                    .image_size()
                    .map_err(|e| Error::Unavailable(e.to_string().into_bytes()))?;
                let write = work::key_effort(image, true).ok_or_else(invalid)?;
                let raw = secret.as_ref().expect("active key has encoded secret");
                let secret_cost = work::key_effort(raw.len() as u64, true).ok_or_else(invalid)?;
                effort = write
                    .checked_add(secret_cost)
                    .filter(|n| *n < (1i64 << 62))
                    .ok_or_else(invalid)?;
            }
            for (_, raw) in &sources {
                let read = work::key_read_effort(raw, true).ok_or_else(invalid)?;
                let write = work::key_effort(work::key_image(raw).ok_or_else(invalid)?, true)
                    .ok_or_else(invalid)?;
                effort = effort
                    .checked_add(read)
                    .and_then(|n| n.checked_add(write))
                    .filter(|n| *n < (1i64 << 62))
                    .ok_or_else(invalid)?;
            }
            if effort > limit {
                return Err(Error::Rejected(b"wasm key effort exceeds limit".to_vec()));
            }
        }
        let mut public = vec![];
        let active = match (active, secret) {
            (Some((id, pair)), Some(secret)) => {
                let raw = pair
                    .public
                    .to_bytes()
                    .map_err(|e| Error::Unavailable(e.to_string().into_bytes()))?;
                Some(Active {
                    id: id.clone(),
                    public: STANDARD.encode(raw).into_bytes(),
                    secret: zeroize::Zeroizing::new(STANDARD.encode(secret.as_slice())),
                })
            }
            _ => None,
        };
        for (address, raw) in sources {
            if let Some(memory) = memory {
                if !work::key_decode(&raw).is_some_and(|amount| memory.reserve(amount)) {
                    continue;
                }
            }
            let allowed = raw.len() <= 5_000_000
                && (raw.len() >= 6
                    && &raw[..4] == b"PVAC"
                    && (1..=5).contains(&raw[4])
                    && raw[5] == 1
                    || raw.len() >= 5 && raw[0] == 0xec);
            if !allowed {
                continue;
            }
            let key = match octra_hfhe::keys::PublicKey::from_bytes(&raw) {
                Ok(v) => v,
                Err(e) if e.is_operational() => {
                    return Err(Error::Unavailable(e.to_string().into_bytes()))
                }
                Err(_) => continue,
            };
            let raw = key
                .to_bytes()
                .map_err(|e| Error::Unavailable(e.to_string().into_bytes()))?;
            public.push((address, STANDARD.encode(raw).into_bytes()));
        }
        Ok(Self {
            caps,
            public,
            effort,
            active,
        })
    }
    pub(crate) fn public_json(
        &self,
    ) -> Result<serde_json::Value, octra_node_protocol::circle_wasm::Error> {
        self.public.iter().map(|(address,key)|Ok(serde_json::json!({"addr":std::str::from_utf8(address).map_err(|_|octra_node_protocol::circle_wasm::Error::Unavailable(b"HFHE address is not UTF-8".to_vec()))?,
            "pubkey_b64":std::str::from_utf8(key).expect("base64 is ASCII")}))).collect::<Result<Vec<_>,_>>().map(serde_json::Value::Array)
    }
    // Retain the fallible native host projection interface.
    #[allow(clippy::unnecessary_wraps)]
    pub(crate) fn active_json(
        &self,
    ) -> Result<serde_json::Value, octra_node_protocol::circle_wasm::Error> {
        let Some(active) = &self.active else {
            return Ok(serde_json::Value::Null);
        };
        let mut value = serde_json::json!({"pubkey_b64":std::str::from_utf8(&active.public).expect("base64 is ASCII"),"seckey_b64":active.secret.as_str()});
        if let Ok(id) = std::str::from_utf8(&active.id) {
            value["key_id"] = serde_json::json!(id);
        } else {
            value["key_id_b64"] = serde_json::json!(STANDARD.encode(&active.id));
        }
        Ok(value)
    }
    pub(crate) fn context_prefix(&self) -> Vec<u8> {
        use octra_node_protocol::transaction::json_string;
        let mut out = b"{\"caps\":[".to_vec();
        let caps = self
            .caps
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        for (i, cap) in caps.into_iter().enumerate() {
            if i > 0 {
                out.push(b',');
            }
            json_string(&mut out, cap.as_bytes());
        }
        out.extend(b"],\"pubkeys\":[");
        let mut keys = self.public.iter().collect::<Vec<_>>();
        keys.sort_by(|a, b| a.0.cmp(&b.0));
        for (i, (address, key)) in keys.into_iter().enumerate() {
            if i > 0 {
                out.push(b',');
            }
            out.extend(b"{\"addr\":");
            json_string(&mut out, address);
            out.extend(b",\"pubkey_b64\":");
            json_string(&mut out, key);
            out.push(b'}');
        }
        out.extend(b"],\"active_key\":");
        if let Some(active) = &self.active {
            out.extend(b"{\"key_id\":");
            json_string(&mut out, &active.id);
            out.extend(b",\"pubkey_b64\":");
            json_string(&mut out, &active.public);
            out.push(b'}');
        } else {
            out.extend(b"null");
        }
        out
    }
}
