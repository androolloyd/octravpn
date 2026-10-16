use super::{refused, Call, Digest, Program, Result, Sha256};
use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::{resource_compute::graph::CachePlan, transaction::json_string};
const LIMIT: usize = 8_000_000;

fn quoted_size(value: &[u8]) -> usize {
    2 + value
        .iter()
        .map(|byte| match byte {
            b'"' | b'\\' | 8 | 12 | b'\n' | b'\r' | b'\t' => 2,
            0..=31 | 127 => 6,
            _ => 1,
        })
        .sum::<usize>()
}
struct Fields {
    bytes: Vec<u8>,
    limit: usize,
}
impl Fields {
    fn new(limit: usize) -> Self {
        Self {
            bytes: vec![b'{'],
            limit,
        }
    }
    fn field(&mut self, name: &[u8], value: &[u8], quoted: bool) -> Result<()> {
        let added = usize::from(self.bytes.len() > 1)
            + quoted_size(name)
            + 1
            + if quoted {
                quoted_size(value)
            } else {
                value.len()
            };
        if self.bytes.len() + added + 1 > self.limit {
            return Err(refused(b"compute replay input size"));
        }
        if self.bytes.len() > 1 {
            self.bytes.push(b',');
        }
        json_string(&mut self.bytes, name);
        self.bytes.push(b':');
        if quoted {
            json_string(&mut self.bytes, value);
        } else {
            self.bytes.extend_from_slice(value);
        }
        Ok(())
    }
    fn string(&mut self, name: &[u8], value: &[u8]) -> Result<()> {
        self.field(name, value, true)
    }
    fn raw(&mut self, name: &[u8], value: &[u8]) -> Result<()> {
        self.field(name, value, false)
    }
    fn number(&mut self, name: &[u8], value: i64) -> Result<()> {
        self.raw(name, value.to_string().as_bytes())
    }
    fn finish(mut self) -> Vec<u8> {
        self.bytes.push(b'}');
        self.bytes
    }
}
pub(super) fn encode(
    calls: &[&Call],
    steps: &[Vec<u8>],
    program: &Program<'_>,
    cache: &CachePlan,
    scope: &[u8],
) -> Result<Vec<u8>> {
    let mut total = 0_usize;
    let mut payloads = Vec::new();
    let code_key = hex::encode(Sha256::digest(program.code_b64));
    for (call, request_bytes) in calls.iter().zip(steps) {
        let request = &call.request;
        let limits = request.limits;
        let request_b64 = STANDARD.encode(request_bytes);
        let mut out = Fields::new(LIMIT - total);
        for (name, value) in [
            (b"action".as_slice(), b"execute".as_slice()),
            (b"code_b64", program.code_b64),
            (b"code_cache_key", code_key.as_bytes()),
            (b"export_name", b"octra_query"),
            (b"request_b64", request_b64.as_bytes()),
            (b"compute_storage_cache_key", &cache.key),
            (b"compute_storage_root", &cache.root),
        ] {
            out.string(name, value)?;
        }
        out.number(b"compute_storage_entries", cache.entries.len() as i64)?;
        out.number(b"compute_storage_bytes", cache.bytes)?;
        out.string(b"compute_session_scope", scope)?;
        out.raw(b"storage_pairs", b"null")?;
        out.string(b"caller", &request.caller)?;
        out.string(b"address", &request.circle_id)?;
        out.string(b"tx_hash", hex::encode(request.id()?).as_bytes())?;
        out.number(b"current_epoch", request.epoch_id)?;
        out.string(b"execution_profile", b"compute")?;
        out.raw(b"is_view", b"true")?;
        out.raw(b"hfhe_strict", b"true")?;
        for (name, value) in [
            (b"fuel_limit".as_slice(), limits.fuel_limit),
            (b"memory_bytes", limits.memory_bytes),
            (b"guest_bytes", limits.guest_bytes),
        ] {
            out.number(
                name,
                value.ok_or_else(|| refused(b"compute replay step refused"))?,
            )?;
        }
        let raw = out.finish();
        total += raw.len();
        payloads.push(raw);
    }
    let mut out = b"{\"action\":\"compute_replay\",\"execution_profile\":\"compute\",\"is_view\":true,\"replay_steps\":[".to_vec();
    for (index, raw) in payloads.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        json_string(&mut out, raw);
    }
    out.extend_from_slice(b"]}");
    Ok(out)
}
pub(super) fn single(
    request: &octra_node_protocol::resource_compute::provider::Execute,
    program: &crate::compute_provider::Program,
    model: &crate::compute_provider::owner::Model,
    bytes: &[u8],
    scope: &[u8],
    cached: bool,
) -> Result<Vec<u8>> {
    // The native host checks the actual serialized transport size. A warm
    // module may omit code even when a full cold transport would exceed it.
    let mut out = Fields::new(usize::MAX);
    out.number(b"guest_bytes", request.guest_bytes)?;
    out.number(b"memory_bytes", request.memory_bytes)?;
    out.string(b"action", b"execute")?;
    out.raw(b"float_mode", b"false")?;
    out.string(
        b"code_cache_key",
        hex::encode(Sha256::digest(&program.code_b64)).as_bytes(),
    )?;
    if cached {
        out.raw(b"code_b64", b"null")?;
    } else {
        out.string(b"code_b64", &program.code_b64)?;
    }
    out.string(b"export_name", b"octra_query")?;
    out.string(b"request_b64", STANDARD.encode(bytes).as_bytes())?;
    out.raw(b"storage_cache_key", b"null")?;
    out.raw(b"storage_pairs", b"null")?;
    out.string(b"caller", &request.caller)?;
    out.string(b"address", &request.circle_id)?;
    out.string(b"tx_hash", &request.request_id)?;
    out.number(b"current_epoch", request.epoch_id)?;
    out.raw(b"hfhe_caps", b"[]")?;
    out.raw(b"hfhe_pubkeys", b"[]")?;
    out.raw(b"hfhe_active_key", b"null")?;
    out.raw(b"hfhe_strict", b"true")?;
    out.raw(b"math", b"false")?;
    out.string(b"hfhe_receipt_mode", b"direct")?;
    out.raw(b"hfhe_receipt_entries", b"[]")?;
    out.raw(b"public_reads", b"[]")?;
    out.number(b"fuel_limit", request.fuel_limit)?;
    out.string(b"compute_storage_cache_key", &model.cache_key)?;
    out.string(b"compute_session_scope", scope)?;
    out.string(b"execution_profile", b"compute")?;
    out.raw(b"is_view", b"true")?;
    out.raw(b"update_policy", b"false")?;
    Ok(out.finish())
}
