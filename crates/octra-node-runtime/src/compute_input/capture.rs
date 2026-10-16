use super::{
    refused, unavailable, BigInt, Digest, Error, Request, Result, Root, Sha256, StateBatch,
};
use crate::circle_store;
use octra_node_protocol::{
    native_json,
    resource_compute::{
        bill,
        graph::{self, Graph, Limits},
    },
    transaction::decode_base64,
};
const MAX_BYTES: usize = bill::MODEL_LIMIT as usize;
fn stored(error: octra_node_protocol::circles::Error) -> Error {
    if error.0 == native_json::Error::Allocation.to_string().as_bytes() {
        unavailable(error)
    } else {
        refused(&error.0)
    }
}

struct Capture<'a> {
    bytes: usize,
    entries: usize,
    max_fee: &'a BigInt,
}
impl Capture<'_> {
    fn fee(&self) -> BigInt {
        BigInt::from(10_000 + self.bytes.div_ceil(16) + 32 * self.entries)
    }
    fn copy(&mut self, tree: &mut StateBatch, source: &Root, path: &[&[u8]]) -> Result<()> {
        let value = source
            .tree
            .get(path)
            .ok_or_else(|| refused(b"compute input value absent"))?;
        if value.len() > 2 * MAX_BYTES - self.bytes || self.entries >= 8192 {
            return Err(refused(b"compute input size exceeds limit"));
        }
        self.bytes += value.len();
        self.entries += 1;
        if self.fee() > *self.max_fee {
            return Err(refused(b"compute input fee exceeds budget"));
        }
        tree.set(path, value.to_vec()).map_err(unavailable)
    }
    fn program(&mut self, source: &Root, request: &Request) -> Result<StateBatch> {
        let program =
            circle_store::public_program(&source.tree, &request.circle_id).map_err(stored)?;
        if program.runtime != b"wasm_v1"
            || program.privacy_class != b"public"
            || program.resource_mode != b"public_resources"
            || program.code_hash != hex::encode(&request.program_root).as_bytes()
            || program.code_b64.len() > MAX_BYTES
        {
            return Err(refused(b"compute input program differs"));
        }
        let code = decode_base64(program.code_b64)
            .map_err(|_| refused(b"compute input program encoding"))?;
        if hex::encode(Sha256::digest(code)).as_bytes() != program.code_hash {
            return Err(refused(b"compute input program digest differs"));
        }
        let paths: [&[&[u8]]; 5] = [
            &[b"runtime"],
            &[b"code_hash"],
            &[b"privacy", b"class"],
            &[b"resources", b"mode"],
            &[b"program", b"code_b64"],
        ];
        let paths = paths
            .into_iter()
            .map(|suffix| {
                let mut path = vec![b"circles".as_slice(), &request.circle_id];
                path.extend_from_slice(suffix);
                path
            })
            .collect::<Vec<_>>();
        let mut tree = StateBatch::default();
        tree.begin().map_err(unavailable)?;
        for path in paths {
            self.copy(&mut tree, source, &path)?;
        }
        Ok(tree)
    }
    fn asset(
        &mut self,
        tree: &mut StateBatch,
        source: &Root,
        circle: &[u8],
        raw_path: &[u8],
        limit: usize,
    ) -> Result<Vec<u8>> {
        let asset =
            circle_store::public_asset(&source.tree, circle, raw_path, limit).map_err(stored)?;
        let meta = &asset.meta;
        let root: [&[u8]; 2] = [b"circles", circle];
        let base: [&[u8]; 5] = [b"circles", circle, b"assets", b"by_hash", &asset.path_key];
        if asset.browser_mode != b"gateway_allowed"
            || asset.resource_mode != b"public_resources"
            || meta.encoding != b"identity"
        {
            return Err(refused(b"compute input asset mode differs"));
        }
        for suffix in [
            &[b"browser".as_slice(), b"mode"][..],
            &[b"resources".as_slice(), b"mode"][..],
        ] {
            let mut path = root.to_vec();
            path.extend_from_slice(suffix);
            self.copy(tree, source, &path)?;
        }
        for suffix in [b"meta".as_slice(), b"body_b64"] {
            let mut path = base.to_vec();
            path.push(suffix);
            self.copy(tree, source, &path)?;
        }
        let body =
            decode_base64(asset.body_b64).map_err(|_| refused(b"compute input asset encoding"))?;
        if body.len() as i64 != meta.size_bytes
            || hex::encode(Sha256::digest(&body)).as_bytes() != meta.blob_hash
        {
            return Err(refused(b"compute input asset digest differs"));
        }
        Ok(body)
    }
}
pub(super) fn capture(
    mut call: Root,
    mut model: Root,
    request: &Request,
    max_fee: &BigInt,
) -> Result<(Root, Root, BigInt)> {
    let mut capture = Capture {
        bytes: 0,
        entries: 0,
        max_fee,
    };
    let call_tree = capture.program(&call, request);
    if let Err(error) = &call_tree {
        if error.is_operational() {
            return Err(error.clone());
        }
    }
    // Upstream evaluates both program captures before selecting an ordinary
    // refusal. The second capture shares the same byte, entry and fee counters.
    let model_tree = capture.program(&model, request);
    if let Err(error) = &model_tree {
        if error.is_operational() {
            return Err(error.clone());
        }
    }
    let call_tree = call_tree?;
    let mut model_tree = model_tree?;
    let limits = Limits {
        max_model_bytes: bill::MODEL_LIMIT / 2,
        max_cache_bytes: bill::MODEL_LIMIT / 2,
        ..Limits::default()
    };
    let raw = capture.asset(
        &mut model_tree,
        &model,
        &request.circle_id,
        b"/model/resource-graph.json",
        limits.max_graph_bytes,
    )?;
    let graph = Graph::parse(&limits, &request.circle_id, &raw)?;
    if graph.graph_root() != hex::encode(&request.graph_root).as_bytes()
        || graph.model().root != hex::encode(&request.model_root).as_bytes()
    {
        return Err(refused(b"compute input graph differs"));
    }
    for shard in graph.shards() {
        let raw = capture.asset(
            &mut model_tree,
            &model,
            &shard.circle_id,
            b"/model/shard.json",
            limits.max_graph_bytes,
        )?;
        let expected = graph.shard_manifest(shard.index)?;
        let matches = match graph::stable_json(&raw) {
            Ok(stable) => stable == expected,
            Err(error) if error.is_operational() => return Err(error),
            Err(_) => false,
        };
        if !matches {
            return Err(refused(b"compute input shard differs"));
        }
        for segment in &shard.segments {
            let body = capture.asset(
                &mut model_tree,
                &model,
                &shard.circle_id,
                &segment.path,
                limits.max_segment_bytes,
            )?;
            if body.len() != segment.bytes
                || hex::encode(Sha256::digest(body)).as_bytes() != segment.sha256
            {
                return Err(refused(b"compute input segment differs"));
            }
        }
    }
    call.tree = call_tree.snapshot();
    model.tree = model_tree.snapshot();
    Ok((call, model, capture.fee()))
}
