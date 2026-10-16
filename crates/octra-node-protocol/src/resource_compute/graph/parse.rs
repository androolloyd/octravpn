use super::{
    array, ascii_fits, digest_json, domains, lower_hex, object, read, refused, unavailable, view,
    Chunk, Document, Graph, Limits, Model, Result, Segment, Shard, Tensor, Value,
};
use crate::{native_integer::parse_int64, transaction::is_valid_address};
use std::collections::BTreeSet;

struct Json<'a> {
    doc: &'a Document,
    value: &'a Value,
}
impl<'a> Json<'a> {
    fn new(doc: &'a Document, value: &'a Value) -> Self {
        Self { doc, value }
    }
    fn fields(&self) -> Result<&'a [(Vec<u8>, usize)]> {
        match self.value {
            Value::Object(fields) => Ok(fields),
            _ => Err(refused(b"resource graph object required")),
        }
    }
    fn exact(&self, names: &[&[u8]], reason: &[u8]) -> Result<()> {
        let fields = self.fields()?;
        let mut keys = fields.iter().map(|(k, _)| k.as_slice()).collect::<Vec<_>>();
        let mut names = names.to_vec();
        keys.sort();
        names.sort();
        if keys == names {
            Ok(())
        } else {
            Err(refused(reason))
        }
    }
    fn field(&self, name: &[u8]) -> Result<Self> {
        self.doc
            .field(self.value, name)
            .map(|v| Self::new(self.doc, v))
            .ok_or_else(|| refused(&[b"resource graph field missing: ".as_slice(), name].concat()))
    }
    fn list(&self) -> Result<Vec<Self>> {
        let Value::List(ids) = self.value else {
            return Err(refused(b"resource graph list required"));
        };
        Ok(ids
            .iter()
            .map(|id| Self::new(self.doc, self.doc.get(*id).expect("JSON arena index")))
            .collect())
    }
    fn text(&self) -> Result<Vec<u8>> {
        match self.value {
            Value::String(raw) if raw.is_ascii() => Ok(raw.clone()),
            _ => Err(refused(b"resource graph ASCII string required")),
        }
    }
    fn int64(&self) -> Result<i64> {
        let value = match self.value {
            Value::Int(v) => Some(v.get()),
            Value::IntLiteral(raw) => parse_int64(raw),
            _ => None,
        };
        value.ok_or_else(|| refused(b"resource graph integer required"))
    }
    fn int(&self) -> Result<usize> {
        let value = self.int64()?;
        if (0..=(1_i64 << 62) - 1).contains(&value) {
            Ok(value as usize)
        } else {
            Err(refused(b"resource graph integer exceeds finite limits"))
        }
    }
    fn ints(&self) -> Result<Vec<usize>> {
        self.list()?.iter().map(Self::int).collect()
    }
    fn text_at(&self, name: &[u8]) -> Result<Vec<u8>> {
        self.field(name)?.text()
    }
    fn int_at(&self, name: &[u8]) -> Result<usize> {
        self.field(name)?.int()
    }
    fn int64_at(&self, name: &[u8]) -> Result<i64> {
        self.field(name)?.int64()
    }
    fn stable(&self) -> Result<Vec<u8>> {
        self.doc.write(self.value, true).map_err(unavailable)
    }
}
fn name(raw: &[u8]) -> bool {
    ascii_fits(raw, 96) && raw.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_')
}
// OCaml Filename.basename on Unix strips trailing slashes before selecting the
// final component. It does not normalize embedded dot components.
fn basename(raw: &[u8]) -> &[u8] {
    if raw.is_empty() {
        return b".";
    }
    if raw.iter().all(|b| *b == b'/') {
        return &raw[..1];
    }
    let end = raw.iter().rposition(|b| *b != b'/').map_or(1, |n| n + 1);
    let raw = &raw[..end.min(raw.len())];
    raw.rsplit(|b| *b == b'/').next().unwrap_or(raw)
}
// Keep the native owned-input interface and its diagnostic/arena ownership.
#[allow(clippy::needless_pass_by_value)]
fn segment(limits: &Limits, json: Json<'_>) -> Result<Segment> {
    json.exact(
        &[b"bytes", b"index", b"offset", b"path", b"sha256"],
        b"resource segment fields differ",
    )?;
    let index = json.int_at(b"index")?;
    let offset = json.int_at(b"offset")?;
    let bytes = json.int_at(b"bytes")?;
    let path = json.text_at(b"path")?;
    let sha256 = json.text_at(b"sha256")?;
    if bytes == 0 || bytes > limits.max_segment_bytes {
        return Err(refused(b"resource segment byte limit exceeded"));
    }
    if !ascii_fits(&path, 128)
        || path.len() <= 12
        || !path.starts_with(b"/model/data/")
        || matches!(basename(&path), b"." | b"..")
    {
        return Err(refused(b"resource segment path refused"));
    }
    if !lower_hex(&sha256) {
        return Err(refused(b"resource segment digest refused"));
    }
    Ok(Segment {
        index,
        offset,
        bytes,
        path,
        sha256,
    })
}
// Keep the native owned-input interface and its diagnostic/arena ownership.
#[allow(clippy::needless_pass_by_value)]
fn chunk(limits: &Limits, json: Json<'_>) -> Result<Chunk> {
    json.exact(
        &[
            b"bytes",
            b"index",
            b"sha256",
            b"shard",
            b"shard_offset",
            b"source",
            b"stream_offset",
            b"tensor",
            b"tensor_chunk",
        ],
        b"resource chunk fields differ",
    )?;
    let index = json.int_at(b"index")?;
    let bytes = json.int_at(b"bytes")?;
    let sha256 = json.text_at(b"sha256")?;
    let source = json.text_at(b"source")?;
    let stream_offset = json.int64_at(b"stream_offset")?;
    let tensor = json.text_at(b"tensor")?;
    let tensor_chunk = json.int_at(b"tensor_chunk")?;
    let shard = json.int_at(b"shard")?;
    let shard_offset = json.int_at(b"shard_offset")?;
    if bytes == 0 || bytes > limits.max_chunk_bytes {
        return Err(refused(b"resource chunk byte limit exceeded"));
    }
    if !lower_hex(&sha256) {
        return Err(refused(b"resource chunk digest refused"));
    }
    if !ascii_fits(&source, 256)
        || basename(&source) != source
        || matches!(source.as_slice(), b"." | b"..")
    {
        return Err(refused(b"resource chunk source refused"));
    }
    if stream_offset < 0 {
        return Err(refused(b"resource chunk stream offset refused"));
    }
    if !name(&tensor) {
        return Err(refused(b"resource tensor name refused"));
    }
    Ok(Chunk {
        index,
        bytes,
        sha256,
        source,
        stream_offset,
        tensor,
        tensor_chunk,
        shard,
        shard_offset,
    })
}
// Keep the native owned-input interface and its diagnostic/arena ownership.
#[allow(clippy::needless_pass_by_value)]
fn tensor(json: Json<'_>) -> Result<Tensor> {
    json.exact(
        &[b"chunks", b"name", b"scale_bits", b"shape", b"source_name"],
        b"resource tensor fields differ",
    )?;
    let name_raw = json.text_at(b"name")?;
    let source_name = json.text_at(b"source_name")?;
    let scale_bits = json.int64_at(b"scale_bits")?;
    let chunks = json.field(b"chunks")?.ints()?;
    let shape = json.field(b"shape")?.ints()?;
    if !name(&name_raw) || !ascii_fits(&source_name, 256) {
        return Err(refused(b"resource tensor identity refused"));
    }
    if chunks.is_empty() || shape.is_empty() || shape.contains(&0) {
        return Err(refused(b"resource tensor dimensions refused"));
    }
    Ok(Tensor {
        name: name_raw,
        source_name,
        scale_bits,
        shape,
        chunks,
    })
}
// Keep the native owned-input interface and its diagnostic/arena ownership.
#[allow(clippy::needless_pass_by_value)]
fn model(limits: &Limits, format: &[u8], json: Json<'_>) -> Result<Model> {
    let legacy = format == b"octra-smollm-resource-graph";
    let mut fields: Vec<&[u8]> = vec![
        b"chunks",
        b"config",
        b"id",
        b"raw_bytes",
        b"root",
        b"tensors",
    ];
    if !legacy {
        fields.push(b"root_domain");
    }
    json.exact(&fields, b"resource model fields differ")?;
    let id = json.text_at(b"id")?;
    let root_domain = if legacy {
        b"octra.smollm360.model.1".to_vec()
    } else {
        json.text_at(b"root_domain")?
    };
    let root = json.text_at(b"root")?;
    let raw_bytes = json.int64_at(b"raw_bytes")?;
    let chunks = json.int_at(b"chunks")?;
    let tensors = json
        .field(b"tensors")?
        .list()?
        .into_iter()
        .map(tensor)
        .collect::<Result<Vec<_>>>()?;
    if !ascii_fits(&id, 256) || !ascii_fits(&root_domain, 128) || !lower_hex(&root) {
        return Err(refused(b"resource model identity refused"));
    }
    if raw_bytes <= 0 || raw_bytes > limits.max_model_bytes {
        return Err(refused(b"resource model byte limit exceeded"));
    }
    if chunks == 0 || chunks > limits.max_chunks {
        return Err(refused(b"resource model chunk limit exceeded"));
    }
    if tensors.is_empty() || tensors.len() > limits.max_tensors {
        return Err(refused(b"resource model tensor limit exceeded"));
    }
    Ok(Model {
        id,
        root_domain,
        root,
        raw_bytes,
        chunks,
        tensors,
    })
}
// Keep the native owned-input interface and its diagnostic/arena ownership.
#[allow(clippy::needless_pass_by_value)]
fn shard(limits: &Limits, json: Json<'_>) -> Result<Shard> {
    json.exact(
        &[
            b"bytes",
            b"chunk_indices",
            b"circle_id",
            b"index",
            b"segments",
            b"sha256",
            b"stream_offset",
        ],
        b"resource shard fields differ",
    )?;
    let index = json.int_at(b"index")?;
    let circle_id = json.text_at(b"circle_id")?;
    let bytes = json.int_at(b"bytes")?;
    let sha256 = json.text_at(b"sha256")?;
    let stream_offset = json.int64_at(b"stream_offset")?;
    let chunk_indices = json.field(b"chunk_indices")?.ints()?;
    let segments = json
        .field(b"segments")?
        .list()?
        .into_iter()
        .map(|v| segment(limits, v))
        .collect::<Result<Vec<_>>>()?;
    if !is_valid_address(&circle_id) || !lower_hex(&sha256) {
        return Err(refused(b"resource shard identity refused"));
    }
    if bytes == 0 || bytes > limits.max_shard_bytes {
        return Err(refused(b"resource shard byte limit exceeded"));
    }
    if stream_offset < 0 || chunk_indices.is_empty() || segments.is_empty() {
        return Err(refused(b"resource shard layout refused"));
    }
    Ok(Shard {
        index,
        circle_id,
        bytes,
        sha256,
        stream_offset,
        chunk_indices,
        segments,
    })
}
fn unique<T: Ord>(values: impl IntoIterator<Item = T>) -> bool {
    let mut seen = BTreeSet::new();
    values.into_iter().all(|v| seen.insert(v))
}
impl Graph {
    pub fn parse(limits: &Limits, root_circle_id: &[u8], raw: &[u8]) -> Result<Self> {
        if raw.is_empty() || raw.len() > limits.max_graph_bytes {
            return Err(refused(b"resource graph byte limit exceeded"));
        }
        if !is_valid_address(root_circle_id) {
            return Err(refused(b"resource root circle refused"));
        }
        let doc = read(raw)?;
        let json = Json::new(&doc, doc.root());
        json.exact(
            &[
                b"chunks",
                b"format",
                b"graph_root",
                b"layout_root",
                b"model",
                b"root_circle_id",
                b"shards",
            ],
            b"resource graph fields differ",
        )?;
        let format = json.text_at(b"format")?;
        let graph_root = json.text_at(b"graph_root")?;
        let layout_root = json.text_at(b"layout_root")?;
        let graph_circle = json.text_at(b"root_circle_id")?;
        let model = model(limits, &format, json.field(b"model")?)?;
        let chunks = json
            .field(b"chunks")?
            .list()?
            .into_iter()
            .map(|v| chunk(limits, v))
            .collect::<Result<Vec<_>>>()?;
        let shards = json
            .field(b"shards")?
            .list()?
            .into_iter()
            .map(|v| shard(limits, v))
            .collect::<Result<Vec<_>>>()?;
        domains(&format)?;
        if graph_circle != root_circle_id {
            return Err(refused(b"resource root circle differs"));
        }
        if !lower_hex(&graph_root) || !lower_hex(&layout_root) {
            return Err(refused(b"resource graph digest refused"));
        }
        if chunks.is_empty() || chunks.len() > limits.max_chunks {
            return Err(refused(b"resource chunk count exceeded"));
        }
        if shards.is_empty() || shards.len() > limits.max_shards {
            return Err(refused(b"resource shard count exceeded"));
        }
        if chunks.iter().enumerate().any(|(i, v)| i != v.index) {
            return Err(refused(b"resource chunk indexes differ"));
        }
        if shards.iter().enumerate().any(|(i, v)| i != v.index) {
            return Err(refused(b"resource shard indexes differ"));
        }
        if !unique(shards.iter().map(|s| &s.circle_id)) {
            return Err(refused(b"resource shard circle ids repeat"));
        }
        if !unique(model.tensors.iter().map(|t| &t.name)) {
            return Err(refused(b"resource tensor names repeat"));
        }
        let graph = Self {
            format,
            root_circle_id: root_circle_id.to_vec(),
            graph_root,
            layout_root,
            model,
            chunks,
            shards,
        };
        graph.segment_layout(limits)?;
        graph.chunk_layout()?;
        graph.roots(&json)?;
        Ok(graph)
    }
    fn segment_layout(&self, limits: &Limits) -> Result<()> {
        if self.shards.iter().map(|s| s.segments.len()).sum::<usize>() > limits.max_segments {
            return Err(refused(b"resource segment count exceeded"));
        }
        for shard in &self.shards {
            let mut offset = 0_usize;
            let valid = shard.segments.iter().enumerate().all(|(i, s)| i == s.index)
                && unique(shard.segments.iter().map(|s| &s.path))
                && shard.segments.iter().all(|s| {
                    let equal = s.offset == offset;
                    offset = offset.wrapping_add(s.bytes);
                    equal
                })
                && offset == shard.bytes;
            if !valid {
                return Err(refused(b"resource segment layout differs"));
            }
        }
        Ok(())
    }
    fn chunk_layout(&self) -> Result<()> {
        if self.chunks.len() != self.model.chunks {
            return Err(refused(b"resource model chunk count differs"));
        }
        if self.chunks.iter().any(|c| c.index >= self.chunks.len()) {
            return Err(refused(b"resource chunk index refused"));
        }
        let mut offset = 0_i64;
        let valid = self.chunks.iter().all(|c| {
            let equal = c.stream_offset == offset;
            offset = offset.wrapping_add(c.bytes as i64);
            equal
        });
        let assigned = self
            .shards
            .iter()
            .flat_map(|s| s.chunk_indices.iter().copied())
            .collect::<Vec<_>>();
        let expected = (0..self.chunks.len()).collect::<Vec<_>>();
        let mut tensors = self
            .model
            .tensors
            .iter()
            .flat_map(|t| t.chunks.iter().copied())
            .collect::<Vec<_>>();
        if !valid || offset != self.model.raw_bytes {
            return Err(refused(b"resource chunk stream differs"));
        }
        if assigned != expected {
            return Err(refused(b"resource shard partition differs"));
        }
        tensors.sort_unstable();
        if tensors != expected || !unique(tensors) {
            return Err(refused(b"resource tensor partition differs"));
        }
        let tensors_valid = self.model.tensors.iter().all(|t| {
            t.chunks.iter().enumerate().all(|(i, index)| {
                let c = &self.chunks[*index];
                c.tensor == t.name && c.tensor_chunk == i
            })
        });
        let mut offset = 0_i64;
        let shards_valid = self.shards.iter().all(|s| {
            let mut local = 0_usize;
            let valid = s.stream_offset == offset
                && s.chunk_indices.iter().all(|index| {
                    let c = &self.chunks[*index];
                    let equal = c.shard == s.index && c.shard_offset == local;
                    local = local.wrapping_add(c.bytes);
                    equal
                })
                && local == s.bytes;
            offset = offset.wrapping_add(s.bytes as i64);
            valid
        });
        if !tensors_valid {
            return Err(refused(b"resource tensor chunks differ"));
        }
        if !shards_valid || offset != self.model.raw_bytes {
            return Err(refused(b"resource shard chunks differ"));
        }
        Ok(())
    }
    fn roots(&self, json: &Json<'_>) -> Result<()> {
        let [layout_domain, graph_domain, _] = domains(&self.format)?;
        let layout = object(vec![
            (b"chunks", json.field(b"chunks")?.stable()?),
            (b"format", json.field(b"format")?.stable()?),
            (b"model", json.field(b"model")?.stable()?),
            (
                b"shards",
                array(self.shards.iter().map(|s| view::shard_json(s, false))),
            ),
        ]);
        let body = object(
            json.fields()?
                .iter()
                .filter(|(k, _)| k != b"graph_root")
                .map(|(k, id)| {
                    Ok((
                        k.as_slice(),
                        json.doc
                            .write(json.doc.get(*id).expect("JSON arena index"), true)
                            .map_err(unavailable)?,
                    ))
                })
                .collect::<Result<Vec<_>>>()?,
        );
        if digest_json(layout_domain, &layout) != self.layout_root {
            return Err(refused(b"resource layout root differs"));
        }
        if digest_json(graph_domain, &body) != self.graph_root {
            return Err(refused(b"resource graph root differs"));
        }
        if view::model_root(&self.model, &self.chunks) != self.model.root {
            return Err(refused(b"resource model root differs"));
        }
        Ok(())
    }
}
