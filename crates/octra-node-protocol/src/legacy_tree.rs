// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native legacy Node/Tree diagnostics. These digests are separate from BFT
//! proposal, transaction-index and ledger commitments.
use crate::{
    native_exception,
    native_json::{Document, Value},
    transaction::{general_float, json_string, native_float, Nonce, Transaction},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("legacy tree parent digest unavailable")]
    ParentUnavailable,
    #[error("legacy tree JSON refusal: {0:?}")]
    Refused(Vec<u8>),
    #[error("legacy tree native exception: {0:?}")]
    Exception(Vec<u8>),
    #[error(transparent)]
    Json(#[from] crate::native_json::Error),
    #[error(transparent)]
    Encoding(#[from] crate::transaction::Error),
}
type Result<T> = std::result::Result<T, Error>;
fn refused(reason: impl AsRef<[u8]>) -> Error {
    Error::Refused(reason.as_ref().to_vec())
}
fn failure(reason: impl AsRef<[u8]>) -> Error {
    Error::Exception(native_exception::string_argument(
        b"Failure",
        reason.as_ref(),
    ))
}
fn missing() -> Error {
    Error::Exception(b"Not_found".to_vec())
}
fn required<'a>(doc: &'a Document, value: &'a Value, key: &[u8]) -> Result<&'a Value> {
    doc.field(value, key).ok_or_else(missing)
}
fn text(doc: &Document, value: &Value, key: &[u8]) -> Result<Vec<u8>> {
    match required(doc, value, key)? {
        Value::String(value) => Ok(value.clone()),
        _ => Err(refused([b"Expected string for ".as_slice(), key].concat())),
    }
}
fn strings(doc: &Document, value: &Value, key: &[u8]) -> Result<Vec<Vec<u8>>> {
    let Value::List(values) = required(doc, value, key)? else {
        return Err(refused([b"Expected list for ".as_slice(), key].concat()));
    };
    values
        .iter()
        .map(|id| match doc.get(*id) {
            Some(Value::String(value)) => Ok(value.clone()),
            _ => Err(refused(
                [b"Expected string list for ".as_slice(), key].concat(),
            )),
        })
        .collect()
}
fn floating(doc: &Document, value: &Value, key: &[u8]) -> Result<f64> {
    match required(doc, value, key)? {
        Value::Float(value) => Ok(*value),
        _ => Err(refused([b"Expected float for ".as_slice(), key].concat())),
    }
}
fn quoted(value: impl AsRef<[u8]>) -> Vec<u8> {
    let mut raw = Vec::new();
    json_string(&mut raw, value.as_ref());
    raw
}
fn object(fields: &[(&[u8], Vec<u8>)]) -> Vec<u8> {
    let mut raw = vec![b'{'];
    for (index, (key, value)) in fields.iter().enumerate() {
        if index != 0 {
            raw.push(b',');
        }
        json_string(&mut raw, key);
        raw.push(b':');
        raw.extend(value);
    }
    raw.push(b'}');
    raw
}
fn array(values: impl IntoIterator<Item = Vec<u8>>) -> Vec<u8> {
    let mut raw = vec![b'['];
    for (index, value) in values.into_iter().enumerate() {
        if index != 0 {
            raw.push(b',');
        }
        raw.extend(value);
    }
    raw.push(b']');
    raw
}
// Keep the native owned-input interface and its diagnostic/arena ownership.
#[allow(clippy::needless_pass_by_value)]
fn number(value: impl ToString) -> Vec<u8> {
    value.to_string().into_bytes()
}
fn float(value: f64) -> Result<Vec<u8>> {
    Ok(if value.is_nan() {
        b"NaN".to_vec()
    } else if value == f64::INFINITY {
        b"Infinity".to_vec()
    } else if value == f64::NEG_INFINITY {
        b"-Infinity".to_vec()
    } else {
        native_float(value)?.into_bytes()
    })
}
fn optional(value: Option<&[u8]>) -> Vec<u8> {
    value.map_or_else(|| b"null".to_vec(), quoted)
}
fn wrap(value: i64) -> i64 {
    value.wrapping_shl(1) >> 1
}
// Match the native integer-to-float projection and rounding exactly.
#[allow(clippy::cast_precision_loss)]
fn default_time(epoch: Nonce) -> f64 {
    wrap(epoch.get().wrapping_mul(10)) as f64
}
/// OCaml 4.14 Stdlib.string_of_float uses %.12g and valid_float_lexem.
pub fn string_of_float(value: f64) -> Vec<u8> {
    let mut raw = if value.is_nan() {
        if value.is_sign_negative() {
            "-nan".into()
        } else {
            "nan".into()
        }
    } else if value.is_infinite() {
        if value.is_sign_negative() {
            "-inf".into()
        } else {
            "inf".into()
        }
    } else {
        general_float(value, 12)
    };
    if raw
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'-')
    {
        raw.push('.');
    }
    raw.into_bytes()
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Metrics {
    pub ths: f64,
    pub npt: f64,
    pub svb: f64,
    pub sp: f64,
    pub cps: f64,
}
impl Metrics {
    pub const EPOCH: Self = Self {
        ths: 1.,
        npt: 1.,
        svb: 1.,
        sp: 1.,
        cps: 1.,
    };
    // Preserve native multiply/add order: FMA changes the hashed float bytes.
    #[allow(clippy::suboptimal_flops)]
    pub fn score(&self) -> f64 {
        0.3 * self.ths + 0.2 * self.npt + 0.2 * self.svb + 0.15 * self.sp + 0.15 * self.cps
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        Ok(object(&[
            (b"ths", float(self.ths)?),
            (b"npt", float(self.npt)?),
            (b"svb", float(self.svb)?),
            (b"sp", float(self.sp)?),
            (b"cps", float(self.cps)?),
        ]))
    }
    pub fn from_value(doc: &Document, value: &Value) -> Result<Self> {
        if !matches!(value, Value::Object(_)) {
            return Err(refused(b"Expected JSON object for metrics"));
        }
        for key in [b"ths".as_slice(), b"npt", b"svb", b"sp", b"cps"] {
            required(doc, value, key)?;
        }
        let fields =
            [b"ths".as_slice(), b"npt", b"svb", b"sp", b"cps"].map(|key| floating(doc, value, key));
        let [Ok(ths), Ok(npt), Ok(svb), Ok(sp), Ok(cps)] = fields else {
            return Err(refused(b"Invalid metrics JSON"));
        };
        Ok(Self {
            ths,
            npt,
            svb,
            sp,
            cps,
        })
    }
}
#[derive(Clone, Debug, PartialEq)]
pub struct Node {
    pub id: Vec<u8>,
    pub parent: Option<Vec<u8>>,
    pub children: Vec<Vec<u8>>,
    pub state_hash: Vec<u8>,
    pub txs: Vec<Vec<u8>>,
    pub tx_hashes: Vec<(Vec<u8>, Vec<u8>)>,
    pub validator: Vec<u8>,
    pub metrics: Metrics,
    pub timestamp: f64,
    pub signature: Vec<u8>,
}
impl Node {
    pub fn hash(&self) -> Vec<u8> {
        hex::encode(Sha256::digest(
            [
                self.id.as_slice(),
                self.state_hash.as_slice(),
                self.validator.as_slice(),
                &string_of_float(self.timestamp),
            ]
            .concat(),
        ))
        .into_bytes()
    }
    fn fields(&self) -> Result<Vec<(&'static [u8], Vec<u8>)>> {
        Ok(vec![
            (b"id", quoted(&self.id)),
            (b"parent", optional(self.parent.as_deref())),
            (b"children", array(self.children.iter().map(quoted))),
            (b"state_hash", quoted(&self.state_hash)),
            (b"txs", array(self.txs.iter().map(quoted))),
            (
                b"txs_with_hashes",
                array(self.tx_hashes.iter().map(|(hash, data)| {
                    object(&[(b"hash", quoted(hash)), (b"data", quoted(data))])
                })),
            ),
            (b"validator", quoted(&self.validator)),
            (b"metrics", self.metrics.encode()?),
            (b"timestamp", float(self.timestamp)?),
        ])
    }
    pub fn signing_payload(&self) -> Result<Vec<u8>> {
        Ok(object(&self.fields()?))
    }
    pub fn sign(&self, private_base64: &[u8]) -> Result<Vec<u8>> {
        let message = self.signing_payload()?;
        let mut decoded = crate::native_base64::decode(private_base64).map_err(|error| {
            Error::Exception(native_exception::string_argument(
                b"Invalid_argument",
                error.to_string().as_bytes(),
            ))
        })?;
        let Ok(mut seed) = <[u8; 32]>::try_from(decoded.as_slice()) else {
            decoded.fill(0);
            return Err(failure(b"Invalid private key"));
        };
        let key = SigningKey::from_bytes(&seed);
        seed.fill(0);
        decoded.fill(0);
        Ok(STANDARD.encode(key.sign(&message).to_bytes()).into_bytes())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut fields = self.fields()?;
        fields.push((b"signature", quoted(&self.signature)));
        Ok(object(&fields))
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        let doc = Document::parse(raw)?;
        Self::from_value(&doc, doc.root())
    }
    pub fn from_value(doc: &Document, value: &Value) -> Result<Self> {
        if !matches!(value, Value::Object(_)) {
            return Err(refused(b"Expected JSON object for node"));
        }
        for key in [
            b"id".as_slice(),
            b"parent",
            b"children",
            b"state_hash",
            b"txs",
            b"validator",
            b"metrics",
            b"timestamp",
            b"signature",
        ] {
            required(doc, value, key)?;
        }
        let metrics = Metrics::from_value(doc, required(doc, value, b"metrics")?);
        let metrics = match metrics {
            Err(error @ Error::Exception(_)) => return Err(error),
            value => value,
        };
        let id = text(doc, value, b"id")?;
        let parent = match required(doc, value, b"parent")? {
            Value::String(value) => Some(value.clone()),
            Value::Null => None,
            _ => return Err(refused(b"Expected string or null for parent")),
        };
        let children = strings(doc, value, b"children")?;
        let state_hash = text(doc, value, b"state_hash")?;
        let txs = strings(doc, value, b"txs")?;
        let validator = text(doc, value, b"validator")?;
        let metrics = metrics?;
        let timestamp = floating(doc, value, b"timestamp")?;
        let signature = text(doc, value, b"signature")?;
        let mut tx_hashes = Vec::new();
        match doc.field(value, b"txs_with_hashes") {
            None => (),
            Some(Value::List(values)) => {
                for id in values {
                    let Some(Value::Object(_)) = doc.get(*id) else {
                        return Err(refused(b"Expected object in txs_with_hashes list"));
                    };
                    let item = doc.get(*id).expect("native JSON member");
                    match (doc.field(item, b"hash"), doc.field(item, b"data")) {
                        (Some(Value::String(hash)), Some(Value::String(data))) => {
                            tx_hashes.push((hash.clone(), data.clone()));
                        }
                        _ => return Err(refused(b"Invalid tx_with_hash structure")),
                    }
                }
            }
            Some(_) => return Err(refused(b"Expected list for txs_with_hashes")),
        }
        Ok(Self {
            id,
            parent,
            children,
            state_hash,
            txs,
            tx_hashes,
            validator,
            metrics,
            timestamp,
            signature,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Performance {
    pub node_id: Vec<u8>,
    pub solved_tasks: Nonce,
    pub avg_time: f64,
    pub reliability: f64,
}
impl Performance {
    pub fn encode(&self) -> Result<Vec<u8>> {
        Ok(object(&[
            (b"node_id", quoted(&self.node_id)),
            (b"solved_tasks", number(self.solved_tasks.get())),
            (b"avg_time", float(self.avg_time)?),
            (b"reliability", float(self.reliability)?),
        ]))
    }
    pub fn from_value(doc: &Document, value: &Value) -> Result<Self> {
        if !matches!(value, Value::Object(_)) {
            return Err(refused(b"Expected JSON object for performance"));
        }
        for key in [
            b"node_id".as_slice(),
            b"solved_tasks",
            b"avg_time",
            b"reliability",
        ] {
            required(doc, value, key)?;
        }
        match (
            text(doc, value, b"node_id"),
            required(doc, value, b"solved_tasks")?,
            floating(doc, value, b"avg_time"),
            floating(doc, value, b"reliability"),
        ) {
            (Ok(node_id), Value::Int(solved_tasks), Ok(avg_time), Ok(reliability)) => Ok(Self {
                node_id,
                solved_tasks: *solved_tasks,
                avg_time,
                reliability,
            }),
            _ => Err(refused(b"Invalid performance JSON")),
        }
    }
}
/// Finalize shares its native mutable node table with the original tree record.
/// Root lists and other record fields remain local to each returned record.
#[derive(Clone, Debug)]
pub struct Tree {
    pub epoch_id: Nonce,
    pub parent_commit: Option<Vec<u8>>,
    nodes: Arc<RwLock<BTreeMap<Vec<u8>, Node>>>,
    pub roots: Vec<Vec<u8>>,
    root_count: Nonce,
    pub finalized_by: Vec<u8>,
    pub performance_summary: Vec<Performance>,
    pub commit_signatures: Vec<(Vec<u8>, Vec<u8>)>,
    pub finalized_at: f64,
    pub recent_tx_count: Nonce,
}
impl Tree {
    pub fn create(epoch_id: Nonce, parent_commit: Vec<u8>) -> Self {
        Self {
            epoch_id,
            parent_commit: Some(parent_commit),
            nodes: Arc::default(),
            roots: Vec::new(),
            root_count: Nonce::default(),
            finalized_by: Vec::new(),
            performance_summary: Vec::new(),
            commit_signatures: Vec::new(),
            finalized_at: default_time(epoch_id),
            recent_tx_count: Nonce::default(),
        }
    }
    /// Observe the native node table/root count even when an older local
    /// archive did not retain its legacy parent digest. Encoding remains closed.
    pub fn unbound(epoch_id: Nonce) -> Self {
        let mut tree = Self::create(epoch_id, Vec::new());
        tree.parent_commit = None;
        tree
    }
    pub fn add_node(&mut self, node: Node) -> Result<bool> {
        if node.metrics.score() < 0.55 {
            return Ok(false);
        }
        let id = node.hash();
        let parent = node.parent.clone();
        let mut nodes = self
            .nodes
            .write()
            .map_err(|_| failure(b"legacy node table unavailable"))?;
        nodes.insert(id.clone(), node);
        match parent {
            None => {
                self.roots.insert(0, id);
                self.root_count = self.root_count.successor();
            }
            Some(parent) => {
                if let Some(node) = nodes.get_mut(&parent) {
                    node.children.insert(0, id);
                }
            }
        }
        Ok(true)
    }
    pub fn add_commit_signature(&mut self, address: Vec<u8>, signature: Vec<u8>) {
        if !self
            .commit_signatures
            .iter()
            .any(|(saved, _)| saved == &address)
        {
            self.commit_signatures.insert(0, (address, signature));
        }
    }
    pub fn finalized(
        &self,
        validator: Vec<u8>,
        performance: Vec<Performance>,
        at: Option<f64>,
    ) -> Result<Self> {
        let mut result = self.clone();
        result.finalized_by = validator;
        result.performance_summary = performance;
        result
            .commit_signatures
            .sort_by(|left, right| left.0.cmp(&right.0));
        result.finalized_at = at.unwrap_or_else(|| default_time(self.epoch_id));
        let nodes = self
            .nodes
            .read()
            .map_err(|_| failure(b"legacy node table unavailable"))?;
        result.recent_tx_count = Nonce::new(nodes.values().fold(0_i64, |count, node| {
            wrap(count.wrapping_add(node.txs.len() as i64))
        }))?;
        Ok(result)
    }
    pub fn root_count(&self) -> Nonce {
        self.root_count
    }
    pub fn nodes(&self) -> Result<BTreeMap<Vec<u8>, Node>> {
        Ok(self
            .nodes
            .read()
            .map_err(|_| failure(b"legacy node table unavailable"))?
            .clone())
    }
    pub fn get_node(&self, id: &[u8]) -> Result<Option<Node>> {
        Ok(self
            .nodes
            .read()
            .map_err(|_| failure(b"legacy node table unavailable"))?
            .get(id)
            .cloned())
    }
    /// Native Map iteration order is unspecified; wire serialization sorts keys.
    pub fn node_ids(&self) -> Result<Vec<Vec<u8>>> {
        Ok(self
            .nodes
            .read()
            .map_err(|_| failure(b"legacy node table unavailable"))?
            .keys()
            .cloned()
            .collect())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        let parent = self
            .parent_commit
            .as_deref()
            .ok_or(Error::ParentUnavailable)?;
        let nodes = self
            .nodes
            .read()
            .map_err(|_| failure(b"legacy node table unavailable"))?;
        let nodes = nodes
            .iter()
            .map(|(id, node)| Ok((id.clone(), node.encode()?)))
            .collect::<Result<Vec<_>>>()?;
        let fields = nodes
            .iter()
            .map(|(key, value)| (key.as_slice(), value.clone()))
            .collect::<Vec<_>>();
        Ok(object(&[
            (b"epoch_id", number(self.epoch_id.get())),
            (b"parent_commit", quoted(parent)),
            (b"roots", array(self.roots.iter().map(quoted))),
            (b"finalized_by", quoted(&self.finalized_by)),
            (
                b"commit_signatures",
                array(
                    self.commit_signatures
                        .iter()
                        .map(|(address, signature)| array([quoted(address), quoted(signature)])),
                ),
            ),
            (
                b"performance_summary",
                array(
                    self.performance_summary
                        .iter()
                        .map(Performance::encode)
                        .collect::<Result<Vec<_>>>()?,
                ),
            ),
            (b"nodes", object(&fields)),
            (b"finalized_at", float(self.finalized_at)?),
            (b"recent_tx_count", number(self.recent_tx_count.get())),
        ]))
    }
    pub fn hash(&self) -> Result<Vec<u8>> {
        Ok(hex::encode(Sha256::digest(self.encode()?)).into_bytes())
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        let doc = Document::parse(raw)?;
        Self::from_value(&doc, doc.root())
    }
    pub fn from_value(doc: &Document, value: &Value) -> Result<Self> {
        if !matches!(value, Value::Object(_)) {
            return Err(refused(b"Expected JSON object for tree"));
        }
        for key in [
            b"epoch_id".as_slice(),
            b"parent_commit",
            b"roots",
            b"finalized_by",
            b"commit_signatures",
            b"performance_summary",
            b"nodes",
            b"finalized_at",
            b"recent_tx_count",
        ] {
            required(doc, value, key)?;
        }
        let int = |key: &[u8]| match required(doc, value, key)? {
            Value::Int(value) => Ok(*value),
            _ => Err(failure([b"Invalid int field: ".as_slice(), key].concat())),
        };
        let string = |key: &[u8]| match required(doc, value, key)? {
            Value::String(value) => Ok(value.clone()),
            _ => Err(failure(
                [b"Invalid string field: ".as_slice(), key].concat(),
            )),
        };
        let epoch_id = int(b"epoch_id")?;
        let parent_commit = string(b"parent_commit")?;
        let mut result = Self::create(epoch_id, parent_commit);
        result.finalized_by = string(b"finalized_by")?;
        result.recent_tx_count = int(b"recent_tx_count")?;
        result.finalized_at = match required(doc, value, b"finalized_at")? {
            Value::Float(value) => *value,
            _ => 0.,
        };
        if let Value::List(values) = required(doc, value, b"roots")? {
            for id in values {
                match doc.get(*id) {
                    Some(Value::String(value)) => result.roots.push(value.clone()),
                    _ => return Err(failure(b"Invalid string list")),
                }
            }
        }
        result.root_count = Nonce::new(wrap(result.roots.len() as i64))?;
        if let Value::List(values) = required(doc, value, b"commit_signatures")? {
            for id in values {
                let Some(Value::List(pair)) = doc.get(*id) else {
                    return Err(failure(b"Invalid commit sig"));
                };
                if pair.len() != 2 {
                    return Err(failure(b"Invalid commit sig"));
                }
                match (doc.get(pair[0]), doc.get(pair[1])) {
                    (Some(Value::String(address)), Some(Value::String(signature))) => result
                        .commit_signatures
                        .push((address.clone(), signature.clone())),
                    _ => return Err(failure(b"Invalid commit sig")),
                }
            }
        }
        if let Value::List(values) = required(doc, value, b"performance_summary")? {
            for id in values {
                let performance = Performance::from_value(doc, doc.get(*id).ok_or_else(missing)?);
                match performance {
                    Ok(value) => result.performance_summary.push(value),
                    Err(error @ Error::Exception(_)) => return Err(error),
                    Err(_) => return Err(failure(b"Invalid performance")),
                }
            }
        }
        if let Value::Object(values) = required(doc, value, b"nodes")? {
            let mut nodes = result
                .nodes
                .write()
                .map_err(|_| failure(b"legacy node table unavailable"))?;
            for (id, value) in values {
                match Node::from_value(doc, doc.get(*value).ok_or_else(missing)?) {
                    Ok(node) => {
                        nodes.insert(id.clone(), node);
                    }
                    Err(Error::Refused(_)) => (),
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(result)
    }
    /// Consensus_epoch_apply_tree's observational epoch-node/finalize step.
    /// The caller supplies Ledger.hash exactly as the native application does.
    pub fn finalize_epoch(
        &mut self,
        epoch: Nonce,
        proposer: &[u8],
        state_hash: Vec<u8>,
        timestamp: f64,
        confirmed: &[Transaction],
    ) -> Result<Vec<u8>> {
        let txs = confirmed
            .iter()
            .map(Transaction::to_json_bytes)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let tx_hashes = confirmed
            .iter()
            .zip(&txs)
            .map(|(tx, json)| Ok((hex::encode(tx.hash()?).into_bytes(), json.clone())))
            .collect::<Result<Vec<_>>>()?;
        let id = hex::encode(Sha256::digest(
            [
                b"epoch:".as_slice(),
                epoch.get().to_string().as_bytes(),
                b":",
                proposer,
            ]
            .concat(),
        ))
        .into_bytes();
        self.add_node(Node {
            id,
            parent: self.roots.first().cloned(),
            children: Vec::new(),
            state_hash,
            txs,
            tx_hashes,
            validator: proposer.to_vec(),
            metrics: Metrics::EPOCH,
            timestamp,
            signature: Vec::new(),
        })?;
        let performance = Performance {
            node_id: proposer.to_vec(),
            solved_tasks: Nonce::new(wrap(confirmed.len() as i64))?,
            avg_time: 0.,
            reliability: 1.,
        };
        self.finalized(proposer.to_vec(), vec![performance], Some(timestamp))?
            .hash()
    }
}
