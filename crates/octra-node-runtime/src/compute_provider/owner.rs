// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Adopted in-memory model owner transitions. Tokens bind operations to a
//! generation; durable job history provides the separate restart boundary.
use octra_node_protocol::resource_compute::{
    graph::cache_key,
    provider::{Execute, Prepare, Prepared},
    Error, Result,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Model {
    pub snapshots: Vec<(i64, Vec<u8>)>,
    pub circle_id: Vec<u8>,
    pub graph_root: Vec<u8>,
    pub model_root: Vec<u8>,
    pub program_root: Vec<u8>,
    pub executor_root: Vec<u8>,
    pub cache_key: Vec<u8>,
    pub cache_root: Vec<u8>,
    pub entries: i64,
    pub bytes: i64,
}
impl Model {
    fn content(&self, request: &Prepare) -> bool {
        self.circle_id == request.circle_id
            && self.graph_root == request.graph_root
            && self.model_root == request.model_root
            && self.program_root == request.program_root
            && self.executor_root == request.executor_root
    }
    pub fn prepared(&self, request: &Prepare) -> bool {
        self.content(request)
            && self.snapshots.iter().any(|(epoch, root)| {
                *epoch == request.model_epoch && *root == request.model_state_root
            })
    }
    pub fn executable(&self, request: &Execute) -> bool {
        self.snapshots
            .iter()
            .any(|(epoch, root)| *epoch == request.model_epoch && *root == request.model_state_root)
            && self.circle_id == request.circle_id
            && self.graph_root == request.graph_root
            && self.model_root == request.model_root
            && self.program_root == request.program_root
            && self.executor_root == request.executor_root
    }
    pub fn response(&self) -> Prepared {
        Prepared {
            cache_key: self.cache_key.clone(),
            graph_root: self.graph_root.clone(),
            model_root: self.model_root.clone(),
            program_root: self.program_root.clone(),
            executor_root: self.executor_root.clone(),
            entries: self.entries,
            bytes: self.bytes,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token {
    id: Vec<u8>,
    generation: i64,
    key: Vec<u8>,
}
impl Token {
    pub fn id(&self) -> &[u8] {
        &self.id
    }
    pub fn generation(&self) -> i64 {
        self.generation
    }
    pub fn key(&self) -> &[u8] {
        &self.key
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    pub token: Token,
    pub request: Prepare,
    pub victim: Option<Model>,
    pub shared: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
// Keep native owned command/result records inline without changing their API.
#[allow(clippy::large_enum_variant)]
pub enum Preparation {
    Ready(Model),
    Build(Plan),
}
#[derive(Clone, Debug)]
pub struct State {
    models: Vec<Model>,
    leases: Vec<Token>,
    loading: Option<Plan>,
    next: i64,
    limit: i64,
    closed: bool,
    seen: Vec<Vec<u8>>,
}
fn refused(reason: &[u8]) -> Error {
    Error::rejected(reason)
}
fn digest(raw: &[u8]) -> Vec<u8> {
    hex::encode(Sha256::digest(raw)).into_bytes()
}
impl State {
    pub fn new(limit: i64) -> Self {
        Self {
            models: vec![],
            leases: vec![],
            loading: None,
            next: 0,
            limit,
            closed: false,
            seen: vec![],
        }
    }
    pub fn models(&self) -> &[Model] {
        &self.models
    }
    pub fn closed(&self) -> bool {
        self.closed
    }
    pub fn drained(&self) -> bool {
        self.closed && self.loading.is_none() && self.leases.is_empty()
    }
    fn loading(&self, token: &Token) -> Option<&Plan> {
        self.loading.as_ref().filter(|plan| plan.token == *token)
    }
    fn leased(&self, key: &[u8]) -> bool {
        self.leases.iter().any(|token| token.key == key)
    }
    fn retiring(&self, key: &[u8]) -> bool {
        self.loading
            .as_ref()
            .and_then(|plan| plan.victim.as_ref())
            .is_some_and(|model| model.cache_key == key)
    }
    fn touch(&mut self, key: &[u8]) {
        let (mut selected, rest): (Vec<_>, Vec<_>) = std::mem::take(&mut self.models)
            .into_iter()
            .partition(|model| model.cache_key == key);
        selected.extend(rest);
        self.models = selected;
    }
    fn admitting(&self) -> Result<()> {
        if self.closed {
            Err(refused(b"resource compute provider stopped"))
        } else if self.next == i64::MAX {
            Err(refused(b"resource compute generation exhausted"))
        } else {
            Ok(())
        }
    }
    pub fn reserve(&mut self, request: &Prepare) -> Result<Preparation> {
        self.admitting()?;
        if let Some(model) = self
            .models
            .iter()
            .find(|model| model.prepared(request))
            .cloned()
        {
            if self.retiring(&model.cache_key) {
                return Err(refused(b"resource compute provider busy"));
            }
            self.touch(&model.cache_key);
            return Ok(Preparation::Ready(model));
        }
        if self.loading.is_some() {
            return Err(refused(b"resource compute provider busy"));
        }
        let key = cache_key(&request.circle_id, &request.graph_root);
        let shared = self.models.iter().any(|model| model.cache_key == key);
        let keys = self
            .models
            .iter()
            .map(|model| &model.cache_key)
            .collect::<BTreeSet<_>>()
            .len();
        let victim = if shared || keys < 2 {
            None
        } else {
            self.models
                .iter()
                .rev()
                .find(|model| !self.leased(&model.cache_key))
                .cloned()
        };
        if !shared && keys >= 2 && victim.is_none() {
            return Err(refused(b"resource compute provider busy"));
        }
        let token = Token {
            id: digest(&request.encode()),
            generation: self.next,
            key,
        };
        let plan = Plan {
            token,
            request: request.clone(),
            victim,
            shared,
        };
        self.loading = Some(plan.clone());
        self.next += 1;
        Ok(Preparation::Build(plan))
    }
    pub fn acquire(&mut self, request: &Execute) -> Result<(Token, Model)> {
        self.admitting()?;
        let model = self
            .models
            .iter()
            .find(|model| model.executable(request))
            .cloned()
            .ok_or_else(|| refused(b"resource compute model not prepared"))?;
        let id = digest(
            &[
                request.request_id.as_slice(),
                request.epoch_id.to_string().as_bytes(),
                &request.state_root,
                request.model_epoch.to_string().as_bytes(),
                &request.model_state_root,
            ]
            .join(&0),
        );
        if self.seen.contains(&id) {
            return Err(refused(b"resource compute execution repeated"));
        }
        if self.retiring(&model.cache_key)
            || self.leases.len() as i64 >= self.limit
            || self.leases.iter().any(|token| token.id == id)
        {
            return Err(refused(b"resource compute provider busy"));
        }
        let token = Token {
            id,
            generation: self.next,
            key: model.cache_key.clone(),
        };
        self.touch(&model.cache_key);
        self.leases.insert(0, token.clone());
        self.next += 1;
        Ok((token, model))
    }
    pub fn remember(&mut self, token: &Token, model: Model) -> Result<()> {
        let plan = self
            .loading(token)
            .ok_or_else(|| refused(b"resource compute preparation changed"))?;
        if self.closed {
            return Err(refused(b"resource compute provider stopped"));
        }
        if model.cache_key != token.key
            || !model.prepared(&plan.request)
            || model.entries < 0
            || model.bytes < 0
            || model.cache_root.len() != 64
            || !model
                .cache_root
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        {
            return Err(refused(b"resource compute loaded model differs"));
        }
        if self
            .models
            .iter()
            .find(|item| item.cache_key == model.cache_key)
            .is_some_and(|item| {
                item.circle_id != model.circle_id
                    || item.graph_root != model.graph_root
                    || item.model_root != model.model_root
                    || item.entries != model.entries
                    || item.bytes != model.bytes
                    || item.cache_root != model.cache_root
            })
        {
            return Err(refused(b"resource compute cache identity differs"));
        }
        let same_binding = |item: &Model| {
            item.cache_key == model.cache_key
                && item.program_root == model.program_root
                && item.executor_root == model.executor_root
        };
        let mut snapshots = model.snapshots.clone();
        if let Some(old) = self.models.iter().find(|item| same_binding(item)) {
            snapshots.extend(
                old.snapshots
                    .iter()
                    .filter(|snapshot| !model.snapshots.contains(snapshot))
                    .cloned(),
            );
        }
        snapshots.truncate(64);
        let (mut aliases, rest): (Vec<_>, Vec<_>) = self
            .models
            .iter()
            .filter(|item| !same_binding(item))
            .cloned()
            .partition(|item| item.cache_key == model.cache_key);
        aliases.truncate(63);
        let mut model = model;
        model.snapshots = snapshots;
        self.models = std::iter::once(model).chain(aliases).chain(rest).collect();
        Ok(())
    }
    pub fn dropped(&mut self, token: &Token) -> bool {
        let victim = self
            .loading(token)
            .and_then(|plan| plan.victim.as_ref())
            .cloned();
        if let Some(model) = victim.filter(|model| !self.leased(&model.cache_key)) {
            self.models.retain(|item| item.cache_key != model.cache_key);
            true
        } else {
            false
        }
    }
    pub fn check(&self, token: &Token) -> Result<()> {
        if self.closed {
            Err(refused(b"resource compute provider stopped"))
        } else if self.loading(token).is_some() || self.leases.contains(token) {
            Ok(())
        } else {
            Err(refused(b"resource compute operation changed"))
        }
    }
    pub fn finish(&mut self, token: &Token) {
        if self.loading(token).is_some() {
            self.loading = None;
        }
    }
    pub fn forget(&mut self, token: &Token) {
        if self.leases.contains(token) {
            self.models.retain(|model| model.cache_key != token.key);
        }
    }
    pub fn lost(&mut self, model: &Model) {
        if !self.leased(&model.cache_key) {
            self.models.retain(|item| {
                item.cache_key != model.cache_key || item.cache_root != model.cache_root
            });
        }
    }
    pub fn release(&mut self, token: &Token, spent: bool) {
        if self.leases.contains(token) {
            if spent {
                self.seen.retain(|id| *id != token.id);
                self.seen.insert(0, token.id.clone());
                self.seen.truncate(128);
            }
            self.leases.retain(|prior| prior != token);
        }
    }
    pub fn close(&mut self) {
        self.closed = true;
    }
}
