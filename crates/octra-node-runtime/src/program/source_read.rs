// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Bounded source-scope verification. Request cancellation leaves ownership of
//! active work with the reader until completion, and never caches host failure.
use octra_node_protocol::{
    program_record::{self, Record},
    transaction::decode_base64,
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
    time::Duration,
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Checked,
    Different,
    Pending,
    Failed,
}
#[derive(Default)]
struct State {
    generation: u64,
    active: BTreeSet<Vec<u8>>,
    cache: Vec<(Vec<u8>, Outcome)>,
    closed: bool,
}
#[derive(Clone, Default)]
pub struct Reader(Arc<Mutex<State>>);
impl Reader {
    pub fn close(&self) {
        if let Ok(mut state) = self.0.lock() {
            state.closed = true;
            state.generation = state.generation.wrapping_add(1);
            state.cache.clear();
        }
    }
    pub async fn query(&self, stored: Option<Vec<u8>>, record: Record) -> Outcome {
        let mut hash = Sha256::new();
        hash.update(program_record::consensus_id());
        hash.update(record.encode());
        hash.update(stored.as_deref().unwrap_or_default());
        let key = hash.finalize().to_vec();
        let generation = {
            let Ok(mut state) = self.0.lock() else {
                return Outcome::Failed;
            };
            if state.closed {
                return Outcome::Pending;
            }
            if let Some(index) = state.cache.iter().position(|(saved, _)| *saved == key) {
                let item = state.cache.remove(index);
                let result = item.1;
                state.cache.insert(0, item);
                return result;
            }
            if state.active.contains(&key) || state.active.len() >= 2 {
                return Outcome::Pending;
            }
            state.active.insert(key.clone());
            state.generation
        };
        let reader = self.clone();
        let job = tokio::spawn(async move {
            let outcome = tokio::task::spawn_blocking(move || {
                std::thread::Builder::new()
                    .name("octra-source-read".into())
                    .stack_size(16 * 1024 * 1024)
                    .spawn(move || {
                        octra_node_protocol::aml::parser::with_recursion_limit(128, || {
                            check(stored.as_deref(), &record)
                        })
                    })
                    .ok()
                    .and_then(|thread| thread.join().ok())
                    .unwrap_or(Outcome::Failed)
            })
            .await
            .unwrap_or(Outcome::Failed);
            let Ok(mut state) = reader.0.lock() else {
                return Outcome::Failed;
            };
            if generation != state.generation || !state.active.remove(&key) {
                return Outcome::Pending;
            }
            if matches!(outcome, Outcome::Checked | Outcome::Different) {
                state.cache.retain(|(saved, _)| *saved != key);
                state.cache.insert(0, (key, outcome));
                state.cache.truncate(128);
            }
            outcome
        });
        tokio::time::timeout(Duration::from_secs(2), job)
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or(Outcome::Pending)
    }
}
fn check(stored: Option<&[u8]>, record: &Record) -> Outcome {
    let Some(code) = stored.and_then(|raw| decode_base64(raw).ok()) else {
        return Outcome::Failed;
    };
    if hex::encode(Sha256::digest(&code)).as_bytes() != record.code_hash {
        return Outcome::Failed;
    }
    match program_record::source::record_scope(&code, record) {
        Ok(()) => Outcome::Checked,
        Err(program_record::source::Error::Invalid(reason))
            if reason == b"program source scope differs" =>
        {
            Outcome::Different
        }
        _ => Outcome::Failed,
    }
}
