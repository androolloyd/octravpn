// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{Execute, Executed, Prepare, Prepared, SelfTest};
use crate::transaction::json_string;
use base64::{engine::general_purpose::STANDARD, Engine};
struct Object(Vec<u8>);
impl Object {
    fn new() -> Self {
        Self(vec![b'{'])
    }
    fn raw(&mut self, name: &[u8], raw: &[u8]) {
        if self.0.len() > 1 {
            self.0.push(b',');
        }
        json_string(&mut self.0, name);
        self.0.push(b':');
        self.0.extend_from_slice(raw);
    }
    fn text(&mut self, name: &[u8], raw: &[u8]) {
        let mut value = Vec::new();
        json_string(&mut value, raw);
        self.raw(name, &value);
    }
    fn int64(&mut self, name: &[u8], value: i64) {
        self.text(name, value.to_string().as_bytes());
    }
    fn int(&mut self, name: &[u8], value: i64) {
        self.raw(name, value.to_string().as_bytes());
    }
    fn finish(mut self) -> Vec<u8> {
        self.0.push(b'}');
        self.0
    }
}
impl Prepare {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Object::new();
        out.text(b"circle_id", &self.circle_id);
        out.text(b"executor_root", &self.executor_root);
        out.text(b"graph_root", &self.graph_root);
        out.int64(b"model_epoch", self.model_epoch);
        out.text(b"model_root", &self.model_root);
        out.text(b"model_state_root", &self.model_state_root);
        out.text(b"program_root", &self.program_root);
        out.finish()
    }
}
impl Execute {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Object::new();
        out.int(b"memory_bytes", self.memory_bytes);
        out.int(b"guest_bytes", self.guest_bytes);
        out.int(b"fuel_limit", self.fuel_limit);
        out.text(b"caller", &self.caller);
        out.text(b"circle_id", &self.circle_id);
        out.int64(b"epoch_id", self.epoch_id);
        out.text(b"executor_root", &self.executor_root);
        out.text(b"graph_root", &self.graph_root);
        out.int(b"max_output_bytes", self.max_output_bytes);
        out.text(b"method_name", &self.method_name);
        out.int64(b"model_epoch", self.model_epoch);
        out.text(b"model_root", &self.model_root);
        out.text(b"model_state_root", &self.model_state_root);
        out.text(b"params_json", &self.params_json);
        out.text(b"program_b64", &self.program_b64);
        out.text(b"program_root", &self.program_root);
        out.text(b"program_runtime", &self.program_runtime);
        out.text(b"request_id", &self.request_id);
        out.text(b"session_id", &self.session_id);
        out.text(b"state_root", &self.state_root);
        let mut entries = vec![b'['];
        for (index, (key, value)) in self.storage.iter().enumerate() {
            if index > 0 {
                entries.push(b',');
            }
            let mut entry = Object::new();
            entry.text(b"key", key);
            entry.text(b"value_b64", STANDARD.encode(value).as_bytes());
            entries.extend_from_slice(&entry.finish());
        }
        entries.push(b']');
        out.raw(b"storage", &entries);
        out.finish()
    }
}
impl SelfTest {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Object::new();
        out.text(b"evidence_root", &self.evidence_root);
        out.text(b"executor_root", &self.executor_root);
        out.text(b"profile", &self.profile);
        out.finish()
    }
}
impl Prepared {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Object::new();
        out.int64(b"bytes", self.bytes);
        out.text(b"cache_key", &self.cache_key);
        out.int(b"entries", self.entries);
        out.text(b"executor_root", &self.executor_root);
        out.text(b"graph_root", &self.graph_root);
        out.text(b"model_root", &self.model_root);
        out.text(b"program_root", &self.program_root);
        out.finish()
    }
}
impl Executed {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Object::new();
        out.int(b"effort_used", self.effort_used);
        out.int64(b"operations", self.operations);
        out.text(b"output_hash", &self.output_hash);
        out.text(b"output_json", &self.output_json);
        out.int64(b"steps", self.steps);
        out.text(b"trace_root", &self.trace_root);
        out.finish()
    }
}
