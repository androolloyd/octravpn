// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Small trusted-output builder: native JSON string bytes never pass through
//! a UTF-8 conversion. Raw fields must already be native encoded JSON.
use octra_node_protocol::transaction::json_string;
pub(super) struct Object(Vec<u8>);
impl Object {
    pub(super) fn new() -> Self {
        Self(vec![b'{'])
    }
    fn key(&mut self, name: &[u8]) {
        if self.0.len() > 1 {
            self.0.push(b',');
        }
        json_string(&mut self.0, name);
        self.0.push(b':');
    }
    pub(super) fn string(&mut self, name: &[u8], value: &[u8]) -> &mut Self {
        self.key(name);
        json_string(&mut self.0, value);
        self
    }
    pub(super) fn raw(&mut self, name: &[u8], value: &[u8]) -> &mut Self {
        self.key(name);
        self.0.extend_from_slice(value);
        self
    }
    pub(super) fn boolean(&mut self, name: &[u8], value: bool) -> &mut Self {
        self.raw(name, if value { b"true" } else { b"false" })
    }
    pub(super) fn optional(&mut self, name: &[u8], value: Option<&[u8]>) -> &mut Self {
        match value {
            Some(value) => self.string(name, value),
            None => self.raw(name, b"null"),
        }
    }
    pub(super) fn epoch(&mut self, name: &[u8], value: Option<i64>) -> &mut Self {
        match value {
            Some(value) => self.string(name, value.to_string().as_bytes()),
            None => self.raw(name, b"null"),
        }
    }
    pub(super) fn finish(mut self) -> Vec<u8> {
        self.0.push(b'}');
        self.0
    }
}
