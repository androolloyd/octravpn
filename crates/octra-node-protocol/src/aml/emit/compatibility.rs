// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Storage namespaces are compiler-version behavior, independent of surface
//! syntax. Historical Protocol emission must retain its original raw keys.
use super::{list_item_prefix, list_length_key, nonreentrant_key, option_presence_key, Emitter};
impl Emitter {
    pub(crate) fn list_length_key(&self, field: &[u8]) -> Vec<u8> {
        if self.is_protocol() {
            [field, b"_len"].concat()
        } else {
            list_length_key(field)
        }
    }
    pub(crate) fn list_item_prefix(&self, field: &[u8]) -> Vec<u8> {
        if self.is_protocol() {
            [field, b":"].concat()
        } else {
            list_item_prefix(field)
        }
    }
    pub(crate) fn option_presence_key(&self, field: &[u8]) -> Vec<u8> {
        if self.is_protocol() {
            [field, b"_some"].concat()
        } else {
            option_presence_key(field)
        }
    }
    pub(crate) fn nonreentrant_key(&self) -> Vec<u8> {
        if self.is_protocol() {
            b"_lock".to_vec()
        } else {
            nonreentrant_key()
        }
    }
    pub(crate) fn length_suffix(&self) -> &'static [u8] {
        if self.is_protocol() {
            b"_len"
        } else {
            b"/length"
        }
    }
}
