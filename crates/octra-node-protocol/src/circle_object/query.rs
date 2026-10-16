// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native object discovery and detail queries over one loaded storage table.
use crate::{
    circle_records::{Kind, Record},
    circle_state::Descriptor,
    circle_storage::StorageTable,
    circles::{self, Error},
    network::endpoint::native_trim,
};
use std::collections::BTreeSet;

pub struct Summary {
    pub object: Vec<u8>,
    pub binding: Record,
    pub policy: Option<Record>,
    pub members: Vec<Vec<u8>>,
}
impl Summary {
    pub fn materialized(&self) -> bool {
        self.binding.materialized() || self.policy.is_some() || !self.members.is_empty()
    }
}
pub struct Member {
    pub reference: Vec<u8>,
    pub state: Record,
    pub descriptor: Option<Descriptor>,
}
pub struct Detail {
    pub summary: Summary,
    pub current_descriptor: Option<Descriptor>,
    pub last_transition: Option<Record>,
}
pub fn validate_member_ref(raw: &[u8]) -> Result<Vec<u8>, Error> {
    let value = native_trim(raw);
    if value.is_empty() {
        Err(Error(b"member_ref must not be empty".to_vec()))
    } else if value.contains(&b':') {
        Err(Error(b"member_ref must not contain ':'".to_vec()))
    } else {
        Ok(value.to_vec())
    }
}
pub struct Query<'a> {
    storage: &'a StorageTable,
}
impl<'a> Query<'a> {
    pub fn new(storage: &'a StorageTable) -> Self {
        Self { storage }
    }
    fn record(&self, kind: Kind, subject: &[u8]) -> Record {
        kind.from_stored(|name| {
            self.storage
                .get(&[kind.prefix(), b":", subject, b":", name].concat())
                .cloned()
        })
    }
    pub fn references(&self) -> Vec<Vec<u8>> {
        self.storage
            .values()
            .keys()
            .filter_map(|key| {
                let fields = key.split(|byte| *byte == b':').collect::<Vec<_>>();
                match fields.as_slice() {
                    [prefix, object, _]
                        if matches!(*prefix, b"object_binding" | b"object_policy") =>
                    {
                        circles::normalize_state_ref(object).ok()
                    }
                    [prefix, object, _, _] if *prefix == b"object_member" => {
                        circles::normalize_state_ref(object).ok()
                    }
                    _ => None,
                }
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
    pub fn member_refs(&self, object: &[u8]) -> Vec<Vec<u8>> {
        // RPC queries sort extracted references. The VM's indexed scan sorts
        // full keys, which can differ when one member name prefixes another.
        let mut members = super::members(self.storage, object);
        members.sort();
        members.dedup();
        members
    }
    pub fn summary(&self, object: &[u8]) -> Summary {
        let binding = self.record(Kind::ObjectBinding, object);
        let policy = self.record(Kind::ObjectPolicy, object);
        Summary {
            object: object.to_vec(),
            binding,
            policy: policy.materialized().then_some(policy),
            members: self.member_refs(object),
        }
    }
    pub fn summaries(&self) -> Vec<Summary> {
        self.references()
            .iter()
            .map(|object| self.summary(object))
            .filter(Summary::materialized)
            .collect()
    }
    fn descriptor(&self, state: Option<&[u8]>) -> Option<Descriptor> {
        let locator = circles::state_locator(state?).ok()?;
        let descriptor = Descriptor::from_stored(|name| {
            self.storage
                .get(
                    &[
                        b"state_descriptor:".as_slice(),
                        locator.path_key.as_bytes(),
                        b":",
                        name,
                    ]
                    .concat(),
                )
                .cloned()
        });
        (descriptor != Descriptor::default()).then_some(descriptor)
    }
    pub fn member(&self, object: &[u8], reference: &[u8]) -> Member {
        let state = self.record(Kind::ObjectMember, &[object, b":", reference].concat());
        let descriptor = self.descriptor(state.get(b"state_ref"));
        Member {
            reference: reference.to_vec(),
            state,
            descriptor,
        }
    }
    pub fn members(&self, object: &[u8]) -> Vec<Member> {
        self.member_refs(object)
            .into_iter()
            .filter_map(|reference| {
                let state = self.record(Kind::ObjectMember, &[object, b":", &reference].concat());
                state.materialized().then_some(Member {
                    reference,
                    state,
                    descriptor: None,
                })
            })
            .collect()
    }
    pub fn detail(&self, object: &[u8]) -> Detail {
        let summary = self.summary(object);
        let current_descriptor = self.descriptor(summary.binding.get(b"current_state_ref"));
        let last_transition = summary
            .binding
            .get(b"last_transition_ref")
            .and_then(|reference| {
                let record = self.record(Kind::ObjectTransition, reference);
                record.materialized().then_some(record)
            });
        Detail {
            summary,
            current_descriptor,
            last_transition,
        }
    }
}
