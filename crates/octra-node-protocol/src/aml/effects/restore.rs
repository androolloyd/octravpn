// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Aml_evidence.restore declaration reconstruction. Definition conflicts are
//! resolved before the ordered binding checks, as in the adopted implementation.
use super::core;
use super::{target_kind, Atom, BTreeMap, BTreeSet, Entry, Error, HostType, Registry, Target};
pub(crate) enum RestoreError {
    Registry,
    Effect(Error),
}
impl Registry {
    pub(crate) fn restore(entries: &[(Atom, Entry)]) -> std::result::Result<Self, RestoreError> {
        let mut state: BTreeMap<&[u8], HostType> = BTreeMap::new();
        let mut events: BTreeMap<&[u8], &[HostType]> = BTreeMap::new();
        let mut faults: BTreeMap<&[u8], (i64, &[u8])> = BTreeMap::new();
        for (_, entry) in entries {
            let same = match entry {
                Entry::State(name, typ) => {
                    state.insert(name, *typ).is_none_or(|prior| prior == *typ)
                }
                Entry::Event(name, types) => events
                    .insert(name, types)
                    .is_none_or(|prior| prior == types.as_slice()),
                Entry::Fault(name, code, message) => faults
                    .insert(name, (*code, message.as_slice()))
                    .is_none_or(|prior| prior == (*code, message.as_slice())),
            };
            if !same {
                return Err(RestoreError::Registry);
            }
        }
        let maximum = core::rule::LOCAL.get(core::rule::Field::TermNodes) as usize;
        if entries.len() > maximum {
            return Err(RestoreError::Effect(Error::BindLimit(entries.len())));
        }
        let mut seen = BTreeSet::new();
        for (atom, entry) in entries {
            if !seen.insert(*atom) {
                return Err(RestoreError::Effect(Error::AtomRepeated(*atom)));
            }
            let target = match entry {
                Entry::State(name, _) => Target::State(name.clone()),
                Entry::Event(name, _) => Target::Event(name.clone()),
                Entry::Fault(name, ..) => Target::Fault(name.clone()),
            };
            if !target_kind(*atom, &target) {
                return Err(RestoreError::Effect(Error::TargetKind(*atom, target)));
            }
            if let Entry::Event(_, types) = entry {
                if types.len() > 64 {
                    return Err(RestoreError::Effect(Error::HostLimit(*atom, types.len())));
                }
            }
        }
        Ok(Self {
            entries: entries.to_vec(),
        })
    }
}
