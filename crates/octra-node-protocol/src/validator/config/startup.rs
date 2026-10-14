// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{Config, Transition};
use crate::validator::policy::Policy;
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Membership {
    Active,
    Scheduled,
    Observer(Vec<u8>),
    Refused(Vec<u8>),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Quorum {
    Safe,
    Unsafe(Vec<u8>),
    Refused(Vec<Vec<u8>>),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Info(Vec<u8>),
    Warn(Vec<u8>),
    Refuse(Vec<Vec<u8>>),
}
pub struct Admission<'a> {
    pub address: &'a [u8],
    pub voting: bool,
    pub role: &'a [u8],
    pub permissionless: bool,
    pub allow_unsafe: bool,
    pub activate: Option<i64>,
}
impl Config {
    pub fn membership(
        &self,
        address: &[u8],
        voting: bool,
        role: &[u8],
        permissionless: bool,
    ) -> Membership {
        if self.active_members.iter().any(|v| v.address == address) {
            Membership::Active
        } else if self.next.iter().any(|v| v.address == address) {
            Membership::Scheduled
        } else if voting && permissionless {
            Membership::Observer(
                b"validator follows finality until selected by the bonded validator lifecycle"
                    .to_vec(),
            )
        } else if voting {
            Membership::Refused(
                b"event = startup_refused reason = validator_membership_missing".to_vec(),
            )
        } else {
            Membership::Observer(
                [
                    b"wallet is not in active or scheduled validator set; role = ".as_slice(),
                    role,
                    b" follows finality without voting",
                ]
                .concat(),
            )
        }
    }
    pub fn scheduled_warning(&self, address: &[u8], voting: bool) -> Option<Vec<u8>> {
        (voting && !self.active_members.iter().any(|v|v.address==address) && self.next.iter().any(|v|v.address==address)).then(||b"wallet is not in active validator set yet; running catchup/non-voting until scheduled activation".to_vec())
    }
    pub fn quorum(&self, allow_unsafe: bool) -> Quorum {
        let v = &self.active;
        if v.n >= 4 {
            Quorum::Safe
        } else if allow_unsafe {
            Quorum::Unsafe(format!("event = unsafe_quorum n = {} env = OCTRA_ALLOW_UNSAFE_QUORUM value = 1 production = false",v.n).into_bytes())
        } else {
            Quorum::Refused(vec![
            format!("event = startup_refused reason = validator_count n = {} f = {} quorum = {} minimum = 4",v.n,v.f,v.quorum).into_bytes(),
            b"safety = false production = false".to_vec(),b"env = OCTRA_CONSENSUS_MODE local_action = unset".to_vec(),b"env = OCTRA_ALLOW_UNSAFE_QUORUM test_value = 1 production = false".to_vec(),
        ])
        }
    }
    pub fn admission(&self, input: &Admission<'_>) -> Vec<Event> {
        let refuse = |s: &[u8]| vec![Event::Refuse(vec![s.to_vec()])];
        if !self.identity_errors.is_empty() {
            return vec![Event::Refuse(self.identity_errors.clone())];
        }
        if self.allowed_pubkeys.is_empty() {
            return refuse(b"event = startup_refused reason = validator_pubkeys_missing env = OCTRA_VALIDATORS");
        }
        if self.current.is_empty() {
            return refuse(
                b"event = startup_refused reason = validator_peers_missing env = OCTRA_VALIDATORS",
            );
        }
        if !self.next.is_empty() && input.activate.is_none() {
            return refuse(b"event = startup_refused reason = validator_activation_missing env = OCTRA_VALIDATORS_ACTIVATE_EPOCH");
        }
        let mut events = match self.membership(
            input.address,
            input.voting,
            input.role,
            input.permissionless,
        ) {
            Membership::Active | Membership::Scheduled => vec![],
            Membership::Observer(m) => vec![Event::Info(m)],
            Membership::Refused(m) => return vec![Event::Refuse(vec![m])],
        };
        if let Some(m) = self.scheduled_warning(input.address, input.voting) {
            events.push(Event::Warn(m));
        }
        match self.quorum(input.allow_unsafe) {
            Quorum::Safe => (),
            Quorum::Unsafe(m) => events.push(Event::Warn(m)),
            Quorum::Refused(m) => events.push(Event::Refuse(m)),
        }
        events
    }
    /// Boot reads environment/config once; replay must not consult changing env.
    pub fn node_admission(
        &self,
        mut input: Admission<'_>,
        policy_value: Option<&[u8]>,
        unsafe_value: Option<&[u8]>,
    ) -> Vec<Event> {
        let policy = match Policy::from_value(policy_value) {
            Ok(p) => p,
            Err(e) => return vec![Event::Refuse(vec![e.to_string().into_bytes()])],
        };
        input.activate = match self.transition {
            Transition::None => input.activate,
            Transition::Active(e) | Transition::Scheduled { epoch: e, .. } => Some(e),
        };
        input.permissionless = policy.lifecycle_enabled();
        input.allow_unsafe = unsafe_value == Some(b"1");
        self.admission(&input)
    }
}
