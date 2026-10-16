// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Bounded signed result recovery. Retained reply context selects the saved
//! validator set; a malformed saved context cannot fall back to current keys.
use super::{Jobs, RequestBook, RequestState, View, MAX_READ_MESSAGES, MAX_REQUESTS};
use crate::{
    compute_history::{History, Saved},
    compute_record::verify_node,
};
use octra_node_protocol::{
    consensus::{hash::validator_set_hash, ValidatorSet},
    resource_compute::{
        call::{Call, CALL_TTL},
        message::{self, Fetch, Output},
        record,
        wire::Message,
        Error, Result,
    },
};
use std::{borrow::Cow, collections::BTreeMap};
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FetchAction {
    Refused,
    Accepted { answer: Option<Output> },
}

pub fn on_fetch(
    requests: &RequestBook,
    history: &History,
    view: &View<'_>,
    budget: &mut ReadBudget,
    node: &[u8],
    fetch: &Fetch,
) -> Result<FetchAction> {
    if !window(view, fetch)? {
        return Ok(FetchAction::Refused);
    }
    let Ok(saved) = saved_reply(history, &fetch.call) else {
        return Ok(FetchAction::Refused);
    };
    let Some(validators) = reply_validators(requests, view.validators, node, fetch, saved.as_ref())
    else {
        return Ok(FetchAction::Refused);
    };
    if !valid_fetch(view, &validators, fetch)? || !budget.take(view, fetch, false) {
        return Ok(FetchAction::Refused);
    }
    if let Some(saved) = saved.filter(|_| fetch.target == node) {
        let Ok(Message::Result(result)) = Message::decode(&saved.reply) else {
            return Ok(FetchAction::Refused);
        };
        if !valid_answer(&validators, fetch, &result)? {
            return Ok(FetchAction::Refused);
        }
        Ok(FetchAction::Accepted {
            answer: Some(result),
        })
    } else {
        Ok(FetchAction::Accepted { answer: None })
    }
}
pub fn on_answer(
    requests: &mut RequestBook,
    history: &History,
    view: &View<'_>,
    budget: &mut ReadBudget,
    node: &[u8],
    fetch: &Fetch,
    result: Output,
) -> Result<bool> {
    if !window(view, fetch)? {
        return Ok(false);
    }
    let Ok(saved) = saved_reply(history, &fetch.call) else {
        return Ok(false);
    };
    let Some(validators) = reply_validators(requests, view.validators, node, fetch, saved.as_ref())
    else {
        return Ok(false);
    };
    if !valid_fetch(view, &validators, fetch)?
        || !valid_answer(&validators, fetch, &result)?
        || !budget.take(view, fetch, true)
    {
        return Ok(false);
    }
    drop(validators);
    let request = &fetch.call.request;
    match history.cancelled(&request.caller, &request.session_id) {
        Ok(false) => {}
        _ => return Ok(false),
    }
    if fetch.call.coordinator != node {
        return Ok(true);
    }
    match requests.get_mut(&request.id()?) {
        Some(state) if state.call() == &fetch.call => {
            state.record_result(node, Some(history), result)
        }
        _ => Ok(false),
    }
}
pub fn saved_reply(history: &History, call: &Call) -> Result<Option<Saved>> {
    let request = &call.request;
    if history
        .cancelled(&request.caller, &request.session_id)
        .map_err(|error| Error::Unavailable(error.0))?
    {
        return Err(Error::rejected(b"compute session cancelled"));
    }
    history
        .saved(
            &request.caller,
            &request.session_id,
            request.sequence,
            &request.id()?,
        )
        .map_err(|error| Error::Unavailable(error.0))
}
pub fn reply_validators<'a>(
    requests: &'a RequestBook,
    current: &'a ValidatorSet,
    node: &[u8],
    fetch: &Fetch,
    saved: Option<&Saved>,
) -> Option<Cow<'a, ValidatorSet>> {
    if let Some(context) = saved
        .and_then(|saved| saved.context.as_deref())
        .filter(|_| fetch.target == node)
    {
        return record::decode_read(&fetch.call, context)
            .ok()
            .map(Cow::Owned);
    }
    let id = fetch.call.request.id().ok()?;
    Some(Cow::Borrowed(match requests.get(&id) {
        Some(state) if state.call() == &fetch.call => state.validators(),
        _ => current,
    }))
}
/// Gates that precede the native request/model historical-root callbacks.
pub fn window_preflight(view: &View<'_>, fetch: &Fetch) -> Result<bool> {
    let Ok(head) = view.current_head() else {
        return Ok(false);
    };
    let call = &fetch.call;
    let request = &call.request;
    Ok(fetch.shape()?
        && request.chain_id == view.chain
        && fetch.epoch_id <= head.epoch
        && head.epoch <= fetch.expires_epoch
        && request.expires_epoch.wrapping_sub(request.epoch_id) <= CALL_TTL)
}
pub fn window(view: &View<'_>, fetch: &Fetch) -> Result<bool> {
    let call = &fetch.call;
    let request = &call.request;
    Ok(window_preflight(view, fetch)?
        && (view.state_root_at)(request.epoch_id).as_deref() == Some(request.state_root.as_slice())
        && (view.state_root_at)(request.model_epoch).as_deref()
            == Some(request.model_state_root.as_slice())
        && super::request::verify_caller(call)?)
}
pub fn valid_fetch(view: &View<'_>, validators: &ValidatorSet, fetch: &Fetch) -> Result<bool> {
    let call = &fetch.call;
    Ok(window(view, fetch)?
        && validator_set_hash(validators)
            .is_ok_and(|root| root.as_slice() == call.request.validator_set_root)
        && validators.is_validator(&fetch.target)
        && verify_node(
            validators,
            &call.coordinator,
            &call.sign_bytes()?,
            &call.signature,
        )
        && verify_node(
            validators,
            &call.coordinator,
            &fetch.sign_bytes()?,
            &fetch.signature,
        ))
}
pub fn valid_answer(validators: &ValidatorSet, fetch: &Fetch, result: &Output) -> Result<bool> {
    let vote = &result.vote;
    Ok(result.shape()?
        && vote.within_budget(&fetch.call.request)
        && vote.node_id == fetch.target
        && vote.request_id == fetch.call.request.id()?
        && vote.output_bytes == result.output_json.len() as i64
        && vote.output_bytes <= fetch.call.request.max_output_bytes
        && vote
            .sign_bytes()
            .is_ok_and(|bytes| verify_node(validators, &vote.node_id, &bytes, &vote.signature)))
}
#[derive(Default)]
pub struct ReadBudget {
    rows: BTreeMap<Vec<u8>, (i64, usize)>,
}
impl ReadBudget {
    pub fn take(&mut self, view: &View<'_>, fetch: &Fetch, answer: bool) -> bool {
        let Ok(head) = view.current_head() else {
            return false;
        };
        self.rows.retain(|_, (epoch, _)| *epoch == head.epoch);
        let prefix = if answer {
            b"answer:".as_slice()
        } else {
            b"fetch:".as_slice()
        };
        let key = [prefix, &fetch.call.coordinator].concat();
        let count = self.rows.get(&key).map_or(0, |(_, count)| *count);
        if count >= MAX_READ_MESSAGES || count == 0 && self.rows.len() >= 2 * MAX_REQUESTS {
            return false;
        }
        self.rows.insert(key, (head.epoch, count + 1));
        true
    }
}
impl RequestState {
    pub fn missing(&self) -> Vec<Vec<u8>> {
        self.selection()
            .members
            .iter()
            .filter(|member| !self.has_vote(&member.node_id))
            .map(|member| member.node_id.clone())
            .collect()
    }
}
impl RequestBook {
    pub fn fetches(
        &self,
        history: &History,
        view: &View<'_>,
        jobs: &Jobs,
        node: &[u8],
        request_key: &[u8],
        mut sign: impl FnMut(&[u8]) -> Result<Vec<u8>>,
    ) -> Result<Option<(usize, Vec<Fetch>)>> {
        let (Some(state), Ok(head)) = (self.get(request_key), view.current_head()) else {
            return Ok(None);
        };
        let call = state.call();
        let request = &call.request;
        if call.coordinator != node
            || head.epoch < request.epoch_id
            || head.epoch > request.expires_epoch
        {
            return Ok(None);
        }
        let id = call.intent_id()?;
        if jobs.get(&id).is_none_or(|(_, _, job)| !job.pending()) {
            return Ok(None);
        }
        let missing = state.missing();
        if missing.is_empty() {
            return Ok(None);
        }
        let Some(round) = history
            .claim_fetch(
                &request.caller,
                &request.session_id,
                &id,
                message::FETCH_ROUNDS as usize,
            )
            .map_err(|error| Error::Unavailable(error.0))?
        else {
            return Ok(None);
        };
        let expires = if request.expires_epoch.wrapping_sub(head.epoch) <= message::FETCH_SPAN {
            request.expires_epoch
        } else {
            head.epoch.wrapping_add(message::FETCH_SPAN)
        };
        let mut reads = Vec::new();
        for target in missing {
            let mut fetch = Fetch {
                call: call.clone(),
                target,
                epoch_id: head.epoch,
                expires_epoch: expires,
                round: round as i64,
                signature: vec![0; 64],
            };
            fetch.signature = sign(&fetch.sign_bytes()?)?;
            reads.push(fetch);
        }
        Ok(Some((round, reads)))
    }
}
