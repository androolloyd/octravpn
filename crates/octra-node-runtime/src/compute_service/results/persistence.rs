// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Durable write plans contain only owned bytes checked against actor state.
use super::{
    history_error, record, Call, Error, History, Message, Output, RequestBook, Response, Result,
    Work,
};

#[derive(Clone, Debug)]
pub struct ResultWrite {
    caller: Vec<u8>,
    session: Vec<u8>,
    sequence: i64,
    request: Vec<u8>,
    reply: Vec<u8>,
    context: Vec<u8>,
}
impl ResultWrite {
    pub fn persist(&self, history: &History) -> Result<bool> {
        history
            .finish(
                &self.caller,
                &self.session,
                self.sequence,
                &self.request,
                &self.reply,
                Some(&self.context),
            )
            .map_err(history_error)
    }
}
#[derive(Clone, Debug)]
pub struct CompletionWrite {
    caller: Vec<u8>,
    session: Vec<u8>,
    id: Vec<u8>,
    before: Vec<u8>,
    body: Vec<u8>,
}
impl CompletionWrite {
    pub fn persist(&self, history: &History) -> Result<()> {
        match history
            .work(&self.caller, &self.id)
            .map_err(history_error)?
        {
            Some(Work::Issued(prior)) if prior == self.before => {}
            _ => return Err(Error::rejected(b"compute saved votes differ")),
        }
        if history
            .save_job(&self.caller, &self.session, &self.id, &self.body)
            .map_err(history_error)?
        {
            Ok(())
        } else {
            Err(Error::rejected(b"compute job changed or cancelled"))
        }
    }
}
impl RequestBook {
    pub fn prepare_result(&self, node: &[u8], call: &Call, result: &Output) -> Result<ResultWrite> {
        let Some(state) = self.rows.get(result.vote.request_id.as_slice()) else {
            return Err(Error::rejected(b"resource compute result identity differs"));
        };
        if !state.valid_result(result)?
            || state.call != *call
            || result.vote.node_id != node
            || result.vote.request_id != call.request.id()?
        {
            return Err(Error::rejected(b"resource compute result identity differs"));
        }
        let context = record::encode_read(call, &state.validators)?;
        let reply = Message::Result(result.clone()).encode()?;
        let request = &call.request;
        Ok(ResultWrite {
            caller: request.caller.clone(),
            session: request.session_id.clone(),
            sequence: request.sequence,
            request: request.id()?.to_vec(),
            reply,
            context,
        })
    }
    pub fn prepare_completed(&self, id: &[u8], response: &Response) -> Result<CompletionWrite> {
        let Some(state) = self.rows.get(response.request.id()?.as_slice()) else {
            return Err(Error::rejected(b"compute job request absent"));
        };
        if state.call.intent_id()?.as_slice() != id {
            return Err(Error::rejected(b"compute job request absent"));
        }
        let before = state.retained_record().encode()?;
        let results = record::select(
            &response.certificate.votes,
            &state.votes.values().cloned().collect::<Vec<_>>(),
        )?;
        let mut selected = state.clone();
        selected.votes = results
            .iter()
            .map(|result| (result.vote.node_id.clone(), result.clone()))
            .collect();
        if !selected
            .saved_response()
            .is_ok_and(|expected| expected == *response)
        {
            return Err(Error::rejected(b"compute job response differs"));
        }
        let body = selected.record(results).encode()?;
        let request = &state.call.request;
        Ok(CompletionWrite {
            caller: request.caller.clone(),
            session: request.session_id.clone(),
            id: id.to_vec(),
            before,
            body,
        })
    }
}
