// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Owned job-admission phases. The actor serializes these phases around its
//! history worker; borrowed host views never cross a blocking-worker boundary.
use super::{
    CancelStatus, CommitteeBook, CommitteeLease, Head, JobStatus, Jobs, Request, RequestBook,
    RequestState, Response, View, MAX_JOBS, MAX_REQUESTS,
};
use crate::compute_history::{History, Scope, Work};
use octra_node_protocol::{
    consensus::hash::validator_set_hash,
    resource_compute::{
        call::{Call, CALL_TTL},
        message::{CancelAck, Offer},
        record::{self, Record},
        Error, Result,
    },
};

fn unavailable(error: crate::compute_history::Error) -> Error {
    Error::Unavailable(error.0)
}
// Preserve the native owned-input and typed diagnostic interface.
#[allow(clippy::needless_pass_by_value)]
fn history_decode(error: Error) -> crate::compute_history::Error {
    let reason = error.as_bytes();
    if error.is_operational() {
        return crate::compute_history::Error(if reason == b"OCE1: allocation unavailable" {
            b"Out_of_memory".to_vec()
        } else {
            reason.to_vec()
        });
    }
    let constructor =
        if reason.starts_with(b"OCE1:") || reason == b"bad resource compute message tag" {
            b"Failure".as_slice()
        } else {
            b"Invalid_argument".as_slice()
        };
    crate::compute_history::Error(octra_node_protocol::native_exception::string_argument(
        constructor,
        reason,
    ))
}

/// This precedes cancellation refresh in native admission. A resumed job may
/// omit legacy caller limits; starting fresh work always requires all limits.
pub fn validate_request(request: &Request, resume: bool) -> Result<()> {
    if !request.shape() {
        return Err(Error::rejected(b"resource compute request refused"));
    }
    if !resume {
        require_limits(request)?;
    }
    Ok(())
}
fn require_limits(request: &Request) -> Result<()> {
    let limits = request.limits;
    for (absent, reason) in [
        (
            limits.unit_price.is_none(),
            b"resource compute caller fee required".as_slice(),
        ),
        (
            limits.memory_bytes.is_none(),
            b"resource compute caller memory required".as_slice(),
        ),
        (
            limits.guest_bytes.is_none(),
            b"resource compute caller pages required".as_slice(),
        ),
        (
            limits.fuel_limit.is_none(),
            b"resource compute caller fuel required".as_slice(),
        ),
        (
            request.valid_until.is_none(),
            b"resource compute caller expiry required".as_slice(),
        ),
    ] {
        if absent {
            return Err(Error::rejected(reason));
        }
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct Admission {
    pub request: Request,
    pub id: Vec<u8>,
    pub head: Head,
    pub validator_root: Vec<u8>,
    preview: Call,
    resume: bool,
    coordinator: bool,
}
#[derive(Clone, Debug)]
// Keep native owned command/result records inline without changing their API.
#[allow(clippy::large_enum_variant)]
pub enum Computation {
    New {
        offer: Offer,
        validator_root: Vec<u8>,
    },
    Reused(CommitteeLease),
    Funding(Call),
    Issued(RequestState),
}
#[derive(Clone, Debug)]
pub struct PlanWrite {
    caller: Vec<u8>,
    session: Vec<u8>,
    id: Vec<u8>,
    body: Vec<u8>,
    expires: Option<i64>,
}
impl PlanWrite {
    pub fn persist(&self, history: &History) -> Result<()> {
        if history
            .plan_job(
                &self.caller,
                &self.session,
                &self.id,
                &self.body,
                self.expires,
            )
            .map_err(unavailable)?
        {
            Ok(())
        } else {
            Err(Error::rejected(b"compute saved plan changed"))
        }
    }
}
#[derive(Clone, Debug)]
pub struct Prepared {
    pub id: Vec<u8>,
    pub request: Request,
    pub computation: Computation,
    pub plan: Option<PlanWrite>,
    head: Head,
}
impl Prepared {
    pub(crate) fn lease_epoch(&self, committees: &mut CommitteeBook) -> Result<Option<i64>> {
        match (&self.computation, &self.plan) {
            (Computation::New { validator_root, .. }, Some(_)) => {
                committees.required_epoch(&self.request, &self.head, validator_root)
            }
            _ => Ok(None),
        }
    }
    /// Call after the optional durable plan succeeds, as in native admission.
    /// A retained Planned row always resumes its original offer instead.
    pub fn reuse(&mut self, view: &View<'_>, committees: &mut CommitteeBook) -> Result<()> {
        let Computation::New { validator_root, .. } = &self.computation else {
            return Ok(());
        };
        if self.plan.is_some() {
            if let Some(lease) =
                committees.for_request(view, &self.request, &self.head, validator_root)?
            {
                self.computation = Computation::Reused(lease);
            }
        }
        Ok(())
    }
    /// The actor installs retained votes before starting certificate recovery.
    pub fn install(&self, requests: &mut RequestBook) -> Result<()> {
        if let Computation::Issued(state) = &self.computation {
            requests.install_restored(state.clone())?;
        }
        Ok(())
    }
}
impl Admission {
    /// Hash the captured validator set and reject future model epochs before
    /// the actor asks its host for a historical snapshot.
    pub(crate) fn preflight_model(view: &View<'_>, request: &Request) -> Result<()> {
        let head = view.current_head()?;
        validator_set_hash(view.validators)
            .map_err(|error| Error::Unavailable(error.to_string().into_bytes()))?;
        if request.model_epoch > head.epoch {
            return Err(Error::rejected(
                b"resource compute model snapshot unavailable",
            ));
        }
        Ok(())
    }
    /// Refresh durable cancellations before this phase, then prune jobs and
    /// refresh cancellations once more before consulting retained/live jobs.
    pub fn begin(
        view: &View<'_>,
        node: &[u8],
        jobs: &Jobs,
        request: Request,
        resume: bool,
    ) -> Result<Self> {
        validate_request(&request, resume)?;
        let head = view.current_head()?.clone();
        let validator_root = validator_set_hash(view.validators)
            .map_err(|error| Error::Unavailable(error.to_string().into_bytes()))?
            .to_vec();
        if request.model_epoch > head.epoch
            || (view.state_root_at)(request.model_epoch).as_deref()
                != Some(request.model_state_root.as_slice())
        {
            return Err(Error::rejected(
                b"resource compute model snapshot unavailable",
            ));
        }
        let coordinator = view.validators.is_validator(node);
        if !resume && !coordinator {
            return Err(Error::rejected(
                b"resource compute coordinator is not a validator",
            ));
        }
        if jobs.session_cancelled(&request.caller, &request.session_id)? {
            return Err(Error::rejected(b"resource compute session cancelled"));
        }
        let preview = request.unsigned_call(view.chain, node, &head, &validator_root, &[0; 32])?;
        if !super::request::verify_caller(&preview)? {
            return Err(Error::rejected(
                b"resource compute caller signature refused",
            ));
        }
        Ok(Self {
            id: preview.intent_id()?.to_vec(),
            request,
            head,
            validator_root,
            preview,
            resume,
            coordinator,
        })
    }
    /// Called after retained completed work was considered. Existing in-memory
    /// jobs bypass these new-lease checks, but still require durable openness.
    pub fn check_capacity(&self, jobs: &Jobs) -> Result<()> {
        if jobs.get(&self.id).is_some() {
            return Ok(());
        }
        if !self.resume
            && self.request.valid_until.is_none_or(|epoch| {
                epoch < self.head.epoch || epoch.wrapping_sub(self.head.epoch) > CALL_TTL
            })
        {
            return Err(Error::rejected(b"resource compute caller expiry refused"));
        }
        if jobs.len() >= MAX_JOBS {
            return Err(Error::rejected(b"resource compute job table full"));
        }
        if !jobs.caller_admitted(&self.request.caller) {
            return Err(Error::rejected(b"resource compute caller already active"));
        }
        if !jobs.cancel_available(&self.request.caller, &self.request.session_id)? {
            return Err(Error::rejected(b"resource compute cancellation table full"));
        }
        Ok(())
    }
    pub fn check_open(&self, history: &History) -> Result<()> {
        if history
            .cancelled(&self.request.caller, &self.request.session_id)
            .map_err(unavailable)?
        {
            Err(Error::rejected(b"resource compute session cancelled"))
        } else {
            Ok(())
        }
    }
    pub fn pending(&self, history: &History) -> Result<Option<Work>> {
        history
            .work(&self.request.caller, &self.id)
            .map_err(unavailable)
    }
    pub fn scope(&self, history: &History) -> Result<Option<Scope>> {
        history
            .scope(&self.request.caller, &self.request.session_id)
            .map_err(unavailable)
    }
    pub fn check_new(&self) -> Result<()> {
        self.check_planned()?;
        require_limits(&self.request)
    }
    pub(crate) fn check_planned(&self) -> Result<()> {
        if self.coordinator {
            Ok(())
        } else {
            Err(Error::rejected(
                b"resource compute coordinator is not a validator",
            ))
        }
    }
    // Preserve the native owned-input and typed diagnostic interface.
    #[allow(clippy::needless_pass_by_value)]
    pub(crate) fn prepare_planned(self, saved: Request, offer: Offer) -> Result<Prepared> {
        self.check_planned()?;
        if saved != self.request || self.head.epoch > offer.expires_epoch {
            return Err(Error::rejected(b"compute saved plan expired or changed"));
        }
        Ok(Prepared {
            id: self.id,
            request: self.request,
            computation: Computation::New {
                offer,
                validator_root: self.validator_root,
            },
            plan: None,
            head: self.head,
        })
    }
    /// The actor restores a retained record in ordered identity/evidence phases
    /// before reaching this transition, preserving the captured validator set.
    pub fn prepare_restored(
        self,
        requests: &RequestBook,
        state: RequestState,
        funding: bool,
    ) -> Result<Prepared> {
        let computation = if funding {
            if Request::from_call(state.call()) != self.request {
                return Err(Error::rejected(b"compute saved intent differs"));
            }
            Computation::Funding(state.call().clone())
        } else {
            if requests.len() >= MAX_REQUESTS {
                return Err(Error::rejected(b"resource compute request table full"));
            }
            Computation::Issued(state)
        };
        Ok(Prepared {
            id: self.id,
            request: self.request,
            computation,
            plan: None,
            head: self.head,
        })
    }
    /// Only a new job reaches this phase. Load scope only for absent work;
    /// malformed unrelated scope cannot override a retained work transition.
    pub fn prepare(
        self,
        view: &View<'_>,
        node: &[u8],
        requests: &RequestBook,
        pending: Option<Work>,
        prior_scope: Option<Scope>,
        mut sign: impl FnMut(&[u8]) -> Result<Vec<u8>>,
    ) -> Result<Prepared> {
        let mut plan = None;
        let computation = match pending {
            Some(Work::Planned(body)) => {
                if !self.coordinator {
                    return Err(Error::rejected(
                        b"resource compute coordinator is not a validator",
                    ));
                }
                let (saved, offer) =
                    Request::read_plan(view, node, &self.request.caller, &self.id, &body)?;
                if saved != self.request || self.head.epoch > offer.expires_epoch {
                    return Err(Error::rejected(b"compute saved plan expired or changed"));
                }
                Computation::New {
                    offer,
                    validator_root: self.validator_root.clone(),
                }
            }
            Some(Work::Funding(body)) => {
                let state =
                    RequestState::restore(view, node, &self.request.caller, &self.id, &body)?;
                if Request::from_call(state.call()) != self.request {
                    return Err(Error::rejected(b"compute saved intent differs"));
                }
                Computation::Funding(state.call().clone())
            }
            Some(Work::Issued(body)) => {
                let state =
                    RequestState::restore(view, node, &self.request.caller, &self.id, &body)?;
                if requests.len() >= MAX_REQUESTS {
                    return Err(Error::rejected(b"resource compute request table full"));
                }
                Computation::Issued(state)
            }
            None => {
                self.check_new()?;
                if prior_scope.is_some_and(|scope| self.request.sequence <= scope.sequence) {
                    return Err(Error::rejected(b"resource compute sequence already issued"));
                }
                let mut offer =
                    self.request
                        .unsigned_offer(view.chain, node, &self.head, &self.validator_root);
                offer.signature = sign(&offer.sign_bytes()?)?;
                let mut call = self.preview;
                call.signature = sign(&call.sign_bytes()?)?;
                let record = Record {
                    offer: offer.clone(),
                    call,
                    capabilities: Vec::new(),
                    commitments: Vec::new(),
                    reveals: Vec::new(),
                    results: Vec::new(),
                    validators: None,
                };
                plan = Some(PlanWrite {
                    caller: self.request.caller.clone(),
                    session: self.request.session_id.clone(),
                    id: self.id.clone(),
                    body: record.encode()?,
                    expires: self.request.valid_until,
                });
                Computation::New {
                    offer,
                    validator_root: self.validator_root,
                }
            }
        };
        Ok(Prepared {
            id: self.id,
            request: self.request,
            computation,
            plan,
            head: self.head,
        })
    }
}

/// Decode failures abort the history transaction. An unreadable funded row may
/// never be removed merely because a best-effort decode returned no identity.
pub fn prune(history: &History, chain: &[u8], epoch: i64) -> Result<usize> {
    history
        .try_prune_jobs(|caller, session, id, body| {
            let record = Record::decode(body).map_err(history_decode)?;
            let call = record.call;
            let intent = call.intent_id().map_err(history_decode)?;
            Ok(call.request.chain_id == chain
                && call.request.caller == caller
                && call.request.session_id == session
                && intent.as_slice() == id
                && call.request.expires_epoch < epoch)
        })
        .map_err(unavailable)
}
pub fn retained_response(
    view: &View<'_>,
    node: &[u8],
    caller: &[u8],
    id: &[u8],
    body: Option<&[u8]>,
) -> Result<Option<Response>> {
    body.map(|body| RequestState::restore(view, node, caller, id, body)?.saved_response())
        .transpose()
}

/// Waiting live jobs intentionally suppress a history read error, matching the
/// status contract. Restarted jobs expose that same read error as Refused.
pub fn live_status(pending: Result<Option<Work>>) -> JobStatus {
    if let Ok(Some(Work::Funding(body))) = pending {
        return match Record::decode(&body).and_then(|record| record.call.header()) {
            Ok(header) => JobStatus::Funding(header),
            Err(_) => JobStatus::Refused(b"compute saved funding unreadable".to_vec()),
        };
    }
    JobStatus::Waiting
}
#[derive(Clone, Debug)]
pub enum PendingStatus {
    Funding(Call),
    Resume(Request),
}
pub fn pending_status(caller: &[u8], id: &[u8], pending: Work) -> Result<PendingStatus> {
    let (body, funding) = match pending {
        Work::Funding(body) => (body, true),
        Work::Planned(body) | Work::Issued(body) => (body, false),
    };
    let record =
        Record::decode(&body).map_err(|_| Error::rejected(b"compute saved work unreadable"))?;
    let call = record.call;
    let intent = call
        .intent_id()
        .map_err(|_| Error::rejected(b"compute saved work unreadable"))?;
    if call.request.caller != caller || intent.as_slice() != id {
        return Err(Error::rejected(b"compute restored job differs"));
    }
    Ok(if funding {
        PendingStatus::Funding(call)
    } else {
        PendingStatus::Resume(Request::from_call(&call))
    })
}
pub fn funding_status(view: &View<'_>, call: &Call, closed: Result<bool>) -> JobStatus {
    let result = (|| {
        let closed = closed?;
        let head = view.current_head()?;
        if closed {
            return Err(Error::rejected(b"resource compute session cancelled"));
        }
        if head.epoch > call.request.expires_epoch {
            return Err(Error::rejected(b"compute funding wait expired"));
        }
        Ok(JobStatus::Funding(call.header()?))
    })();
    result.unwrap_or_else(|error: Error| JobStatus::Refused(error.as_bytes().to_vec()))
}
pub fn cancelled_status(
    state: &RequestState,
    stored: Option<(crate::compute_history::Notice, Vec<CancelAck>)>,
) -> Result<JobStatus> {
    let mut members: Vec<_> = state
        .selection()
        .members
        .iter()
        .map(|member| member.node_id.clone())
        .collect();
    members.sort();
    members.dedup();
    let receipts = match &stored {
        Some((_, rows)) => {
            record::select_cancels(state.call(), state.validators(), &members, rows)?
        }
        None => Vec::new(),
    };
    let missing = members
        .iter()
        .filter(|member| {
            !receipts
                .iter()
                .any(|ack| ack.node_id.as_slice() == member.as_slice())
        })
        .cloned()
        .collect();
    Ok(JobStatus::Cancelled(CancelStatus {
        selection_root: state.selection().root.clone(),
        members,
        missing,
        receipts,
        expires: stored.map(|(notice, _)| notice.expires),
    }))
}
