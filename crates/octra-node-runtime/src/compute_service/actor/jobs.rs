// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{
    history_error, Arc, AssertUnwindSafe, BTreeMap, BTreeSet, Call, Context, Error, FutureExt,
    JobHandle, JobHost, Record, Request, RequestState, Response, Result, State, ValidatorSet,
};
use crate::compute_service::{
    admission::{self, Admission, Computation},
    command::Admit,
};

impl State {
    fn retained_context(&self, validators: ValidatorSet) -> Context {
        Context {
            chain: self.service.0.deps.chain().to_vec(),
            validators,
            head: None,
            evidence: self.evidence.clone(),
            root_at: Box::new(|_| None),
        }
    }
    // Keep the operation on the exclusive native execution/actor interface.
    #[allow(clippy::needless_pass_by_ref_mut)]
    pub(super) async fn read_plan(
        &mut self,
        caller: &[u8],
        id: &[u8],
        body: &[u8],
    ) -> Result<(
        Request,
        octra_node_protocol::resource_compute::message::Offer,
    )> {
        AssertUnwindSafe(async {
            let record = Record::decode(body)
                .map_err(|_| Error::rejected(b"compute saved plan unreadable"))?;
            let mut context = self.retained_context(self.service.0.deps.validators());
            let header = Request::plan_header(
                &context.view(),
                self.service.0.deps.node(),
                caller,
                id,
                record,
            )?;
            let epoch = header.epoch();
            let root = self
                .service
                .0
                .deps
                .state_root_at(epoch)
                .await
                .map_err(|_| Error::rejected(b"compute saved plan unreadable"))?;
            context.root_at = Box::new(move |at| (at == epoch).then(|| root.clone()).flatten());
            let offer = header.authenticate(&context.view())?;
            let epoch = offer.model_epoch();
            let root = self
                .service
                .0
                .deps
                .state_root_at(epoch)
                .await
                .map_err(|_| Error::rejected(b"compute saved plan unreadable"))?;
            context.root_at = Box::new(move |at| (at == epoch).then(|| root.clone()).flatten());
            offer.finish(&context.view())
        })
        .catch_unwind()
        .await
        .map_err(|_| Error::rejected(b"compute saved plan unreadable"))?
    }
    pub(super) async fn prune_jobs(&self, epoch: i64) -> Result<()> {
        let chain = self.service.0.deps.chain().to_vec();
        self.service
            .0
            .history
            .run(move |history| admission::prune(history, &chain, epoch).map(|_| ()))
            .await
    }
    pub(super) async fn restore(
        &mut self,
        caller: &[u8],
        id: &[u8],
        body: &[u8],
    ) -> Result<RequestState> {
        AssertUnwindSafe(async {
            let record = Record::decode(body)
                .map_err(|_| Error::rejected(b"compute job record unreadable"))?;
            let validators = record
                .validators
                .clone()
                .unwrap_or_else(|| self.service.0.deps.validators());
            let mut context = self.retained_context(validators);
            let header = RequestState::restore_record_header(
                &context.view(),
                self.service.0.deps.node(),
                caller,
                id,
                record,
            )?;
            let mut roots = BTreeMap::new();
            for (epoch, expected) in header.roots() {
                let actual = self
                    .service
                    .0
                    .deps
                    .state_root_at(epoch)
                    .await
                    .map_err(|_| Error::rejected(b"compute job record unreadable"))?;
                if actual.as_deref() != Some(expected) {
                    return Err(Error::rejected(b"compute job identity refused"));
                }
                roots.insert(epoch, actual.expect("matched retained state root"));
            }
            let call_roots = roots.clone();
            context.root_at = Box::new(move |epoch| call_roots.get(&epoch).cloned());
            let offer = header.authenticate(&context.view())?;
            let epoch = offer.model_epoch();
            if let Some(root) = self
                .service
                .0
                .deps
                .state_root_at(epoch)
                .await
                .map_err(|_| Error::rejected(b"compute job record unreadable"))?
            {
                roots.insert(epoch, root);
            } else {
                roots.remove(&epoch);
            }
            context.root_at = Box::new(move |epoch| roots.get(&epoch).cloned());
            let restored = offer.identity(&context.view())?;
            if restored.needs_evidence()? {
                // An ordinary self-test error is false capability evidence upstream;
                // an exception belongs to restore_state's unreadable-record catch.
                context.evidence = AssertUnwindSafe(self.evidence())
                    .catch_unwind()
                    .await
                    .map_err(|_| Error::rejected(b"compute job record unreadable"))?
                    .ok();
            }
            restored.finish(&context.view())
        })
        .catch_unwind()
        .await
        .map_err(|_| Error::rejected(b"compute job record unreadable"))?
    }
    pub(super) async fn retained(
        &mut self,
        caller: Vec<u8>,
        id: Vec<u8>,
    ) -> Result<Option<Response>> {
        let owner = caller.clone();
        let key = id.clone();
        let body = self
            .service
            .0
            .history
            .run(move |history| history.load_job(&owner, &key).map_err(history_error))
            .await?;
        match body {
            None => Ok(None),
            Some(body) => self
                .restore(&caller, &id, &body)
                .await?
                .saved_response()
                .map(Some),
        }
    }
    pub(super) async fn admit(&mut self, input: Admit) -> Result<(Vec<u8>, JobHandle)> {
        admission::validate_request(&input.request, input.resume)?;
        // Capture the head before refresh, but take the validator snapshot after
        // refresh, in the same order as the native admission path.
        let initial = self.context(BTreeSet::new()).await?;
        let head = initial.view().current_head()?.clone();
        let node = self.service.0.deps.node().to_vec();
        self.cancellations(&initial.view(), &node)
            .refresh(head.epoch)
            .await?;
        let mut context = initial;
        context.validators = self.service.0.deps.validators();
        Admission::preflight_model(&context.view(), &input.request)?;
        let epoch = input.request.model_epoch;
        let root = self.service.0.deps.state_root_at(epoch).await?;
        context.root_at = Box::new(move |at| (at == epoch).then(|| root.clone()).flatten());
        let admission = Admission::begin(
            &context.view(),
            &node,
            &self.jobs,
            input.request,
            input.resume,
        )?;
        self.prune_jobs(head.epoch).await?;
        self.cancellations(&context.view(), &node)
            .refresh(head.epoch)
            .await?;
        self.jobs.prune_finished();
        if self.jobs.get(&admission.id).is_none() {
            if let Some(response) = self
                .retained(admission.request.caller.clone(), admission.id.clone())
                .await?
            {
                return Ok((admission.id, JobHandle::ready(Ok(response))));
            }
        }
        admission.check_capacity(&self.jobs)?;
        let read = admission.clone();
        self.service
            .0
            .history
            .run(move |history| read.check_open(history))
            .await?;
        if let Some((_, _, job)) = self.jobs.get(&admission.id) {
            return Ok((admission.id, job));
        }
        let read = admission.clone();
        let pending = self
            .service
            .0
            .history
            .run(move |history| read.pending(history))
            .await?;
        let prior_scope = if pending.is_none() {
            admission.check_new()?;
            let read = admission.clone();
            self.service
                .0
                .history
                .run(move |history| read.scope(history))
                .await?
        } else {
            None
        };
        let mut prepared = match pending {
            Some(crate::compute_history::Work::Planned(body)) => {
                admission.check_planned()?;
                let (saved, offer) = self
                    .read_plan(&admission.request.caller, &admission.id, &body)
                    .await?;
                admission.prepare_planned(saved, offer)?
            }
            Some(crate::compute_history::Work::Funding(body)) => {
                let state = self
                    .restore(&admission.request.caller, &admission.id, &body)
                    .await?;
                admission.prepare_restored(&self.requests, state, true)?
            }
            Some(crate::compute_history::Work::Issued(body)) => {
                let state = self
                    .restore(&admission.request.caller, &admission.id, &body)
                    .await?;
                admission.prepare_restored(&self.requests, state, false)?
            }
            None => {
                let view = context.view();
                let deps = self.service.0.deps.clone();
                admission.prepare(&view, &node, &self.requests, None, prior_scope, |bytes| {
                    deps.sign(bytes)
                })?
            }
        };
        if let Some(plan) = prepared.plan.clone() {
            self.service
                .0
                .history
                .run(move |history| plan.persist(history))
                .await?;
        }
        if prepared.plan.is_some() {
            let required = prepared
                .lease_epoch(&mut self.committees)?
                .into_iter()
                .collect();
            let lease_context = self.context(required).await?;
            prepared.reuse(&lease_context.view(), &mut self.committees)?;
        }
        prepared.install(&mut self.requests)?;
        let service = self.service.clone();
        let request = prepared.request.clone();
        let work = async move {
            match prepared.computation {
                Computation::New {
                    offer,
                    validator_root,
                } => Box::pin(service.compute_new(request, validator_root, offer)).await,
                Computation::Reused(lease) => service.compute_reused(request, lease).await,
                Computation::Funding(call) => service.await_funding(call).await,
                Computation::Issued(state) => match state.saved_response() {
                    Ok(response) => Ok(response),
                    Err(_) => {
                        service
                            .wait_certificate(state.call().request.id()?.to_vec())
                            .await
                    }
                },
            }
        };
        let id = prepared.id;
        let host: Arc<dyn JobHost> = Arc::new(self.service.clone());
        let job = self.jobs.start(host, &prepared.request, id.clone(), work)?;
        Ok((id, job))
    }
    pub(super) async fn save_result(
        &self,
        call: Call,
        result: octra_node_protocol::resource_compute::message::Output,
    ) -> Result<bool> {
        let write = self
            .requests
            .prepare_result(self.service.0.deps.node(), &call, &result)?;
        self.service
            .0
            .history
            .run(move |history| write.persist(history))
            .await
    }
    pub(super) async fn save_job(&self, id: Vec<u8>, response: Response) -> Result<()> {
        let write = self.requests.prepare_completed(&id, &response)?;
        self.service
            .0
            .history
            .run(move |history| write.persist(history))
            .await
    }
}
