// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::super::{command::Apply, provider};
use super::{
    cancellation, domain_hash, reads, BTreeMap, BTreeSet, Context, Error, Execution, RequestState,
    Result, State, View,
};
use octra_node_protocol::resource_compute::{
    message::{Fetch, Output},
    wire::Message,
};
impl State {
    pub(super) async fn apply(&mut self, input: Apply) -> Result<bool> {
        self.prune();
        let node = self.service.0.deps.node().to_vec();
        let epoch = self
            .service
            .0
            .deps
            .head()
            .filter(|head| head.epoch >= 0 && head.state_root.len() == 32)
            .map(|head| head.epoch);
        self.routes.prune(epoch);
        let mut rounds = if matches!(
            &input.message,
            Message::CancelRound(_) | Message::CancelAck(_)
        ) {
            self.service.0.deps.cancel_rounds().await
        } else {
            false
        };
        if !self.routes.allowed(rounds, &node, &input.message)? {
            return Ok(false);
        }
        if let Message::Call(call) = &input.message {
            if self
                .jobs
                .session_cancelled(&call.request.caller, &call.request.session_id)?
            {
                return Ok(false);
            }
        }
        if self.seen.known(&input.wire_key) {
            if matches!(input.message, Message::Cancel(_) | Message::CancelRound(_)) {
                let _ = self.apply_direct(input.message, input.funds).await?;
            }
            return Ok(false);
        }
        if !self
            .apply_direct(input.message.clone(), input.funds)
            .await?
        {
            return Ok(false);
        }
        if matches!(&input.message, Message::Cancel(_)) {
            // The plain cancellation may have just closed its durable session;
            // native checks the round feature only after direct admission.
            rounds = self.service.0.deps.cancel_rounds().await;
        }
        let quota = cancellation::RelayQuota::for_message(
            &self.jobs,
            rounds,
            &node,
            input.source.as_deref(),
            &input.message,
        )?;
        if !quota
            .claim(
                &self.service.0.history,
                epoch.unwrap_or(i64::MAX),
                self.service.0.deps.now(),
            )
            .await
            .unwrap_or(false)
        {
            return Ok(false);
        }
        if !matches!(input.message, Message::Reveal(_)) {
            self.seen.remember(&input.wire_key);
        }
        self.routes
            .remember(input.source.as_deref(), &node, &input.message)?;
        Ok(true)
    }
    async fn apply_direct(
        &mut self,
        message: Message,
        funds: Option<crate::compute_deposits::Funded>,
    ) -> Result<bool> {
        let mut context = if let Message::Fetch(fetch) | Message::Answer(fetch, _) = &message {
            let Some(context) = self.fetch_context(fetch).await? else {
                return Ok(false);
            };
            context
        } else {
            self.context(BTreeSet::new()).await?
        };
        if let Message::Offer(offer) = &message {
            let view = context.view();
            if view.current_head().is_err() || !view.offer_preflight_checked(offer)? {
                return Ok(false);
            }
            let epoch = offer.model_epoch;
            let root = self.service.0.deps.state_root_at(epoch).await?;
            context.root_at = Box::new(move |requested| {
                if requested == epoch {
                    root.clone()
                } else {
                    None
                }
            });
        }
        if let Message::Call(call) = &message {
            let retained = self
                .requests
                .get(&call.request.id()?)
                .is_some_and(|state| state.call() == call);
            if !retained {
                if self.offers.preflight_call(&context.view(), call).is_err() {
                    return Ok(false);
                }
                // verify_call authenticates only its execution epoch here;
                // the matching offer already binds the historical model root.
                let epoch = call.request.epoch_id;
                let root = self.service.0.deps.state_root_at(epoch).await?;
                context.root_at = Box::new(move |requested| {
                    if requested == epoch {
                        root.clone()
                    } else {
                        None
                    }
                });
            }
        }
        if matches!(&message, Message::Capability(_)) {
            // Native capability verification captures a valid current view
            // before self-test and suppresses self-test failures to refusal.
            // Capability validation does not read its model epoch's state root.
            if context.view().current_head().is_err() {
                return Ok(false);
            }
            context.evidence = match self.evidence().await {
                Ok(evidence) => Some(evidence),
                Err(_) => return Ok(false),
            };
        }
        let view = context.view();
        let node = self.service.0.deps.node().to_vec();
        match message {
            Message::Offer(offer) => {
                if !self.offers.offer(&view, offer.clone())? {
                    return Ok(false);
                }
                let id = offer.id()?;
                if let Some(engine) = self.service.0.provider.clone() {
                    if let Some(state) = self.offers.get_mut(&id) {
                        if !state.local_started {
                            state.local_started = true;
                            let service = self.service.clone();
                            self.spawn_background(async move {
                                provider::candidate(&engine, &service, &offer).await
                            });
                        }
                    }
                }
                Ok(true)
            }
            Message::Capability(capability) => self.offers.capability(&view, &capability),
            Message::Commitment(commitment) => self.offers.commitment(&view, &commitment),
            Message::Reveal(reveal) => self.offers.reveal(&view, &reveal),
            Message::Call(call) => {
                let Some(funds) = funds else {
                    return Ok(false);
                };
                let Some(admitted) =
                    self.requests
                        .admit_checked(&view, &self.offers, call.clone(), &funds)?
                else {
                    return Ok(false);
                };
                let selected = admitted
                    .selection
                    .members
                    .iter()
                    .any(|member| member.node_id == node);
                let execution = if selected && self.service.provider_enabled() {
                    let state = RequestState::from_admission(call.clone(), admitted);
                    let local = node.clone();
                    match self
                        .service
                        .0
                        .history
                        .run(move |history| state.reserve(history, &local, true))
                        .await
                    {
                        Ok(execution) => execution,
                        Err(_) => return Ok(false),
                    }
                } else {
                    Execution::Skipped
                };
                match execution {
                    Execution::Retained(result) => {
                        if !self
                            .requests
                            .get(&result.vote.request_id)
                            .is_some_and(|state| state.valid_result(&result).unwrap_or(false))
                        {
                            return Ok(false);
                        }
                        let service = self.service.clone();
                        self.spawn_background(async move {
                            service.publish(Message::Result(result)).await.map(|_| ())
                        });
                    }
                    Execution::Execute => {
                        if let Some(engine) = self.service.0.provider.clone() {
                            let service = self.service.clone();
                            self.spawn_background(async move {
                                provider::execute_selected(&engine, &service, &call).await
                            });
                        }
                    }
                    Execution::Skipped => {}
                }
                Ok(true)
            }
            Message::Result(result) => {
                let Some(state) = self.requests.get(&result.vote.request_id) else {
                    return Ok(false);
                };
                let request = state.call().request.clone();
                let closed = self
                    .service
                    .0
                    .history
                    .run(move |history| {
                        history
                            .cancelled(&request.caller, &request.session_id)
                            .map_err(|error| Error::Unavailable(error.0))
                    })
                    .await;
                if closed != Ok(false) {
                    return Ok(false);
                }
                self.record_result(result).await
            }
            Message::Cancel(cancel) => {
                if cancel.chain_id != view.chain {
                    return Ok(false);
                }
                Ok(self
                    .cancellations(&view, &node)
                    .cancel(&cancel, false, None)
                    .await
                    .is_ok())
            }
            Message::CancelRound(round) => {
                self.cancellations(&view, &node).apply_round(&round).await
            }
            Message::CancelAck(ack) => self.cancellations(&view, &node).apply_ack(&ack).await,
            Message::Fetch(fetch) => self.fetch(&view, &node, fetch).await,
            Message::Answer(fetch, result) => self.answer(&view, &node, fetch, result).await,
        }
    }
    async fn record_result(&mut self, result: Output) -> Result<bool> {
        let key = result.vote.request_id.clone();
        let Some(state) = self.requests.get(&key).cloned() else {
            return Ok(false);
        };
        let node = self.service.0.deps.node().to_vec();
        let Ok((state, accepted)) = self
            .service
            .0
            .history
            .run(move |history| state.record_result_owned(&node, Some(history), result))
            .await
        else {
            return Ok(false);
        };
        if accepted {
            self.requests.install_restored(state)?;
        }
        Ok(accepted)
    }
    async fn fetch_context(&mut self, fetch: &Fetch) -> Result<Option<Context>> {
        let mut context = self.context(BTreeSet::new()).await?;
        if !reads::window_preflight(&context.view(), fetch)? {
            return Ok(None);
        }
        let request = &fetch.call.request;
        let Some(root) = self.service.0.deps.state_root_at(request.epoch_id).await? else {
            return Ok(None);
        };
        if root != request.state_root {
            return Ok(None);
        }
        let Some(model_root) = self
            .service
            .0
            .deps
            .state_root_at(request.model_epoch)
            .await?
        else {
            return Ok(None);
        };
        if model_root != request.model_state_root {
            return Ok(None);
        }
        let mut roots = BTreeMap::new();
        roots.insert(request.epoch_id, root);
        roots.insert(request.model_epoch, model_root);
        context.root_at = Box::new(move |epoch| roots.get(&epoch).cloned());
        Ok(Some(context))
    }
    fn take_read(&mut self, view: &View<'_>, fetch: &Fetch, answer: bool) -> bool {
        let head = self.service.0.deps.head();
        let budget_view = View {
            chain: view.chain,
            validators: view.validators,
            head: head.as_ref(),
            state_root_at: view.state_root_at,
            evidence: view.evidence,
        };
        self.reads.take(&budget_view, fetch, answer)
    }
    async fn fetch(&mut self, view: &View<'_>, node: &[u8], fetch: Fetch) -> Result<bool> {
        if !reads::window(view, &fetch)? {
            return Ok(false);
        }
        let call = fetch.call.clone();
        let Ok(saved) = self
            .service
            .0
            .history
            .run(move |history| reads::saved_reply(history, &call))
            .await
        else {
            return Ok(false);
        };
        let current = self.service.0.deps.validators();
        let Some(validators) =
            reads::reply_validators(&self.requests, &current, node, &fetch, saved.as_ref())
        else {
            return Ok(false);
        };
        let validators = validators.into_owned();
        let Some(context) = self.fetch_context(&fetch).await? else {
            return Ok(false);
        };
        let view = context.view();
        if !reads::valid_fetch(&view, &validators, &fetch)? || !self.take_read(&view, &fetch, false)
        {
            return Ok(false);
        }
        if let Some(saved) = saved.filter(|_| fetch.target == node) {
            let Ok(Message::Result(result)) = Message::decode(&saved.reply) else {
                return Ok(false);
            };
            if !reads::valid_answer(&validators, &fetch, &result)? {
                return Ok(false);
            }
            let service = self.service.clone();
            self.spawn_background(async move {
                service
                    .publish(Message::Answer(fetch, result))
                    .await
                    .map(|_| ())
            });
        }
        Ok(true)
    }
    async fn answer(
        &mut self,
        view: &View<'_>,
        node: &[u8],
        fetch: Fetch,
        result: Output,
    ) -> Result<bool> {
        if !reads::window(view, &fetch)? {
            return Ok(false);
        }
        let call = fetch.call.clone();
        let Ok(saved) = self
            .service
            .0
            .history
            .run(move |history| reads::saved_reply(history, &call))
            .await
        else {
            return Ok(false);
        };
        let current = self.service.0.deps.validators();
        let Some(validators) =
            reads::reply_validators(&self.requests, &current, node, &fetch, saved.as_ref())
        else {
            return Ok(false);
        };
        let validators = validators.into_owned();
        let Some(context) = self.fetch_context(&fetch).await? else {
            return Ok(false);
        };
        let view = context.view();
        if !reads::valid_fetch(&view, &validators, &fetch)?
            || !reads::valid_answer(&validators, &fetch, &result)?
            || !self.take_read(&view, &fetch, true)
        {
            return Ok(false);
        }
        let request = fetch.call.request.clone();
        if self
            .service
            .0
            .history
            .run(move |history| {
                history
                    .cancelled(&request.caller, &request.session_id)
                    .map_err(|error| Error::Unavailable(error.0))
            })
            .await
            != Ok(false)
        {
            return Ok(false);
        }
        if fetch.call.coordinator != node {
            return Ok(true);
        }
        if !self
            .requests
            .get(&fetch.call.request.id()?)
            .is_some_and(|state| state.call() == &fetch.call)
        {
            return Ok(false);
        }
        self.record_result(result).await
    }
    pub(super) async fn wake_reveals(&mut self) -> Result<()> {
        self.prune();
        if self.relay_pending.is_some() {
            return Ok(());
        }
        let now = self.service.0.deps.now();
        let node = self.service.0.deps.node().to_vec();
        let mut reveals = BTreeSet::new();
        for state in self.offers.states() {
            for reveal in state.reveals() {
                let payload = Message::Reveal(reveal.clone()).encode()?;
                let id = domain_hash(b"octra:resource_compute_wire", &payload);
                if !self.seen.known(&id) {
                    reveals.insert((reveal.node_id != node, payload));
                }
            }
        }
        let live: BTreeSet<_> = reveals
            .iter()
            .map(|(_, payload)| domain_hash(b"octra:resource_compute_wire", payload))
            .collect();
        self.relay_retry
            .retain(|id, deadline| now < *deadline && live.contains(id));
        let Some((foreign, payload)) = reveals.into_iter().find(|(_, payload)| {
            !self
                .relay_retry
                .contains_key(&domain_hash(b"octra:resource_compute_wire", payload))
        }) else {
            return Ok(());
        };
        let send_now = self.service.0.deps.now();
        let allowed = self
            .service
            .0
            .history
            .run(move |history| {
                history
                    .claim_send(!foreign, send_now)
                    .map_err(|error| Error::Unavailable(error.0))
            })
            .await;
        if allowed == Ok(true) {
            self.relay_pending = Some(payload.clone());
            let service = self.service.clone();
            self.spawn_background(async move { service.send_reveal(payload).await });
        }
        Ok(())
    }
    pub(super) async fn sent_reveal(&mut self, payload: Vec<u8>, sent: bool) -> Result<()> {
        if self.relay_pending.as_deref() == Some(payload.as_slice()) {
            self.relay_pending = None;
            let id = domain_hash(b"octra:resource_compute_wire", &payload);
            if sent {
                self.seen.remember(&id);
            } else {
                self.relay_retry
                    .insert(id, self.service.0.deps.now().wrapping_add(3000));
            }
        }
        self.wake_reveals().await
    }
}
