// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Serialized actor transitions. Durable work leaves Tokio through the history
//! owner; only the actor mutates job leases, committee leases and duplicate IDs.
use super::{
    domain_hash, durable_scope, record, round_signed, round_validators, validate_receipts, verify,
    verify_ack, verify_notice, CancelAck, CancelRound, CancelStatus, Cancellation, CommitteeBook,
    Error, HistoryWorker, Jobs, Message, Notice, RequestBook, RequestState, Result, ValidatorSet,
    View,
};
use octra_node_protocol::{
    consensus::seen::Seen, resource_compute::call::CALL_TTL, transaction::is_valid_address,
};

pub struct Coordinator<'a, 'view> {
    pub view: &'a View<'view>,
    pub node: &'a [u8],
    pub requests: &'a RequestBook,
    pub jobs: &'a mut Jobs,
    pub committees: &'a mut CommitteeBook,
    pub history: &'a HistoryWorker,
    pub seen: &'a mut Seen,
}
fn history_error(error: crate::compute_history::Error) -> Error {
    Error::Unavailable(error.0)
}
pub(super) fn wire_id(body: &[u8]) -> [u8; 32] {
    domain_hash(b"octra:resource_compute_wire", body)
}
impl Coordinator<'_, '_> {
    /// Notice authentication precedes every in-memory change. A corrupt saved
    /// notice therefore cannot partly repopulate the cancellation registry.
    pub async fn refresh(&mut self, epoch: i64) -> Result<()> {
        let rows = self
            .history
            .run(move |history| {
                history.prune_cancels(epoch).map_err(history_error)?;
                history.pending_notices(epoch).map_err(history_error)
            })
            .await?;
        if !rows
            .iter()
            .all(|notice| verify_notice(self.view.chain, notice, |id| self.seen.known(id)))
        {
            return Err(Error::rejected(b"compute saved cancellation differs"));
        }
        self.jobs.prune_cancelled(epoch);
        for notice in rows {
            self.seen.remember(&wire_id(&notice.body));
            if self
                .jobs
                .cancel_expiry(&notice.caller, &notice.session)?
                .is_none_or(|expires| expires < notice.expires)
            {
                self.jobs
                    .remember_cancelled(&notice.caller, &notice.session, notice.expires)?;
            }
        }
        Ok(())
    }

    /// The callback is copied into the worker together with the signed scope;
    /// no borrowed finalized view or actor-owned registry enters the worker.
    async fn scope<F>(
        &self,
        cancel: &Cancellation,
        origin: &[u8],
        accept: F,
    ) -> Option<ValidatorSet>
    where
        F: Fn(&ValidatorSet) -> bool + Send + Sync + 'static,
    {
        if let Some(prior) = self
            .requests
            .cancel_scope(self.view.chain, cancel, origin, |validators| {
                accept(validators)
            })
            .ok()
            .flatten()
        {
            return Some(prior);
        }
        let chain = self.view.chain.to_vec();
        let cancel = cancel.clone();
        let origin = origin.to_vec();
        self.history
            .run(move |history| Ok(durable_scope(history, &chain, &cancel, &origin, accept)))
            .await
            .ok()
            .flatten()
    }

    pub async fn selected_round(&self, round: &CancelRound, member: bool) -> Option<ValidatorSet> {
        let delivery = round.clone();
        let node = self.node.to_vec();
        let prior = self
            .scope(&round.cancel, &round.origin, move |validators| {
                round_signed(validators, &node, &delivery, member)
            })
            .await;
        round_validators(self.view.validators, prior, self.node, round, member)
    }

    pub async fn cancel(
        &mut self,
        cancel: &Cancellation,
        send: bool,
        round: Option<&CancelRound>,
    ) -> Result<usize> {
        if !is_valid_address(&cancel.caller) || !cancel.shape() {
            return Err(Error::rejected(b"resource compute cancellation refused"));
        }
        if !verify(self.view.chain, cancel) {
            return Err(Error::rejected(
                b"resource compute cancellation signature refused",
            ));
        }
        let epoch = self.view.current_head()?.epoch;
        if cancel
            .until
            .is_some_and(|until| until < epoch || until - epoch > CALL_TTL)
        {
            return Err(Error::rejected(
                b"resource compute cancellation expired or too distant",
            ));
        }
        self.refresh(epoch).await?;
        let owned = cancel.clone();
        let known = self
            .history
            .run(move |history| {
                history
                    .known_job(&owned.caller, &owned.session_id)
                    .map_err(history_error)
            })
            .await?;
        let pending = if known {
            None
        } else {
            self.requests
                .states()
                .filter(|state| {
                    state.call().request.caller == cancel.caller
                        && state.call().request.session_id == cancel.session_id
                })
                .map(|state| state.call().request.expires_epoch)
                .max()
        };
        if !known && pending.is_none() {
            return if send {
                Err(Error::rejected(b"resource compute session unknown"))
            } else {
                Ok(0)
            };
        }
        let owned = cancel.clone();
        let deadline = self
            .history
            .run(move |history| {
                history
                    .cancel_deadline(&owned.caller, &owned.session_id)
                    .map_err(history_error)
            })
            .await?
            .or(pending);
        if deadline.is_some_and(|until| cancel.until != Some(until)) {
            return Err(Error::rejected(
                b"resource compute cancellation deadline required",
            ));
        }
        if !self
            .jobs
            .cancel_available(&cancel.caller, &cancel.session_id)?
        {
            return Err(Error::rejected(b"resource compute cancellation table full"));
        }
        // The native queue rejects overflow even when an explicit deadline was
        // supplied. Incoming plain/round cancellation does not use that gate.
        let fallback = if send && round.is_none() {
            epoch
                .checked_add(CALL_TTL)
                .ok_or_else(|| Error::rejected(b"compute cancel expiry refused"))?
        } else {
            epoch.wrapping_add(CALL_TTL)
        };
        let owned = cancel.clone();
        let queued = send && round.is_none();
        let recorded = self
            .history
            .run(move |history| {
                if queued {
                    let body = Message::Cancel(owned.clone()).encode()?;
                    history
                        .queue_cancel(
                            epoch,
                            owned.until.unwrap_or(fallback),
                            &owned.caller,
                            &owned.session_id,
                            &body,
                            owned.until,
                        )
                        .map_err(history_error)
                } else {
                    history
                        .cancel(&owned.caller, &owned.session_id, owned.until)
                        .map_err(history_error)
                }
            })
            .await?;
        if !recorded {
            return Err(Error::rejected(
                b"resource compute cancellation not recorded",
            ));
        }
        let expires = round.map_or_else(|| cancel.until.unwrap_or(fallback), |value| value.expires);
        self.jobs
            .remember_cancelled(&cancel.caller, &cancel.session_id, expires)?;
        self.committees.remove(&cancel.caller, &cancel.session_id)?;
        Ok(self.jobs.cancel_session(&cancel.caller, &cancel.session_id))
    }

    pub async fn apply_round(&mut self, round: &CancelRound) -> Result<bool> {
        let Ok(head) = self.view.current_head() else {
            return Ok(false);
        };
        if !round.shape()
            || round.cancel.chain_id != self.view.chain
            || round.epoch > head.epoch
            || round.expires < head.epoch
            || !verify(self.view.chain, &round.cancel)
            || self.selected_round(round, false).await.is_none()
        {
            return Ok(false);
        }
        Ok(self.cancel(&round.cancel, false, Some(round)).await.is_ok())
    }

    pub async fn apply_ack(&self, ack: &CancelAck) -> Result<bool> {
        let Ok(head) = self.view.current_head() else {
            return Ok(false);
        };
        let epoch = head.epoch;
        if ack.epoch > epoch || ack.delivery.expires < epoch || !verify_ack(self.view.chain, ack) {
            return Ok(false);
        }
        let delivery = &ack.delivery;
        let allowed = |validators: &ValidatorSet| {
            validators.public_key(&delivery.origin) == Some(ack.origin_key.as_slice())
                && validators.public_key(&ack.node_id) == Some(ack.node_key.as_slice())
        };
        if !allowed(self.view.validators) {
            let owned = ack.clone();
            if self
                .scope(&delivery.cancel, &delivery.origin, move |validators| {
                    validators.public_key(&owned.delivery.origin)
                        == Some(owned.origin_key.as_slice())
                        && validators.public_key(&owned.node_id) == Some(owned.node_key.as_slice())
                })
                .await
                .is_none()
            {
                return Ok(false);
            }
        }
        if delivery.origin != self.node {
            return Ok(true);
        }
        let owned = ack.clone();
        self.history
            .run(move |history| {
                let cancel = &owned.delivery.cancel;
                history
                    .confirm_cancel(
                        epoch,
                        owned.delivery.expires,
                        owned.delivery.round,
                        &cancel.caller,
                        &cancel.session_id,
                        &Message::Cancel(cancel.clone()).encode()?,
                        &owned.node_id,
                        &Message::CancelAck(owned.clone()).encode()?,
                    )
                    .map_err(history_error)
            })
            .await
    }

    async fn stored(
        &self,
        caller: &[u8],
        session: &[u8],
    ) -> Result<Option<(Notice, Vec<CancelAck>)>> {
        let epoch = self.view.current_head()?.epoch;
        let caller = caller.to_vec();
        let session = session.to_vec();
        let saved = self
            .history
            .run(move |history| {
                history
                    .cancel_acks(epoch, &caller, &session)
                    .map_err(history_error)
            })
            .await?;
        validate_receipts(self.view.chain, self.node, saved, |id| self.seen.known(id))
    }

    pub async fn read(&self, cancel: &Cancellation) -> Result<Vec<CancelAck>> {
        self.view.current_head()?;
        if !cancel.shape() || !verify(self.view.chain, cancel) {
            return Err(Error::rejected(b"compute cancel read signature refused"));
        }
        match self.stored(&cancel.caller, &cancel.session_id).await? {
            None => Ok(Vec::new()),
            Some((notice, receipts))
                if notice.body == Message::Cancel(cancel.clone()).encode()? =>
            {
                Ok(receipts)
            }
            Some(_) => Err(Error::rejected(b"compute cancel request differs")),
        }
    }

    /// Call only after restoring the issued job and confirming durable session
    /// cancellation. Pending/planned jobs keep their native refused status.
    pub async fn status(&self, state: &RequestState) -> Result<CancelStatus> {
        let mut members = state
            .selection()
            .members
            .iter()
            .map(|member| member.node_id.clone())
            .collect::<Vec<_>>();
        members.sort();
        members.dedup();
        let stored = self
            .stored(
                &state.call().request.caller,
                &state.call().request.session_id,
            )
            .await?;
        let receipts = match &stored {
            None => Vec::new(),
            Some((_, rows)) => {
                record::select_cancels(state.call(), state.validators(), &members, rows)?
            }
        };
        let missing = members
            .iter()
            .filter(|node| !receipts.iter().any(|ack| &ack.node_id == *node))
            .cloned()
            .collect();
        Ok(CancelStatus {
            selection_root: state.selection().root.clone(),
            members,
            missing,
            receipts,
            expires: stored.map(|(notice, _)| notice.expires),
        })
    }

    /// The actor prunes expired planned jobs before polling. Claiming persists
    /// retry number and global send deadline before any network delivery starts.
    pub async fn poll(
        &mut self,
        target: Option<(Vec<u8>, Vec<u8>)>,
        now: i64,
        rounds: bool,
        sign: &(dyn Fn(&[u8]) -> Result<Vec<u8>> + Sync),
    ) -> Result<Option<Notice>> {
        let epoch = self.view.current_head()?.epoch;
        self.refresh(epoch).await?;
        self.poll_after_refresh(target, now, rounds, sign).await
    }
    /// Actor polling observes time and network support after durable refresh.
    /// Reusing this phase avoids advancing the pruning cursor a second time.
    pub(crate) async fn poll_after_refresh(
        &mut self,
        target: Option<(Vec<u8>, Vec<u8>)>,
        now: i64,
        rounds: bool,
        sign: &(dyn Fn(&[u8]) -> Result<Vec<u8>> + Sync),
    ) -> Result<Option<Notice>> {
        self.poll_after_refresh_with_clock(target, move || now, rounds, sign)
            .await
    }
    /// The production clock is observed on the history lane, after bounded
    /// queue admission; waiting for an earlier transaction cannot stale it.
    // Keep the operation on the exclusive native execution/actor interface.
    #[allow(clippy::needless_pass_by_ref_mut)]
    pub(crate) async fn poll_after_refresh_with_clock(
        &mut self,
        target: Option<(Vec<u8>, Vec<u8>)>,
        now: impl FnOnce() -> i64 + Send + 'static,
        rounds: bool,
        sign: &(dyn Fn(&[u8]) -> Result<Vec<u8>> + Sync),
    ) -> Result<Option<Notice>> {
        let epoch = self.view.current_head()?.epoch;
        let next = self
            .history
            .run(move |history| {
                let now = now();
                history
                    .claim_notice(
                        epoch,
                        target
                            .as_ref()
                            .map(|(caller, session)| (caller.as_slice(), session.as_slice())),
                        Some(now),
                        rounds,
                    )
                    .map_err(history_error)
            })
            .await?;
        if let Some(notice) = &next {
            if notice.round > 1 {
                if let Ok(Message::Cancel(cancel)) = Message::decode(&notice.body) {
                    let delivery =
                        signed_round(cancel, self.node, epoch, notice.expires, notice.round, sign)?;
                    if let Some(validators) = self.selected_round(&delivery, true).await {
                        if let Some(key) = validators.public_key(self.node) {
                            let ack = signed_ack(
                                delivery,
                                key.to_vec(),
                                self.node,
                                key.to_vec(),
                                epoch,
                                sign,
                            )?;
                            // The self acknowledgement is best effort, matching
                            // native polling; the claimed notice still delivers.
                            let _ = self.apply_ack(&ack).await;
                        }
                    }
                }
            }
        }
        Ok(next)
    }

    pub async fn ack_keys(
        &self,
        delivery: &CancelRound,
        now: i64,
    ) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        let cancel = delivery.cancel.clone();
        let closed = self
            .history
            .run(move |history| {
                history
                    .cancelled(&cancel.caller, &cancel.session_id)
                    .map_err(history_error)
            })
            .await;
        if closed != Ok(true) {
            return Ok(None);
        }
        let Some(validators) = self.selected_round(delivery, true).await else {
            return Ok(None);
        };
        let (Some(origin), Some(node)) = (
            validators.public_key(&delivery.origin),
            validators.public_key(self.node),
        ) else {
            return Ok(None);
        };
        let keys = (origin.to_vec(), node.to_vec());
        let allowed = self
            .history
            .run(move |history| history.claim_relay(now).map_err(history_error))
            .await;
        Ok((allowed == Ok(true)).then_some(keys))
    }
}

pub fn signed_round(
    cancel: Cancellation,
    node: &[u8],
    epoch: i64,
    expires: i64,
    round: i64,
    sign: &(dyn Fn(&[u8]) -> Result<Vec<u8>> + Sync),
) -> Result<CancelRound> {
    let mut delivery = CancelRound {
        cancel,
        origin: node.to_vec(),
        epoch,
        expires,
        round,
        signature: vec![0; 64],
    };
    delivery.signature = sign(&delivery.sign_bytes()?)?;
    Ok(delivery)
}
pub fn signed_ack(
    delivery: CancelRound,
    origin_key: Vec<u8>,
    node: &[u8],
    node_key: Vec<u8>,
    epoch: i64,
    sign: &(dyn Fn(&[u8]) -> Result<Vec<u8>> + Sync),
) -> Result<CancelAck> {
    let mut ack = CancelAck {
        delivery,
        origin_key,
        node_id: node.to_vec(),
        node_key,
        epoch,
        signature: vec![0; 64],
    };
    ack.signature = sign(&ack.sign_bytes()?)?;
    Ok(ack)
}

/// Construct immediately before sending so a retried delivery binds the latest
/// finalized epoch, as native send_cancel does after the actor claims a notice.
pub fn notice_message(
    notice: &Notice,
    node: &[u8],
    epoch: i64,
    sign: &(dyn Fn(&[u8]) -> Result<Vec<u8>> + Sync),
) -> Result<Vec<u8>> {
    if notice.round == 1 {
        return Ok(notice.body.clone());
    }
    let Message::Cancel(cancel) = Message::decode(&notice.body)? else {
        return Err(Error::rejected(b"compute cancel retry context"));
    };
    Message::CancelRound(signed_round(
        cancel,
        node,
        epoch,
        notice.expires,
        notice.round,
        sign,
    )?)
    .encode()
}
