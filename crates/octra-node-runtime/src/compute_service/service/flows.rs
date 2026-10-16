// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{
    async_trait, CertificateProgress, Command, CommitteeLease, Duration, Error, Evidence, Head,
    JobHost, OfferSnapshot, Request, Response, Result, Service, ValidatorSet, View,
};
use futures::FutureExt;
use octra_node_protocol::{
    consensus::hash::validator_set_hash,
    resource_compute::{
        call::{Call, CALL_TTL},
        message::{self, Offer, Output},
        wire::Message,
    },
};
use std::{collections::BTreeSet, panic::AssertUnwindSafe};
impl Service {
    async fn wait_providers(&self, key: Vec<u8>) -> Result<(Head, OfferSnapshot)> {
        loop {
            let snapshot = self
                .call(|reply| Command::QueryOffer(key.clone(), reply), false)
                .await?
                .ok_or_else(|| Error::rejected(b"resource compute offer unavailable"))?;
            let head = self
                .0
                .deps
                .head()
                .filter(|head| head.epoch >= 0 && head.state_root.len() == 32)
                .ok_or_else(|| Error::rejected(b"resource compute finalized head unavailable"))?;
            if head.epoch > snapshot.offer.expires_epoch {
                return Err(Error::rejected(
                    b"resource compute committee formation expired",
                ));
            }
            let ready: BTreeSet<_> = snapshot
                .capabilities
                .iter()
                .filter(|capability| {
                    snapshot
                        .commitments
                        .iter()
                        .any(|value| value.node_id == capability.node_id)
                        && snapshot
                            .reveals
                            .iter()
                            .any(|value| value.node_id == capability.node_id)
                })
                .map(|value| &value.node_id)
                .collect();
            let size = (message::MAX_MEMBERS as i64).min(self.0.deps.validators().n);
            let latest = snapshot
                .reveals
                .iter()
                .fold(-1, |epoch, value| epoch.max(value.reveal_epoch));
            if size > 0 && ready.len() as i64 >= size && head.epoch > latest {
                return Ok((head, snapshot));
            }
            self.0.deps.sleep(Duration::from_millis(100)).await;
        }
    }
    pub(in crate::compute_service) async fn wait_certificate(
        &self,
        key: Vec<u8>,
    ) -> Result<Response> {
        let (mut ticks, mut round, mut next) = (0_usize, 0_usize, 10_usize);
        loop {
            match self
                .call(|reply| Command::QueryCertificate(key.clone(), reply), false)
                .await?
            {
                CertificateProgress::Finished(response) => return Ok(response),
                CertificateProgress::Refused(reason) => return Err(Error::rejected(reason)),
                CertificateProgress::Pending => {}
            }
            if ticks >= next && round < message::FETCH_ROUNDS as usize {
                match self
                    .call(|reply| Command::RequestReplies(key.clone(), reply), false)
                    .await?
                {
                    None => round = message::FETCH_ROUNDS as usize,
                    Some((saved, reads)) => {
                        for fetch in reads {
                            let _ = AssertUnwindSafe(async {
                                tokio::select! {_=self.publish(Message::Fetch(fetch))=>{},()=self.0.deps.sleep(Duration::from_secs(2))=>{}}
                            }).catch_unwind().await;
                        }
                        round = saved + 1;
                        next = ticks + (10 << round);
                    }
                }
            }
            self.0.deps.sleep(Duration::from_millis(100)).await;
            ticks = ticks.wrapping_add(1);
        }
    }
    pub(in crate::compute_service) async fn await_funding(&self, call: Call) -> Result<Response> {
        use super::super::funding::{FundingStep, FundingWait};
        let mut wait = FundingWait::new();
        loop {
            wait.check()?;
            let released = match self.read_funding(call.clone()).await? {
                None => false,
                Some(funds) => {
                    self.call(
                        |reply| Command::FundCall((call.clone(), funds), reply),
                        false,
                    )
                    .await?
                }
            };
            let head = self
                .0
                .deps
                .head()
                .filter(|head| head.epoch >= 0 && head.state_root.len() == 32)
                .ok_or_else(|| Error::rejected(b"resource compute finalized head unavailable"));
            let published = released && self.publish(Message::Call(call.clone())).await?;
            match wait.advance(&call, Ok(released), published, head)? {
                FundingStep::Certificate => {
                    return self.wait_certificate(call.request.id()?.to_vec()).await
                }
                FundingStep::Retry(duration) => self.0.deps.sleep(duration).await,
            }
        }
    }
    async fn send_call(&self, call: Call) -> Result<Response> {
        self.call(|reply| Command::IssueCall(call.clone(), reply), false)
            .await?;
        self.await_funding(call).await
    }
    pub(in crate::compute_service) async fn compute_new(
        &self,
        request: Request,
        validator_root: Vec<u8>,
        offer: Offer,
    ) -> Result<Response> {
        let key = offer.id()?.to_vec();
        let _ = self.publish(Message::Offer(offer)).await?;
        let (head, snapshot) = self.wait_providers(key).await?;
        let validators = self.0.deps.validators();
        let root = validator_set_hash(&validators)
            .map_err(|error| Error::Unavailable(error.to_string().into_bytes()))?;
        if validator_root != root {
            return Err(Error::rejected(b"resource compute validator set changed"));
        }
        let preview = request.unsigned_request_at(
            self.0.deps.chain(),
            head.epoch,
            &head.state_root,
            head.epoch.wrapping_add(CALL_TTL),
            &root,
            &[0; 32],
        )?;
        let view = View {
            chain: self.0.deps.chain(),
            validators: &validators,
            head: Some(&head),
            state_root_at: &|_| None,
            evidence: None,
        };
        let selection = snapshot.selection(&view, &preview)?;
        if selection.members.len() as i64 != (message::MAX_MEMBERS as i64).min(validators.n) {
            return Err(Error::rejected(b"resource compute committee unavailable"));
        }
        let mut call = request.unsigned_call(
            self.0.deps.chain(),
            self.0.deps.node(),
            &head,
            &root,
            &selection.root,
        )?;
        call.signature = self.0.deps.sign(&call.sign_bytes()?)?;
        let response = self.send_call(call).await?;
        if let Some(lease) = CommitteeLease::from_response(&request, &snapshot, &response)? {
            self.call(|reply| Command::RememberCommittee(lease, reply), false)
                .await?;
        }
        Ok(response)
    }
    pub(in crate::compute_service) async fn compute_reused(
        &self,
        request: Request,
        lease: CommitteeLease,
    ) -> Result<Response> {
        let mut call = lease.unsigned_call(&request, self.0.deps.chain(), self.0.deps.node())?;
        call.signature = self.0.deps.sign(&call.sign_bytes()?)?;
        self.send_call(call).await
    }
}
#[async_trait]
impl super::super::provider::ProviderHost for Service {
    fn node(&self) -> &[u8] {
        self.0.deps.node()
    }
    fn validators(&self) -> ValidatorSet {
        self.0.deps.validators()
    }
    fn head(&self) -> Option<Head> {
        self.0.deps.head()
    }
    fn sign(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        self.0.deps.sign(bytes)
    }
    fn nonce(&self) -> Vec<u8> {
        self.0.deps.nonce()
    }
    async fn evidence(&self) -> Result<Evidence> {
        self.call(|reply| Command::Evidence((), reply), false).await
    }
    async fn publish(&self, message: Message) -> Result<bool> {
        Self::publish(self, message).await
    }
    async fn save_result(&self, call: Call, result: Output) -> Result<bool> {
        self.call(|reply| Command::SaveResult((call, result), reply), false)
            .await
    }
    async fn sleep(&self, duration: Duration) {
        self.0.deps.sleep(duration).await;
    }
}
#[async_trait]
impl JobHost for Service {
    async fn save_job(&self, id: Vec<u8>, response: Response) -> Result<()> {
        self.call(|reply| Command::SaveJob((id, response), reply), false)
            .await
    }
    async fn complete_job(&self, id: Vec<u8>, caller: Vec<u8>) -> Result<()> {
        self.call(|reply| Command::CompleteJob((id, caller), reply), false)
            .await
    }
}
