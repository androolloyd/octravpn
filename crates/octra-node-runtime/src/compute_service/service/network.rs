// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::super::command::Apply;
use super::{Command, Duration, Error, Funded, Result, Service};
use futures::FutureExt;
use octra_node_protocol::{
    network::domain_hash,
    resource_compute::{call::Call, message::CancelAck, wire::Message},
};
use std::panic::AssertUnwindSafe;
impl Service {
    pub(in crate::compute_service) async fn read_funding(
        &self,
        call: Call,
    ) -> Result<Option<Funded>> {
        let Some(head) = self
            .call(|reply| Command::CheckFunding(call.clone(), reply), false)
            .await?
        else {
            return Ok(None);
        };
        let key = call.request.id()?.to_vec();
        let deps = self.0.deps.clone();
        let service = self.clone();
        let observation = call
            .header()
            .map(move |header| async move { deps.funding(head, header).await });
        super::super::funding::read_observation(
            observation,
            async move {
                let _ = service
                    .call(|reply| Command::DropFunding(key, reply), false)
                    .await;
            },
            self.0.deps.sleep(Duration::from_secs(2)),
        )
        .await
    }
    async fn message_funding(&self, message: &Message) -> Result<Option<Funded>> {
        match message {
            Message::Call(call) => self.read_funding(call.clone()).await,
            _ => Ok(None),
        }
    }
    pub async fn publish(&self, message: Message) -> Result<bool> {
        let payload = message.encode()?;
        let Ok(funds) = self.message_funding(&message).await else {
            return Ok(false);
        };
        let apply = Apply {
            wire_key: domain_hash(b"octra:resource_compute_wire", &payload),
            source: None,
            message: message.clone(),
            funds,
        };
        let accepted = self
            .call(|reply| Command::Apply(apply, reply), false)
            .await?;
        if accepted {
            if !matches!(message, Message::Reveal(_)) {
                self.0.deps.broadcast(payload).await?;
            }
            self.forward_reveals().await?;
        }
        Ok(accepted)
    }
    pub async fn on_message(&self, source: Vec<u8>, payload: Vec<u8>) -> Result<()> {
        let Ok(message) = Message::decode(&payload) else {
            return Ok(());
        };
        let generation = self.generation();
        let accepted = AssertUnwindSafe(async {
            let Ok(funds) = self.message_funding(&message).await else {
                return false;
            };
            let apply = Apply {
                wire_key: domain_hash(b"octra:resource_compute_wire", &payload),
                source: Some(source.clone()),
                message: message.clone(),
                funds,
            };
            self.call(|reply| Command::Apply(apply, reply), true)
                .await
                .unwrap_or(false)
        })
        .catch_unwind()
        .await
        .unwrap_or(false);
        if !accepted {
            return Ok(());
        }
        match &message {
            Message::Reveal(_) => {}
            Message::CancelAck(ack) => {
                if let Some(peer) = self
                    .call(
                        |reply| Command::CancelPath(ack.delivery.clone(), reply),
                        false,
                    )
                    .await?
                {
                    self.send_deadline(peer, payload.clone()).await;
                }
            }
            _ => self.0.deps.relay(source.clone(), payload).await?,
        }
        if let Message::CancelRound(delivery) = message {
            if let Some(head) = self
                .0
                .deps
                .head()
                .filter(|head| head.epoch >= 0 && head.state_root.len() == 32)
            {
                if self.open() && generation == self.generation() && head.epoch <= delivery.expires
                {
                    if let Some((origin_key, node_key)) = self
                        .call(|reply| Command::CancelKeys(delivery.clone(), reply), false)
                        .await
                        .unwrap_or(None)
                    {
                        if self.open() && generation == self.generation() {
                            let mut ack = CancelAck {
                                delivery,
                                origin_key,
                                node_id: self.0.deps.node().to_vec(),
                                node_key,
                                epoch: head.epoch,
                                signature: vec![0; 64],
                            };
                            ack.signature = self.0.deps.sign(&ack.sign_bytes()?)?;
                            self.send_deadline(source, Message::CancelAck(ack).encode()?)
                                .await;
                        }
                    }
                }
            }
        }
        self.forward_reveals().await
    }
    async fn send_deadline(&self, peer: Vec<u8>, payload: Vec<u8>) {
        let _ = AssertUnwindSafe(async {
            tokio::select! {_=self.0.deps.send(peer,payload)=>{},()=self.0.deps.sleep(Duration::from_secs(2))=>{}}
        }).catch_unwind().await;
    }
    pub(in crate::compute_service) async fn forward_reveals(&self) -> Result<()> {
        self.call(|reply| Command::WakeReveals((), reply), false)
            .await
    }
    pub(in crate::compute_service) async fn send_reveal(&self, payload: Vec<u8>) -> Result<()> {
        // Native Lwt.protected + finalize owns the send through caller
        // cancellation. Keep the bounded attempt and its actor completion
        // together, including panics from the host transport dependency.
        let service = self.clone();
        tokio::spawn(async move {
            let sent = AssertUnwindSafe(async {
                tokio::select! {result=service.0.deps.broadcast(payload.clone())=>result.is_ok(),()=service.0.deps.sleep(octra_node_protocol::network::swarm::SEND_DEADLINE.saturating_mul(2))=>false}
            }).catch_unwind().await.unwrap_or(false);
            service.call(|reply| Command::SentReveal((payload, sent), reply), false).await
        }).await.map_err(|error| Error::Unavailable(error.to_string().into_bytes()))?
    }
    pub(in crate::compute_service) async fn send_cancel(
        &self,
        target: Option<(Vec<u8>, Vec<u8>)>,
    ) -> Result<()> {
        // Delivery failures never replace a successful cancellation result or
        // stop the periodic retry loop. The durable notice remains pollable.
        let _ = AssertUnwindSafe(async {
            let Some(notice) = self
                .call(|reply| Command::PollCancel(target, reply), false)
                .await?
            else {
                return Ok::<(), Error>(());
            };
            let payload = if notice.round == 1 {
                notice.body.clone()
            } else {
                let head = self
                    .0
                    .deps
                    .head()
                    .filter(|head| head.epoch >= 0 && head.state_root.len() == 32)
                    .ok_or_else(|| Error::rejected(b"compute cancel retry context"))?;
                super::super::cancellation::notice_message(
                    &notice,
                    self.0.deps.node(),
                    head.epoch,
                    &|bytes| self.0.deps.sign(bytes),
                )?
            };
            tokio::select! {_=self.0.deps.broadcast(payload)=>{},()=self.0.deps.sleep(Duration::from_secs(2))=>{}}
            Ok(())
        }).catch_unwind().await;
        Ok(())
    }
}
