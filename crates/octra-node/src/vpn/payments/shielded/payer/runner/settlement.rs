use super::super::{native::Operation, records::Intent, INTENT};
use super::{Purchase, Services, State};
use crate::vpn::payments::shielded::wallet::Receipt;
use anyhow::{ensure, Context, Result};
use octra_private_payments_experimental::invoice::SignedInvoice;
use octravpn_core::payments::{PlanBinding, PrivateResult};

impl Purchase {
    /// Reauthenticate an already reconciled credit against retained native
    /// finality. This cannot create a signature, submission, quote or credit.
    pub(super) async fn recorded_credit(&self) -> Result<Option<PlanBinding>> {
        let mut binding = None;
        for slot in 0..=self.terms.additional.len() {
            let Some(paid) = self.recorded_class_credit(slot).await? else {
                return Ok(None);
            };
            ensure!(
                binding.as_ref().is_none_or(|prior| prior == &paid),
                "private class credits belong to different channels"
            );
            binding = Some(paid);
        }
        Ok(binding)
    }
    pub(super) async fn recorded_class_credit(&self, slot: usize) -> Result<Option<PlanBinding>> {
        let Some(saved) = self.settled_receipt(slot).await? else {
            return Ok(None);
        };
        for sequence in self
            .payer
            .native_sequences(&self.terms.relayer_public, Operation::Purchase(saved.quote))
            .await?
        {
            let attempt = self
                .payer
                .native_attempt(&self.terms.relayer_public, sequence)
                .await?;
            if self.payer.confirmed_native(&attempt).await?.is_some() {
                saved.check(&attempt)?;
                return Ok(Some(saved.binding));
            }
        }
        anyhow::bail!("saved private credit has no canonical native purchase")
    }
    pub(super) async fn recorded_entry<A: crate::Host>(
        &self,
        node: &crate::Node<A>,
    ) -> Result<(PlanBinding, Vec<super::super::reconnect::Permit>)> {
        let mut binding = None;
        let mut permits = Vec::new();
        for slot in 0..=self.terms.additional.len() {
            let (paid, permit) = self.recorded_class_entry(node, slot).await?;
            ensure!(
                binding.as_ref().is_none_or(|prior| prior == &paid),
                "retained class credits belong to different channels"
            );
            binding = Some(paid);
            permits.push(permit);
        }
        for permit in &permits {
            permit.check()?;
        }
        Ok((binding.context("entry has no channel")?, permits))
    }
    async fn recorded_class_entry<A: crate::Host>(
        &self,
        node: &crate::Node<A>,
        slot: usize,
    ) -> Result<(PlanBinding, super::super::reconnect::Permit)> {
        let saved = self
            .settled_receipt(slot)
            .await?
            .context("entry has no settled capacity")?;
        for sequence in self
            .payer
            .native_sequences(&self.terms.relayer_public, Operation::Purchase(saved.quote))
            .await?
        {
            let attempt = self
                .payer
                .native_attempt(&self.terms.relayer_public, sequence)
                .await?;
            if self
                .payer
                .confirmation_location(&attempt.hash()?)
                .await?
                .is_some()
            {
                saved.check(&attempt)?;
                let permit = self.payer.retained_purchase(node, &attempt).await?;
                return Ok((saved.binding, permit));
            }
        }
        anyhow::bail!("entry has no retained canonical purchase proof")
    }
    async fn settled_receipt(&self, slot: usize) -> Result<Option<Settled>> {
        let Some(result) = self.reply(self.receipt_phase(slot)?).await? else {
            return Ok(None);
        };
        let binding = self.opened(
            &self
                .reply(0)
                .await?
                .context("paid private channel missing")?,
        )?;
        let invoice = self.quoted(
            &self
                .reply(self.quote_phase(slot)?)
                .await?
                .context("paid private quote missing")?,
            binding.plan,
            slot,
        )?;
        let quote = invoice.id()?;
        let commitment = self.receipt_commitment(quote).await?;
        let PrivateResult::Receipt {
            channel,
            quote: got,
            credit_id,
        } = result
        else {
            anyhow::bail!("saved private credit differs");
        };
        ensure!(
            channel == binding.plan
                && got == quote
                && credit_id == self.payer.1.credit_id(commitment),
            "saved private receipt differs"
        );
        Ok(Some(Settled {
            binding,
            quote,
            commitment,
        }))
    }
    pub(super) async fn settle<A: crate::Host>(
        &self,
        services: &Services<'_, A>,
        invoice: &SignedInvoice,
        binding: PlanBinding,
        slot: usize,
    ) -> Result<State> {
        let receipt_phase = self.receipt_phase(slot)?;
        let quote = invoice.id()?;
        let operation = Operation::Purchase(quote);
        // Search the durable signature journal before preparing/rebasing. An
        // earlier attempt may have committed while the client was offline.
        for sequence in self
            .payer
            .native_sequences(&self.terms.relayer_public, operation)
            .await?
        {
            let attempt = self
                .payer
                .native_attempt(&self.terms.relayer_public, sequence)
                .await?;
            let Some(epoch) = self.payer.confirmed_native(&attempt).await? else {
                continue;
            };
            let view = services.index.view().await?;
            ensure!(
                self.payer.reconcile_native(&attempt, view.index()).await? == Some(epoch),
                "private purchase confirmation changed"
            );
            let anchor = self
                .payer
                .recovery_proof(epoch)
                .await?
                .map_or(epoch, |proof| proof.anchor())
                .max(self.payer.1.directory.history.anchor().epoch.0);
            self.payer.retain_native(&attempt, anchor).await?;
            let (evidence, credit_id) = self.evidence(quote, epoch, view.index()).await?;
            let result = if let Some(result) = self.reply(receipt_phase).await? {
                result
            } else {
                let (_, now) = self.payer.current(view.index()).await?;
                let request = self
                    .receipt_request(binding.plan, quote, evidence, now, slot)
                    .await?;
                request.request.check_time(now)?;
                self.exchange(receipt_phase, &request, services.control)
                    .await?
            };
            let PrivateResult::Receipt {
                channel,
                quote: got,
                credit_id: credited,
            } = result
            else {
                anyhow::bail!("private receipt reply differs");
            };
            ensure!(
                channel == binding.plan && got == quote && credited == credit_id,
                "private receipt differs from canonical purchase"
            );
            view.with_current(|_| Ok(()))?;
            return Ok(State::Credited {
                binding,
                credit_id,
                epoch,
            });
        }
        ensure!(
            self.reply(receipt_phase).await?.is_none(),
            "private receipt has no canonical payment"
        );
        let view = services.index.view().await?;
        let public = octravpn_core::b64::encode(self.terms.relayer_public);
        let native = octra_node_protocol::transaction::address_from_public_key(public.as_bytes());
        let relayer_address = native.as_slice().try_into()?;
        self.payer
            .prepare(
                invoice,
                &self.limits(slot)?,
                view.index(),
                relayer_address,
                services.prover,
            )
            .await?;
        let attempt = self
            .payer
            .sign_native(operation, view.index(), services.relayer, self.terms.fees)
            .await?;
        self.payer
            .broadcast(services.submission, &attempt, view.index())
            .await?;
        Ok(State::Submitted {
            hash: attempt.hash()?,
        })
    }

    pub(super) async fn receipt_credit(&self, quote: [u8; 32]) -> Result<[u8; 32]> {
        Ok(self
            .payer
            .1
            .credit_id(self.receipt_commitment(quote).await?))
    }

    #[cfg(test)]
    pub(crate) async fn bundle_reconnect_case<A: crate::Host>(&self, node: &crate::Node<A>) {
        node.suspend("all class retained entry proof qualification");
        assert!(crate::SnapshotLease::capture(node.shared.clone()).is_err());
        let (_, permits) = self.recorded_entry(node).await.unwrap();
        assert_eq!(permits.len(), 1 + self.terms.additional.len());
        assert!(crate::SnapshotLease::capture(node.shared.clone()).is_err());
        let head = node.head().await.unwrap();
        node.shared
            .quarantine_root(&head, "catchup_apply_failed:invalid");
        assert!(permits.iter().all(|permit| permit.check().is_err()));
        assert!(self.recorded_entry(node).await.is_err());
        let ticket = node.shared.root_quarantine_ticket();
        assert!(node.shared.complete_catchup(&ticket));
        assert!(node.resume().await.unwrap());
        assert!(permits.iter().all(|permit| permit.check().is_err()));
        let (_, fresh) = self.recorded_entry(node).await.unwrap();
        assert!(fresh.iter().all(|permit| permit.check().is_ok()));
    }

    #[cfg(test)]
    pub(crate) async fn retain_ahead_case(&self) {
        let saved = self.settled_receipt(0).await.unwrap().unwrap();
        let head = crate::SnapshotLease::capture(self.payer.1.directory.shared.clone())
            .unwrap()
            .committed()
            .head()
            .cursor
            .epoch
            .0;
        for sequence in self
            .payer
            .native_sequences(&self.terms.relayer_public, Operation::Purchase(saved.quote))
            .await
            .unwrap()
        {
            let attempt = self
                .payer
                .native_attempt(&self.terms.relayer_public, sequence)
                .await
                .unwrap();
            if let Some(epoch) = self.payer.confirmed_native(&attempt).await.unwrap() {
                assert!(head > epoch);
                saved.check(&attempt).unwrap();
                self.payer.retain_native(&attempt, head).await.unwrap();
                assert_eq!(
                    self.payer
                        .recovery_proof(epoch)
                        .await
                        .unwrap()
                        .unwrap()
                        .anchor(),
                    head
                );
                return;
            }
        }
        panic!("settled purchase has no canonical attempt");
    }

    async fn receipt_commitment(&self, quote: [u8; 32]) -> Result<[u8; 32]> {
        let mut tx = self.payer.0.disk.begin().await?;
        let intent: Intent = self
            .payer
            .0
            .disk
            .load(&mut tx, INTENT, &self.payer.intent_tag(&quote)?)
            .await?
            .context("private purchase intent missing")?;
        tx.rollback().await?;
        ensure!(
            intent.progress == super::super::Progress::Paid,
            "private purchase has not reconciled"
        );
        Ok(intent
            .attempt
            .context("private purchase proof missing")?
            .outputs[0])
    }

    async fn evidence(
        &self,
        quote: [u8; 32],
        epoch: u64,
        index: &octra_private_payments_experimental::pool::PoolIndex,
    ) -> Result<(String, [u8; 32])> {
        let mut tx = self.payer.0.disk.begin().await?;
        let intent: Intent = self
            .payer
            .0
            .disk
            .load(&mut tx, INTENT, &self.payer.intent_tag(&quote)?)
            .await?
            .context("private purchase intent missing")?;
        tx.rollback().await?;
        ensure!(
            intent.progress == super::super::Progress::Paid,
            "private purchase has not reconciled"
        );
        let proof = intent.attempt.context("private purchase proof missing")?;
        let historical = self.payer.historical(epoch).await?;
        let count = self.payer.1.state(&historical.after)?.count;
        let membership = index.membership_at(proof.count.try_into()?, count)?;
        let call = proof.call.call()?;
        let evidence = Receipt {
            epoch,
            commitment: proof.outputs[0],
            membership: &membership,
            call: &call,
            relayer: super::super::super::native(&proof.call.relayer)?,
        }
        .evidence()?;
        Ok((evidence, self.payer.1.credit_id(proof.outputs[0])))
    }
}

struct Settled {
    binding: PlanBinding,
    quote: [u8; 32],
    commitment: [u8; 32],
}
impl Settled {
    fn check(&self, attempt: &super::super::native::SignedAttempt) -> Result<()> {
        let parameters: serde_json::Value = serde_json::from_slice(
            attempt
                .transaction()
                .message
                .as_deref()
                .context("paid native purchase parameters missing")?,
        )?;
        ensure!(
            parameters.get(7).and_then(serde_json::Value::as_str)
                == Some(hex::encode(self.quote).as_str())
                && parameters.get(11).and_then(serde_json::Value::as_str)
                    == Some(hex::encode(self.commitment).as_str()),
            "saved private credit differs from its confirmed native output"
        );
        Ok(())
    }
}
