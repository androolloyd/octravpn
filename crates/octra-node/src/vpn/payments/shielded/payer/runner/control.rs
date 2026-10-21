use super::{Purchase, REPLY};
use anyhow::{ensure, Context, Result};
use octra_private_payments_experimental::invoice::SignedInvoice;
use octravpn_core::{
    payments::{
        PlanBinding, PrivateAction, PrivateExchange, PrivateRequest, PrivateResult,
        SignedPrivateReply, SignedPrivateRequest,
    },
    Address,
};

impl Purchase {
    pub(super) fn quote_phase(&self, slot: usize) -> Result<u8> {
        self.terms.class(slot)?;
        Ok(u8::try_from(
            slot.checked_mul(2)
                .and_then(|p| p.checked_add(1))
                .context("private class phase overflow")?,
        )?)
    }
    pub(super) fn receipt_phase(&self, slot: usize) -> Result<u8> {
        self.quote_phase(slot)?
            .checked_add(1)
            .context("private class phase overflow")
    }
    fn phase_slot(&self, phase: u8) -> Result<usize> {
        ensure!(phase > 0, "private class phase missing");
        let slot = usize::from((phase - 1) / 2);
        self.terms.class(slot)?;
        Ok(slot)
    }
    pub(super) fn request_id(&self, phase: u8) -> Result<[u8; 32]> {
        Ok(*self.payer.0.key.derive_bytes(
            b"private purchase request v1",
            &[self.payer.0.wallet.as_slice(), &self.id, &[phase]].concat(),
        )?)
    }
    async fn request(
        &self,
        phase: u8,
        action: PrivateAction,
        window: Option<(u64, u64)>,
    ) -> Result<SignedPrivateRequest> {
        let key = self.receipt_identity()?;
        let id = self.request_id(phase)?;
        if let Some(saved) = self.payer.recorded_request(id, key.public).await? {
            ensure!(
                saved.request.target == self.terms.target
                    && serde_json::to_vec(&saved.request.action)? == serde_json::to_vec(&action)?,
                "private purchase request changes saved terms"
            );
            return Ok(saved);
        }
        let (valid_from_ms, expires_ms) =
            window.unwrap_or((self.terms.valid_from_ms, self.terms.expires_ms));
        self.payer
            .record_request(SignedPrivateRequest::sign(
                PrivateRequest {
                    target: self.terms.target.clone(),
                    id,
                    valid_from_ms,
                    expires_ms,
                    action,
                },
                &key,
            )?)
            .await
    }
    pub(super) async fn open_request(&self) -> Result<SignedPrivateRequest> {
        self.request(
            0,
            PrivateAction::Open {
                offer: self.terms.offer,
                ceiling_ou: self.terms.ceiling_ou,
            },
            None,
        )
        .await
    }
    pub(super) async fn quote_request(
        &self,
        channel: u64,
        slot: usize,
    ) -> Result<SignedPrivateRequest> {
        let class = self.terms.class(slot)?;
        self.request(
            self.quote_phase(slot)?,
            PrivateAction::Quote {
                channel,
                class: class.traffic_class,
                bytes: class.bytes,
                validity_ms: self.terms.invoice_lifetime_ms,
            },
            None,
        )
        .await
    }
    pub(super) async fn receipt_request(
        &self,
        channel: u64,
        quote: [u8; 32],
        evidence: String,
        now: u64,
        slot: usize,
    ) -> Result<SignedPrivateRequest> {
        self.request(
            self.receipt_phase(slot)?,
            PrivateAction::Receipt {
                channel,
                quote,
                evidence,
            },
            Some((
                now,
                now.checked_add(86_400_000)
                    .context("private receipt window overflow")?,
            )),
        )
        .await
    }
    pub(super) async fn reply(&self, phase: u8) -> Result<Option<PrivateResult>> {
        let mut tx = self.payer.0.disk.begin().await?;
        let saved: Option<SignedPrivateReply> = self
            .payer
            .0
            .disk
            .load(&mut tx, REPLY, &self.tag(REPLY, phase)?)
            .await?;
        tx.rollback().await?;
        let Some(saved) = saved else {
            return Ok(None);
        };
        let key = self.receipt_identity()?;
        let id = self.request_id(phase)?;
        let request = self.payer.saved_request(id, key.public).await?;
        Ok(Some(serde_json::from_slice(&saved.verify(&request)?)?))
    }
    pub(super) async fn exchange(
        &self,
        phase: u8,
        request: &SignedPrivateRequest,
        control: &dyn PrivateExchange,
    ) -> Result<PrivateResult> {
        let reply = control.exchange(request).await?;
        let result: PrivateResult = serde_json::from_slice(&reply.verify(request)?)?;
        match phase {
            0 => {
                self.opened(&result)?;
            }
            phase if phase % 2 == 1 => {
                let slot = self.phase_slot(phase)?;
                let PrivateAction::Quote { channel, .. } = request.request.action else {
                    anyhow::bail!("private quote action differs");
                };
                let invoice = self.quoted(&result, channel, slot)?;
                let (consent, lease) = self.payer.consent(&invoice, &self.limits(slot)?).await?;
                invoice.verify(&consent)?;
                lease.with_current(crate::vpn::payments::PLAN_MAX_AGE, || Ok(()))?;
            }
            phase => {
                self.phase_slot(phase)?;
                let PrivateAction::Receipt { channel, quote, .. } = &request.request.action else {
                    anyhow::bail!("private receipt action differs");
                };
                let PrivateResult::Receipt {
                    channel: got,
                    quote: id,
                    credit_id,
                } = &result
                else {
                    anyhow::bail!("private receipt reply differs");
                };
                ensure!(
                    got == channel && id == quote,
                    "private receipt identity differs"
                );
                // The acknowledgement must identify our exact canonical note,
                // not merely echo the operator's own channel/quote identifiers.
                let expected = self.receipt_credit(*quote).await?;
                ensure!(*credit_id == expected, "private receipt credit differs");
            }
        }
        let mut tx = self.payer.0.disk.begin().await?;
        self.payer
            .0
            .disk
            .insert(&mut tx, REPLY, &self.tag(REPLY, phase)?, &[0; 32], &reply)
            .await?;
        self.payer.0.disk.commit(tx).await?;
        Ok(result)
    }
    pub(super) fn opened(&self, result: &PrivateResult) -> Result<PlanBinding> {
        let PrivateResult::Open {
            binding,
            operator_generation,
            tariff,
            ceiling_ou,
        } = result
        else {
            anyhow::bail!("private open reply differs");
        };
        binding.validate()?;
        ensure!(
            binding.deployment == self.terms.target.pool
                && binding.payer == Address::from_pubkey(&self.receipt_identity()?.public.0)
                && binding.generation == 1
                && binding.plan > 0
                && binding.offer == self.terms.offer
                && binding.manifest_hash == self.terms.manifest_hash
                && tariff.hash_hex()? == self.terms.manifest_hash
                && *operator_generation == self.terms.operator_generation
                && *ceiling_ou == self.terms.ceiling_ou,
            "private channel changes accepted terms"
        );
        Ok(binding.as_ref().clone())
    }
    pub(super) fn quoted(
        &self,
        result: &PrivateResult,
        channel: u64,
        slot: usize,
    ) -> Result<SignedInvoice> {
        let class = self.terms.class(slot)?;
        let PrivateResult::Quote {
            channel: got,
            invoice,
        } = result
        else {
            anyhow::bail!("private quote reply differs");
        };
        ensure!(invoice.len() <= 43_692, "private invoice exceeds bound");
        let bytes = octravpn_core::b64::decode(invoice)?;
        ensure!(
            bytes.len() <= 32_768 && octravpn_core::b64::encode(&bytes) == *invoice,
            "private invoice encoding differs"
        );
        let signed = SignedInvoice::decode_private(&bytes)?;
        let q = &signed.invoice;
        ensure!(
            *got == channel
                && q.offer == self.terms.offer
                && q.chain_origin == self.terms.target.chain_origin
                && q.directory_circle.as_slice()
                    == self.terms.target.directory.display().as_bytes()
                && q.operator_key == self.terms.target.operator.0
                && q.bond_generation == self.terms.operator_generation
                && hex::encode(q.tariff_hash) == self.terms.manifest_hash
                && q.receipt_key == self.receipt_identity()?.public.0
                && q.traffic_class == class.traffic_class
                && q.bytes == class.bytes
                && q.amount_ou()? <= class.max_cost_ou
                && q.valid_from_ms >= self.terms.valid_from_ms
                && q.expires_ms <= self.terms.expires_ms,
            "private invoice changes accepted terms"
        );
        Ok(signed)
    }
    pub(super) fn limits(&self, slot: usize) -> Result<super::super::super::Limits> {
        let class = self.terms.class(slot)?;
        Ok(super::super::super::Limits {
            receipt_key: self.receipt_identity()?.public.0,
            traffic_class: class.traffic_class,
            max_bytes: class.bytes,
            max_cost_ou: class.max_cost_ou,
        })
    }
    pub(super) async fn check_offer(&self) -> Result<()> {
        let offer = self.payer.1.offer(self.terms.offer).await?;
        ensure!(
            offer.purchasable()
                && offer.manifest_hash == self.terms.manifest_hash
                && offer.operator_generation == self.terms.operator_generation
                && offer.receipt_key.context("private operator key missing")?
                    == self.terms.target.operator,
            "private purchase differs from canonical offer"
        );
        Ok(())
    }
}
