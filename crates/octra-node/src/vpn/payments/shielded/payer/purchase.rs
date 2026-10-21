use super::super::Limits;
use super::{
    records::{Accepted, Coin, Creation, Intent},
    Incoming, Payer, Progress, Proposal, INTENT,
};
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use octra_private_payments_experimental::{
    invoice::{Consent, Settlement, SignedInvoice},
    pool::{self, envelope, transaction::Prover, Membership, PoolIndex},
};

impl Payer {
    pub(super) async fn consent(
        &self,
        signed: &SignedInvoice,
        limits: &Limits,
    ) -> Result<(Consent, crate::SnapshotLease)> {
        let q = &signed.invoice;
        let terms = self.1.directory.offer(q.offer).await?;
        ensure!(terms.purchasable(), "payer offer is no longer purchasable");
        let Settlement::ShieldedPool { circle, note_owner } = &q.settlement else {
            anyhow::bail!("payer requires a shielded invoice");
        };
        ensure!(*circle == self.1.address, "payer settlement pool differs");
        let class = terms
            .tariff
            .classes()
            .get(usize::from(limits.traffic_class))
            .context("payer traffic class missing")?;
        Ok((
            Consent {
                chain_origin: self.1.origin,
                directory_circle: super::super::native(&self.1.directory.config.program)?,
                operator_key: terms.receipt_key.context("payer operator key missing")?.0,
                bond_generation: terms.operator_generation,
                offer: terms.offer,
                tariff_hash: super::super::hash(&terms.manifest_hash)?,
                receipt_key: limits.receipt_key,
                settlement: Settlement::ShieldedPool {
                    circle: self.1.address,
                    note_owner: *note_owner,
                },
                traffic_class: limits.traffic_class,
                rate_ou_per_mib: class.rate_ou_per_mib,
                max_bytes: limits.max_bytes,
                max_cost_ou: limits.max_cost_ou,
                canonical_ms: terms.canonical_ms,
                active_from_ms: terms.offer_start_ms,
                purchase_deadline_ms: (terms.offer_end_ms != 0).then_some(terms.offer_end_ms),
            },
            terms.publication().clone(),
        ))
    }
    async fn stage(
        &self,
        signed: &SignedInvoice,
        limits: &Limits,
        index: &PoolIndex,
        relayer: [u8; 47],
    ) -> Result<Intent> {
        let quote = signed.id()?;
        let accepted = Accepted {
            receipt: limits.receipt_key,
            class: limits.traffic_class,
            bytes: limits.max_bytes,
            cost: limits.max_cost_ou,
            relayer: std::str::from_utf8(&relayer)?.to_owned(),
        };
        let encoded = signed.encode_private()?;
        let mut tx = self.0.disk.begin().await?;
        if let Some(intent) = self
            .0
            .disk
            .load::<Intent>(&mut tx, INTENT, &self.intent_tag(&quote)?)
            .await?
        {
            ensure!(
                intent.invoice == *encoded && intent.accepted == accepted,
                "payer retry changes accepted purchase limits"
            );
            ensure!(
                matches!(intent.progress, Progress::Preparing | Progress::Ready),
                "payer quote is already final"
            );
            tx.rollback().await?;
            return Ok(intent);
        }
        tx.rollback().await?;
        let cost = signed.invoice.amount_ou()?;
        ensure!(cost > 0, "zero-rate traffic uses a free grant");
        let chosen = self.select(cost, index).await?;
        let total = Self::total(&chosen)?;
        self.reserve(
            INTENT,
            quote,
            chosen,
            u8::from(total > cost),
            |inputs, change_slot| Intent {
                invoice: encoded.to_vec(),
                accepted,
                inputs,
                change_slot,
                progress: Progress::Preparing,
                attempt: None,
            },
        )
        .await
    }
    fn proposal(&self, quote: [u8; 32], intent: &Intent) -> Result<Proposal> {
        let attempt = intent
            .attempt
            .clone()
            .context("payer proof has not been prepared")?;
        let result = Proposal {
            quote,
            attempt,
            source: self.1.clone(),
            change_slot: intent.change_slot,
        };
        result.statement()?;
        Ok(result)
    }
    pub(super) async fn ready(
        &self,
        signed: &SignedInvoice,
        limits: &Limits,
        index: &PoolIndex,
        intent: &Intent,
    ) -> Result<Proposal> {
        let (consent, offer) = self.consent(signed, limits).await?;
        let quote = signed.verify(&consent)?;
        let (pool, _) = self.current(index).await?;
        ensure!(
            pool.committed().head() == offer.committed().head(),
            "payer offer publication changed while preparing"
        );
        offer.with_current(super::super::PLAN_MAX_AGE, || self.proposal(quote, intent))
    }
    /// Reserve notes and the change key before proving. Retries retain the
    /// exact consent and inputs; root rebasing cannot authorize another debit.
    pub async fn prepare(
        &self,
        signed: &SignedInvoice,
        limits: &Limits,
        index: &PoolIndex,
        relayer: [u8; 47],
        prover: &Prover,
    ) -> Result<Proposal> {
        let _gate = self.0.gate.lock().await;
        super::super::native(std::str::from_utf8(&relayer)?)?;
        self.current(index).await?;
        let (consent, _) = self.consent(signed, limits).await?;
        let quote = signed.verify(&consent)?;
        ensure!(
            prover.verification_key()? == STANDARD.decode(&self.1.config.verification_key_b64)?,
            "payer prover does not match the accepted pool key"
        );
        let mut intent = self.stage(signed, limits, index, relayer).await?;
        let roots = index.roots();
        if intent.attempt.as_ref().is_some_and(|a| {
            a.roots == [pool::encode_field(roots.0), pool::encode_field(roots.1)]
                && a.count == roots.2
        }) {
            return self.ready(signed, limits, index, &intent).await;
        }
        let (inputs, total) = self.reserved(quote, &intent.inputs, index, false).await?;
        let purchase = pool::purchase::prepare(signed, &consent)?;
        let cost = signed.invoice.amount_ou()?;
        let change = total
            .checked_sub(cost)
            .context("payer input no longer covers purchase")?;
        let change = if let Some(slot) = intent.change_slot {
            let address = self.note_address(slot)?;
            Some(envelope::Draft::new(
                pool::decode_field(&address.owner)?,
                change,
                &address.view_public,
            )?)
        } else {
            ensure!(change == 0, "payer change slot missing");
            None
        };
        let call = purchase.call(change.as_ref(), relayer);
        let context = call.context(&self.1.origin, &self.1.address, &relayer)?;
        let mut outputs = vec![purchase.output.bind(&context)];
        if let Some(change) = &change {
            outputs.push(change.bind(&context));
        }
        let attempt = self
            .prove(
                index,
                &call,
                &relayer,
                &inputs,
                &outputs,
                consent.canonical_ms,
                prover,
            )
            .await?;
        intent.attempt = Some(attempt);
        intent.progress = Progress::Ready;
        let mut tx = self.0.disk.begin().await?;
        self.0
            .disk
            .replace(&mut tx, INTENT, &self.intent_tag(&quote)?, &intent)
            .await?;
        self.0.disk.commit(tx).await?;
        self.ready(signed, limits, index, &intent).await
    }
    /// Canonical inclusion, not an operator HTTP acknowledgement, finalizes a
    /// purchase. The exact change note is imported without resetting an already
    /// imported note's later reservation or spend state.
    pub async fn complete(
        &self,
        quote: [u8; 32],
        index: &PoolIndex,
        epoch: u64,
        operator: &Membership,
        change: Option<&Membership>,
    ) -> Result<()> {
        let _gate = self.0.gate.lock().await;
        self.current(index).await?;
        let mut tx = self.0.disk.begin().await?;
        let mut intent: Intent = self
            .0
            .disk
            .load(&mut tx, INTENT, &self.intent_tag(&quote)?)
            .await?
            .context("payer intent missing")?;
        tx.rollback().await?;
        if intent.progress == Progress::Paid {
            return Ok(());
        }
        ensure!(
            intent.progress == Progress::Ready,
            "payer intent has no published proposal"
        );
        let proposal = self.proposal(quote, &intent)?;
        ensure!(
            operator.index == proposal.first_output_index()?,
            "payer receipt output position differs"
        );
        let at = self
            .locate(epoch, proposal.attempt.outputs[0], operator)
            .await?;
        let call = proposal.call()?;
        ensure!(
            at.paid_at >= call.valid_from_ms && at.paid_at < call.expires_ms,
            "payer payment occurred outside accepted window"
        );
        let mut states = Vec::new();
        for id in &intent.inputs {
            let coin = self.input(id).await?;
            ensure!(
                coin.reserved == Some(quote) && !coin.spent,
                "payer input ownership changed"
            );
            let (note, key) = self.open_coin_at(&coin, index).await?;
            states.push(index.spent(&pool::encode_field(note.nullifier(self.1.domain, &key)?))?);
        }
        ensure!(
            states.iter().all(|s| *s) || states.iter().all(|s| !*s),
            "payer has a mixed unexpected input spend"
        );
        let spent = states.iter().all(|s| *s);
        let incoming = if spent {
            match (intent.change_slot, change) {
                (Some(slot), Some(path)) => {
                    ensure!(
                        u64::from(path.index) == proposal.attempt.count + 1,
                        "payer change position differs"
                    );
                    let incoming = Incoming {
                        slot,
                        epoch,
                        commitment: proposal.attempt.outputs[1],
                        membership: path,
                        output: 1,
                        call: &call,
                        relayer: super::super::native(&proposal.attempt.call.relayer)?,
                    };
                    let coin = Coin {
                        slot,
                        creation: Creation::new(&incoming)?,
                        reserved: None,
                        spent: false,
                        income: None,
                    };
                    self.open_coin(&coin).await?;
                    Some(coin)
                }
                (None, None) => None,
                _ => anyhow::bail!("payer change inclusion missing or unexpected"),
            }
        } else {
            // Another payer may have funded this same invoice. Its canonical
            // output changed the append root, so our old proof cannot execute.
            ensure!(
                index.roots().2 > proposal.attempt.count,
                "payer sponsored purchase has not invalidated original roots"
            );
            None
        };
        self.current(index).await?;
        let mut tx = self.0.disk.begin().await?;
        self.finish_notes(&mut tx, quote, &intent.inputs, spent, incoming)
            .await?;
        intent.progress = Progress::Paid;
        self.0
            .disk
            .replace(&mut tx, INTENT, &self.intent_tag(&quote)?, &intent)
            .await?;
        self.0.disk.commit(tx).await
    }
    /// Release only definitely unspent reservations after both canonical expiry
    /// and invalidation of every exposed proof's old roots. A local timeout or
    /// a regressing future epoch clock cannot authorize an input twice.
    pub async fn expire(&self, quote: [u8; 32], index: &PoolIndex) -> Result<()> {
        self.release(quote, index, true).await
    }
    /// Cancel before expiry only when no proof was exposed, or canonical roots
    /// already invalidated it. Spent input notes always require reconciliation.
    pub async fn cancel(&self, quote: [u8; 32], index: &PoolIndex) -> Result<()> {
        self.release(quote, index, false).await
    }
    async fn release(&self, quote: [u8; 32], index: &PoolIndex, expired: bool) -> Result<()> {
        let _gate = self.0.gate.lock().await;
        let (_, now) = self.current(index).await?;
        let mut tx = self.0.disk.begin().await?;
        let mut intent: Intent = self
            .0
            .disk
            .load(&mut tx, INTENT, &self.intent_tag(&quote)?)
            .await?
            .context("payer intent missing")?;
        tx.rollback().await?;
        if matches!(intent.progress, Progress::Expired | Progress::Cancelled) {
            return Ok(());
        }
        ensure!(
            intent.progress != Progress::Paid,
            "payer purchase is already final"
        );
        let invoice = SignedInvoice::decode_private(&intent.invoice)?;
        ensure!(
            !expired || now >= invoice.invoice.expires_ms,
            "payer invoice has not canonically expired"
        );
        self.release_safe(quote, &intent.inputs, intent.attempt.as_ref(), index)
            .await?;
        self.current(index).await?;
        let mut tx = self.0.disk.begin().await?;
        self.finish_notes(&mut tx, quote, &intent.inputs, false, None)
            .await?;
        intent.progress = if expired {
            Progress::Expired
        } else {
            Progress::Cancelled
        };
        self.0
            .disk
            .replace(&mut tx, INTENT, &self.intent_tag(&quote)?, &intent)
            .await?;
        self.0.disk.commit(tx).await
    }
}
