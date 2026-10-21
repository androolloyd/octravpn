//! Proof of an already settled purchase while this node is not serving.
//! This cannot reconcile notes, reserve fees, sign, submit or buy capacity.
use super::{native::Operation, native::SignedAttempt, records::Intent, Payer, Progress, INTENT};
use anyhow::{ensure, Context, Result};
use std::sync::Arc;

pub(super) struct Permit {
    shared: Arc<crate::Shared>,
    ticket: crate::published::RootQuarantineTicket,
}
impl Permit {
    pub(super) fn check(&self) -> Result<()> {
        self.shared.with_root_ticket(&self.ticket, || Ok(()))
    }
}

impl Payer {
    pub(super) async fn retained_purchase<A: crate::Host>(
        &self,
        node: &crate::Node<A>,
        attempt: &SignedAttempt,
    ) -> Result<Permit> {
        ensure!(
            Arc::ptr_eq(&node.shared, &self.1.directory.shared),
            "retained purchase belongs to another node"
        );
        self.saved_native(attempt).await?;
        let Operation::Purchase(quote) = attempt.operation else {
            anyhow::bail!("only settled capacity can reconnect an entry");
        };
        let mut tx = self.0.disk.begin().await?;
        let intent: Intent = self
            .0
            .disk
            .load(&mut tx, INTENT, &self.intent_tag(&quote)?)
            .await?
            .context("settled purchase intent missing")?;
        tx.rollback().await?;
        let prepared = intent.attempt.context("settled purchase proof missing")?;
        let parameters: serde_json::Value = serde_json::from_slice(
            attempt
                .transaction()
                .message
                .as_deref()
                .context("settled purchase parameters missing")?,
        )?;
        ensure!(
            intent.progress == Progress::Paid
                && prepared.parameters == parameters
                && prepared.call.quote == quote
                && prepared.call.deposit == 0
                && prepared.call.withdraw == 0
                && parameters.get(11).and_then(serde_json::Value::as_str)
                    == Some(hex::encode(prepared.outputs[0]).as_str())
                && attempt.transaction().amount == 0.into(),
            "retained entry requires the exact already settled purchase"
        );
        let epoch = self
            .confirmation_location(&attempt.hash()?)
            .await?
            .context("settled purchase confirmation locator missing")?;
        let proof = self
            .recovery_proof(epoch)
            .await?
            .context("settled purchase retained execution proof missing")?;
        ensure!(proof.epoch() == epoch, "retained purchase epoch differs");
        let permit = Permit {
            shared: node.shared.clone(),
            ticket: node.shared.root_quarantine_ticket(),
        };
        permit.check()?;
        let committed = node.retained_view().await?;
        let verified = proof.verify_at(&self.1, &committed).await?;
        self.1.check_exchange(
            &verified.record,
            &parameters,
            &attempt.transaction().from.as_slice().try_into()?,
            0,
            Some(attempt.transaction()),
        )?;
        permit.check()?;
        Ok(permit)
    }
}

#[cfg(test)]
pub(crate) async fn qualification<A: crate::Host>(
    payer: &Payer,
    node: &crate::Node<A>,
    attempt: &SignedAttempt,
    paid: bool,
) {
    if !paid {
        assert!(payer.retained_purchase(node, attempt).await.is_err());
        return;
    }
    node.suspend("retained entry proof qualification before chain sync");
    assert!(crate::SnapshotLease::capture(node.shared.clone()).is_err());
    assert!(payer.confirmed_native(attempt).await.is_err());
    let permit = payer.retained_purchase(node, attempt).await.unwrap();
    permit.check().unwrap();
    // Historical proof verification did not publish a fresh chain view.
    assert!(crate::SnapshotLease::capture(node.shared.clone()).is_err());
    let epoch = payer
        .confirmation_location(&attempt.hash().unwrap())
        .await
        .unwrap()
        .unwrap();
    let proof = payer.recovery_proof(epoch).await.unwrap().unwrap();
    let mut bytes = proof.encode().unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    let tampered = super::super::history::Proof::decode(&bytes).unwrap();
    assert!(tampered
        .verify_at(&payer.1, &node.retained_view().await.unwrap())
        .await
        .is_err());
    assert!(node.resume().await.unwrap());
    permit.check().unwrap();
}
