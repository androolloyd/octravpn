use anyhow::{ensure, Result};
use octra_node_protocol::{
    state::Ledger,
    transaction, transaction_outcome,
    transaction_policy::{self, Profile},
};
pub use octra_node_runtime::proposal_select::Limits;
use octra_node_runtime::{
    admission,
    consensus_bundle::{Accepted, Rules},
};

pub(super) fn check(
    profile: &Profile,
    limits: &Limits,
    rules: &Rules,
    bundle: &Accepted,
    ledger: &Ledger,
) -> Result<()> {
    let inputs = transaction_outcome::merge(&bundle.txs, &bundle.rejections)?;
    transaction::check_compute(rules.envelope.compute, rules.envelope.settle, &inputs)?;
    transaction::check_envelopes(rules.envelope.envelope, &inputs)?;
    transaction_outcome::check_charged(rules.envelope.compute, &bundle.rejections)?;
    for tx in &inputs {
        ensure!(
            profile.consensus_admits(tx.op_type),
            "disabled operation: {}",
            tx.op_type.as_str()
        );
    }
    for tx in &inputs {
        ensure!(
            tx.ou >= transaction_policy::ou_cost(tx, &rules.stealth_minimum),
            "underpriced transaction"
        );
    }
    ensure!(
        limits.within(&inputs, &rules.stealth_minimum)?,
        "bundle limit exceeded"
    );
    for tx in &inputs {
        admission::signature(
            tx,
            ledger
                .account(&tx.from)
                .and_then(|a| a.public_key.as_deref()),
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use ed25519_dalek::{Signer, SigningKey};
    use octra_node_protocol::transaction::{
        address_from_public_key, Nonce, OpType, RuleMode, Transaction,
    };

    fn transfer(nonce: i64) -> Transaction {
        let key = SigningKey::from_bytes(&[91; 32]);
        let public = STANDARD.encode(key.verifying_key().to_bytes()).into_bytes();
        let mut tx = Transaction {
            from: address_from_public_key(&public),
            to: address_from_public_key(b"receiver"),
            amount: 1.into(),
            nonce: Nonce::new(nonce).unwrap(),
            ou: 100_000.into(),
            timestamp: 10.,
            signature: vec![],
            public_key: Some(public),
            message: None,
            encrypted_data: None,
            op_type: OpType::Standard,
        };
        tx.signature = STANDARD
            .encode(key.sign(&tx.signing_bytes().unwrap()).to_bytes())
            .into_bytes();
        tx
    }
    fn rules() -> Rules {
        Rules {
            payload: octra_node_protocol::transaction_payload::Limits::default(),
            crypto_active: false,
            stealth_minimum: 5000.into(),
            envelope: transaction_outcome::Rules {
                envelope: RuleMode::Active,
                compute: RuleMode::Prior,
                settle: RuleMode::Prior,
            },
        }
    }
    fn bundle(confirmed: Vec<Transaction>, rejected: Transaction) -> Accepted {
        let mut inputs = confirmed.clone();
        inputs.push(rejected.clone());
        Accepted {
            tx_hashes: confirmed
                .iter()
                .map(|tx| hex::encode(tx.hash().unwrap()).into_bytes())
                .collect(),
            txs: confirmed,
            receipts_json: vec![],
            rejections: transaction_outcome::build(
                &inputs,
                &[(
                    rejected,
                    b"insufficient_balance".to_vec(),
                    b"fixture".to_vec(),
                )],
                &[],
            )
            .unwrap(),
        }
    }

    #[test]
    fn rejected_candidates_cannot_bypass_signature_or_operation_admission() {
        let ledger = Ledger::from_accounts(std::collections::BTreeMap::new()).unwrap();
        let limits = Limits::new(2, 10_000, 100_000.into());
        let good = transfer(1);
        let mut bad = transfer(2);
        bad.signature[0] ^= 1;
        let rejected = bundle(vec![good.clone()], bad);
        assert!(
            check(&Profile::default(), &limits, &rules(), &rejected, &ledger)
                .unwrap_err()
                .to_string()
                .contains("signature")
        );
        let mut disabled = transfer(2);
        disabled.op_type = OpType::CircleCall;
        let rejected = bundle(vec![good], disabled);
        assert!(
            check(&Profile::default(), &limits, &rules(), &rejected, &ledger)
                .unwrap_err()
                .to_string()
                .contains("disabled operation")
        );
    }

    #[test]
    fn bundle_budget_includes_rejections_and_counts_scheduled_cost() {
        let ledger = Ledger::from_accounts(std::collections::BTreeMap::new()).unwrap();
        let candidate = bundle(vec![transfer(1)], transfer(2));
        // Offered fees total 200,000 OU, but native scheduled costs total 2,000.
        check(
            &Profile::default(),
            &Limits::new(2, 10_000, 2000.into()),
            &rules(),
            &candidate,
            &ledger,
        )
        .unwrap();
        for limits in [
            Limits::new(1, 10_000, 2000.into()),
            Limits::new(2, 10_000, 1999.into()),
        ] {
            assert!(
                check(&Profile::default(), &limits, &rules(), &candidate, &ledger)
                    .unwrap_err()
                    .to_string()
                    .contains("bundle limit")
            );
        }
        let mut underpriced = transfer(2);
        underpriced.ou = 999.into();
        assert!(check(
            &Profile::default(),
            &Limits::new(2, 10_000, 2000.into()),
            &rules(),
            &bundle(vec![transfer(1)], underpriced),
            &ledger
        )
        .unwrap_err()
        .to_string()
        .contains("underpriced"));
    }
}
