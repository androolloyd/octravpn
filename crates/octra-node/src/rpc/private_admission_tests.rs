//! BFT intake defers semantic private checks just like the native speculative
//! pools. Queue acceptance grants neither a proof verdict nor canonical state.
use super::*;
use octra_node_protocol::transaction::Nonce;

fn material() -> Value {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../octra-node-runtime/tests/fixtures/private-balance.json"
    ))
    .unwrap();
    let input = &fixture["cases"][0]["input"];
    json!({
        "public": input["public"],
        "payload": serde_json::from_slice::<Value>(
            &STANDARD.decode(input["payload"].as_str().unwrap()).unwrap()
        ).unwrap()
    })
}

fn transactions(fixture: &Fixture) -> Vec<Transaction> {
    let material = material();
    let payload = &material["payload"];
    let cases = [
        (11, OpType::Encrypt, payload.clone()),
        (12, OpType::Decrypt, payload.clone()),
        (
            13,
            OpType::Stealth,
            json!({
                "version":5,
                "delta_cipher":payload["cipher"],
                "commitment":payload["amount_commitment"],
                "range_proof_delta":payload["range_proof_balance"],
                "range_proof_balance":payload["range_proof_balance"],
                "eph_pub":"fixture ephemeral public key",
                "stealth_tag":"00".repeat(16),
                "enc_amount":"fixture encrypted amount",
                "claim_pub":"00".repeat(32),
                "amount_commitment":payload["amount_commitment"],
                "send_zero_proof":payload["zero_proof"]
            }),
        ),
        (
            14,
            OpType::Claim,
            json!({
                "version":5,"output_id":0,
                "claim_cipher":payload["cipher"],
                "commitment":payload["amount_commitment"],
                "claim_secret":"00".repeat(32),
                "zero_proof":payload["zero_proof"]
            }),
        ),
        // The KAT and public-key envelope are genuinely valid. Only the later
        // migration selector is invalid; malformed envelopes still fail intake.
        (
            11,
            OpType::KeySwitch,
            json!({
                "new_pubkey":material["public"],
                "aes_kat":octra_node_runtime::crypto_payload::expected_kat(),
                "migration_mode":"unsupported_semantic_mode"
            }),
        ),
    ];
    cases
        .into_iter()
        .map(|(who, op, payload)| {
            let address = payment_host::address(who);
            let target = if op == OpType::Stealth {
                "stealth"
            } else {
                &address
            };
            let mut tx = fixture.transaction(
                who,
                target,
                op,
                json!([]),
                if matches!(op, OpType::Encrypt | OpType::Decrypt) {
                    7
                } else {
                    0
                },
                serde_json::to_vec(&payload).unwrap(),
            );
            tx.message = None;
            tx.ou = 5000.into();
            if op == OpType::KeySwitch {
                tx.nonce = tx.nonce.successor();
            }
            sign_current(tx, who)
        })
        .collect()
}

#[tokio::test]
async fn private_rpc_acceptance_defers_invalid_semantics_without_receipts_or_mutation() {
    let fixture = Box::pin(Fixture::with_application(None, Application::Circle)).await;
    let rpc = Rpc::open(&fixture, fixture.native.clone()).await;
    let before = fixture.node.snapshot().unwrap();
    let accounts = (11..=14)
        .map(|who| account(&fixture, who))
        .collect::<Vec<_>>();
    let transactions = transactions(&fixture);
    for tx in &transactions {
        // These must reach the deferred stage, rather than pass because a
        // malformed payload or release-profile refusal is being ignored.
        octra_node_runtime::admission::payload(
            tx,
            octra_node_protocol::transaction_payload::Limits::default(),
        )
        .unwrap();
        assert_accepted(&rpc.submit(tx).await, tx);
        assert!(rpc.pending.transactions().unwrap().contains(tx));
        let failed = fixture
            .native
            .build_proposal(draft(&fixture).await, vec![tx.clone()])
            .await
            .err()
            .expect("semantically invalid private work entered a proposal");
        assert!(
            matches!(failed, executor::ProposalError::Invalid(_)),
            "{failed:?}"
        );
        assert!(fixture
            .node
            .store
            .vm_receipt(before.head(), hex::encode(tx.hash().unwrap()).as_bytes())
            .await
            .unwrap()
            .is_none());
    }
    assert_eq!(
        rpc.pending.transactions().unwrap().len(),
        transactions.len()
    );
    let after = fixture.node.snapshot().unwrap();
    assert_eq!(before.head(), after.head());
    assert_eq!(
        before.state().root().unwrap(),
        after.state().root().unwrap()
    );
    assert_eq!(
        accounts,
        (11..=14)
            .map(|who| account(&fixture, who))
            .collect::<Vec<_>>()
    );
    rpc.context.executor.shutdown_preverification().await;
    rpc.close().await;
    fixture.node.shutdown().await.unwrap();
}

#[tokio::test]
async fn private_rpc_still_refuses_bad_shape_signature_profile_and_nonce() {
    let fixture = Box::pin(Fixture::with_application(None, Application::Circle)).await;
    let rpc = Rpc::open(&fixture, fixture.native.clone()).await;
    let transactions = transactions(&fixture);
    let mut forged = transactions[0].clone();
    forged.signature = STANDARD.encode([0; 64]).into_bytes();
    assert_eq!(rpc.submit(&forged).await["error"]["code"], 101);
    let mut malformed = transactions[0].clone();
    malformed.encrypted_data = Some(b"{}".to_vec());
    assert_eq!(
        rpc.submit(&sign_current(malformed, 11)).await["error"]["code"],
        105
    );
    let mut wrong_kat = transactions[4].clone();
    let mut payload: Value =
        serde_json::from_slice(wrong_kat.encrypted_data.as_ref().unwrap()).unwrap();
    payload["aes_kat"] = json!("00".repeat(16));
    wrong_kat.encrypted_data = Some(serde_json::to_vec(&payload).unwrap());
    assert_eq!(
        rpc.submit(&sign_current(wrong_kat, 11)).await["error"]["code"],
        105
    );
    let mut stale = transactions[0].clone();
    stale.nonce = account(&fixture, 11).nonce;
    assert_eq!(
        rpc.submit(&sign_current(stale, 11)).await["error"]["code"],
        102
    );
    let disabled = Rpc::open(&fixture, configured(&fixture, Profile::default())).await;
    assert_eq!(
        disabled.submit(&transactions[0]).await["error"]["code"],
        116
    );
    assert!(rpc.pending.transactions().unwrap().is_empty());
    assert!(disabled.pending.transactions().unwrap().is_empty());
    disabled.close().await;
    rpc.context.executor.shutdown_preverification().await;
    rpc.close().await;
    fixture.node.shutdown().await.unwrap();
}

#[tokio::test]
async fn intake_route_refusals_precede_unknown_sender_and_signature_without_queue_effects() {
    let fixture = Box::pin(Fixture::with_application(None, Application::Circle)).await;
    let observer = Rpc::open(
        &fixture,
        fixture
            .native
            .clone()
            .with_submission_policy(true, Nonce::new(32).unwrap()),
    )
    .await;
    let disabled = Rpc::open(&fixture, configured(&fixture, Profile::default())).await;
    let before = fixture.node.snapshot().unwrap();
    let mut unknown = fixture.transaction(
        11,
        &payment_host::address(12),
        OpType::Standard,
        json!([]),
        1,
        vec![],
    );
    unknown.from = payment_host::address(99).into_bytes();
    unknown.public_key = Some(
        STANDARD
            .encode(payment_host::key(99).verifying_key().to_bytes())
            .into_bytes(),
    );
    unknown.nonce = Nonce::new(1).unwrap();
    unknown.message = None;
    unknown.encrypted_data = None;
    unknown = sign_current(unknown, 99);
    unknown.signature = STANDARD.encode([0; 64]).into_bytes();
    assert!(account_store::load(
        &StateBatch::from_snapshot(before.state().clone()),
        &unknown.from
    )
    .unwrap()
    .is_none());
    // The native route refuses observer/profile before looking up the sender or
    // authenticating this deliberately invalid signature and private payload.
    assert_eq!(observer.submit(&unknown).await["error"]["code"], 117);
    unknown.op_type = OpType::Encrypt;
    unknown.to.clone_from(&unknown.from);
    assert_eq!(disabled.submit(&unknown).await["error"]["code"], 116);
    assert!(observer.pending.transactions().unwrap().is_empty());
    assert!(disabled.pending.transactions().unwrap().is_empty());
    let after = fixture.node.snapshot().unwrap();
    assert_eq!(before.head(), after.head());
    assert_eq!(
        before.state().root().unwrap(),
        after.state().root().unwrap()
    );
    observer.close().await;
    disabled.close().await;
    fixture.native.shutdown_preverification().await;
    fixture.node.shutdown().await.unwrap();
}

#[tokio::test]
async fn intake_compute_refusal_precedes_timestamp_observer_and_profile() {
    let fixture = Box::pin(Fixture::with_application(None, Application::Circle)).await;
    let observer = Rpc::open(
        &fixture,
        fixture
            .native
            .clone()
            .with_submission_policy(true, Nonce::new(32).unwrap()),
    )
    .await;
    let disabled = Rpc::open(&fixture, configured(&fixture, Profile::default())).await;
    let before = fixture.node.snapshot().unwrap();
    let mut tx = fixture.transaction(
        11,
        &payment_host::address(12),
        OpType::ComputeFund,
        json!([]),
        1,
        vec![],
    );
    tx.message = None;
    tx.encrypted_data = None;
    tx.timestamp = 0.;
    tx.signature = STANDARD.encode([0; 64]).into_bytes();
    // Native Node_rest_facade.validate_and_submit_tx checks inactive compute
    // transfers before its Tx_view pre_route timestamp/observer/profile checks.
    for rpc in [&observer, &disabled] {
        let response = rpc.submit(&tx).await;
        assert_eq!(response["error"]["code"], 105, "{response}");
        assert_eq!(
            response["error"]["data"], "compute transfers not active",
            "{response}"
        );
        assert!(rpc.pending.transactions().unwrap().is_empty());
    }
    let after = fixture.node.snapshot().unwrap();
    assert_eq!(before.head(), after.head());
    assert_eq!(
        before.state().root().unwrap(),
        after.state().root().unwrap()
    );
    observer.close().await;
    disabled.close().await;
    fixture.native.shutdown_preverification().await;
    fixture.node.shutdown().await.unwrap();
}
