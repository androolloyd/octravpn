//! Production Program transaction tests for the staged payment application.
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::Signer;
use num_bigint::BigInt;
use octra_node_protocol::{
    contract, program_upgrade,
    state::Ledger,
    transaction::{self, OpType},
};
use octra_node_runtime::{epoch_execution::Effect, program::store};
use serde_json::{json, Value};
#[path = "common/payments_host.rs"]
#[allow(dead_code)]
mod harness;
use harness::*;

#[test]
fn local_compiler_artifact_matches_legacy_factory_execution() {
    use octra_node_protocol::program_trust::Keys;
    use octra_node_runtime::program::Artifact;
    use sha2::{Digest, Sha256};
    let compiled = payment_compilation();
    let code = STANDARD
        .decode(compiled["bytecode"].as_str().unwrap())
        .unwrap();
    assert!(code.starts_with(b"OCTB"));
    assert_eq!(binaries().0, code);
    assert!(compiled.get("program_envelope").is_none());
    assert!(compiled.get("deploy_payload").is_none());
    assert_eq!(compiled["certificate"]["declaration"], "program");
    assert_eq!(compiled["target_admission"], "legacy-binary");
    assert_eq!(compiled["typed_admission"], false);
    assert_eq!(
        compiled["certificate"]["schema"],
        "aml_bytecode_certificate_v1"
    );
    assert_eq!(
        compiled["certificate"]["source_hash"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../../program/octranet-payments.aml"
        )))
    );
    assert_eq!(
        compiled["certificate"]["bytecode_hash"],
        hex::encode(Sha256::digest(&code))
    );
    let legacy = Artifact::binary(&code, true, &Keys::default()).unwrap();
    assert_eq!(legacy.admission(), b"binary");
    assert!(legacy.admitted().facts().is_none());
    // Source certificates describe a build; this child is not typed Program
    // admission. The existing factory API deploys exactly this legacy image.
}

#[test]
fn operator_unstake_is_seven_days_and_independent_of_payer_exit() {
    let mut c = Chain::new();
    c.funded_plan();
    assert_eq!(c.number("get_operator_unstake_ms", json!([])), WEEK as u64);
    assert_eq!(c.number("get_user_exit_ms", json!([])), DAY as u64);
    c.now += 1000;
    let stopped = c.now;
    c.ok(11, "request_operator_unstake", json!([]), 0);
    assert_eq!(
        c.number("get_operator_unlock_ms", json!([address(11)])),
        (stopped + WEEK) as u64
    );
    assert_eq!(c.view("can_forward", json!([0])), false);
    c.denied(12, "open_plan", json!([0, 1]), 0, "operator unavailable");
    c.denied(11, "bond_operator", json!([]), 1, "operator unstaking");
    c.denied(
        13,
        "withdraw_operator_stake",
        json!([]),
        0,
        "unstake not requested",
    );
    c.now = stopped + DAY - 1;
    c.ok(13, "claim", c.receipt(0, 1, 1_048_576), 0);
    assert_eq!(c.number("get_earnings", json!([address(11)])), 10);
    c.now = stopped + DAY;
    c.denied(
        13,
        "claim",
        c.receipt(0, 2, 2_097_152),
        0,
        "operator settlement window closed",
    );
    c.ok(12, "release_stopped_plan", json!([0]), 0);
    assert_eq!(c.number("get_reserved", json!([address(12)])), 0);
    c.ok(11, "request_operator_unstake", json!([]), 0);
    assert_eq!(
        c.number("get_operator_unlock_ms", json!([address(11)])),
        (stopped + WEEK) as u64
    );
    c.ok(12, "request_exit", json!([]), 0);
    c.now += DAY;
    c.ok(12, "withdraw_remaining", json!([]), 0);
    assert_eq!(c.locked(), STAKE + 10);
    c.denied(
        11,
        "withdraw_operator_stake",
        json!([]),
        0,
        "operator unstake window open",
    );
    c.now = stopped + WEEK - 1;
    c.denied(
        11,
        "withdraw_operator_stake",
        json!([]),
        0,
        "operator unstake window open",
    );
    c.now = stopped + WEEK;
    c.ok(11, "withdraw_operator_stake", json!([]), 0);
    assert_eq!(c.locked(), 10);
    assert_eq!(c.number("get_earnings", json!([address(11)])), 10);
    c.ok(11, "withdraw_earnings", json!([10]), 0);
    assert_eq!(c.locked(), 0);
    assert_eq!(
        c.ledger.account(c.program.as_bytes()).unwrap().balance,
        BigInt::from(0)
    );
    c.denied(
        11,
        "withdraw_operator_stake",
        json!([]),
        0,
        "unstake not requested",
    );
}

#[test]
fn payer_has_exactly_24_hours_and_withdraws_successful_claim_difference() {
    let mut c = Chain::new();
    c.funded_plan();
    let deadline = START + DAY;
    c.ok(12, "request_exit", json!([]), 0);
    assert_eq!(c.view("can_forward", json!([0])), false);
    c.denied(
        12,
        "fund",
        json!([address(12)]),
        1,
        "account not accepting funds",
    );
    c.now = deadline - 1;
    c.denied(
        12,
        "withdraw_remaining",
        json!([]),
        0,
        "settlement window open",
    );
    c.ok(14, "claim", c.receipt(1, 1, 1_048_576), 0);
    c.ok(12, "request_exit", json!([]), 0);
    assert_eq!(
        c.number("get_exit_deadline_ms", json!([address(12)])),
        deadline as u64
    );
    c.now = deadline;
    c.denied(
        14,
        "claim",
        c.receipt(1, 2, 2_097_152),
        0,
        "claim window closed",
    );
    c.ok(12, "withdraw_remaining", json!([]), 0);
    assert_eq!(c.number("get_funds", json!([address(12)])), 0);
    assert_eq!(c.locked(), STAKE + 100);
    c.register(2);
    c.ok(12, "fund", json!([address(12)]), FUND);
    c.denied(
        14,
        "claim",
        c.receipt(1, 2, 2_097_152),
        0,
        "plan generation closed",
    );
    assert_eq!(c.number("get_funds", json!([address(12)])), FUND);
}

#[test]
fn tariffs_are_immutable_and_receipt_races_cannot_cancel_higher_authorizations() {
    let mut c = Chain::new();
    c.funded_plan();
    c.denied(11, "append_class", json!([0, 999]), 0, "offer immutable");
    c.denied(13, "append_class", json!([0, 999]), 0, "not offer operator");
    c.ok(12, "claim", c.receipt(0, 1000, 1), 0);
    c.ok(13, "claim", c.receipt(0, 1, 1_048_576), 0);
    assert_eq!(c.number("get_earnings", json!([address(11)])), 10);
    c.denied(
        13,
        "claim",
        c.receipt(0, 1, 1_048_576),
        0,
        "usage already redeemed",
    );
    c.ok(13, "claim", c.receipt(1, 1, 1_048_576), 0);
    assert_eq!(c.number("get_earnings", json!([address(11)])), 110);
    assert_eq!(c.number("get_funds", json!([address(12)])), FUND - 110);
    assert_eq!(c.number("get_reserved", json!([address(12)])), 890);
    assert_eq!(c.locked(), STAKE + FUND);
    c.denied(
        13,
        "claim",
        c.receipt(1, 2, 100 * 1_048_576),
        0,
        "plan budget exhausted",
    );
    c.denied(
        12,
        "open_plan",
        json!([0, FUND - 889]),
        0,
        "budget unavailable",
    );
    let mut altered = c.receipt(0, 3, 2_097_152);
    altered[1] = json!(1);
    c.denied(14, "claim", altered, 0, "invalid usage authorization");
    c.ok(13, "claim", c.receipt(0, 1, 2_097_152), 0);
    assert_eq!(c.number("get_earnings", json!([address(11)])), 120);
}

#[test]
fn invalid_clock_and_unauthorized_receipts_cannot_move_money() {
    let mut c = Chain::new();
    c.funded_plan();
    c.now = 0;
    c.denied(
        11,
        "request_operator_unstake",
        json!([]),
        0,
        "invalid canonical clock",
    );
    c.denied(12, "request_exit", json!([]), 0, "invalid canonical clock");
    c.denied(
        13,
        "claim",
        c.receipt(0, 1, 1),
        0,
        "invalid canonical clock",
    );
    c.now = START;
    c.denied(
        13,
        "claim",
        c.receipt(0, 0, 1),
        0,
        "invalid receipt sequence",
    );
    let mut bad_key = c.receipt(0, 1, 1);
    bad_key[4] = json!(sign(22, "wrong receipt key"));
    c.denied(13, "claim", bad_key, 0, "invalid usage authorization");
    let mut oversized = c.receipt(0, 1, 1);
    oversized[3] = json!("18446744073709551616");
    c.denied(13, "claim", oversized, 0, "exceeds uint64");
    let mut oversized_sequence = c.receipt(0, 1, 1);
    oversized_sequence[2] = json!("18446744073709551616");
    c.denied(
        13,
        "claim",
        oversized_sequence,
        0,
        "invalid receipt sequence",
    );
    let message = format!(
        "Octranet register v1|{DOMAIN}|{}|{}|1",
        c.program,
        address(13)
    );
    c.denied(
        13,
        "register",
        json!([
            STANDARD.encode(key(22).verifying_key().as_bytes()),
            sign(21, &message)
        ]),
        0,
        "receipt key possession failed",
    );
    assert_eq!(c.locked(), STAKE + FUND);
    assert_eq!(c.number("get_reserved", json!([address(12)])), 1000);
}

#[test]
fn legacy_uint_entry_guards_reject_negative_arguments_without_moving_custody() {
    let mut c = Chain::new();
    c.funded_plan();
    c.ok(11, "create_offer", json!([MANIFEST]), 0);
    let receipt = c.receipt(0, 1, 1);
    // The deployed child has no typed ABI facts. These refusals must come from
    // the unsigned guards embedded in the exact source-compiled OCTB image.
    for negative in [json!(-1), json!("-1")] {
        for index in 0..4 {
            let mut args = receipt.clone();
            args[index] = negative.clone();
            c.denied(13, "claim", args, 0, "execution reverted");
        }
        c.denied(
            12,
            "open_plan",
            json!([0, negative.clone()]),
            0,
            "execution reverted",
        );
        c.denied(
            11,
            "append_class",
            json!([1, negative.clone()]),
            0,
            "execution reverted",
        );
        c.denied(
            11,
            "withdraw_earnings",
            json!([negative]),
            0,
            "execution reverted",
        );
    }
    assert_eq!(c.number("get_offer_classes", json!([1])), 0);
    assert_eq!(c.number("get_reserved", json!([address(12)])), 1000);
    assert_eq!(c.number("get_funds", json!([address(12)])), FUND);
    assert_eq!(c.number("get_earnings", json!([address(11)])), 0);
    assert_eq!(c.locked(), STAKE + FUND);
    assert_eq!(c.view("can_forward", json!([0])), true);
}

#[test]
fn legacy_uint_entry_guards_reject_values_above_u256() {
    let mut c = Chain::new();
    c.funded_plan();
    c.ok(11, "create_offer", json!([MANIFEST]), 0);
    let receipt = c.receipt(0, 1, 1);
    // Legacy JSON accepts numeric strings, including native hexadecimal forms.
    // Both encodings must be bounded before any uint argument reaches the body.
    let overflow = BigInt::from(1_u8) << 256_usize;
    for oversized in [overflow.to_string(), format!("0x1{}", "0".repeat(64))] {
        for index in 0..4 {
            let mut args = receipt.clone();
            args[index] = json!(oversized);
            c.denied(13, "claim", args, 0, "execution reverted");
        }
        c.denied(
            12,
            "open_plan",
            json!([0, oversized]),
            0,
            "execution reverted",
        );
        c.denied(
            11,
            "append_class",
            json!([1, oversized]),
            0,
            "execution reverted",
        );
    }
    assert_eq!(c.number("get_offer_classes", json!([1])), 0);
    assert_eq!(c.number("get_plan_remaining", json!([0])), 1000);
    assert_eq!(c.number("get_reserved", json!([address(12)])), 1000);
    assert_eq!(c.locked(), STAKE + FUND);
}

#[test]
fn malformed_legacy_scalar_shapes_cannot_alias_a_funded_account_or_plan() {
    let mut c = Chain::new();
    c.funded_plan();
    let receipt = c.receipt(0, 1, 1);
    // Legacy deliberately coerces null/list/object arguments to an empty string
    // rather than applying a typed ABI. Check the actual application guards and
    // rollback, not a nonexistent typed-input rejection. Some other coercions
    // (such as a true budget) are accepted and are not asserted invalid here.
    for malformed in [Value::Null, json!([]), json!({"value": 0})] {
        c.denied(
            14,
            "fund",
            json!([malformed.clone()]),
            1,
            "account not accepting funds",
        );
        c.denied(
            12,
            "open_plan",
            json!([0, malformed.clone()]),
            0,
            "budget unavailable",
        );
        let mut args = receipt.clone();
        args[0] = malformed;
        c.denied(13, "claim", args, 0, "plan generation closed");
    }
    for account in [json!(true), json!(0), json!("not-an-address")] {
        c.denied(
            14,
            "fund",
            json!([account]),
            1,
            "account not accepting funds",
        );
    }
    assert_eq!(c.number("get_funds", json!([address(12)])), FUND);
    assert_eq!(c.number("get_reserved", json!([address(12)])), 1000);
    assert_eq!(c.number("get_earnings", json!([address(11)])), 0);
    assert_eq!(c.locked(), STAKE + FUND);
    assert_eq!(c.view("can_forward", json!([0])), true);
}

#[test]
fn small_order_receipt_keys_cannot_register_or_receive_custody() {
    let mut c = Chain::new();
    c.funded_plan();
    let mut identity = [0_u8; 32];
    identity[0] = 1;
    // R = identity, S = 0 would otherwise pass the signature equation for an
    // identity public key and any transcript. Exercise the VM's key guard via
    // real signed registration transactions, not only the Rust receipt codec.
    let mut forged_signature = [0_u8; 64];
    forged_signature[..32].copy_from_slice(&identity);
    for public in [identity, [0_u8; 32]] {
        assert!(!octra_node_protocol::network::public_key_safe(&public));
        c.denied(
            13,
            "register",
            json!([STANDARD.encode(public), STANDARD.encode(forged_signature)]),
            0,
            "receipt key possession failed",
        );
        assert_eq!(c.number("get_active", json!([address(13)])), 0);
        assert_eq!(c.number("get_generation", json!([address(13)])), 0);
        c.denied(
            14,
            "fund",
            json!([address(13)]),
            1,
            "account not accepting funds",
        );
    }
    assert_eq!(c.number("get_funds", json!([address(13)])), 0);
    assert_eq!(c.number("get_funds", json!([address(12)])), FUND);
    assert_eq!(c.number("get_reserved", json!([address(12)])), 1000);
    assert_eq!(c.locked(), STAKE + FUND);
}

#[test]
fn deployment_rejects_invalid_domains_stake_floors_and_liability_caps() {
    let mut c = Chain::new();
    for (params, reason) in [
        (
            json!(["a".repeat(63), 200_000_000, STAKE]),
            "digest must be lowercase SHA256",
        ),
        (
            json!(["A".repeat(64), 200_000_000, STAKE]),
            "digest must be lowercase SHA256",
        ),
        (
            json!([DOMAIN, 200_000_000, STAKE - 1]),
            "operator stake below floor",
        ),
        (json!([DOMAIN, STAKE, STAKE]), "invalid custody cap"),
        (json!([DOMAIN, 0, STAKE]), "invalid custody cap"),
        (
            json!([DOMAIN, "18446744073709551616", STAKE]),
            "invalid custody cap",
        ),
    ] {
        let root = c.state.root().unwrap();
        let target = String::from_utf8(contract::address(
            &binaries().0,
            address(14).as_bytes(),
            c.nonce(14).get(),
        ))
        .unwrap();
        let tx = c.transaction(
            14,
            &target,
            OpType::ContractDeploy,
            params,
            0,
            STANDARD.encode(&binaries().0).into_bytes(),
        );
        let (effect, _) = c.execute(&tx);
        let Effect::RejectedAfterFee { refusal, .. } = effect else {
            panic!("{effect:?}")
        };
        assert!(
            String::from_utf8_lossy(&refusal.reason).contains(reason),
            "{refusal:?}"
        );
        assert_eq!(c.state.root().unwrap(), root);
        assert!(store::meta(&c.state.snapshot(), target.as_bytes())
            .unwrap()
            .is_none());
    }
}

#[test]
fn signatures_cannot_be_replayed_into_another_program_or_domain() {
    let mut c = Chain::new();
    c.funded_plan();
    let authorization = c.receipt(0, 1, 1_048_576);
    let first = c.program.clone();
    let factory = c.factory.clone();
    let receipt = c.ok_at(
        11,
        &factory,
        "deploy_payments",
        json!([STANDARD.encode(&binaries().0), DOMAIN, 200_000_000, STAKE]),
        0,
    );
    receipt["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["event"] == "PaymentsDeployed")
        .unwrap()["values"][0]
        .as_str()
        .unwrap()
        .clone_into(&mut c.program);
    assert_ne!(first, c.program);
    c.funded_plan();
    c.denied(13, "claim", authorization, 0, "invalid usage authorization");
    let wrong_domain = format!(
        "Octranet usage v1|{MANIFEST}|{}|{}|1|0|0|{MANIFEST}|0|1|1048576",
        c.program,
        address(12)
    );
    c.denied(
        13,
        "claim",
        json!([0, 0, 1, 1_048_576, sign(21, &wrong_domain)]),
        0,
        "invalid usage authorization",
    );
}

#[test]
fn rebond_does_not_revive_an_old_offer_plan_or_claim_window() {
    let mut c = Chain::new();
    c.funded_plan();
    c.ok(11, "request_operator_unstake", json!([]), 0);
    c.now += WEEK;
    c.ok(11, "withdraw_operator_stake", json!([]), 0);
    c.ok(11, "bond_operator", json!([]), STAKE);
    assert_eq!(c.number("get_operator_generation", json!([address(11)])), 2);
    assert_eq!(c.view("can_forward", json!([0])), false);
    c.denied(
        12,
        "open_plan",
        json!([0, 1]),
        0,
        "operator generation closed",
    );
    c.denied(
        13,
        "claim",
        c.receipt(0, 1, 1_048_576),
        0,
        "operator settlement window closed",
    );
    c.ok(12, "release_stopped_plan", json!([0]), 0);
    c.ok(12, "release_stopped_plan", json!([0]), 0);
    assert_eq!(c.number("get_reserved", json!([address(12)])), 0);
    c.ok(11, "create_offer", json!([MANIFEST]), 0);
    c.ok(11, "append_class", json!([1, 0]), 0);
    c.ok(11, "seal_offer", json!([1]), 0);
    c.ok(12, "open_plan", json!([1, FUND]), 0);
    assert_eq!(c.view("can_forward", json!([1])), true);
}

#[test]
fn failed_transfers_roll_back_liabilities_and_custody_cap_includes_stake() {
    let mut c = Chain::new();
    c.funded_plan();
    c.denied(
        12,
        "fund",
        json!([address(12)]),
        100_000_000,
        "custody cap exceeded",
    );
    c.ok(13, "claim", c.receipt(0, 1, 1_048_576), 0);
    let mut accounts = c.ledger.accounts().clone();
    accounts.get_mut(c.program.as_bytes()).unwrap().balance = BigInt::from(0);
    c.ledger = Ledger::from_accounts(accounts).unwrap();
    c.denied(
        11,
        "withdraw_earnings",
        json!([10]),
        0,
        "earnings transfer failed",
    );
    assert_eq!(c.number("get_earnings", json!([address(11)])), 10);
    c.ok(12, "request_exit", json!([]), 0);
    c.ok(11, "request_operator_unstake", json!([]), 0);
    c.now += DAY;
    c.denied(12, "withdraw_remaining", json!([]), 0, "withdrawal failed");
    assert_eq!(c.number("get_funds", json!([address(12)])), FUND - 10);
    c.now = START + WEEK;
    c.denied(
        11,
        "withdraw_operator_stake",
        json!([]),
        0,
        "unstake transfer failed",
    );
    assert_eq!(c.number("get_operator_stake", json!([address(11)])), STAKE);
    assert_eq!(c.locked(), STAKE + FUND);
}

#[test]
fn native_wallet_upgrade_cannot_replace_factory_child_custody() {
    let mut c = Chain::new();
    c.funded_plan();
    let meta = store::meta(&c.state.snapshot(), c.program.as_bytes())
        .unwrap()
        .unwrap();
    assert_eq!(meta.owner, c.factory.as_bytes());
    for who in [11, 12, 13] {
        let root = c.state.root().unwrap();
        let mut tx = c.transaction(
            who,
            &c.program,
            OpType::ContractUpgrade,
            Value::Null,
            0,
            STANDARD.encode(&binaries().1).into_bytes(),
        );
        tx.message = Some(program_upgrade::message(&meta.code_hash));
        tx.signature = STANDARD
            .encode(key(who).sign(&tx.signing_bytes().unwrap()).to_bytes())
            .into_bytes();
        assert!(tx.verify(tx.public_key.as_ref().unwrap()));
        let (effect, _) = c.execute(&tx);
        let Effect::RejectedAfterFee { refusal, .. } = effect else {
            panic!("{effect:?}")
        };
        assert_eq!(refusal.reason, b"only the program owner can upgrade");
        assert_eq!(c.state.root().unwrap(), root);
    }
    let mut forged = c.transaction(
        11,
        &c.program,
        OpType::ContractUpgrade,
        Value::Null,
        0,
        STANDARD.encode(&binaries().1).into_bytes(),
    );
    forged.from = c.factory.as_bytes().to_vec();
    forged.signature = STANDARD
        .encode(key(11).sign(&forged.signing_bytes().unwrap()).to_bytes())
        .into_bytes();
    assert!(forged.verify(forged.public_key.as_ref().unwrap()));
    let refusal =
        transaction::normalize_envelope(&forged, forged.public_key.as_deref()).unwrap_err();
    assert!(format!("{refusal:?}").contains("sender public key does not match address"));
}
