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
fn prepaid_purchase_settles_before_delivery_and_rejects_old_usage_authority() {
    let mut c = Chain::new();
    c.funded_plan();
    assert_eq!(c.number("get_prepaid_bytes", json!([0, 0])), 0);
    let mut old = c.receipt(0, 1, 1_048_576);
    let legacy_message = format!(
        "Octranet usage v1|{DOMAIN}|{}|{}|1|0|0|{MANIFEST}|0|1|1048576",
        c.program,
        address(12)
    );
    old[4] = json!(sign(21, &legacy_message));
    c.denied(13, "claim", old, 0, "invalid usage authorization");
    assert_eq!(c.number("get_earnings", json!([address(11)])), 0);
    // This is an advance purchase, with no delivery acknowledgment or traffic
    // in this transaction harness. The forwarding meter is qualified separately.
    let bytes = 100 * 1_048_576;
    c.ok(13, "claim", c.receipt(0, 2, bytes), 0);
    assert_eq!(c.number("get_prepaid_bytes", json!([0, 0])), bytes);
    assert_eq!(c.number("get_prepaid_cost", json!([0, 0])), 1000);
    assert_eq!(c.number("get_plan_remaining", json!([0])), 0);
    assert_eq!(c.number("get_earnings", json!([address(11)])), 1000);
    assert_eq!(c.number("get_funds", json!([address(12)])), FUND - 1000);
    // Spending the monetary budget purchases the allowance; it must not revoke
    // the plan before the payer has an opportunity to consume those bytes.
    assert_eq!(c.view("can_forward", json!([0])), true);
    c.denied(
        13,
        "claim",
        c.receipt(0, 2, bytes),
        0,
        "usage already redeemed or exceeds uint64",
    );
    c.denied(
        13,
        "claim",
        c.receipt(0, 3, bytes + 1),
        0,
        "plan budget exhausted",
    );
}

#[test]
fn operator_unstake_is_seven_days_and_independent_of_payer_exit() {
    let mut c = Chain::new();
    c.funded_plan();
    assert_eq!(c.number("get_operator_unstake_ms", json!([])), WEEK as u64);
    assert_eq!(c.number("get_user_exit_ms", json!([])), 0);
    c.ok(13, "claim", c.receipt(0, 1, 1_048_576), 0);
    let held_purchase = c.receipt(0, 2, 2_097_152);
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
    c.denied(
        13,
        "claim",
        held_purchase.clone(),
        0,
        "operator settlement window closed",
    );
    c.now = stopped + DAY - 1;
    c.denied(
        13,
        "claim",
        held_purchase,
        0,
        "operator settlement window closed",
    );
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
fn payer_instantly_withdraws_available_oct_and_revokes_held_purchases() {
    let mut c = Chain::new();
    c.funded_plan();
    c.ok(14, "claim", c.receipt(1, 1, 1_048_576), 0);
    let held_purchase = c.receipt(1, 2, 2_097_152);
    c.ok(12, "request_exit", json!([]), 0);
    c.denied(14, "claim", held_purchase.clone(), 0, "claim window closed");
    assert_eq!(c.view("can_forward", json!([0])), false);
    c.denied(
        12,
        "fund",
        json!([address(12)]),
        1,
        "account not accepting funds",
    );
    c.denied(14, "claim", held_purchase, 0, "claim window closed");
    c.now += 1;
    c.ok(12, "request_exit", json!([]), 0);
    assert_eq!(
        c.number("get_exit_deadline_ms", json!([address(12)])),
        START as u64
    );
    let before = c
        .ledger
        .account(address(12).as_bytes())
        .unwrap()
        .balance
        .clone();
    c.ok(12, "withdraw_remaining", json!([]), 0);
    assert_eq!(c.number("get_funds", json!([address(12)])), 0);
    assert_eq!(c.number("get_reserved", json!([address(12)])), 0);
    assert_eq!(c.number("get_channel_balance", json!([address(12)])), 0);
    assert_eq!(
        c.ledger.account(address(12).as_bytes()).unwrap().balance,
        before - FEE + FUND - 100
    );
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

fn register_account(c: &mut Chain, who: u8, receipt_key: u8, generation: u64) {
    let message = format!(
        "Octranet register v1|{DOMAIN}|{}|{}|{generation}",
        c.program,
        address(who)
    );
    c.ok(
        who,
        "register",
        json!([
            STANDARD.encode(key(receipt_key).verifying_key().as_bytes()),
            sign(receipt_key, &message)
        ]),
        0,
    );
}

fn purchase(c: &Chain, plan: u64, class: u64, sequence: u64, bytes: u64, receipt_key: u8) -> Value {
    let message = c.view("get_usage_message", json!([plan, class, sequence, bytes]));
    json!([
        plan,
        class,
        sequence,
        bytes,
        sign(receipt_key, message.as_str().unwrap())
    ])
}

#[test]
fn instant_withdrawal_races_are_atomic_in_both_orders_and_stake_is_separate() {
    let mut paid_first = Chain::new();
    paid_first.funded_plan();
    paid_first.ok(13, "claim", paid_first.receipt(0, 1, 1_048_576), 0);
    paid_first.ok(12, "withdraw_remaining", json!([]), 0);
    assert_eq!(paid_first.locked(), STAKE + 10);
    assert_eq!(
        paid_first.number("get_prepaid_bytes", json!([0, 0])),
        1_048_576
    );
    assert_eq!(paid_first.number("get_earnings", json!([address(11)])), 10);

    let mut withdrawn_first = Chain::new();
    withdrawn_first.funded_plan();
    let held = withdrawn_first.receipt(0, 1, 1_048_576);
    withdrawn_first.ok(12, "withdraw_remaining", json!([]), 0);
    withdrawn_first.denied(13, "claim", held, 0, "plan generation closed");
    assert_eq!(withdrawn_first.locked(), STAKE);
    assert_eq!(
        withdrawn_first.number("get_earnings", json!([address(11)])),
        0
    );
    assert_eq!(
        withdrawn_first.number("get_operator_stake", json!([address(11)])),
        STAKE
    );
}

#[test]
fn partial_channel_withdrawal_invalidates_all_plans_and_preserves_receipt_key() {
    let mut c = Chain::new();
    c.funded_plan();
    c.ok(12, "open_plan", json!([0, 500]), 0);
    c.ok(13, "claim", c.receipt(0, 1, 1_048_576), 0);
    let held = c.receipt(0, 2, 2_097_152);
    let old_key = c.view("get_plan_receipt_key", json!([0]));
    c.denied(
        12,
        "withdraw_channel",
        json!([0]),
        0,
        "channel balance unavailable",
    );
    c.denied(
        12,
        "withdraw_channel",
        json!([FUND]),
        0,
        "channel balance unavailable",
    );
    c.ok(12, "withdraw_channel", json!([100]), 0);
    assert_eq!(c.number("get_generation", json!([address(12)])), 2);
    assert_eq!(c.number("get_active", json!([address(12)])), 1);
    assert_eq!(c.number("get_reserved", json!([address(12)])), 0);
    assert_eq!(
        c.number("get_channel_balance", json!([address(12)])),
        FUND - 110
    );
    assert_eq!(c.view("can_forward", json!([0])), false);
    assert_eq!(c.view("can_forward", json!([1])), false);
    assert_eq!(c.number("get_prepaid_bytes", json!([0, 0])), 1_048_576);
    c.denied(13, "claim", held, 0, "plan generation closed");
    c.ok(12, "open_plan", json!([0, 1000]), 0);
    assert_eq!(c.number("get_plan_generation", json!([2])), 2);
    assert_eq!(c.view("get_plan_receipt_key", json!([2])), old_key);
    c.ok(13, "claim", purchase(&c, 2, 0, 1, 1_048_576, 21), 0);
    assert_eq!(c.number("get_earnings", json!([address(11)])), 20);
    c.ok(12, "withdraw_remaining", json!([]), 0);
    register_account(&mut c, 12, 22, 3);
    assert_eq!(c.view("get_plan_receipt_key", json!([0])), old_key);
    assert_ne!(c.view("get_receipt_key", json!([address(12)])), old_key);
}

#[test]
fn exit_earnings_fund_own_traffic_and_cross_operator_purchases_without_custody_changes() {
    let mut c = Chain::with_cap(300_000_000);
    c.funded_plan();
    c.ok(13, "claim", c.receipt(0, 1, 10_485_760), 0);
    assert_eq!(c.number("get_channel_balance", json!([address(11)])), 100);
    register_account(&mut c, 11, 23, 1);
    c.ok(11, "fund", json!([address(11)]), 3);
    let locked = c.locked();
    let before = c.ok(11, "open_plan", json!([0, 10]), 0);
    assert!(before["events"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["event"] == "EarningsAllocated"));
    assert_eq!(c.number("get_funds", json!([address(11)])), 10);
    assert_eq!(c.number("get_earnings", json!([address(11)])), 93);
    assert_eq!(c.number("get_channel_balance", json!([address(11)])), 103);
    assert_eq!(c.locked(), locked);
    c.ok(13, "claim", purchase(&c, 1, 0, 1, 1_048_576, 23), 0);
    assert_eq!(c.number("get_channel_balance", json!([address(11)])), 103);
    assert_eq!(c.locked(), locked);

    c.ok(13, "bond_operator", json!([]), STAKE);
    c.ok(13, "create_offer", json!([MANIFEST]), 0);
    c.ok(13, "append_class", json!([1, 10]), 0);
    c.ok(13, "seal_offer", json!([1]), 0);
    let locked = c.locked();
    c.ok(11, "open_plan", json!([1, 20]), 0);
    c.ok(14, "claim", purchase(&c, 2, 0, 1, 1_048_576, 23), 0);
    assert_eq!(c.number("get_channel_balance", json!([address(11)])), 93);
    assert_eq!(c.number("get_channel_balance", json!([address(13)])), 10);
    assert_eq!(c.locked(), locked);
    c.ok(11, "withdraw_channel", json!([90]), 0);
    assert_eq!(c.number("get_channel_balance", json!([address(11)])), 3);
    assert_eq!(c.number("get_reserved", json!([address(11)])), 0);
    assert_eq!(c.number("get_operator_stake", json!([address(11)])), STAKE);
    assert_eq!(c.number("get_operator_stake", json!([address(13)])), STAKE);
    c.ok(13, "withdraw_remaining", json!([]), 0);
    assert_eq!(c.number("get_channel_balance", json!([address(13)])), 0);
}

#[test]
fn immutable_rate_successors_enforce_full_notice_and_exact_quote_boundary() {
    let mut c = Chain::new();
    c.funded_plan();
    assert_eq!(c.number("get_rate_notice_ms", json!([])), DAY as u64);
    assert_eq!(c.number("get_offer_series", json!([0])), 0);
    assert_eq!(c.number("get_offer_start_ms", json!([0])), START as u64);
    c.ok(13, "claim", c.receipt(0, 1, 1_048_576), 0);
    let old_held = c.receipt(0, 2, 2_097_152);
    c.denied(
        13,
        "create_rate_change",
        json!([0, MANIFEST]),
        0,
        "not offer operator",
    );
    c.ok(11, "create_rate_change", json!([0, "c".repeat(64)]), 0);
    c.ok(11, "append_class", json!([1, 20]), 0);
    c.ok(11, "seal_offer", json!([1]), 0);
    let activation = START + DAY;
    assert_eq!(c.number("get_offer_series", json!([1])), 0);
    assert_eq!(c.number("get_offer_parent", json!([1])), 0);
    assert_eq!(c.number("get_offer_has_parent", json!([1])), 1);
    assert_eq!(
        c.number("get_offer_start_ms", json!([1])),
        activation as u64
    );
    assert_eq!(c.number("get_offer_end_ms", json!([0])), activation as u64);
    c.denied(12, "open_plan", json!([1, 100]), 0, "offer quote inactive");
    c.denied(11, "append_class", json!([1, 30]), 0, "offer immutable");
    c.now = activation - 1;
    c.ok(13, "claim", c.receipt(0, 2, 1_048_577), 0);
    c.ok(12, "open_plan", json!([0, 100]), 0);
    c.denied(12, "open_plan", json!([1, 100]), 0, "offer quote inactive");
    c.now = activation;
    c.denied(13, "claim", old_held, 0, "offer quote inactive");
    c.denied(12, "open_plan", json!([0, 100]), 0, "offer quote inactive");
    c.denied(
        11,
        "create_rate_change",
        json!([0, MANIFEST]),
        0,
        "parent quote inactive",
    );
    c.denied(
        11,
        "cancel_rate_change",
        json!([1]),
        0,
        "rate change already active",
    );
    c.ok(12, "open_plan", json!([1, 100]), 0);
    c.ok(13, "claim", purchase(&c, 2, 0, 1, 1_048_576, 21), 0);
    assert_eq!(c.number("get_prepaid_cost", json!([2, 0])), 20);
    assert_eq!(
        c.view("can_forward", json!([0])),
        true,
        "already purchased old-price bytes remain eligible"
    );
    c.now = activation + 1;
    c.denied(
        13,
        "claim",
        c.receipt(0, 3, 3_145_728),
        0,
        "offer quote inactive",
    );
    c.ok(12, "open_plan", json!([1, 100]), 0);
}

#[test]
fn rescheduling_and_cancelling_rate_notice_never_activates_stale_quotes() {
    let mut c = Chain::new();
    c.funded_plan();
    c.ok(11, "create_rate_change", json!([0, MANIFEST]), 0);
    c.ok(11, "append_class", json!([1, 20]), 0);
    c.ok(11, "seal_offer", json!([1]), 0);
    c.now += DAY / 2;
    c.ok(11, "create_rate_change", json!([0, "c".repeat(64)]), 0);
    c.ok(11, "append_class", json!([2, 30]), 0);
    c.ok(11, "seal_offer", json!([2]), 0);
    let activation = c.now + DAY;
    assert_eq!(c.number("get_offer_cancelled", json!([1])), 1);
    assert_eq!(c.number("get_offer_replacement", json!([0])), 2);
    assert_eq!(c.number("get_offer_end_ms", json!([0])), activation as u64);
    assert_eq!(
        c.number("get_offer_start_ms", json!([2])),
        activation as u64
    );
    c.now = START + DAY;
    c.denied(12, "open_plan", json!([1, 100]), 0, "offer quote inactive");
    c.denied(12, "open_plan", json!([2, 100]), 0, "offer quote inactive");
    c.ok(12, "open_plan", json!([0, 100]), 0);
    c.denied(
        13,
        "cancel_rate_change",
        json!([2]),
        0,
        "not offer operator",
    );
    c.ok(11, "cancel_rate_change", json!([2]), 0);
    assert_eq!(c.number("get_offer_end_ms", json!([0])), 0);
    assert_eq!(c.number("get_offer_replacement", json!([0])), 0);
    c.now = activation;
    c.denied(12, "open_plan", json!([2, 100]), 0, "offer quote inactive");
    c.ok(12, "open_plan", json!([0, 100]), 0);
    c.ok(11, "create_offer", json!(["d".repeat(64)]), 0);
    c.ok(11, "append_class", json!([3, 40]), 0);
    c.ok(11, "seal_offer", json!([3]), 0);
    assert_eq!(c.number("get_offer_series", json!([3])), 3);
    c.ok(12, "open_plan", json!([3, 100]), 0);
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
            json!([negative.clone()]),
            0,
            "execution reverted",
        );
        c.denied(
            12,
            "withdraw_channel",
            json!([negative.clone()]),
            0,
            "execution reverted",
        );
        c.denied(
            11,
            "create_rate_change",
            json!([negative.clone(), MANIFEST]),
            0,
            "execution reverted",
        );
        c.denied(
            11,
            "cancel_rate_change",
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
            json!([1, oversized.clone()]),
            0,
            "execution reverted",
        );
        c.denied(
            12,
            "withdraw_channel",
            json!([oversized.clone()]),
            0,
            "execution reverted",
        );
        c.denied(
            11,
            "create_rate_change",
            json!([oversized.clone(), MANIFEST]),
            0,
            "execution reverted",
        );
        c.denied(
            11,
            "cancel_rate_change",
            json!([oversized]),
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
        c.denied(
            12,
            "withdraw_channel",
            json!([malformed.clone()]),
            0,
            "channel balance unavailable",
        );
        c.denied(
            11,
            "create_rate_change",
            json!([malformed.clone(), MANIFEST]),
            0,
            "not offer operator",
        );
        c.denied(
            11,
            "create_rate_change",
            json!([0, malformed.clone()]),
            0,
            "digest must be lowercase SHA256",
        );
        c.denied(
            11,
            "cancel_rate_change",
            json!([malformed.clone()]),
            0,
            "not offer operator",
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
        "Octranet prepaid v1|{MANIFEST}|{}|{}|1|0|0|{MANIFEST}|0|1|1048576",
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
    c.denied(
        12,
        "withdraw_channel",
        json!([1]),
        0,
        "channel withdrawal failed",
    );
    assert_eq!(c.number("get_generation", json!([address(12)])), 1);
    assert_eq!(c.number("get_reserved", json!([address(12)])), 990);
    c.ok(12, "request_exit", json!([]), 0);
    c.ok(11, "request_operator_unstake", json!([]), 0);
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
