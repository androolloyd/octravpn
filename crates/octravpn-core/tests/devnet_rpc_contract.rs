//! Contract test pinning Octra devnet's real JSON-RPC response shapes.
//!
//! Every fixture below is a VERBATIM response captured from
//! https://devnet.octrascan.io/rpc (2026-07-04). They guard the exact class of
//! bug that the v4 relay daemon-e2e surfaced: a mock whose shape had drifted
//! from devnet's masked four money-path bugs that passed every unit + integration
//! test —
//!   * nonce off-by-one   (mock pre-incremented `pending_nonce`; devnet reports last-used),
//!   * float `timestamp`  (decoded into `Option<u64>` → whole response failed),
//!   * event-less tx      (admission scanned tx events devnet never returns).
//!
//! If devnet changes its wire format, or a struct / `next_nonce` regresses so it
//! no longer matches these captured shapes, this test fails loudly — before the
//! bug reaches a live daemon. Keep the fixtures verbatim; re-capture (don't
//! hand-edit) if the endpoint's contract genuinely changes.

use octravpn_core::rpc::{next_nonce, BalanceResult, NodeStatus};

/// `node_status` — note `timestamp` is a FLOAT and `epoch` a bare integer.
const DEVNET_NODE_STATUS: &str = r#"{"epoch":1112267,"current_epoch":1112267,"validator":"oct7xCozDD9JEsbeVpo5C7HXp2BJbKqfmNUHmDDCCTtWcGb","roots":0,"timestamp":1783211572.922005,"network_version":"v3.0.0-irmin","head_epoch":1112266,"state_root":"0bfe8d25681ac8c3b1f35265e5a6f594d967b52db08fe60660f6fe2500b53a1c07055dd82167cbeb71d52b5930008f771f196af970f81a19b1993f98610741e7","txid_hi":"647695","irmin_commit":"261b500c91247ee48342535b87e43086738a098de5e427a7f6c5e45ed3d4b207eaab261587f276e309be347ed69cf5b700d86d8eae0d3aa16a8a184efba206a5"}"#;

/// `octra_balance` — `nonce` == `pending_nonce` == the LAST-USED nonce.
const DEVNET_BALANCE: &str = r#"{"address":"oct8Tdgu4RLbSGah1fVoVHW4T4cLFDmsoKhTyVD8gCndNFm","balance":"55360.193057","balance_raw":"55360193057","nonce":494,"pending_nonce":494,"has_public_key":false}"#;

/// `octra_transaction` for a confirmed contract-call (the actual relay_claim from
/// the passing daemon-e2e). No `events`/`logs`; `timestamp` is a float; `message`
/// carries the call ARGS.
const DEVNET_CALL_TX: &str = r#"{"status":"confirmed","tx_hash":"aea25ba3b10ed7588d05ac1a9c74a1bfe0e7bce9d6d785ad7f70b53c0109f6cb","epoch":1105518,"from":"octG15XHxJ15yAAsyrjdTxzPMjhJCwjZrjZMJkvHf76FdYH","to":"oct598NT924k8TAk3a21gWrzkhGPrmTe74RdwP9SX17JwTW","amount":"0","amount_raw":"0","nonce":70,"ou":"1000","timestamp":1783142737.6245904,"op_type":"call","message":"[0,\"preimage-elided\"]"}"#;

/// Guards bug #2: devnet `timestamp` is a float; `Option<u64>` would fail the
/// whole decode. `epoch` (what the daemon actually reads) must survive.
#[test]
fn node_status_decodes_devnet_float_timestamp() {
    let ns: NodeStatus =
        serde_json::from_str(DEVNET_NODE_STATUS).expect("NodeStatus must decode the real devnet shape");
    assert_eq!(ns.epoch, 1_112_267);
    assert!(
        ns.timestamp.is_some(),
        "float timestamp must decode into the struct, not fail the response"
    );
}

/// Guards bug #1 (the systemic one): devnet reports the LAST-USED nonce, so the
/// next tx must be `nonce + 1`. `next_nonce` must add the +1 that foundry `cast`
/// applies — otherwise every daemon tx from a used account is `102 invalid nonce`.
#[test]
fn balance_decodes_and_next_nonce_is_last_used_plus_one() {
    let b: BalanceResult =
        serde_json::from_str(DEVNET_BALANCE).expect("BalanceResult must decode the real devnet shape");
    assert_eq!(b.nonce, 494);
    assert_eq!(b.pending_nonce, 494);
    assert_eq!(
        next_nonce(&b),
        495,
        "next nonce must be devnet last-used + 1 (matches `cast`: octra_balance.nonce + 1)"
    );
}

/// Guards the verifier bug: devnet `octra_transaction` carries NO events/logs, so
/// session admission (and anything else) must confirm on-chain facts via contract
/// STATE, never by scanning tx events. Also re-pins the float tx `timestamp`.
#[test]
fn confirmed_call_tx_has_no_events_and_float_timestamp() {
    let v: serde_json::Value = serde_json::from_str(DEVNET_CALL_TX).unwrap();
    let obj = v.as_object().unwrap();
    assert!(
        !obj.contains_key("events") && !obj.contains_key("logs"),
        "devnet tx returns no events — do NOT rely on them for admission/verification"
    );
    assert_eq!(obj["op_type"], "call");
    assert!(
        obj["timestamp"].is_f64(),
        "tx timestamp is a float on devnet"
    );
}
