//! End-to-end tests against the in-process mock chain (v1 AML).
//!
//! Covers the v1 model:
//!   - bond + register endpoint
//!   - create tailnet, add member, configure exit
//!   - single-hop open / validator-only settle / no-show
//!   - FHE-backed encrypted earnings + two-step claim
//!   - 3-hop onion build/peel round-trip (no chain needed; the data
//!     plane keeps multi-hop onion routing even while v1 AML is
//!     single-hop)

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, sync::Arc, time::Duration};

    use octravpn_core::{
        address::Address,
        commit,
        onion::{build_onion, peel_layer, HopAction, HopBuildInput},
        receipt::{Receipt, ReceiptContext, SignedReceipt, CHAIN_ID_TEST},
        rpc::RpcClient,
        session::SessionId,
        sig::KeyPair,
    };
    use serde_json::json;
    use tokio::time::sleep;
    use x25519_dalek::{PublicKey as X25519Pub, StaticSecret};

    async fn spawn_mock(port: u16, program: &str) -> Arc<()> {
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let prog = program.to_string();
        tokio::spawn(async move {
            octra_mock_rpc::serve(addr, prog).await.ok();
        });
        sleep(Duration::from_millis(150)).await;
        Arc::new(())
    }

    fn mock_url(port: u16) -> String {
        format!("http://127.0.0.1:{port}/rpc")
    }

    async fn bond_operator(rpc: &RpcClient, addr: &str) {
        rpc.raw_call("octra_test_bondEndpoint", json!([addr]))
            .await
            .expect("bond endpoint");
    }

    #[tokio::test]
    async fn node_status_round_trip() {
        let _g = spawn_mock(18101, "octPROG").await;
        let rpc = RpcClient::new(mock_url(18101));
        let s = rpc.node_status().await.unwrap();
        assert!(s.epoch >= 1);
    }

    #[tokio::test]
    async fn full_lifecycle_endpoint_tailnet_session_claim() {
        let _g = spawn_mock(18102, "octPROG").await;
        let rpc = RpcClient::new(mock_url(18102));

        let val = "octV1Address0000000000000000000000000001";
        let owner = "octOWNER000000000000000000000000000000001";
        let client = "octCLIENT00000000000000000000000000000001";

        bond_operator(&rpc, val).await;

        // 1. Register endpoint (post-bond, no signature pubkeys in v1).
        let register_tx = json!({
            "kind": "contract_call",
            "from": val,
            "to": "octPROG",
            "method": "register_endpoint",
            "params": [
                "1.2.3.4:51820",
                "deadbeef".repeat(8),
                "cafe".repeat(16),                  // hfhe_pubkey (mock-opaque)
                "beef".repeat(16),                  // initial_enc_zero (mock-opaque)
                "eu-west",
                100u64,
            ],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        });
        rpc.submit(&register_tx).await.unwrap();

        // 2. Create a tailnet with 2000 OU treasury.
        let create_tx = json!({
            "kind": "contract_call",
            "from": owner,
            "to": "octPROG",
            "method": "create_tailnet",
            "params": ["ac".repeat(32)],
            "value": 2000u64,
            "fee": 10u64,
            "nonce": 0u64,
        });
        let r = rpc.submit(&create_tx).await.unwrap();
        let tx = rpc.transaction(&r.hash).await.unwrap();
        let tid = tx["events"]
            .as_array()
            .cloned()
            .unwrap()
            .into_iter()
            .find(|e| e["name"] == "TailnetCreated")
            .and_then(|e| e["tailnet_id"].as_u64())
            .unwrap();

        // 3. Owner adds client as member.
        let add_member_tx = json!({
            "kind": "contract_call",
            "from": owner,
            "to": "octPROG",
            "method": "add_member",
            "params": [tid, client],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 1u64,
        });
        rpc.submit(&add_member_tx).await.unwrap();

        // 4. Owner configures the validator as a tailnet exit.
        let cfg_exit_tx = json!({
            "kind": "contract_call",
            "from": owner,
            "to": "octPROG",
            "method": "configure_tailnet_exit",
            "params": [tid, val],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 2u64,
        });
        rpc.submit(&cfg_exit_tx).await.unwrap();

        // 5. Active list shows the endpoint.
        let prog = Address::from_display("octPROG");
        let active = rpc
            .contract_call(
                &prog,
                "list_active_endpoints",
                &[json!(0u64), json!(50u64)],
                None,
            )
            .await
            .unwrap();
        let arr = active.as_array().unwrap();
        assert!(arr.iter().any(|v| v.as_str() == Some(val)));

        // 6. Open single-hop session: pick exit + max_pay = 1000.
        let open_tx = json!({
            "kind": "contract_call",
            "from": client,
            "to": "octPROG",
            "method": "open_session",
            "params": [tid, val, 1000u64],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        });
        let r = rpc.submit(&open_tx).await.unwrap();
        let tx = rpc.transaction(&r.hash).await.unwrap();
        let sid = tx["events"]
            .as_array()
            .cloned()
            .unwrap()
            .into_iter()
            .find(|e| e["name"] == "SessionOpened")
            .and_then(|e| e["session_id"].as_u64())
            .unwrap();

        // 7. Two-tx settle. Operator claims bytes_used=2 first.
        let claim_tx = json!({
            "kind": "contract_call",
            "from": val,
            "to": "octPROG",
            "method": "settle_claim",
            "params": [sid, 2u64],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 1u64,
        });
        let r = rpc.submit(&claim_tx).await.unwrap();
        let tx = rpc.transaction(&r.hash).await.unwrap();
        let names: Vec<_> = tx["events"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|e| e["name"].as_str().map(String::from))
            .collect();
        assert!(names.iter().any(|n| n == "SettleClaimed"));
        assert!(
            !names.iter().any(|n| n == "SessionSettled"),
            "settlement must not apply on the claim tx alone"
        );

        // 8. Client confirms with matching bytes — settlement applies:
        //    bytes_used=2 → 200 gross, 1 fee, 199 net pay, 800 refund.
        let confirm_tx = json!({
            "kind": "contract_call",
            "from": client,
            "to": "octPROG",
            "method": "settle_confirm",
            "params": [sid, 2u64],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 2u64,
        });
        let r = rpc.submit(&confirm_tx).await.unwrap();
        let tx = rpc.transaction(&r.hash).await.unwrap();
        let event = tx["events"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .find(|e| e["name"].as_str() == Some("SessionSettled"))
            .expect("settled event");
        assert_eq!(event["total_paid"].as_u64(), Some(200));
        assert_eq!(event["refund"].as_u64(), Some(800));

        // 8. Tailnet treasury: 2000 - 1000 + 800 = 1800.
        let tnet = rpc
            .contract_call(&prog, "get_tailnet", &[json!(tid)], None)
            .await
            .unwrap();
        assert_eq!(tnet["treasury"].as_u64(), Some(1800));

        // 9. Program treasury collected the protocol fee (1 OU).
        let pt = rpc
            .contract_call(&prog, "get_program_treasury", &[], None)
            .await
            .unwrap();
        assert_eq!(pt.as_u64(), Some(1));

        // 10. Encrypted earnings: mock-cleartext = 199 OU.
        let earn = rpc
            .contract_call(&prog, "get_encrypted_earnings", &[json!(val)], None)
            .await
            .unwrap();
        assert_eq!(earn.as_str(), Some("hfhe_v1|mock|00000000000000c7")); // 0xc7 = 199

        // 11. Claim earnings: AML-side verify + plain transfer.
        let claim_tx = json!({
            "kind": "contract_call",
            "from": val,
            "to": "octPROG",
            "method": "claim_earnings",
            "params": [199u64, "00".repeat(32)],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 1u64,
        });
        let r = rpc.submit(&claim_tx).await.unwrap();
        let tx = rpc.transaction(&r.hash).await.unwrap();
        let has_claimed = tx["events"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .any(|e| e["name"].as_str() == Some("EarningsClaimed"));
        assert!(has_claimed);

        // 12. Earnings ledger reset to zero.
        let earn = rpc
            .contract_call(&prog, "get_encrypted_earnings", &[json!(val)], None)
            .await
            .unwrap();
        assert_eq!(earn.as_str(), Some("hfhe_v1|mock|0000000000000000"));
    }

    #[tokio::test]
    async fn no_show_refund_returns_to_treasury() {
        let _g = spawn_mock(18104, "octPROG").await;
        let rpc = RpcClient::new(mock_url(18104));
        let val = "octV2Address0000000000000000000000000NOSH";
        let owner = "octOWNER0000000000000000000000000000NOSHO";
        let client = "octCLIENT0000000000000000000000000000NOSHO";

        bond_operator(&rpc, val).await;
        rpc.submit(&json!({
            "kind": "contract_call",
            "from": val,
            "to": "octPROG",
            "method": "register_endpoint",
            "params": [
                "10.0.0.1:51820",
                "11".repeat(32),
                "cc".repeat(32),
                "dd".repeat(32),
                "eu-west",
                100u64,
            ],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        }))
        .await
        .unwrap();

        // Create a tailnet with 100 OU treasury and add client.
        let create_tx = json!({
            "kind": "contract_call",
            "from": owner,
            "to": "octPROG",
            "method": "create_tailnet",
            "params": ["bb".repeat(32)],
            "value": 100u64,
            "fee": 10u64,
            "nonce": 0u64,
        });
        let r = rpc.submit(&create_tx).await.unwrap();
        let tx = rpc.transaction(&r.hash).await.unwrap();
        let tid = tx["events"]
            .as_array()
            .cloned()
            .unwrap()
            .into_iter()
            .find(|e| e["name"] == "TailnetCreated")
            .and_then(|e| e["tailnet_id"].as_u64())
            .unwrap();

        rpc.submit(&json!({
            "kind": "contract_call",
            "from": owner,
            "to": "octPROG",
            "method": "add_member",
            "params": [tid, client],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 1u64,
        }))
        .await
        .unwrap();

        // Owner configures exit so client can open a session.
        rpc.submit(&json!({
            "kind": "contract_call",
            "from": owner,
            "to": "octPROG",
            "method": "configure_tailnet_exit",
            "params": [tid, val],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 2u64,
        }))
        .await
        .unwrap();

        // Client opens a session for 30 OU.
        let open_tx = json!({
            "kind": "contract_call",
            "from": client,
            "to": "octPROG",
            "method": "open_session",
            "params": [tid, val, 30u64],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        });
        let r = rpc.submit(&open_tx).await.unwrap();
        let tx = rpc.transaction(&r.hash).await.unwrap();
        let sid = tx["events"]
            .as_array()
            .cloned()
            .unwrap()
            .into_iter()
            .find(|e| e["name"] == "SessionOpened")
            .and_then(|e| e["session_id"].as_u64())
            .unwrap();

        // No-show claim refunds to treasury.
        let claim_tx = json!({
            "kind": "contract_call",
            "from": client,
            "to": "octPROG",
            "method": "claim_no_show",
            "params": [sid],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 1u64,
        });
        let r = rpc.submit(&claim_tx).await.unwrap();
        let st = rpc.transaction(&r.hash).await.unwrap();
        let has_refunded = st["events"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .any(|e| e["name"].as_str() == Some("SessionRefunded"));
        assert!(has_refunded);

        // Treasury back to 100 (30 came out, 30 went back).
        let prog = Address::from_display("octPROG");
        let tnet = rpc
            .contract_call(&prog, "get_tailnet", &[json!(tid)], None)
            .await
            .unwrap();
        assert_eq!(tnet["treasury"].as_u64(), Some(100));
    }

    #[test]
    fn three_hop_onion_round_trip() {
        use rand::rngs::OsRng;
        let s1 = StaticSecret::random_from_rng(OsRng);
        let s2 = StaticSecret::random_from_rng(OsRng);
        let s3 = StaticSecret::random_from_rng(OsRng);
        let p1 = X25519Pub::from(&s1).to_bytes();
        let p2 = X25519Pub::from(&s2).to_bytes();
        let p3 = X25519Pub::from(&s3).to_bytes();

        let onion = build_onion(
            &[
                HopBuildInput {
                    static_pubkey: p1,
                    endpoint: "n1:51820".into(),
                },
                HopBuildInput {
                    static_pubkey: p2,
                    endpoint: "n2:51820".into(),
                },
                HopBuildInput {
                    static_pubkey: p3,
                    endpoint: "n3:51820".into(),
                },
            ],
            b"final-payload",
        )
        .unwrap();

        let l1 = peel_layer(&s1, &onion).unwrap();
        let HopAction::Forward {
            endpoint,
            next_static_pubkey,
        } = l1.action.clone()
        else {
            panic!("hop1 must forward")
        };
        assert_eq!(endpoint, "n2:51820");
        assert_eq!(next_static_pubkey, p2);

        let l2 = peel_layer(&s2, &l1.inner).unwrap();
        let HopAction::Forward { endpoint, .. } = l2.action.clone() else {
            panic!("hop2 must forward")
        };
        assert_eq!(endpoint, "n3:51820");

        let l3 = peel_layer(&s3, &l2.inner).unwrap();
        assert_eq!(l3.action, HopAction::Egress);
        assert_eq!(l3.inner, b"final-payload");
    }

    #[test]
    fn pedersen_commitment_route_hiding() {
        let v = Address::from_display("octVALIDATOR");
        let b1 = commit::fresh_blind();
        let b2 = commit::fresh_blind();
        let c1 = commit::commit(&v, &b1);
        let c2 = commit::commit(&v, &b2);
        assert_ne!(c1, c2);
        assert!(commit::verify_open(
            &c1,
            &commit::Opening {
                addr: v.clone(),
                blind: b1
            }
        ));
        assert!(commit::verify_open(
            &c2,
            &commit::Opening { addr: v, blind: b2 }
        ));
    }

    #[test]
    fn dual_signed_receipt_round_trip() {
        // Client-side dual-sig still works as a primitive; v1 AML
        // doesn't verify it on-chain but the data-plane still uses
        // signed receipts for client/operator dispute resolution.
        use octravpn_core::session::Blind;
        let client = KeyPair::generate();
        let node = KeyPair::generate();
        let r = Receipt {
            context: ReceiptContext::v1_1(
                Address::from_pubkey(&[0xABu8; 32]),
                CHAIN_ID_TEST,
            ),
            session_id: SessionId::new([1u8; 32]),
            seq: 5,
            bytes_used: 1024,
            blind: Blind::new([9u8; 32]),
        };
        let sr = SignedReceipt::build(r, &client, &node);
        sr.verify().unwrap();
    }
}
