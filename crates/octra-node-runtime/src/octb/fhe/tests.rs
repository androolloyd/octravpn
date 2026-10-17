use super::*;
use octra_node_protocol::circle_storage::StorageTable;
#[test]
fn native_async_suspension_releases_parser_lane_before_host_verification() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../../../tests/fixtures/private-crypto.json")).unwrap();
    let input = &fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["input"]["operation"] == "proof" && case["expected"].get("ok").is_some())
        .unwrap()["input"];
    let bytes = |name: &str| STANDARD.decode(input[name].as_str().unwrap()).unwrap();
    let key = crate::private_crypto::proof_pubkey(&bytes("public")).unwrap();
    let cipher = crate::private_crypto::decode_cipher(&bytes("delta"), false, true).unwrap();
    for asynchronous in [false, true] {
        struct Observe {
            asynchronous: bool,
            called: bool,
        }
        impl Host for Observe {
            fn fhe_verify(&mut self, proof: Proof<'_>) -> Result<bool, Unavailable> {
                self.called = true;
                assert_eq!(proof.asynchronous, self.asynchronous);
                assert_eq!(
                    VERIFIER.try_lock().is_ok(),
                    self.asynchronous,
                    "native Suspend unwinds parser lane; synchronous try retains it"
                );
                Ok(false) // Only mutex ownership is under test, not a proof verdict.
            }
        }
        let mut host = Observe {
            asynchronous,
            called: false,
        };
        let mut machine = Machine::new(
            super::super::Context::default(),
            super::super::Options {
                is_view: true,
                async_exec: asynchronous,
                ..super::super::Options::default()
            },
            StorageTable::new(0),
        );
        machine.regs[0] = Value::PublicKey(Arc::new(Key::from_public_key(&key).unwrap()));
        machine.regs[1] = Value::Cipher(Arc::new(Cipher::from_value(&cipher).unwrap()));
        machine.regs[2] = Value::string(bytes("proof"));
        machine.regs[3] = Value::string(bytes("commitment"));
        machine
            .execute_fhe(&I::FheVerifyBound(4, 0, 1, 2, 3), &mut host, &mut None)
            .unwrap();
        assert!(
            host.called,
            "actual callback must be reached, not an early proof-size refusal"
        );
        assert_eq!(machine.regs[4], Value::Bool(false));
    }
}
