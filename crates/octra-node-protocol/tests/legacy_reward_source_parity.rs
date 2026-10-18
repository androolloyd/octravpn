use octra_node_protocol::{
    consensus::{policy::Protocol, reward, reward_attribution::legacy},
    oce1::Writer,
    transaction::Nonce,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[test]
fn native_epoch_header_and_historical_reward_fallback_are_source_bound() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/legacy-reward-source.json")).unwrap();
    let source: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], source["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], source["files"]);
    assert_eq!(fixture["instrumentation"], json!({}));
    for (field, bytes) in [
        (
            "oracle_sha256",
            include_bytes!("../../../scripts/node-port/legacy-reward-source-oracle.ml").as_slice(),
        ),
        (
            "runner_sha256",
            include_bytes!("../../../scripts/node-port/native-oracle.py").as_slice(),
        ),
        (
            "generator_sha256",
            include_bytes!("../../../scripts/node-port/legacy-reward-source-fixtures.py")
                .as_slice(),
        ),
    ] {
        assert_eq!(fixture[field], hex::encode(Sha256::digest(bytes)));
    }
    let cases = fixture["cases"].as_array().unwrap();
    assert!(cases.len() >= 450);
    for (index, case) in cases.iter().enumerate() {
        let j = &case["input"];
        let header = hex::decode(j["header"].as_str().unwrap()).unwrap();
        let result = match legacy::DecodedHeader::parse(&header) {
            None => json!({"decoded":false}),
            Some(header) => {
                let authority = legacy::Authority {
                    protocol: Protocol::new(
                        j["protocol_activation"].as_str().unwrap().parse().unwrap(),
                    )
                    .unwrap(),
                    validator_activation_epoch: j["validator_activation"]
                        .as_str()
                        .map(|x| Nonce::new(x.parse().unwrap()).unwrap()),
                    validator_pubkeys: j["keys"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|pair| {
                            (
                                hex::decode(pair[0].as_str().unwrap()).unwrap(),
                                hex::decode(pair[1].as_str().unwrap()).unwrap(),
                            )
                        })
                        .collect(),
                };
                let source = match authority.source(&header.reward) {
                    Ok(source) => {
                        let mut writer = Writer::new();
                        reward::put(&mut writer, &source).unwrap();
                        json!({"ok":hex::encode(writer.into_bytes())})
                    }
                    Err(error) => json!({"error":hex::encode(error.as_bytes())}),
                };
                json!({"decoded":true,"epoch":header.reward.epoch.get().to_string(),"root":hex::encode(header.state_root),"previous_root":hex::encode(header.previous_root),"parent_commit":hex::encode(header.parent_commit),"start_txid":header.start_txid.to_string(),"count":header.transaction_count.get().to_string(),"source":source})
            }
        };
        assert_eq!(
            result, case["expected"],
            "native legacy reward/header case {index}"
        );
    }
}
