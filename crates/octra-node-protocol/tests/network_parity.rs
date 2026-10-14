use ed25519_dalek::{Signer, SigningKey};
use octra_node_protocol::{
    network::{
        self,
        budget::{self, Action, Budget, PeerClass, Verdict},
        frame::{self, Frame},
        handshake::{self, Ack, Finish, Hello, Profile},
    },
    oce1::{self, Error, Reader},
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
fn fixture() -> Value {
    let value: Value = serde_json::from_str(include_str!("fixtures/network.json")).unwrap();
    let sources: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(value["upstream_commit"], sources["upstream_commit"]);
    for (path, hash) in value["source_sha256"].as_object().unwrap() {
        assert_eq!(*hash, sources["files"][path]);
    }
    value
}
fn raw(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}
fn integer(v: &Value) -> i64 {
    v.as_i64().unwrap()
}
fn blob(bytes: &[u8]) -> Value {
    json!({"hex":if bytes.len()<=1024{hex::encode(bytes)}else{String::new()},"length":bytes.len(),"sha256":hex::encode(Sha256::digest(bytes))})
}
fn result(result: Result<Value, Error>) -> Value {
    result.unwrap_or_else(|e| json!({"error_hex":hex::encode(e.as_bytes())}))
}
fn validation(result: Result<(), Error>) -> Value {
    result.map_or_else(|e| json!(hex::encode(e.as_bytes())), |()| Value::Null)
}
fn key(value: &Value) -> SigningKey {
    SigningKey::from_bytes(&raw(&value["seed"]).try_into().unwrap())
}
fn hello(value: &Value) -> Hello {
    let key = key(value);
    let public_key = if value["public_key"].is_null() {
        key.verifying_key().to_bytes().to_vec()
    } else {
        raw(&value["public_key"])
    };
    let mut h = Hello {
        chain_id: raw(&value["chain_id"]),
        protocol_version: integer(&value["protocol_version"]) as u16,
        node_id: if value["node_id"].is_null() {
            handshake::node_id(&public_key)
        } else {
            raw(&value["node_id"])
        },
        node_address: raw(&value["node_address"]),
        public_key,
        config_hash: raw(&value["config_hash"]),
        listen_port: integer(&value["listen_port"]) as u16,
        best_epoch: value["best_epoch"].as_str().unwrap().parse().unwrap(),
        best_root: raw(&value["best_root"]),
        nonce: raw(&value["nonce"]),
        signature: Vec::new(),
    };
    h.signature = if value["signature"].is_null() {
        key.sign(&h.sign_bytes().unwrap()).to_bytes().to_vec()
    } else {
        raw(&value["signature"])
    };
    h
}
fn oce1(value: &Value) -> Result<Value, Error> {
    let wire = raw(&value["wire"]);
    let mut reader = Reader::new(&wire);
    let out = match value["kind"].as_str().unwrap() {
        "u8" => json!(reader.get_u8()?),
        "u16" => json!(reader.get_u16()?),
        "u32" => json!((reader.get_u32()? as i32).to_string()),
        "u64" => json!((reader.get_u64()? as i64).to_string()),
        "bool" => json!(reader.get_bool()?),
        "bytes" => json!(hex::encode(
            reader.get_bytes_bounded(integer(&value["maximum"]) as usize)?
        )),
        "option" => json!(reader.get_option(Reader::get_u8)?),
        "list" => json!(reader.get_list(integer(&value["maximum"]) as usize, Reader::get_u8)?),
        _ => panic!("unknown OCE1 case"),
    };
    reader.finish()?;
    Ok(out)
}
fn class(value: &Value) -> PeerClass {
    if value == "validator" {
        PeerClass::Validator
    } else {
        PeerClass::Observer
    }
}
fn lane_name(lane: budget::Lane) -> &'static str {
    match lane {
        budget::Lane::Control => "control",
        budget::Lane::Consensus => "consensus",
        budget::Lane::Artifact => "artifact",
        budget::Lane::Tx => "tx",
        budget::Lane::Data => "data",
    }
}
fn pure_case(value: &Value) -> Result<Value, Error> {
    Ok(match value["op"].as_str().unwrap() {
        "frame_meta" => {
            let message = integer(&value["message"]) as u8;
            json!({"known":frame::known_message(message),"maximum":frame::max_payload_size(message),"name":frame::message_name(message),"lane":lane_name(budget::lane(message))})
        }
        "frame_encode" => blob(
            &Frame {
                message: integer(&value["message"]) as u8,
                payload: vec![integer(&value["byte"]) as u8; integer(&value["length"]) as usize],
            }
            .encode()?,
        ),
        "oce1" => oce1(value)?,
        "hash32" => blob(&oce1::hash32_bytes(&raw(&value["value"]))?),
        "hello" => {
            let hello = hello(&value["hello"]);
            let allowed = value["allowed"]
                .as_array()
                .unwrap()
                .iter()
                .map(raw)
                .collect::<Vec<_>>();
            json!({"encoded":blob(&hello.encode()?),"sign_bytes":hex::encode(hello.sign_bytes()?),"node_id":hex::encode(handshake::node_id(&hello.public_key)),"validation":validation(hello.validate(&raw(&value["chain_id"]),&raw(&value["config_hash"]),&allowed))})
        }
        "decode" => {
            let wire = raw(&value["wire"]);
            blob(&match value["kind"].as_str().unwrap() {
                "hello" => Hello::decode(&wire)?.encode()?,
                "ack" => Ack::decode(&wire)?.encode()?,
                "finish" => Finish::decode(&wire)?.encode()?,
                "profile" => Profile::decode(&wire)?.encode()?,
                _ => panic!("unknown message"),
            })
        }
        "exchange" => {
            let a = hello(&value["initiator"]);
            let b = hello(&value["responder"]);
            let mut ack = Ack::new(b.clone(), a.nonce.clone(), &key(&value["responder"]))?;
            let mut finish = Finish::new(&a, &b, &key(&value["initiator"]))?;
            match value["mutation"].as_str().unwrap() {
                "ack_nonce" => ack.challenge_nonce = vec![42; 32],
                "ack_signature" => ack.signature = vec![0; 64],
                "finish_nonce" => finish.responder_nonce = vec![42; 32],
                "finish_identity" => finish.responder_node_id = vec![b'0'; 64],
                "finish_chain" => finish.chain_id = b"other".to_vec(),
                "finish_config" => finish.config_hash = vec![42; 32],
                "finish_signature" => finish.signature = vec![0; 64],
                "none" => {}
                _ => panic!("unknown mutation"),
            }
            json!({"ack":blob(&ack.encode()?),"finish":blob(&finish.encode()?),"ack_sign_bytes":hex::encode(ack.sign_bytes()?),"finish_sign_bytes":hex::encode(finish.sign_bytes()?),"ack_validation":validation(ack.validate(&a,&[])),"finish_validation":validation(finish.validate(&a,&b))})
        }
        "profile" => {
            let chain = raw(&value["chain_id"]);
            let node = raw(&value["node_id"]);
            let key = key(value);
            let mut profile = Profile::new(
                &chain,
                &node,
                value["epoch"].as_str().unwrap().parse().unwrap(),
                raw(&value["config_hash"]).try_into().unwrap(),
                &key,
            )?;
            if !value["signature"].is_null() {
                profile.signature = raw(&value["signature"]);
            }
            json!({"encoded":blob(&profile.encode()?),"sign_bytes":hex::encode(profile.sign_bytes(&chain,&node)?),"validation":validation(profile.validate(&chain,&node,&key.verifying_key().to_bytes()))})
        }
        "ed25519" => {
            let public = raw(&value["public"]);
            json!({"safe":network::public_key_safe(&public),"verified":network::verify_ed25519(&public,&raw(&value["message"]),&raw(&value["signature"]))})
        }
        "budget" => {
            let mut budget = Budget::new(value["now"].as_f64().unwrap(), class(&value["class"]));
            let mut out = Vec::new();
            for step in value["steps"].as_array().unwrap() {
                if !step["class"].is_null() {
                    budget.set_peer_class(class(&step["class"]));
                }
                out.push(match budget.admit(step["now"].as_f64().unwrap(),integer(&step["message"]) as u8,integer(&step["bytes"])){Verdict::Accept=>json!({"accept":true}),Verdict::Drop(r)=>json!({"reason":r.reason,"lane":lane_name(r.lane),"class":if r.peer_class==PeerClass::Validator{"validator"}else{"observer"},"frames":r.frames,"bytes":r.bytes,"frame_bytes":r.frame_bytes,"max_frames":r.max_frames,"max_bytes":r.max_bytes,"action":if r.action==Action::Close{"close"}else{"discard"}})});
            }
            json!(out)
        }
        _ => panic!("unknown pure case"),
    })
}
#[test]
fn oce1_handshake_profile_and_budgets_match_native() {
    for (index, case) in fixture()["cases"].as_array().unwrap().iter().enumerate() {
        if matches!(
            case["input"]["op"].as_str().unwrap(),
            "frame_decode" | "ed25519_seed"
        ) {
            continue;
        }
        assert_eq!(
            result(pure_case(&case["input"])),
            case["expected"],
            "case {index} {}",
            case["input"]["op"]
        );
    }
}
#[test]
fn native_guard_and_exact_signature_equation_acceptance() {
    let mut weak = 0;
    for case in fixture()["cases"].as_array().unwrap() {
        if case["input"]["op"] != "ed25519_seed" {
            continue;
        }
        let input = &case["input"];
        let expected = &case["expected"];
        let public = raw(&expected["public"]);
        let signature = raw(&expected["signature"]);
        let message = raw(&input["message"]);
        assert_eq!(
            hex::encode(key(input).verifying_key().to_bytes()),
            expected["public"]
        );
        assert_eq!(network::public_key_safe(&public), expected["safe"]);
        assert_eq!(
            network::verify_ed25519(&public, &message, &signature),
            expected["verified"]
        );
        if input["kind"] == "normal" {
            assert_eq!(
                hex::encode(key(input).sign(&message).to_bytes()),
                expected["signature"]
            );
        }
        if input["kind"] == "weak_r" {
            assert_eq!(expected["verified"], true);
            weak += 1;
        }
    }
    assert_eq!(weak, 12);
}
#[tokio::test]
async fn frame_stream_decoding_and_early_rejection_match_native() {
    for (index, case) in fixture()["cases"].as_array().unwrap().iter().enumerate() {
        if case["input"]["op"] != "frame_decode" {
            continue;
        }
        let input = &case["input"];
        let wire = raw(&input["wire"]);
        let (mut reader, mut writer) = tokio::io::duplex(64);
        let send = async {
            let _ = writer.write_all(&wire).await;
            let _ = writer.shutdown().await;
        };
        let receive = frame::read_frame(
            &mut reader,
            Duration::from_secs(1),
            integer(&input["cap"]) as usize,
        );
        let ((), decoded) = tokio::join!(send, receive);
        let actual = result(
            decoded.map(|frame| json!({"message":frame.message,"payload":blob(&frame.payload)})),
        );
        assert_eq!(actual, case["expected"], "frame case {index}");
    }
}
