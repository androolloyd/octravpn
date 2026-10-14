use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::SigningKey;
use octra_node_protocol::{
    consensus::{codec::Wire, Validator, ValidatorSet},
    transaction::address_from_public_key,
    validator::config::{self, Admission, Build, Config, Event, Scheduled, Transition},
};
use serde_json::{json, Value};
fn raw(v: &Value) -> Vec<u8> {
    STANDARD.decode(v.as_str().unwrap()).unwrap()
}
fn opt(v: &Value) -> Option<Vec<u8>> {
    (!v.is_null()).then(|| raw(v))
}
fn bytes(v: &Value) -> Vec<Vec<u8>> {
    v.as_array().unwrap().iter().map(raw).collect()
}
fn b64(v: &[u8]) -> Value {
    json!(STANDARD.encode(v))
}
fn set(s: &ValidatorSet) -> Value {
    b64(&s.encode().unwrap())
}
fn validator(v: &Validator) -> Value {
    json!([b64(&v.address), b64(&v.pubkey)])
}
fn scheduled(s: &Scheduled) -> Value {
    json!([
        s.activate_epoch.to_string(),
        set(&s.validators),
        b64(s.fingerprint.as_bytes())
    ])
}
fn dump(c: &Config) -> Value {
    json!({"allowed":c.allowed_pubkeys.iter().map(|v|b64(v)).collect::<Vec<_>>(),"errors":c.identity_errors.iter().map(|v|b64(v)).collect::<Vec<_>>(),
        "program":c.program_trust.as_deref().map(b64),"profile":c.runtime_profile.as_deref().map(b64),
        "current":c.current.iter().map(validator).collect::<Vec<_>>(),"next":c.next.iter().map(validator).collect::<Vec<_>>(),"members":c.active_members.iter().map(validator).collect::<Vec<_>>(),
        "stake":set(&c.stake),"active":set(&c.active),"scheduled":c.scheduled.as_ref().map(scheduled),"light":c.light_scheduled.as_ref().map(|(e,s)|json!([e.to_string(),set(s)])),"hash":b64(&c.hash),
        "transition":match &c.transition {Transition::None=>Value::Null,Transition::Active(e)=>json!(["active",e.to_string()]),Transition::Scheduled{epoch,n,quorum,fingerprint}=>json!(["scheduled",epoch.to_string(),n,quorum,b64(fingerprint.as_bytes())])}
    })
}
fn outcome(c: &Config, input: &Value) -> Value {
    let address = if let Some(id) = input["self"].as_u64() {
        address_from_public_key(
            STANDARD
                .encode(
                    SigningKey::from_bytes(&[id as u8; 32])
                        .verifying_key()
                        .to_bytes(),
                )
                .as_bytes(),
        )
    } else {
        raw(&input["self"])
    };
    let role = raw(&input["role"]);
    let policy = opt(&input["admission"]);
    let unsafe_value = opt(&input["unsafe"]);
    let activate = input["activate"].as_str().map(|e| e.parse().unwrap());
    let events = c.node_admission(
        Admission {
            address: &address,
            voting: input["voting"] == true,
            role: &role,
            permissionless: false,
            allow_unsafe: false,
            activate,
        },
        policy.as_deref(),
        unsafe_value.as_deref(),
    );
    let events = events
        .into_iter()
        .map(|e| match e {
            Event::Info(m) => json!(["info", b64(&m)]),
            Event::Warn(m) => json!(["warn", b64(&m)]),
            Event::Refuse(ms) => json!(["refuse", ms.iter().map(|m| b64(m)).collect::<Vec<_>>()]),
        })
        .collect::<Vec<_>>();
    let height: i64 = input["height"].as_str().unwrap().parse().unwrap();
    let chain = raw(&input["chain"]);
    let effective = [height, height + 1, 63, 64, 127, 128, 1_306_546, 1_306_547]
        .map(|e| set(&c.validators_at(&chain, e).unwrap()));
    json!({"config":dump(c),"message":c.transition_message(height).as_deref().map(|s|b64(s.as_bytes())),"admission":events,"effective":effective})
}
fn anchor(input: &Value, material: &Value, native: &Value) -> Value {
    use octra_node_protocol::{
        consensus::{relief::Mark, RoundSync},
        validator::config::anchor::Source,
    };
    let current = bytes(&material["current"]).join(&b',');
    let next = bytes(&material["next"]).join(&b',');
    let active = opt(&material["active_raw"]);
    let pending = opt(&material["pending_raw"]);
    let chain = raw(&input["chain"]);
    let height: i64 = input["height"].as_str().unwrap().parse().unwrap();
    let primary = opt(&input["primary"])
        .or_else(|| input["activate"].as_str().map(|s| s.as_bytes().to_vec()));
    let fallback = opt(&input["fallback"]);
    let source = Source {
        chain: &chain,
        height,
        current: Some(&current),
        next: Some(&next),
        activate: primary.as_deref(),
        fallback_activate: fallback.as_deref(),
        active: active.as_deref(),
        pending: pending.as_deref(),
    };
    let mark = (!native["mark"].is_null()).then(|| {
        let m = &native["mark"];
        Mark {
            height: m["height"].as_str().unwrap().parse().unwrap(),
            round: m["round"].as_i64().unwrap(),
            activate_epoch: m["activate"].as_str().unwrap().parse().unwrap(),
            source_hash: raw(&m["source"]),
            target_hash: raw(&m["target"]),
            fingerprint: raw(&m["fingerprint"]),
            proof: bytes(&m["proof"])
                .iter()
                .map(|v| RoundSync::decode(v).unwrap())
                .collect(),
        }
    });
    let relief = |_| {
        if input["relief"] == "error" {
            Err(b"fixture relief unreadable".to_vec())
        } else {
            Ok(mark.clone())
        }
    };
    let result = |r: Result<ValidatorSet, Vec<u8>>| match r {
        Ok(v) => json!({"set":set(&v)}),
        Err(e) => json!({"error":b64(&e)}),
    };
    let queries=[height,height+1,64,128,height+32].map(|e|json!({"stake":result(source.stake_set(e)),"expected":([None,Some(-1),Some(63),Some(64),Some(65)].map(|r|result(source.expected_set(e,r,&relief))))}));
    json!({"mark":native["mark"],"queries":queries})
}
fn run(input: &Value, expected: &Value) -> Value {
    let material = &expected["material"];
    let current = bytes(&material["current"]);
    let next = bytes(&material["next"]);
    let chain_pending = bytes(&material["pending"]);
    let chain = raw(&input["chain"]);
    let height = input["height"].as_str().unwrap().parse().unwrap();
    let consensus = input["consensus"] == true;
    let base = Config::build(Build {
        chain: &chain,
        consensus,
        height,
        current: &current,
        next: &next,
        chain_pending: &chain_pending,
        activate: input["activate"].as_str().map(|e| e.parse().unwrap()),
        program_trust: opt(&input["program"]),
        runtime_profile: opt(&input["profile"]),
    })
    .unwrap();
    let active = opt(&material["active_raw"]);
    let pending = opt(&material["pending_raw"]);
    let bound = match base.bind(
        &chain,
        consensus,
        height,
        active.as_deref(),
        pending.as_deref(),
    ) {
        Ok(c) => outcome(&c, input),
        Err(e) => json!({"error":b64(e.to_string().as_bytes())}),
    };
    let (loaded, warnings) = match config::load_pending(pending.as_deref()) {
        Ok(s) => (s.as_ref().map(scheduled), vec![]),
        Err(e) => (
            None,
            vec![b64(
                format!("persistent validator_set_update ignored: {e}").as_bytes()
            )],
        ),
    };
    json!({"material":material,"anchor":anchor(input,material,&expected["anchor"]),"base":outcome(&base,input),"bound":bound,"loaded":{"value":loaded,"warnings":warnings},"pending_entries":config::pending_entries(pending.as_deref()).iter().map(|v|b64(v)).collect::<Vec<_>>()})
}
#[test]
fn native_validator_configuration_and_startup_admission() {
    let fixture: Value =
        serde_json::from_slice(include_bytes!("fixtures/validator-config.json")).unwrap();
    let source: Value =
        serde_json::from_slice(include_bytes!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], source["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], source["files"]);
    for (i, c) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        assert_eq!(
            run(&c["input"], &c["expected"]),
            c["expected"],
            "case {i}: {}",
            c["input"]
        );
    }
}
