//! Actual Circle deploy/spawn/value host plus full-depth Groth16 transitions.
//! Local test setup is ephemeral; it is not a production ceremony or launch.
use ark_bn254::Bn254;
use ark_groth16::{prepare_verifying_key, Groth16, Proof, ProvingKey};
use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::{
    circle_program::Deploy,
    native_json::Document,
    state::{Account, Ledger},
    transaction::{OpType, Transaction},
};
use octra_node_runtime::{
    circle::{WasmProfile, WasmRules},
    circle_store,
    circle_transaction::{self, Rules},
    epoch_execution::Effect,
    execution::Outcome,
    groth16,
    state_batch::StateBatch,
};
use octra_private_payments_experimental::{
    native_stealth,
    pool::{
        self, app, call::Call, envelope, wire, Domain, Note, PoolCircuit, PoolIndex, Spend,
        SpendKey,
    },
};
use rand::rngs::OsRng;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::Instant;

#[path = "../../../crates/octra-node-runtime/tests/common/payments_host.rs"]
#[allow(dead_code)]
mod host;

fn payload(code: &[u8]) -> Value {
    json!({"runtime":"octb", "privacy_class":"public", "browser_mode":"gateway_allowed",
        "resource_mode":"public_resources", "code_b64":STANDARD.encode(code),
        "limits":{"max_stable_bytes":"33554432", "max_assets_bytes":"33554432",
            "max_inline_value":"65536", "max_wasm_bytes":"33554432"}})
}
fn compile(source: &str) -> Vec<u8> {
    let compiled = octra_node_runtime::program::build::legacy(source.as_bytes(), true, true)
        .unwrap_or_else(|e| panic!("pool AML compile: {e}"));
    STANDARD
        .decode(compiled["bytecode"].as_str().unwrap())
        .unwrap()
}

struct Circle {
    host: host::Chain,
    rules: Rules,
}
impl Circle {
    fn new(source: &str) -> Self {
        let mut state = StateBatch::default();
        state.begin().unwrap();
        let accounts = (11..=14)
            .map(|id| {
                (
                    host::address(id).into_bytes(),
                    Account {
                        balance: 1_000_000_000_000_u64.into(),
                        ..Account::default()
                    },
                )
            })
            .collect();
        let mut c = Self {
            host: host::Chain {
                state,
                ledger: Ledger::from_accounts(accounts).unwrap(),
                runtime: host::common::runtime(),
                now: host::START,
                program: String::new(),
                factory: String::new(),
            },
            rules: Rules {
                wasm: WasmRules {
                    wasm_float: true,
                    proof_exec: true,
                    math: true,
                },
                manifest: WasmProfile::Manifest,
                update_policy: true,
                inspect: true,
                storage_proof: true,
                fhe_work: true,
                object_cost: true,
            },
        };
        let factory = payload(&compile(app::FACTORY));
        let deploy = Deploy::from_document(
            &Document::parse(&serde_json::to_vec(&factory).unwrap()).unwrap(),
        )
        .unwrap();
        c.host.factory =
            String::from_utf8(deploy.id(host::address(11).as_bytes(), c.host.nonce(11))).unwrap();
        let tx = c.host.transaction(
            11,
            &c.host.factory,
            OpType::CircleDeploy,
            factory,
            0,
            vec![],
        );
        let (effect, _) = c.execute(&tx);
        assert!(
            matches!(effect, Effect::Confirmed(_)),
            "factory deploy {effect:?}"
        );
        let receipt = c.call_at(
            &c.host.factory.clone(),
            "deploy_pool",
            json!([STANDARD.encode(serde_json::to_vec(&payload(&compile(source))).unwrap())]),
            0,
            true,
        );
        c.host.program = receipt["events"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["event"] == "ShieldedPoolDeployed")
            .unwrap()["values"][0]
            .as_str()
            .unwrap()
            .into();
        let info = circle_store::info(&c.host.state.snapshot(), c.host.program.as_bytes())
            .unwrap()
            .unwrap();
        assert_eq!(info.owner, c.host.factory.as_bytes());
        assert_eq!(
            c.host.state.snapshot().get(&[
                b"circles",
                c.host.program.as_bytes(),
                b"origin",
                b"owner_mode"
            ]),
            Some(b"parent".as_slice())
        );
        c.call("initialize", json!([]), 0, true);
        c
    }

    fn execute(&mut self, tx: &Transaction) -> (Effect, Value) {
        let batch = circle_transaction::execute(
            &self.host.runtime,
            self.rules,
            100,
            self.host.seconds(),
            std::slice::from_ref(tx),
            &mut self.host.ledger,
            &mut self.host.state,
        )
        .unwrap();
        let Outcome::Completed(completion) = batch.outcomes[0].outcome.clone() else {
            panic!("fixture nonce")
        };
        let effect = Effect::from_completion(tx, completion).unwrap();
        let receipt = batch
            .receipts
            .values()
            .next()
            .map_or(Value::Null, |r| serde_json::from_slice(r).unwrap());
        (effect, receipt)
    }

    fn call_at(
        &mut self,
        target: &str,
        method: &str,
        params: Value,
        amount: u64,
        success: bool,
    ) -> Value {
        let root = self.host.state.root().unwrap();
        let before = self
            .host
            .ledger
            .account(host::address(11).as_bytes())
            .unwrap()
            .balance
            .clone();
        let tx = self.host.transaction(
            11,
            target,
            OpType::CircleCall,
            params,
            amount,
            method.as_bytes().to_vec(),
        );
        let (effect, receipt) = self.execute(&tx);
        assert_eq!(
            matches!(effect, Effect::Confirmed(_)),
            success,
            "{method}: {effect:?} {receipt}"
        );
        if !success {
            assert!(matches!(effect, Effect::RejectedAfterFee { .. }));
            assert_eq!(
                self.host.state.root().unwrap(),
                root,
                "refusal changed stable state"
            );
            assert_eq!(
                self.host
                    .ledger
                    .account(host::address(11).as_bytes())
                    .unwrap()
                    .balance,
                before - host::FEE,
                "refused native value did not roll back"
            );
        }
        receipt
    }

    fn call(&mut self, method: &str, params: Value, amount: u64, success: bool) -> Value {
        self.call_at(&self.host.program.clone(), method, params, amount, success)
    }
}

fn params(circuit: &PoolCircuit, call: &Call, proof: &Proof<Bn254>) -> Value {
    let s = &circuit.statement;
    let field = |f| hex::encode(pool::encode_field(f));
    let expected = json!([
        field(s.new_notes),
        field(s.new_spent),
        s.new_count,
        s.withdraw,
        std::str::from_utf8(&call.payout).unwrap(),
        call.valid_from_ms,
        call.expires_ms,
        hex::encode(call.quote),
        field(s.authorization),
        field(s.nullifiers[0]),
        field(s.nullifiers[1]),
        field(s.outputs[0]),
        field(s.outputs[1]),
        call.boxes[0],
        call.boxes[1],
        STANDARD.encode(wire::proof(proof).unwrap())
    ]);
    let actual = pool::transaction::parameters(s, call, &wire::proof(proof).unwrap()).unwrap();
    assert_eq!(
        actual, expected,
        "native parameter builder differs from independent ABI encoding"
    );
    actual
}

fn prove(circuit: PoolCircuit, pk: &ProvingKey<Bn254>) -> Proof<Bn254> {
    let inputs = circuit.statement.fields();
    let proof =
        Groth16::<Bn254>::create_random_proof_with_reduction(circuit, pk, &mut OsRng).unwrap();
    assert!(
        Groth16::<Bn254>::verify_proof(&prepare_verifying_key(&pk.vk), &proof, &inputs).unwrap()
    );
    proof
}

fn call(circle: &Circle, boxes: [String; 2], quote: u8) -> Call {
    Call {
        quote: [quote; 32],
        valid_from_ms: circle.host.now as u64,
        expires_ms: circle.host.now as u64 + 60_000,
        payout: host::address(14).as_bytes().try_into().unwrap(),
        deposit_ou: 0,
        withdraw_ou: 0,
        boxes,
    }
}

#[test]
fn full_depth_pool_circle_deposit_private_purchase_earnings_spend_expiry_replay_and_exit() {
    let started = Instant::now();
    let chain = [23; 32];
    let provisional =
        Domain::new(&chain, host::address(12).as_bytes().try_into().unwrap()).unwrap();
    let setup_key = SpendKey::random();
    let note = Note::new(setup_key.owner(provisional), 1, &[9; 32]).unwrap();
    let (setup, _) = PoolIndex::default()
        .prepare(provisional, &[], &[note], 1, 0, [9; 32])
        .unwrap();
    eprintln!("pool: production 32/254-depth parameter setup");
    let pk =
        Groth16::<Bn254>::generate_random_parameters_with_reduction(setup, &mut OsRng).unwrap();
    let vk = wire::key(&pk.vk).unwrap();
    eprintln!(
        "pool: setup {:?}; native key {} bytes",
        started.elapsed(),
        vk.len()
    );
    let source = app::source(&chain, &vk, 1_000_000).unwrap();
    let mut circle = Circle::new(&source);
    let circle_address: [u8; 47] = circle.host.program.as_bytes().try_into().unwrap();
    let relayer: [u8; 47] = host::address(11).as_bytes().try_into().unwrap();
    let domain = Domain::new(&chain, &circle_address).unwrap();
    let payer = SpendKey::random();
    let operator = SpendKey::random();
    let exit = SpendKey::random();
    let view = native_stealth::view_secret(&[24; 32]);
    let public = native_stealth::view_public(&view);
    let mut index = PoolIndex::default();
    let mut public_events = Vec::new();
    let mut observed = Vec::new();
    // The two deposited notes exercise private 2-in / 2-out joining next.
    let drafts = [
        envelope::Draft::new(payer.owner(domain), 60, &public).unwrap(),
        envelope::Draft::new(payer.owner(domain), 40, &public).unwrap(),
    ];
    let mut c = call(
        &circle,
        std::array::from_fn(|i| drafts[i].ciphertext.clone()),
        0,
    );
    c.deposit_ou = 100;
    let context = c.context(&chain, &circle_address, &relayer).unwrap();
    let notes: [Note; 2] = std::array::from_fn(|i| drafts[i].bind(&context));
    let (deposit, proposed) = index.prepare(domain, &[], &notes, 100, 0, context).unwrap();
    let deposit_proof = prove(deposit.clone(), &pk);
    assert!(groth16::verify(
        &vk,
        &wire::proof(&deposit_proof).unwrap(),
        &wire::inputs(&deposit.statement)
    ));
    // Every public scalar is actually bound by the native wire verifier.
    for slot in 0..pool::INPUTS {
        let mut raw = wire::inputs(&deposit.statement);
        raw[slot * 32 + 31] ^= 1;
        assert!(
            !groth16::verify(&vk, &wire::proof(&deposit_proof).unwrap(), &raw),
            "unbound native input {slot}"
        );
    }
    let mut tampered = params(&deposit, &c, &deposit_proof);
    tampered[4] = json!(host::address(13));
    circle.call("exchange", tampered, 100, false);
    let rules = circle.rules;
    circle.rules.wasm.proof_exec = false;
    circle.call("exchange", params(&deposit, &c, &deposit_proof), 100, false);
    circle.rules = rules;
    let receipt = circle.call("exchange", params(&deposit, &c, &deposit_proof), 100, true);
    public_events.push(
        json!({"inputs":STANDARD.encode(wire::inputs(&deposit.statement)),
        "proof":STANDARD.encode(wire::proof(&deposit_proof).unwrap()), "receipt":receipt}),
    );
    index = index.observe(&deposit.statement).unwrap();
    observed.push(deposit.statement.clone());
    assert_eq!(index.roots(), proposed.roots());
    circle.call("exchange", params(&deposit, &c, &deposit_proof), 100, false);
    eprintln!(
        "pool: canonical local Circle deposit {:?}",
        started.elapsed()
    );

    let drafts = [
        envelope::Draft::new(operator.owner(domain), 30, &public).unwrap(),
        envelope::Draft::new(payer.owner(domain), 70, &public).unwrap(),
    ];
    let c = call(
        &circle,
        std::array::from_fn(|i| drafts[i].ciphertext.clone()),
        19,
    );
    let context = c.context(&chain, &circle_address, &relayer).unwrap();
    let bought: [Note; 2] = std::array::from_fn(|i| drafts[i].bind(&context));
    let (purchase, _) = index
        .prepare(
            domain,
            &[
                Spend {
                    note: &notes[0],
                    key: &payer,
                    index: 0,
                },
                Spend {
                    note: &notes[1],
                    key: &payer,
                    index: 1,
                },
            ],
            &bought,
            0,
            0,
            context,
        )
        .unwrap();
    let purchase_proof = prove(purchase.clone(), &pk);
    // A late purchase rolls back roots/custody; the same private input funds
    // remain available. No block clock or transaction rule is modified.
    circle.host.now = c.expires_ms as i64;
    circle.call("exchange", params(&purchase, &c, &purchase_proof), 0, false);
    assert!(index
        .prepare(
            domain,
            &[Spend {
                note: &notes[0],
                key: &payer,
                index: 0
            }],
            &[],
            0,
            60,
            [8; 32]
        )
        .is_ok());
    // Renew the private call at the advanced clock; no time is rewound and no
    // operator can debit the refused transaction's inputs in the meantime.
    let c = call(&circle, c.boxes, 21);
    let context = c.context(&chain, &circle_address, &relayer).unwrap();
    let bought: [Note; 2] = std::array::from_fn(|i| drafts[i].bind(&context));
    let (purchase, proposed) = index
        .prepare(
            domain,
            &[
                Spend {
                    note: &notes[0],
                    key: &payer,
                    index: 0,
                },
                Spend {
                    note: &notes[1],
                    key: &payer,
                    index: 1,
                },
            ],
            &bought,
            0,
            0,
            context,
        )
        .unwrap();
    let purchase_proof = prove(purchase.clone(), &pk);
    c.validate(
        &purchase.statement,
        &chain,
        &circle_address,
        &relayer,
        circle.host.now as u64,
    )
    .unwrap();
    let receipt = circle.call("exchange", params(&purchase, &c, &purchase_proof), 0, true);
    public_events.push(
        json!({"inputs":STANDARD.encode(wire::inputs(&purchase.statement)),
        "proof":STANDARD.encode(wire::proof(&purchase_proof).unwrap()), "receipt":receipt}),
    );
    index = index.observe(&purchase.statement).unwrap();
    observed.push(purchase.statement.clone());
    assert_eq!(index.roots(), proposed.roots());
    circle.call("exchange", params(&purchase, &c, &purchase_proof), 0, false);
    let earned = envelope::open(
        domain,
        operator.owner(domain),
        &view,
        &c.boxes[0],
        &context,
        purchase.statement.outputs[0],
    )
    .unwrap();
    assert_eq!(earned.value(), 30);

    let drafts = [
        envelope::Draft::new(exit.owner(domain), 20, &public).unwrap(),
        envelope::Draft::new(operator.owner(domain), 10, &public).unwrap(),
    ];
    let c = call(
        &circle,
        std::array::from_fn(|i| drafts[i].ciphertext.clone()),
        20,
    );
    let context = c.context(&chain, &circle_address, &relayer).unwrap();
    let onward: [Note; 2] = std::array::from_fn(|i| drafts[i].bind(&context));
    let (next_payment, _) = index
        .prepare(
            domain,
            &[Spend {
                note: &earned,
                key: &operator,
                index: 2,
            }],
            &onward,
            0,
            0,
            context,
        )
        .unwrap();
    let proof = prove(next_payment.clone(), &pk);
    let receipt = circle.call("exchange", params(&next_payment, &c, &proof), 0, true);
    public_events.push(
        json!({"inputs":STANDARD.encode(wire::inputs(&next_payment.statement)),
        "proof":STANDARD.encode(wire::proof(&proof).unwrap()), "receipt":receipt}),
    );
    index = index.observe(&next_payment.statement).unwrap();
    observed.push(next_payment.statement.clone());
    eprintln!(
        "pool: private earned-note onward spend {:?}",
        started.elapsed()
    );

    for (note, key, position) in [
        (&bought[1], &payer, 3),
        (&onward[1], &operator, 5),
        (&onward[0], &exit, 4),
    ] {
        let mut c = call(&circle, [String::new(), String::new()], 0);
        c.withdraw_ou = note.value();
        let context = c.context(&chain, &circle_address, &relayer).unwrap();
        let (withdraw, _) = index
            .prepare(
                domain,
                &[Spend {
                    note,
                    key,
                    index: position,
                }],
                &[],
                0,
                note.value(),
                context,
            )
            .unwrap();
        let proof = prove(withdraw.clone(), &pk);
        let before = circle
            .host
            .ledger
            .account(host::address(14).as_bytes())
            .unwrap()
            .balance
            .clone();
        let receipt = circle.call("exchange", params(&withdraw, &c, &proof), 0, true);
        assert_eq!(
            circle
                .host
                .ledger
                .account(host::address(14).as_bytes())
                .unwrap()
                .balance,
            before + note.value()
        );
        public_events.push(
            json!({"inputs":STANDARD.encode(wire::inputs(&withdraw.statement)),
            "proof":STANDARD.encode(wire::proof(&proof).unwrap()), "receipt":receipt}),
        );
        index = index.observe(&withdraw.statement).unwrap();
        observed.push(withdraw.statement.clone());
        circle.call("exchange", params(&withdraw, &c, &proof), 0, false);
    }
    // Six public roots/events rebuild the same index after losing wallet memory.
    assert_eq!(index.roots().2, 6);
    let mut recovered = PoolIndex::default();
    for statement in observed {
        recovered = recovered.observe(&statement).unwrap();
    }
    assert_eq!(recovered.roots(), index.roots());
    assert_eq!(
        circle
            .host
            .ledger
            .account(circle.host.program.as_bytes())
            .unwrap()
            .balance,
        0.into()
    );
    if let Some(path) = std::env::var_os("OCTRA_PRIVATE_POOL_EVIDENCE") {
        let report = json!({"circuit":pool::CIRCUIT, "note_depth":pool::NOTE_DEPTH,
            "spent_depth":pool::SPENT_DEPTH, "native_public_inputs":pool::INPUTS,
            "native_key":STANDARD.encode(vk), "source":source,
            "bytecode":STANDARD.encode(compile(&source)),
            "factory_bytecode":STANDARD.encode(compile(app::FACTORY)),
            "source_sha256":hex::encode(Sha256::digest(source.as_bytes())),
            "factory":app::FACTORY, "chain_origin":hex::encode(chain),
            "circle":circle.host.program, "relayer":std::str::from_utf8(&relayer).unwrap(),
            "transitions":public_events, "elapsed_ms":started.elapsed().as_millis(),
            "setup":"ephemeral local test entropy; no proving key or toxic waste exported",
            "release_enabled":false, "public_network_qualified":false});
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        use std::io::Write;
        file.write_all(serde_json::to_string_pretty(&report).unwrap().as_bytes())
            .unwrap();
    }
    eprintln!(
        "pool: PASS six full-depth native Circle transitions {:?}",
        started.elapsed()
    );
}
