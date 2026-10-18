//! Real Circle deploy/spawn/calls through the unchanged transaction/value host.
//! These component tests do not confer canonical publication or network authority.
use super::test_host as host;
use super::*;
use octra_node_protocol::{
    aml::{
        ast::{Stmt, Visibility},
        parser,
        source::{self, Syntax},
    },
    circle_program::Deploy,
    native_json::Document,
    state::{Account, Ledger},
    transaction::{OpType, RuleMode},
};
use octra_node_runtime::{
    circle::{WasmProfile, WasmRules},
    circle_query::Query,
    circle_transaction::{self, Rules},
    circle_view::Profile,
    epoch_execution::Effect,
};
use serde_json::{json, Value};
use std::sync::OnceLock;

const CAP: u64 = 200_000_000;
fn compiled() -> &'static Value {
    static BUILD: OnceLock<Value> = OnceLock::new();
    BUILD.get_or_init(|| build::compile(host::DOMAIN, CAP, host::STAKE).unwrap())
}
fn factory() -> &'static Vec<u8> {
    static BUILD: OnceLock<Vec<u8>> = OnceLock::new();
    BUILD.get_or_init(|| {
        source::compile(
            include_bytes!("../../../../../program/octranet-payments-circle-factory.aml"),
            Syntax::Source,
            true,
        )
        .unwrap()
        .octb
    })
}
pub(super) fn payload(code: &[u8]) -> Value {
    json!({"runtime":"octb","privacy_class":"public","browser_mode":"gateway_allowed",
        "resource_mode":"public_resources","code_b64":STANDARD.encode(code),
        "limits":{"max_stable_bytes":"33554432","max_assets_bytes":"33554432",
            "max_inline_value":"65536","max_wasm_bytes":"33554432"}})
}
fn rules() -> Rules {
    Rules {
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
    }
}
struct Circle {
    host: host::Chain,
    rules: Rules,
}
impl Circle {
    fn new() -> Self {
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
            rules: rules(),
        };
        let p = payload(factory());
        let deploy =
            Deploy::from_document(&Document::parse(&serde_json::to_vec(&p).unwrap()).unwrap())
                .unwrap();
        c.host.factory =
            String::from_utf8(deploy.id(host::address(11).as_bytes(), c.host.nonce(11))).unwrap();
        let tx = c
            .host
            .transaction(11, &c.host.factory, OpType::CircleDeploy, p, 0, vec![]);
        let (effect, _) = c.execute(&tx);
        assert!(
            matches!(effect, Effect::Confirmed(_)),
            "factory deploy {effect:?}"
        );
        let receipt = c.call_at(
            11,
            &c.host.factory.clone(),
            "deploy_payments",
            json!([STANDARD.encode(
                serde_json::to_vec(&payload(
                    &STANDARD
                        .decode(compiled()["bytecode"].as_str().unwrap())
                        .unwrap()
                ))
                .unwrap()
            )]),
            0,
        );
        c.host.program = receipt["events"]
            .as_array()
            .unwrap()
            .iter()
            .find(|event| event["event"] == "PaymentsCircleDeployed")
            .unwrap()["values"][0]
            .as_str()
            .unwrap()
            .to_owned();
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
        c
    }
    fn execute(&mut self, tx: &octra_node_protocol::transaction::Transaction) -> (Effect, Value) {
        let seconds = self.host.seconds();
        let batch = circle_transaction::execute(
            &self.host.runtime,
            self.rules,
            100,
            seconds,
            std::slice::from_ref(tx),
            &mut self.host.ledger,
            &mut self.host.state,
        )
        .unwrap();
        let octra_node_runtime::execution::Outcome::Completed(completion) =
            batch.outcomes[0].outcome.clone()
        else {
            panic!("fixture nonce mismatch");
        };
        let effect = Effect::from_completion(tx, completion).unwrap();
        let receipt = batch
            .receipts
            .values()
            .next()
            .map_or(Value::Null, |raw| serde_json::from_slice(raw).unwrap());
        (effect, receipt)
    }
    fn call_at(
        &mut self,
        who: u8,
        target: &str,
        method: &str,
        params: Value,
        amount: u64,
    ) -> Value {
        let tx = self.host.transaction(
            who,
            target,
            OpType::CircleCall,
            params,
            amount,
            method.as_bytes().to_vec(),
        );
        let (effect, receipt) = self.execute(&tx);
        assert!(
            matches!(effect, Effect::Confirmed(_)),
            "{method}: {effect:?} {receipt}"
        );
        receipt
    }
    fn call(&mut self, who: u8, method: &str, params: Value, amount: u64) -> Value {
        self.call_at(who, &self.host.program.clone(), method, params, amount)
    }
    fn denied(&mut self, who: u8, method: &str, params: Value, amount: u64) {
        let root = self.host.state.root().unwrap();
        let balance = self
            .host
            .ledger
            .account(host::address(who).as_bytes())
            .unwrap()
            .balance
            .clone();
        let tx = self.host.transaction(
            who,
            &self.host.program,
            OpType::CircleCall,
            params,
            amount,
            method.as_bytes().to_vec(),
        );
        let (effect, receipt) = self.execute(&tx);
        assert!(
            matches!(effect, Effect::RejectedAfterFee { .. }),
            "{method}: {effect:?} {receipt}"
        );
        assert_eq!(
            self.host.state.root().unwrap(),
            root,
            "failed call must retain stable state"
        );
        assert_eq!(
            self.host
                .ledger
                .account(host::address(who).as_bytes())
                .unwrap()
                .balance,
            balance - host::FEE,
            "failed value must roll back"
        );
    }
    fn view(&self, method: &str, params: &Value) -> Value {
        let snapshot = self.host.state.snapshot();
        let profile = Profile {
            proof_exec: RuleMode::Active,
            math: true,
            ..Profile::prior(100)
        };
        let params = Document::parse(&serde_json::to_vec(params).unwrap()).unwrap();
        let result = Query::new(&snapshot, &profile)
            .unwrap()
            .with_runtime(&self.host.runtime)
            .circle(
                self.host.program.as_bytes(),
                method.as_bytes(),
                &params,
                host::address(11).as_bytes(),
                5_000_000,
            )
            .unwrap();
        assert!(result.success, "{method}: {:?}", result.error);
        serde_json::from_slice(&result.response.unwrap().result_json()).unwrap()
    }
    fn uint(&self, field: &[u8], indices: &[&str]) -> u64 {
        let config = self.config();
        let snapshot = self.host.state.snapshot();
        Fields::new(&snapshot, &config)
            .uint(field, indices)
            .unwrap()
    }
    fn config(&self) -> Config {
        Config {
            application: Application::Circle,
            program: self.host.program.clone(),
            code_hash: hex::encode(Sha256::digest(
                STANDARD
                    .decode(compiled()["bytecode"].as_str().unwrap())
                    .unwrap(),
            )),
            factory: self.host.factory.clone(),
            factory_code_hash: hex::encode(Sha256::digest(factory())),
            domain: host::DOMAIN.into(),
            operator_circle: host::address(14),
            offer: 0,
        }
    }
    fn initialize(&mut self) {
        self.call(14, "initialize", json!([]), 0);
    }
    fn funded(&mut self) {
        self.initialize();
        self.call(11, "bond_operator", json!([]), host::STAKE);
        let message = format!(
            "Octranet register v1|{}|{}|{}|1",
            host::DOMAIN,
            self.host.program,
            host::address(12)
        );
        self.call(
            12,
            "register",
            json!([
                STANDARD.encode(host::key(21).verifying_key().as_bytes()),
                host::sign(21, &message)
            ]),
            0,
        );
        self.call(12, "fund", json!([host::address(12)]), host::FUND);
        self.call(11, "create_offer", json!([host::MANIFEST]), 0);
        self.call(11, "append_class", json!([0, 10]), 0);
        self.call(11, "seal_offer", json!([0]), 0);
        self.call(12, "open_plan", json!([0, 1000]), 0);
    }
}

#[test]
fn specialization_preserves_every_body_and_guards_all_original_entrypoints() {
    let source = build::source(host::DOMAIN, CAP, host::STAKE).unwrap();
    let ast = parser::parse(source.as_bytes()).unwrap();
    assert!(ast.contract.constructor.is_none());
    for function in ast.contract.functions.iter().filter(|function| {
        function.visibility == Visibility::Public && function.name != b"initialize"
    }) {
        let mut first = ast.nodes.statement(function.body[0]);
        while let Stmt::Located(_, _, inner) = first {
            first = ast.nodes.statement(*inner);
        }
        let Stmt::Expr(expression) = first else {
            panic!("unguarded {:?}", function.name);
        };
        assert!(
            matches!(ast.nodes.expression(*expression), octra_node_protocol::aml::ast::Expr::Call(name,args) if name == b"require_initialized" && args.is_empty())
        );
    }
    assert_eq!(compiled()["typed_admission"], false);
    assert_eq!(
        compiled()["initialization"],
        "separate-finalized-circle-call"
    );
    assert!(build::source("bad", CAP, host::STAKE).is_err());
    assert!(build::source(host::DOMAIN, host::STAKE, host::STAKE).is_err());
}

#[test]
fn parent_owned_spawn_is_uninitialized_and_permissionless_init_has_only_pinned_terms() {
    let mut c = Circle::new();
    for (method, params, amount) in [
        ("bond_operator", json!([]), host::STAKE),
        ("fund", json!([host::address(12)]), 1000),
        ("register", json!(["bad", "bad"]), 0),
        ("create_offer", json!([host::MANIFEST]), 0),
        ("request_operator_unstake", json!([]), 0),
        ("withdraw_operator_stake", json!([]), 0),
        ("open_plan", json!([0, 1]), 0),
        ("claim", json!([0, 0, 1, 1, "bad"]), 0),
        ("request_exit", json!([]), 0),
        ("withdraw_remaining", json!([]), 0),
        ("withdraw_channel", json!([1]), 0),
        ("withdraw_earnings", json!([1]), 0),
    ] {
        c.denied(12, method, params, amount);
    }
    // A different caller may initialize first; no caller chooses any terms.
    c.initialize();
    let root = c.host.state.root().unwrap();
    c.call(13, "initialize", json!([]), 0);
    assert_eq!(c.host.state.root().unwrap(), root);
    assert_eq!(c.view("get_domain", &json!([])), host::DOMAIN);
    assert_eq!(c.view("get_custody_cap", &json!([])), CAP.to_string());
    assert_eq!(
        c.view("get_min_operator_stake", &json!([])),
        host::STAKE.to_string()
    );
    // A signed wallet cannot use the parent Circle address as its own identity.
    let tx = c.host.transaction(
        11,
        &c.host.program,
        OpType::CircleProgramUpdate,
        json!({"code_b64":compiled()["bytecode"]}),
        0,
        vec![],
    );
    assert!(matches!(c.execute(&tx).0, Effect::Rejected(_)));
}

#[test]
fn circle_custody_buys_before_delivery_withdraws_immediately_and_uses_canonical_week() {
    let mut c = Circle::new();
    c.funded();
    let message = format!(
        "Octranet prepaid v1|{}|{}|{}|1|0|0|{}|0|1|1048576",
        host::DOMAIN,
        c.host.program,
        host::address(12),
        host::MANIFEST
    );
    c.call(
        13,
        "claim",
        json!([0, 0, 1, 1_048_576, host::sign(21, &message)]),
        0,
    );
    assert_eq!(c.uint(b"class_bytes", &["0", "0"]), 1_048_576);
    assert_eq!(c.uint(b"earnings", &[&host::address(11)]), 10);
    // Unsupported claims roll back real ledger value and all stable state.
    c.denied(12, "withdraw_channel", json!([host::FUND + 1]), 0);
    let before = c
        .host
        .ledger
        .account(host::address(12).as_bytes())
        .unwrap()
        .balance
        .clone();
    c.call(12, "withdraw_remaining", json!([]), 0);
    assert_eq!(
        c.host
            .ledger
            .account(host::address(12).as_bytes())
            .unwrap()
            .balance,
        before - host::FEE + host::FUND - 10
    );
    let first = c.host.now;
    c.call(11, "request_operator_unstake", json!([]), 0);
    assert_eq!(
        c.uint(b"operator_unlock", &[&host::address(11)]),
        u64::try_from(first + host::WEEK).unwrap()
    );
    c.host.now += host::WEEK - 1;
    c.call(11, "request_operator_unstake", json!([]), 0);
    c.denied(11, "withdraw_operator_stake", json!([]), 0);
    c.host.now += 1;
    let before = c
        .host
        .ledger
        .account(host::address(11).as_bytes())
        .unwrap()
        .balance
        .clone();
    c.call(11, "withdraw_operator_stake", json!([]), 0);
    assert_eq!(
        c.host
            .ledger
            .account(host::address(11).as_bytes())
            .unwrap()
            .balance,
        before - host::FEE + host::STAKE
    );
}

#[test]
fn circle_value_host_requires_active_proof_rules_and_current_call_code() {
    for stale in [false, true] {
        let mut c = Circle::new();
        c.initialize();
        let before = c
            .host
            .ledger
            .account(host::address(11).as_bytes())
            .unwrap()
            .balance
            .clone();
        if stale {
            c.host
                .state
                .set(
                    &[b"circles", c.host.program.as_bytes(), b"call_code"],
                    b"stale".to_vec(),
                )
                .unwrap();
        } else {
            c.rules.wasm.proof_exec = false;
        }
        // Funding may enter custody under native outer value staging, but the
        // app cannot authorize outbound value without the actual host policy.
        c.call(11, "bond_operator", json!([]), host::STAKE);
        c.call(11, "request_operator_unstake", json!([]), 0);
        c.host.now += host::WEEK;
        c.denied(11, "withdraw_operator_stake", json!([]), 0);
        assert!(
            c.host
                .ledger
                .account(host::address(11).as_bytes())
                .unwrap()
                .balance
                < before
        );
        let cfg = c.config();
        if stale {
            assert!(check_application(
                Application::Circle,
                &c.host.state.snapshot(),
                &cfg.program,
                &cfg.code_hash,
                Some(cfg.factory.as_bytes())
            )
            .is_err());
        }
    }
}

#[test]
fn circle_adapter_refuses_kind_confusion_and_corrupt_stable_fields() {
    let mut c = Circle::new();
    c.initialize();
    let config = c.config();
    let snapshot = c.host.state.snapshot();
    check_application(
        Application::Circle,
        &snapshot,
        &config.program,
        &config.code_hash,
        Some(config.factory.as_bytes()),
    )
    .unwrap();
    assert!(check_application(
        Application::Program,
        &snapshot,
        &config.program,
        &config.code_hash,
        Some(config.factory.as_bytes())
    )
    .is_err());
    let hash = octra_node_protocol::circles::stable_key(b"domain");
    let forged = circle_store::StableEntry {
        key: b"other".to_vec(),
        hash: hash.as_bytes().to_vec(),
        value: circle_store::StableValue::Inline(host::DOMAIN.as_bytes().to_vec()),
    };
    c.host
        .state
        .set(
            &[
                b"circles",
                c.host.program.as_bytes(),
                b"stable",
                b"by_hash",
                hash.as_bytes(),
            ],
            forged.encode(),
        )
        .unwrap();
    assert!(Fields::new(&c.host.state.snapshot(), &config)
        .text(b"domain", &[])
        .is_err());
    let chain = ChainIdentity::genesis("kind-separation", octra_exex::StateRoot([7; 32]));
    assert_ne!(
        network_domain(&chain),
        application_domain(&chain, Application::Circle)
    );
    let mut legacy = serde_json::to_value(&config).unwrap();
    legacy.as_object_mut().unwrap().remove("application");
    assert_eq!(
        serde_json::from_value::<Config>(legacy)
            .unwrap()
            .application,
        Application::Program
    );
}

#[test]
fn plain_transfer_does_not_create_channel_credit_or_purchase_authority() {
    let mut c = Circle::new();
    let tx = c.host.transaction(
        12,
        &c.host.program,
        OpType::Standard,
        json!([]),
        1234,
        vec![],
    );
    assert!(matches!(c.execute(&tx).0, Effect::Confirmed(_)));
    assert_eq!(
        c.host
            .ledger
            .account(c.host.program.as_bytes())
            .unwrap()
            .balance,
        1234.into()
    );
    c.initialize();
    assert_eq!(c.uint(b"locked_value", &[]), 0);
    assert_eq!(c.uint(b"funds", &[&host::address(12)]), 0);
    c.denied(12, "withdraw_remaining", json!([]), 0);
    assert_eq!(
        c.host
            .ledger
            .account(c.host.program.as_bytes())
            .unwrap()
            .balance,
        1234.into()
    );
}

#[test]
fn native_circle_artifact_is_the_exact_local_specialization() {
    let path = std::env::var_os("OCTRA_CIRCLE_PREPAID_ORACLE").map_or_else(
        || {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../octra-node-runtime/tests/fixtures/circle-prepaid.json")
        },
        std::path::PathBuf::from,
    );
    let fixture: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let terms = &fixture["build"]["terms"];
    let actual = build::compile(
        terms["domain"].as_str().unwrap(),
        terms["custody_cap"].as_u64().unwrap(),
        terms["minimum_stake"].as_u64().unwrap(),
    )
    .unwrap();
    assert_eq!(
        fixture["build"], actual,
        "native output must bind the exact source transform and unchanged local emitter"
    );
    assert_eq!(
        fixture["dependencies"]["crates/octra-node/src/vpn/payments/build.rs"],
        hex::encode(Sha256::digest(include_bytes!("build.rs")))
    );
}
