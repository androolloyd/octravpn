//! Stateful application qualification through the production Program transaction
//! adapter. This is not public-chain, networking or traffic-delivery qualification.
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use num_bigint::BigInt;
use octra_node_protocol::{
    aml::{
        compiler::package::CompilerMode,
        source::{self, Syntax},
    },
    contract,
    native_json::Document,
    state::{Account, Ledger},
    transaction::{self, Nonce, OpType, RuleMode, Transaction},
};
use octra_node_runtime::{
    circle::{CircleRuntime, WasmProfile, WasmRules},
    circle_query::Query,
    circle_transaction::Rules,
    circle_view::Profile,
    epoch_execution::Effect,
    program::{artifact::SourceRules, store},
    program_transaction::Calls,
    state_batch::StateBatch,
};
use serde_json::{json, Value};
use std::{collections::BTreeMap, sync::OnceLock};

#[path = "circle_host.rs"]
#[allow(dead_code)]
pub(crate) mod common;

pub(crate) const DAY: i64 = 86_400_000;
pub(crate) const WEEK: i64 = 604_800_000;
pub(crate) const START: i64 = 1_800_000_000_000;
pub(crate) const STAKE: u64 = 100_000_000;
pub(crate) const FUND: u64 = 5_000_000;
pub(crate) const FEE: u64 = 5_000_000;
pub(crate) const DOMAIN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
pub(crate) const MANIFEST: &str =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

pub(crate) fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}
pub(crate) fn address(n: u8) -> String {
    String::from_utf8(transaction::address_from_public_key(
        STANDARD
            .encode(key(n).verifying_key().as_bytes())
            .as_bytes(),
    ))
    .unwrap()
}
pub(crate) fn sign(n: u8, message: &str) -> String {
    STANDARD.encode(key(n).sign(message.as_bytes()).to_bytes())
}
pub(crate) fn payment_compilation() -> &'static Value {
    static COMPILATION: OnceLock<Value> = OnceLock::new();
    COMPILATION.get_or_init(|| {
        // The same explicit local build used by the node's compile-legacy CLI.
        // This source needs both Program epoch_time and legacy Ed25519; its
        // complete typed compileAml admission is deliberately not claimed.
        octra_node_runtime::program::build::legacy(
            include_bytes!("../../../../program/octranet-payments.aml"),
            true,
            true,
        )
        .unwrap_or_else(|error| panic!("payment local compilation: {error}"))
    })
}
pub(crate) fn binaries() -> &'static (Vec<u8>, Vec<u8>) {
    static CODE: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
    CODE.get_or_init(|| {
        (
            STANDARD
                .decode(payment_compilation()["bytecode"].as_str().unwrap())
                .unwrap(),
            source::compile(
                include_bytes!("../../../../program/octranet-payments-factory.aml"),
                Syntax::Source,
                true,
            )
            .unwrap()
            .octb,
        )
    })
}
pub(crate) struct Chain {
    pub(crate) state: StateBatch,
    pub(crate) ledger: Ledger,
    pub(crate) runtime: CircleRuntime,
    pub(crate) now: i64,
    pub(crate) program: String,
    pub(crate) factory: String,
}
impl Chain {
    pub(crate) fn new() -> Self {
        Self::with_code(&binaries().0)
    }
    pub(crate) fn with_code(payment_code: &[u8]) -> Self {
        Self::with_code_and_cap(payment_code, 200_000_000)
    }
    pub(crate) fn with_cap(cap: u64) -> Self {
        Self::with_code_and_cap(&binaries().0, cap)
    }
    fn with_code_and_cap(payment_code: &[u8], cap: u64) -> Self {
        let accounts = (11..=14)
            .map(|n| {
                (
                    address(n).into_bytes(),
                    Account {
                        balance: BigInt::from(1_000_000_000_000_u64),
                        ..Account::default()
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        let mut state = StateBatch::default();
        state.begin().unwrap();
        let mut chain = Self {
            state,
            ledger: Ledger::from_accounts(accounts).unwrap(),
            runtime: common::runtime(),
            now: START,
            program: String::new(),
            factory: String::new(),
        };
        let code = &binaries().1;
        let nonce = chain.nonce(11);
        chain.factory =
            String::from_utf8(contract::address(code, address(11).as_bytes(), nonce.get()))
                .unwrap();
        let tx = chain.transaction(
            11,
            &chain.factory,
            OpType::ContractDeploy,
            json!([]),
            0,
            STANDARD.encode(code).into_bytes(),
        );
        let (effect, _) = chain.execute(&tx);
        assert!(
            matches!(effect, Effect::Confirmed(_)),
            "factory deploy {effect:?}"
        );
        let factory = chain.factory.clone();
        let receipt = chain.ok_at(
            11,
            &factory,
            "deploy_payments",
            json!([STANDARD.encode(payment_code), DOMAIN, cap, STAKE]),
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
            .clone_into(&mut chain.program);
        let meta = store::meta(&chain.state.snapshot(), chain.program.as_bytes())
            .unwrap()
            .unwrap();
        assert_eq!(meta.owner, chain.factory.as_bytes());
        chain
    }
    pub(crate) fn nonce(&self, who: u8) -> Nonce {
        self.ledger
            .account(address(who).as_bytes())
            .unwrap()
            .nonce
            .successor()
    }
    #[allow(clippy::needless_pass_by_value)] // JSON fixtures are passed as owned literals.
    pub(crate) fn transaction(
        &self,
        who: u8,
        target: &str,
        op_type: OpType,
        params: Value,
        amount: u64,
        data: Vec<u8>,
    ) -> Transaction {
        let mut tx = Transaction {
            from: address(who).into_bytes(),
            to: target.as_bytes().to_vec(),
            amount: BigInt::from(amount),
            nonce: self.nonce(who),
            ou: BigInt::from(FEE),
            timestamp: self.seconds(),
            signature: vec![],
            public_key: Some(
                STANDARD
                    .encode(key(who).verifying_key().as_bytes())
                    .into_bytes(),
            ),
            message: Some(serde_json::to_vec(&params).unwrap()),
            op_type,
            encrypted_data: Some(data),
        };
        tx.signature = STANDARD
            .encode(key(who).sign(&tx.signing_bytes().unwrap()).to_bytes())
            .into_bytes();
        assert!(tx.verify(tx.public_key.as_ref().unwrap()));
        tx
    }
    pub(crate) fn seconds(&self) -> f64 {
        assert!((0..=(1_i64 << 53)).contains(&self.now));
        #[allow(clippy::cast_precision_loss)] // Integer fixture milliseconds fit the f64 mantissa.
        let millis = self.now as f64;
        millis / 1000.0
    }
    pub(crate) fn execute(&mut self, tx: &Transaction) -> (Effect, Value) {
        let seconds = self.seconds();
        assert_eq!(
            octra_node_protocol::consensus::policy::time_of_seconds(seconds).unwrap(),
            self.now
        );
        let root = hex::encode(self.state.root().unwrap());
        let mut calls = Calls::new(
            &self.runtime,
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
            },
            SourceRules {
                compiler: CompilerMode::Source,
                overlap: false,
                point_ops: true,
                loops: true,
            },
            100,
            seconds,
            root.as_bytes(),
            64,
        )
        .unwrap();
        let effect = calls
            .process(tx, &mut self.ledger, &mut self.state)
            .unwrap();
        let receipt = calls
            .receipts()
            .values()
            .next()
            .map_or(Value::Null, |raw| serde_json::from_slice(raw).unwrap());
        (effect, receipt)
    }
    pub(crate) fn ok_at(
        &mut self,
        who: u8,
        target: &str,
        method: &str,
        params: Value,
        amount: u64,
    ) -> Value {
        let tx = self.transaction(
            who,
            target,
            OpType::ContractCall,
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
    pub(crate) fn ok(&mut self, who: u8, method: &str, params: Value, amount: u64) -> Value {
        self.ok_at(who, &self.program.clone(), method, params, amount)
    }
    pub(crate) fn denied(
        &mut self,
        who: u8,
        method: &str,
        params: Value,
        amount: u64,
        reason: &str,
    ) {
        let root = self.state.root().unwrap();
        let before = self
            .ledger
            .account(address(who).as_bytes())
            .unwrap()
            .balance
            .clone();
        let tx = self.transaction(
            who,
            &self.program,
            OpType::ContractCall,
            params,
            amount,
            method.as_bytes().to_vec(),
        );
        let (effect, receipt) = self.execute(&tx);
        let Effect::RejectedAfterFee { refusal, .. } = effect else {
            panic!("{method}: {effect:?} {receipt}")
        };
        assert!(
            String::from_utf8_lossy(&refusal.reason).contains(reason),
            "{method}: {refusal:?} {receipt}"
        );
        assert_eq!(
            self.state.root().unwrap(),
            root,
            "revert must roll back application state"
        );
        assert_eq!(
            self.ledger
                .account(address(who).as_bytes())
                .unwrap()
                .balance,
            before - FEE,
            "value must roll back; native fee remains charged"
        );
    }
    #[allow(clippy::needless_pass_by_value)] // JSON fixtures are passed as owned literals.
    pub(crate) fn view(&self, method: &str, params: Value) -> Value {
        let snapshot = self.state.snapshot();
        let profile = Profile {
            proof_exec: RuleMode::Active,
            math: true,
            ..Profile::prior(100)
        };
        let result = Query::new(&snapshot, &profile)
            .unwrap()
            .with_runtime(&self.runtime)
            .program(
                self.program.as_bytes(),
                method.as_bytes(),
                &Document::parse(&serde_json::to_vec(&params).unwrap()).unwrap(),
                address(11).as_bytes(),
                5_000_000,
            )
            .unwrap();
        assert!(result.success, "view {method}: {:?}", result.error);
        serde_json::from_slice(&result.response.unwrap().result_json()).unwrap()
    }
    pub(crate) fn number(&self, method: &str, params: Value) -> u64 {
        let v = self.view(method, params);
        v.as_u64()
            .unwrap_or_else(|| v.as_str().unwrap().parse().unwrap())
    }
    pub(crate) fn register(&mut self, generation: u64) {
        let message = format!(
            "Octranet register v1|{DOMAIN}|{}|{}|{generation}",
            self.program,
            address(12)
        );
        self.ok(
            12,
            "register",
            json!([
                STANDARD.encode(key(21).verifying_key().as_bytes()),
                sign(21, &message)
            ]),
            0,
        );
    }
    pub(crate) fn register_operator_key(&mut self, who: u8, key_id: u8, generation: u64) {
        let message = format!(
            "Octranet operator key v1|{DOMAIN}|{}|{}|{generation}",
            self.program,
            address(who)
        );
        self.ok(
            who,
            "register_operator_receipt_key",
            json!([
                STANDARD.encode(key(key_id).verifying_key().as_bytes()),
                sign(key_id, &message)
            ]),
            0,
        );
    }
    pub(crate) fn funded_plan(&mut self) {
        self.funded_plan_for_manifest(MANIFEST);
    }
    pub(crate) fn funded_plan_for_manifest(&mut self, manifest: &str) {
        self.ok(11, "bond_operator", json!([]), STAKE);
        self.register_operator_key(11, 11, 1);
        self.register(1);
        self.ok(12, "fund", json!([address(12)]), FUND);
        self.ok(11, "create_offer", json!([manifest]), 0);
        self.ok(11, "append_class", json!([0, 10]), 0);
        self.ok(11, "append_class", json!([0, 100]), 0);
        self.ok(11, "seal_offer", json!([0]), 0);
        self.ok(12, "open_plan", json!([0, 1000]), 0);
        assert_eq!(self.view("can_forward", json!([0])), true);
    }
    pub(crate) fn receipt(&self, class: u64, seq: u64, bytes: u64) -> Value {
        let message = format!(
            "Octranet prepaid v1|{DOMAIN}|{}|{}|1|0|0|{MANIFEST}|{class}|{seq}|{bytes}",
            self.program,
            address(12)
        );
        assert_eq!(
            self.view("get_usage_message", json!([0, class, seq, bytes])),
            message
        );
        json!([0, class, seq, bytes, sign(21, &message)])
    }
    pub(crate) fn locked(&self) -> u64 {
        self.number("get_locked_value", json!([]))
    }
}
