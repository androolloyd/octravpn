use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::{
    aml::compiler::package::CompilerMode,
    program_record::{source::Sources, Record},
    program_upgrade,
    program_wire::Source,
    state::Ledger,
    transaction::{Nonce, OpType, Transaction},
};
use octra_node_runtime::{
    circle::{CircleRuntime, WasmProfile, WasmRules},
    circle_transaction::Rules,
    execution::{Completion, OperationHost, Route},
    program::{
        artifact::SourceRules,
        source_read::{Outcome, Reader},
        store::Meta,
    },
    program_transaction::Calls,
    state_batch::StateBatch,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
const OWNER: &[u8] = b"oct11111111111111111111111111111111111111111111";
const OTHER: &[u8] = b"oct22222222222222222222222222222222222222222222";
const ADDRESS: &[u8] = b"oct33333333333333333333333333333333333333333333";
fn setup() -> (StateBatch, Ledger, Sources, Vec<u8>, Record) {
    let sources = Sources {
        main: b"main.aml".to_vec(),
        files: vec![Source {
            path: b"main.aml".to_vec(),
            body: b"contract Record { view fn read(): int { return 73 } }".to_vec(),
        }],
        compiler: b"protocol".to_vec(),
        loops: false,
    };
    let (code, _) = sources.compile(true).unwrap();
    let record = sources.verify(true, false, &code).unwrap();
    let meta = Meta {
        address: ADDRESS.to_vec(),
        code_hash: hex::encode(Sha256::digest(&code)).into_bytes(),
        version: b"test".to_vec(),
        owner: OWNER.to_vec(),
        ctype: b"CUSTOM".to_vec(),
        admission: b"binary".to_vec(),
    };
    let mut state = StateBatch::default();
    state.begin().unwrap();
    state
        .set(&[b"contracts", ADDRESS, b"meta"], meta.encode())
        .unwrap();
    state
        .set(
            &[b"contracts", ADDRESS, b"bytecode"],
            STANDARD.encode(&code).into_bytes(),
        )
        .unwrap();
    let mut ledger = Ledger::empty();
    for address in [OWNER, OTHER] {
        ledger
            .add_account(address, 10_000_000.into(), None)
            .unwrap();
    }
    (state, ledger, sources, code, record)
}
fn request(sources: &Sources, record: &Record) -> Transaction {
    Transaction {
        from: OWNER.to_vec(),
        to: ADDRESS.to_vec(),
        amount: 0.into(),
        nonce: Nonce::new(1).unwrap(),
        ou: octra_node_protocol::program_record::source::fee(record),
        timestamp: 17.,
        signature: vec![],
        public_key: None,
        message: Some(program_upgrade::source_message(&record.code_hash)),
        op_type: OpType::ContractUpgrade,
        encrypted_data: Some(STANDARD.encode(sources.encode()).into_bytes()),
    }
}
fn apply(
    tx: &Transaction,
    state: &mut StateBatch,
    ledger: &mut Ledger,
) -> Result<Completion, octra_node_runtime::execution::Error> {
    let runtime = CircleRuntime::new(Arc::new(octra_node_runtime::circle_hfhe::Backend));
    let rules = Rules {
        scalar_work: false,
        wasm: WasmRules {
            wasm_float: false,
            proof_exec: false,
            proof_key: false,
            math: false,
        },
        manifest: WasmProfile::Manifest,
        update_policy: false,
        inspect: false,
        storage_proof: true,
        fhe_work: false,
        object_cost: false,
        program_inputs: true,
    };
    let source = SourceRules {
        compiler: CompilerMode::Protocol,
        overlap: false,
        point_ops: true,
        loops: false,
        metered: true,
        records: true,
    };
    Calls::new(&runtime, rules, source, 17, 17., &[0; 32], 64)
        .unwrap()
        .execute(Route::Upgrade, tx, ledger, state)
}
#[test]
fn only_owner_with_current_code_and_fee_can_commit_source() {
    for scenario in 0..4 {
        let (mut state, mut ledger, sources, _, record) = setup();
        let mut tx = request(&sources, &record);
        match scenario {
            0 => tx.from = OTHER.to_vec(),
            1 => tx.message = Some(program_upgrade::source_message(&[b'0'; 64])),
            2 => tx.ou = 1.into(),
            _ => (),
        }
        let result = apply(&tx, &mut state, &mut ledger).unwrap();
        if scenario < 3 {
            assert!(matches!(result, Completion::Rejected(_)));
            assert!(state
                .snapshot()
                .get(&[b"contracts", ADDRESS, b"record"])
                .is_none());
        } else {
            assert!(matches!(result, Completion::Confirmed { .. }));
            let saved = state.snapshot();
            assert_eq!(
                Record::decode(saved.get(&[b"contracts", ADDRESS, b"record"]).unwrap()).unwrap(),
                record
            );
            assert!(matches!(
                apply(&tx, &mut state, &mut ledger).unwrap(),
                Completion::Rejected(_)
            ));
        }
    }
}
#[test]
fn corrupt_stored_image_is_unavailable_and_cannot_publish() {
    let (mut state, mut ledger, sources, _, record) = setup();
    let tx = request(&sources, &record);
    state
        .set(&[b"contracts", ADDRESS, b"bytecode"], b"AAAA".to_vec())
        .unwrap();
    assert!(apply(&tx, &mut state, &mut ledger).is_err());
    assert!(state
        .snapshot()
        .get(&[b"contracts", ADDRESS, b"record"])
        .is_none());
}
#[tokio::test]
async fn source_reader_binds_code_hash_and_stops() {
    let (_, _, _, code, record) = setup();
    let reader = Reader::default();
    assert_eq!(
        reader
            .query(Some(STANDARD.encode(&code).into_bytes()), record.clone())
            .await,
        Outcome::Checked
    );
    assert_eq!(
        reader
            .query(Some(STANDARD.encode(b"wrong").into_bytes()), record.clone())
            .await,
        Outcome::Failed
    );
    reader.close();
    assert_eq!(
        reader
            .query(Some(STANDARD.encode(code).into_bytes()), record)
            .await,
        Outcome::Pending
    );
}
