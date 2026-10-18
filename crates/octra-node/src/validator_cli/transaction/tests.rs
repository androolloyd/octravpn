use super::*;
use axum::{extract::State, routing::post, Json, Router};
use clap::Parser;
use octra_node_protocol::{control_payload::Bond, native_json::Document};
use std::sync::{Arc, Mutex};

#[derive(Parser)]
struct Cli {
    #[command(flatten)]
    options: Options,
}
fn options(args: &[&str]) -> Options {
    Cli::try_parse_from(std::iter::once("validator-tx").chain(args.iter().copied()))
        .unwrap()
        .options
}
fn fixture(directory: &Path) -> PathBuf {
    let key = SigningKey::from_bytes(&[7; 32]);
    let public = STANDARD.encode(key.verifying_key().as_bytes());
    let address =
        String::from_utf8(transaction::address_from_public_key(public.as_bytes())).unwrap();
    let file = directory.join("wallet.json");
    std::fs::write(
        &file,
        serde_json::to_vec(
            &json!({"address":address,"pub":public,"priv":STANDARD.encode(key.to_bytes())}),
        )
        .unwrap(),
    )
    .unwrap();
    file
}
fn fixed(wallet: &Path, operation: &str) -> Options {
    options(&[
        "--wallet",
        wallet.to_str().unwrap(),
        "--op",
        operation,
        "--nonce",
        "17",
        "--timestamp",
        "1700000000.125",
        "--prepare",
    ])
}

#[test]
fn local_intent_wallet_directory_matches_native_for_relative_filenames() {
    // Empty parent would create validator-control and then fail its parent
    // directory fsync, rather than persisting the first request successfully.
    for (wallet, expected) in [
        ("wallet.json", "."),
        ("./wallet.json", "."),
        ("keys/wallet.json", "keys"),
        ("../wallet.json", ".."),
        ("/isolated-fixture/wallet.json", "/isolated-fixture"),
    ] {
        assert_eq!(wallet_directory(Path::new(wallet)), Path::new(expected));
    }
}

#[test]
fn bond_uses_native_domains_and_large_integer_native_wire() {
    let dir = tempfile::tempdir().unwrap();
    let path = fixture(dir.path());
    let wallet = Wallet::read(&path).unwrap();
    let mut args = fixed(&path, "validator_bond");
    args.chain_id = Some("private-cli-fixture".into());
    args.amount = "184467440737095516160000".into();
    let tx = args
        .draft(&wallet, Nonce::new(17).unwrap(), 1_700_000_000.125)
        .unwrap();
    assert_eq!(tx.to, registry::escrow_address());
    assert_eq!(tx.ou, BigInt::from(1000));
    assert_eq!(tx.amount.to_string(), args.amount);
    assert!(tx.verify(wallet.file.public.as_bytes()));
    let payload: Value = serde_json::from_slice(tx.message.as_ref().unwrap()).unwrap();
    let bond = Bond {
        consensus_public_key: payload["consensus_pubkey"]
            .as_str()
            .unwrap()
            .as_bytes()
            .to_vec(),
        proof: payload["proof"].as_str().unwrap().as_bytes().to_vec(),
    };
    assert_eq!(
        registry::verify_bond_proof(
            b"private-cli-fixture",
            &tx.from,
            &tx.amount,
            tx.nonce,
            &bond
        )
        .unwrap(),
        wallet.key.verifying_key().as_bytes()
    );
    assert!(
        registry::verify_bond_proof(b"other-chain", &tx.from, &tx.amount, tx.nonce, &bond).is_err()
    );
    assert!(registry::verify_bond_proof(
        b"private-cli-fixture",
        &tx.from,
        &tx.amount,
        Nonce::new(18).unwrap(),
        &bond
    )
    .is_err());
    let raw = tx.to_json_bytes().unwrap();
    let decoded = Transaction::from_document(&Document::parse(&raw).unwrap()).unwrap();
    assert_eq!(decoded, tx);
    assert_eq!(decoded.hash().unwrap(), tx.hash().unwrap());
    let signing = tx.signing_bytes().unwrap();
    assert!(signing.starts_with(format!("{{\"from\":\"{}\",\"to_\":\"{}\",\"amount\":\"{}\",\"nonce\":17,\"ou\":\"1000\",\"timestamp\":1700000000.125,\"op_type\":\"validator_bond\",\"message\":", wallet.file.address, String::from_utf8(tx.to).unwrap(), args.amount).as_bytes()));
}

#[test]
fn validator_messages_costs_and_arbitrary_native_op_are_preserved() {
    let dir = tempfile::tempdir().unwrap();
    let path = fixture(dir.path());
    let wallet = Wallet::read(&path).unwrap();
    for operation in [
        "validator_set_update",
        "validator_ready",
        "validator_evidence",
    ] {
        let mut args = fixed(&path, operation);
        assert!(args.draft(&wallet, Nonce::new(17).unwrap(), 1.0).is_err());
        args.message = Some(" \t\r\n\u{000c}".into());
        assert!(args.draft(&wallet, Nonce::new(17).unwrap(), 1.0).is_err());
        args.message = Some("{\"fixture\":true}".into());
        let tx = args.draft(&wallet, Nonce::new(17).unwrap(), 1.0).unwrap();
        assert_eq!(tx.message, Some(b"{\"fixture\":true}".to_vec()));
        assert_eq!(
            tx.ou,
            BigInt::from(if operation == "validator_evidence" {
                5000
            } else {
                1000
            })
        );
    }
    for operation in ["validator_exit", "validator_withdraw", "standard"] {
        let args = fixed(&path, operation);
        let tx = args.draft(&wallet, Nonce::new(17).unwrap(), 1.0).unwrap();
        assert_eq!(tx.to, wallet.file.address.as_bytes());
        assert!(tx.verify(wallet.file.public.as_bytes()));
    }
    assert!(fixed(&path, "unknown_op")
        .draft(&wallet, Nonce::new(17).unwrap(), 1.0)
        .is_err());
}

#[tokio::test]
async fn offline_prepare_print_only_and_exact_message_file_never_use_rpc() {
    let dir = tempfile::tempdir().unwrap();
    let path = fixture(dir.path());
    let message_path = dir.path().join("payload");
    std::fs::write(&message_path, b"custom\x00message\n").unwrap();
    let mut args = fixed(&path, "validator_bond");
    args.message = Some("ignored".into());
    args.message_file = Some(message_path.clone());
    args.ou = Some("12345".into());
    let output = args.execute().await.unwrap();
    let prepared: Value = serde_json::from_slice(&output).unwrap();
    let tx = Transaction::from_document(
        &Document::parse(&serde_json::to_vec(&prepared["tx"]).unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(tx.message, Some(b"custom\x00message\n".to_vec()));
    assert_eq!(tx.ou, BigInt::from(12345));
    assert_eq!(prepared["tx_hash"], hex::encode(tx.hash().unwrap()));
    let mut args = fixed(&path, "validator_bond");
    args.message_file = Some(message_path);
    args.ou = Some("12345".into());
    args.prepare = false;
    args.print_only = true;
    assert_eq!(args.execute().await.unwrap(), tx.to_json_bytes().unwrap());
    assert!(dir
        .path()
        .read_dir()
        .unwrap()
        .all(|entry| entry.unwrap().path().is_file()));
}

#[test]
fn key_identity_integer_and_finite_timestamp_refusals_do_not_sign() {
    let dir = tempfile::tempdir().unwrap();
    let path = fixture(dir.path());
    let wallet = Wallet::read(&path).unwrap();
    let mut args = fixed(&path, "validator_exit");
    args.amount = "not-an-integer".into();
    assert!(args.draft(&wallet, Nonce::new(17).unwrap(), 1.0).is_err());
    args.amount = "0".into();
    assert!(args
        .draft(&wallet, Nonce::new(17).unwrap(), f64::NAN)
        .is_err());
    assert!(explicit_nonce("-1").is_err());
    assert!(explicit_nonce("4611686018427387904").is_err());
    let mut value: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    value["pub"] =
        json!(STANDARD.encode(SigningKey::from_bytes(&[8; 32]).verifying_key().as_bytes()));
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(Wallet::read(&path).is_err());
}

#[tokio::test]
async fn capabilities_and_signed_wallet_intents_preserve_local_controls() {
    let capabilities: Value =
        serde_json::from_slice(&options(&["--capabilities"]).execute().await.unwrap()).unwrap();
    assert_eq!(
        capabilities,
        json!({"exit_intent":true,"prepare_transaction":true})
    );
    let dir = tempfile::tempdir().unwrap();
    let path = fixture(dir.path());
    let args = options(&[
        "--wallet",
        path.to_str().unwrap(),
        "--exit-intent",
        "request",
        "--chain-id",
        "private-cli-fixture",
        "--bonded-epoch",
        "9",
    ]);
    let requested: Value = serde_json::from_slice(&args.execute().await.unwrap()).unwrap();
    let wallet = Wallet::read(&path).unwrap();
    let identity = Identity {
        chain_id: b"private-cli-fixture".to_vec(),
        address: wallet.file.address.into_bytes(),
        pubkey: wallet.file.public.into_bytes(),
        bonded_epoch: 9,
    };
    let control = octra_node_runtime::validator_control::Control::new(dir.path());
    assert_eq!(
        requested["intent_id"].as_str().unwrap(),
        control.status(&identity).unwrap().unwrap()
    );
    let args = options(&[
        "--wallet",
        path.to_str().unwrap(),
        "--exit-intent",
        "cancel",
        "--chain-id",
        "private-cli-fixture",
        "--bonded-epoch",
        "9",
    ]);
    assert_eq!(
        serde_json::from_slice::<Value>(&args.execute().await.unwrap()).unwrap(),
        json!({"intent_id":null,"status":"cancel"})
    );
    assert!(control.status(&identity).unwrap().is_none());
}

struct Server {
    url: String,
    received: Arc<Mutex<Vec<Value>>>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}
impl Server {
    async fn open(error: bool) -> Self {
        let received = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new().route("/", post(|State((received,error)): State<(Arc<Mutex<Vec<Value>>>,bool)>, Json(request):Json<Value>| async move {
            received.lock().unwrap().push(request.clone());
            if error {
                return Json(json!({"jsonrpc":"2.0","id":1,"error":{"code":110,"message":"fixture refused"}}));
            }
            let result = match request["method"].as_str().unwrap() {
                "octra_account" => json!({"nonce":16}),
                "octra_submit" => json!({"accepted":true}),
                other => panic!("unexpected fixture method {other}"),
            };
            Json(json!({"jsonrpc":"2.0","id":1,"result":result}))
        })).with_state((received.clone(),error));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
        });
        Self {
            url,
            received,
            stop: Some(stop),
            task,
        }
    }
    async fn close(mut self) {
        self.stop.take().unwrap().send(()).unwrap();
        self.task.await.unwrap();
    }
}

#[tokio::test]
async fn rpc_discovers_native_nonce_and_submits_exactly_one_signed_transaction() {
    let dir = tempfile::tempdir().unwrap();
    let path = fixture(dir.path());
    let server = Server::open(false).await;
    let mut args = fixed(&path, "validator_exit");
    args.prepare = false;
    args.nonce = None;
    args.rpc = Some(server.url.clone());
    assert_eq!(
        serde_json::from_slice::<Value>(&args.execute().await.unwrap()).unwrap(),
        json!({"accepted":true})
    );
    let received = server.received.lock().unwrap().clone();
    assert_eq!(received.len(), 2);
    assert_eq!(received[0]["method"], "octra_account");
    assert_eq!(received[0]["params"][1], 1);
    assert_eq!(received[1]["method"], "octra_submit");
    let tx = Transaction::from_document(
        &Document::parse(&serde_json::to_vec(&received[1]["params"][0]).unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(tx.nonce, Nonce::new(17).unwrap());
    assert!(tx.verify(tx.public_key.as_deref().unwrap()));
    server.close().await;
}

#[tokio::test]
async fn rpc_refusal_never_retries_a_mutating_submission() {
    let dir = tempfile::tempdir().unwrap();
    let path = fixture(dir.path());
    let server = Server::open(true).await;
    let mut args = fixed(&path, "validator_withdraw");
    args.prepare = false;
    args.rpc = Some(server.url.clone());
    let error = args.execute().await.unwrap_err().to_string();
    assert!(error.contains("110") && error.contains("fixture refused"));
    assert_eq!(server.received.lock().unwrap().len(), 1);
    server.close().await;
}

#[tokio::test]
async fn native_hyphenated_values_prepare_exact_signed_bytes_but_nonce_still_refuses() {
    let directory = tempfile::tempdir().unwrap();
    let path = fixture(directory.path());
    let args = options(&[
        "--wallet",
        path.to_str().unwrap(),
        "--op",
        "standard",
        "--nonce",
        "17",
        "--amount",
        "-1",
        "--ou",
        "-2",
        "--message",
        "--native-message",
        "--to",
        "-recipient",
        "--chain-id",
        "-chain",
        "--timestamp",
        "-1.25",
        "--prepare",
    ]);
    let wallet = Wallet::read(&path).unwrap();
    let tx = args.draft(&wallet, Nonce::new(17).unwrap(), -1.25).unwrap();
    let result: Value = serde_json::from_slice(&args.execute().await.unwrap()).unwrap();
    assert_eq!(
        result["tx"],
        serde_json::from_slice::<Value>(&tx.to_json_bytes().unwrap()).unwrap()
    );
    assert!(
        Transaction::from_document(
            &Document::parse(&serde_json::to_vec(&result["tx"]).unwrap()).unwrap()
        )
        .is_err(),
        "offline preparation never relaxes negative-value admission"
    );
    assert_eq!(tx.amount, BigInt::from(-1));
    assert_eq!(tx.ou, BigInt::from(-2));
    assert_eq!(tx.message.as_deref(), Some(b"--native-message".as_slice()));
    assert_eq!(tx.to, b"-recipient");
    assert_eq!(tx.timestamp.to_bits(), (-1.25f64).to_bits());
    assert!(tx.verify(wallet.file.public.as_bytes()));
    assert_eq!(result["tx_hash"], hex::encode(tx.hash().unwrap()));
    // Preparation is not admission. No runtime policy or balance is changed.
    let args = options(&[
        "--wallet",
        path.to_str().unwrap(),
        "--op",
        "standard",
        "--nonce",
        "-1",
        "--prepare",
    ]);
    let error = args.execute().await.unwrap_err();
    assert!(
        error.to_string().contains("nonce must be nonnegative"),
        "{error}"
    );
    let args = options(&[
        "--wallet",
        path.to_str().unwrap(),
        "--op",
        "standard",
        "--nonce",
        "17",
        "--timestamp",
        "-inf",
        "--prepare",
    ]);
    assert!(args
        .execute()
        .await
        .unwrap_err()
        .to_string()
        .contains("timestamp must be finite"));
    let parsed = options(&[
        "--wallet",
        path.to_str().unwrap(),
        "--exit-intent",
        "request",
        "--chain-id",
        "-chain",
        "--bonded-epoch",
        "0x9",
    ]);
    assert_eq!(parsed.bonded_epoch, Some(9));
    let negative = options(&[
        "--wallet",
        path.to_str().unwrap(),
        "--exit-intent",
        "request",
        "--chain-id",
        "-chain",
        "--bonded-epoch",
        "-1",
    ]);
    assert_eq!(negative.bonded_epoch, Some(-1));
    assert!(negative.execute().await.is_err());
    assert!(!directory
        .path()
        .join("validator-control/exit.json")
        .exists());
}
