use super::*;
use ed25519_dalek::{Signer as _, SigningKey};
use octra_browser::{application::Call, SnapshotIdentity};
use octra_exex::StateRoot;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Key {
    signed: AtomicUsize,
    invalid: bool,
}
#[async_trait]
impl Signer for Key {
    fn public_key(&self) -> [u8; 32] {
        SigningKey::from_bytes(&[42; 32]).verifying_key().to_bytes()
    }
    async fn sign(&self, bytes: &[u8]) -> Result<[u8; 64], Error> {
        self.signed.fetch_add(1, Ordering::SeqCst);
        Ok(if self.invalid {
            [0; 64]
        } else {
            SigningKey::from_bytes(&[42; 32]).sign(bytes).to_bytes()
        })
    }
}
struct Host {
    snapshot: Provenance,
    available: BigInt,
    nonce: Mutex<i64>,
    sent: Mutex<Vec<Transaction>>,
}
#[async_trait]
impl Node for Host {
    async fn account(&self, _: &Context, _: &[u8]) -> Result<Account, Error> {
        Ok(Account {
            provenance: self.snapshot.clone(),
            available: self.available.clone(),
            next_nonce: Nonce::new(*self.nonce.lock().await).unwrap(),
            timestamp: 1.,
        })
    }
    async fn submit(&self, context: &Context, tx: Transaction) -> Result<(), Error> {
        assert_eq!(context.provenance, self.snapshot);
        assert_eq!(tx.to, context.circle_id.as_bytes());
        assert!(tx.verify(tx.public_key.as_ref().unwrap()));
        let mut nonce = self.nonce.lock().await;
        assert_eq!(tx.nonce.get(), *nonce);
        *nonce += 1;
        self.sent.lock().await.push(tx);
        Ok(())
    }
    async fn status(&self, _: &Context, _: &[u8], _: &str) -> Result<Value, Error> {
        Err(Error::NotFound)
    }
}
fn setup(available: i64, invalid_key: bool) -> (Wallet, Arc<Key>, Arc<Host>, Intent) {
    let context = Context {
        circle_id: format!("oct{}", "1".repeat(44)),
        provenance: Provenance::Canonical(SnapshotIdentity {
            chain_id: "wallet-test".into(),
            genesis_root: hex::encode([1; 32]),
            epoch: 1,
            state_root: hex::encode([2; 32]),
            ledger_root: "3".repeat(128),
            irmin_commit: "4".repeat(128),
        }),
    };
    let node = Arc::new(Host {
        snapshot: context.provenance.clone(),
        available: available.into(),
        nonce: Mutex::new(1),
        sent: Mutex::new(vec![]),
    });
    let key = Arc::new(Key {
        signed: AtomicUsize::new(0),
        invalid: invalid_key,
    });
    let policy = Policy {
        chain: ChainIdentity {
            chain_id: "wallet-test".into(),
            genesis_root: StateRoot([1; 32]),
        },
        max_amount: 10.into(),
        max_ou: 1000.into(),
    };
    let wallet = Wallet::new(node.clone(), key.clone(), policy).unwrap();
    (
        wallet,
        key,
        node,
        Intent {
            context,
            call: Call {
                method: "inc".into(),
                params: vec![],
                amount: "1".into(),
                ou: "1000".into(),
            },
        },
    )
}
#[tokio::test]
async fn spending_chain_and_native_parameter_guards_precede_signing() {
    let (wallet, key, node, good) = setup(10000, false);
    for variant in 0..9 {
        let mut intent = good.clone();
        match variant {
            0 => intent.context.provenance = Provenance::UnpinnedRpc,
            1 => {
                if let Provenance::Canonical(p) = &mut intent.context.provenance {
                    p.genesis_root = "0".repeat(64);
                }
            }
            2 => intent.context.circle_id = "counter".into(),
            3 => intent.call.amount = "11".into(),
            4 => intent.call.ou = "1001".into(),
            5 => intent.call.ou = "999".into(),
            6 => intent.call.amount = "-1".into(),
            7 => intent.call.params = vec![json!("<script>")],
            _ => {
                if let Provenance::Canonical(p) = &mut intent.context.provenance {
                    p.epoch += 1;
                }
            }
        }
        assert!(wallet.call(intent).await.is_err(), "variant {variant}");
    }
    assert_eq!(key.signed.load(Ordering::SeqCst), 0);
    assert!(node.sent.lock().await.is_empty());
    let (wallet, key, _, intent) = setup(1000, false);
    assert!(wallet
        .call(intent)
        .await
        .unwrap_err()
        .to_string()
        .contains("insufficient"));
    assert_eq!(key.signed.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn signer_output_is_verified_and_pending_nonces_are_serialized() {
    let (wallet, key, node, intent) = setup(10000, true);
    assert!(wallet
        .call(intent)
        .await
        .unwrap_err()
        .to_string()
        .contains("invalid signature"));
    assert_eq!(key.signed.load(Ordering::SeqCst), 1);
    assert!(node.sent.lock().await.is_empty());
    let (wallet, _, node, intent) = setup(10000, false);
    let (first, second) = tokio::join!(wallet.call(intent.clone()), wallet.call(intent));
    let first = first.unwrap();
    let second = second.unwrap();
    assert_ne!(first["hash"], second["hash"]);
    let transactions = node.sent.lock().await;
    for (i, tx) in transactions.iter().enumerate() {
        assert_eq!(tx.nonce.get(), i64::try_from(i + 1).unwrap());
        assert_eq!(tx.amount, 1.into());
        assert_eq!(tx.ou, 1000.into());
        assert_eq!(tx.op_type, OpType::CircleCall);
        assert_eq!(tx.message.as_deref(), Some(b"[]".as_slice()));
        assert_eq!(tx.encrypted_data.as_deref(), Some(b"inc".as_slice()));
    }
    assert_eq!(first["hash"], hex::encode(transactions[0].hash().unwrap()));
    assert_eq!(second["hash"], hex::encode(transactions[1].hash().unwrap()));
}
#[tokio::test]
async fn unavailable_nonce_and_invalid_status_cannot_reach_signer() {
    let (wallet, key, node, intent) = setup(10000, false);
    *node.nonce.lock().await = 0;
    assert!(wallet
        .call(intent.clone())
        .await
        .unwrap_err()
        .to_string()
        .contains("account context"));
    let request = ReadRequest {
        context: intent.context,
        method: ReadMethod::TransactionWait,
        params: json!({"hash":"A".repeat(64)}),
    };
    assert!(wallet
        .read(request)
        .await
        .unwrap_err()
        .to_string()
        .contains("invalid transaction hash"));
    assert_eq!(key.signed.load(Ordering::SeqCst), 0);
}
