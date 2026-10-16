#![cfg(unix)]
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::SigningKey;
use octra_node_protocol::{
    transaction::{address_from_public_key, Nonce, OpType, Transaction},
    validator::intent::Identity,
};
use octra_node_runtime::{
    validator_control::Control,
    validator_duty::post::{self, Eligibility, Failure, Host, Post, Retry},
};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};
use tokio::sync::Notify;

fn identity(epoch: i64) -> (Identity, Vec<u8>) {
    let seed = [17_u8; 32]; // Public deterministic development fixture.
    let public = STANDARD
        .encode(SigningKey::from_bytes(&seed).verifying_key().as_bytes())
        .into_bytes();
    (
        Identity {
            chain_id: b"duty-devnet".to_vec(),
            address: address_from_public_key(&public),
            pubkey: public,
            bonded_epoch: epoch,
        },
        STANDARD.encode(seed).into_bytes(),
    )
}
fn tx(nonce: i64) -> Transaction {
    Transaction {
        from: vec![],
        to: vec![],
        amount: 0.into(),
        nonce: Nonce::new(nonce).unwrap(),
        ou: 5000.into(),
        timestamp: 0.,
        signature: vec![],
        public_key: None,
        message: None,
        encrypted_data: None,
        op_type: OpType::ValidatorReady,
    }
}

#[test]
fn durable_exit_intent_pauses_current_registration_and_cannot_replay_after_rebond() {
    let dir = tempfile::tempdir().unwrap();
    let (current, private) = identity(4);
    let control = Control::new(dir.path());
    let lease = control.duty_guard(&current).unwrap();
    assert_eq!(
        control
            .request(current.clone(), &private)
            .unwrap_err()
            .to_string(),
        "validator control is busy"
    );
    drop(lease);
    let id = control.request(current.clone(), &private).unwrap();
    assert_eq!(control.request(current.clone(), &private).unwrap(), id);
    drop(control);
    let control = Control::new(dir.path());
    assert_eq!(control.status(&current).unwrap(), Some(id));
    assert_eq!(
        control.duty_guard(&current).err().unwrap().to_string(),
        "validator exit intent pauses duty"
    );
    let (later, _) = identity(5);
    assert!(control.status(&later).unwrap().is_none());
    drop(control.duty_guard(&later).unwrap());
    let (earlier, _) = identity(3);
    assert_eq!(
        control.status(&earlier).unwrap_err().to_string(),
        "validator exit intent registration is ahead"
    );
    control.cancel(&current, &private).unwrap();
    assert!(control.status(&current).unwrap().is_none());
    drop(control.duty_guard(&current).unwrap());
}

#[test]
fn local_control_rejects_public_files_and_symlink_replacement() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let dir = tempfile::tempdir().unwrap();
    let (current, private) = identity(4);
    let control = Control::new(dir.path());
    control.request(current.clone(), &private).unwrap();
    let path = dir.path().join("validator-control/exit.json");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        control.status(&current).unwrap_err().to_string(),
        "invalid validator exit intent file"
    );
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let prior = std::fs::read(&path).unwrap();
    let target = dir.path().join("external.json");
    std::fs::rename(&path, &target).unwrap();
    symlink(&target, &path).unwrap();
    assert_eq!(
        control.status(&current).unwrap_err().to_string(),
        "invalid validator exit intent file"
    );
    assert_eq!(std::fs::read(target).unwrap(), prior);
}

#[tokio::test]
async fn dropping_admission_waiter_does_not_release_an_owned_duty_lease() {
    let dir = tempfile::tempdir().unwrap();
    let (current, private) = identity(4);
    let control = Arc::new(Control::new(dir.path()));
    let lease = Arc::new(control.duty_guard(&current).unwrap());
    let release = Arc::new(Notify::new());
    let ready = Arc::new(Notify::new());
    let (done, waiting) = tokio::sync::oneshot::channel();
    let worker = {
        let release = release.clone();
        let ready = ready.clone();
        tokio::spawn(async move {
            let _lease = lease;
            ready.notify_one();
            release.notified().await;
            let _ = done.send(());
        })
    };
    ready.notified().await;
    let waiter = tokio::spawn(async move {
        let _ = waiting.await;
    });
    waiter.abort();
    let _ = waiter.await;
    assert_eq!(
        control
            .request(current.clone(), &private)
            .unwrap_err()
            .to_string(),
        "validator control is busy"
    );
    release.notify_one();
    worker.await.unwrap();
    assert!(control.request(current, &private).is_ok());
}

struct Delivery {
    calls: AtomicUsize,
    started: Notify,
    release: Notify,
    current: Mutex<Option<Arc<dyn Fn() -> bool + Send + Sync>>>,
    eligible: AtomicBool,
}
#[async_trait::async_trait]
impl Host for Delivery {
    fn staged(&self, _: &[u8]) -> bool {
        true
    }
    fn landed(&self, _: &Transaction) -> bool {
        false
    }
    fn eligible(&self, _: &Transaction, _: Option<i64>) -> Eligibility {
        if self.eligible.load(Ordering::SeqCst) {
            Eligibility::Eligible
        } else {
            Eligibility::Expired
        }
    }
    async fn post(
        &self,
        _: Transaction,
        _: Option<i64>,
        current: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> Result<(), Failure> {
        *self.current.lock().unwrap() = Some(current);
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.started.notify_one();
        self.release.notified().await;
        Ok(())
    }
    fn warn(&self, _: &str) {}
}

#[tokio::test]
async fn retained_delivery_cannot_be_overwritten_and_shutdown_revokes_generation() {
    let host = Arc::new(Delivery {
        calls: AtomicUsize::new(0),
        started: Notify::new(),
        release: Notify::new(),
        current: Mutex::new(None),
        eligible: AtomicBool::new(true),
    });
    let post = Post::new(host.clone());
    post.put(
        b"first".to_vec(),
        tx(1),
        Some(Retry {
            bonded_epoch: 4,
            retain: true,
        }),
    );
    tokio::time::timeout(std::time::Duration::from_secs(2), host.started.notified())
        .await
        .unwrap();
    let current = host.current.lock().unwrap().clone().unwrap();
    assert!(current());
    post.put(
        b"second".to_vec(),
        tx(2),
        Some(Retry {
            bonded_epoch: 4,
            retain: true,
        }),
    );
    assert_eq!(host.calls.load(Ordering::SeqCst), 1);
    assert!(post.pending());
    post.stop();
    assert!(!current());
    tokio::time::timeout(std::time::Duration::from_secs(2), post.shutdown())
        .await
        .unwrap();
    assert!(!post.pending());
    assert_eq!(host.calls.load(Ordering::SeqCst), 1);
    assert!(matches!(post::http_failure(429), Failure::Retry(_)));
    assert!(matches!(post::http_failure(403), Failure::Refused(_)));
    host.current.lock().unwrap().take();
}
