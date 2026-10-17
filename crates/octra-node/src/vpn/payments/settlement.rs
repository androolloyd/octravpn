//! Durable cumulative usage becomes an ordinary signed Program claim. Intake
//! acknowledgement never completes a receipt: only authenticated canonical
//! counters do. Canonical paid OU can also cover additional bytes in the same
//! tariff rounding bucket; this avoids paying another network fee for no debt.
//! One pending slot per plan/class coalesces smaller vouchers. An immutable
//! lifetime fee budget reserves every new signed attempt before submission.
use super::{Payments, Plan};
use crate::rpc::Context as Submission;
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use octra_node_protocol::{
    native_json::Document,
    transaction::{self, OpType, Transaction},
};
use octra_node_runtime::{account_store, state_batch::StateBatch};
use octravpn_core::payments::SignedUsage;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{watch, Notify, Semaphore};

const MAX_SLOTS: usize = 4096;
const MAX_ATTEMPTS: usize = 8;
const MAX_JOURNAL: u64 = 64 * 1024 * 1024;
const FEE_OU: u64 = 1000;
const CONFIRM_WAIT: Duration = Duration::from_secs(45);

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Attempt {
    authorization: SignedUsage,
    transaction: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Slot {
    usage: SignedUsage,
    attempts: Vec<Attempt>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u8,
    identity: serde_json::Value,
    fee_budget_ou: u64,
    // Never released: rejected/ambiguous attempts may still have paid a fee.
    fees_reserved_ou: u64,
    // At most one new signed claim per canonical head limits fee amplification.
    // Replaying an identical signed attempt cannot pay twice on chain.
    last_submission_root: Option<String>,
    slots: BTreeMap<String, Slot>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    journal: Journal,
    sha256: String,
}

fn slot_id(usage: &SignedUsage) -> Result<String> {
    usage.verify()?;
    ensure!(
        usage.usage.total_bytes > 0,
        "zero-byte usage is not redeemable"
    );
    let mut hash = Sha256::new();
    hash.update(b"Octranet native claim slot v1\0");
    hash.update(serde_json::to_vec(&usage.usage.binding())?);
    hash.update(usage.receipt_key.0);
    hash.update([usage.usage.traffic_class]);
    Ok(hex::encode(hash.finalize()))
}
fn clock() -> Result<f64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64())
}
fn check_transaction(tx: &Transaction, signed: &SignedUsage, operator_key: &[u8]) -> Result<()> {
    let expected = serde_json::to_vec(&signed.claim_params()?)?;
    ensure!(
        tx.from == transaction::address_from_public_key(operator_key)
            && tx.to == signed.usage.deployment.program.display().as_bytes()
            && tx.amount == 0.into()
            && tx.ou == FEE_OU.into()
            && tx.op_type == OpType::ContractCall
            && tx.encrypted_data.as_deref() == Some(b"claim")
            && tx.message.as_deref() == Some(expected.as_slice())
            && tx.public_key.as_deref() == Some(operator_key)
            && tx.timestamp.is_finite()
            && tx.timestamp >= 0.
            && tx.verify(operator_key),
        "durable Octranet claim transaction binding differs"
    );
    let normalized = transaction::normalize_envelope(tx, Some(operator_key))?;
    ensure!(normalized == *tx, "durable claim envelope differs");
    Ok(())
}

/// A private, directory-relative journal and exclusive process writer. The
/// in-memory image changes only after fsync+rename+directory fsync succeeds.
struct Disk {
    directory: File,
    _writer: File,
    state: Mutex<Journal>,
    failed: AtomicBool,
}
impl Disk {
    #[cfg(not(unix))]
    fn open(_: &Path, _: serde_json::Value, _: u64) -> Result<Self> {
        anyhow::bail!("native payment settlement requires Unix writer locking")
    }
    #[cfg(unix)]
    #[allow(clippy::verbose_bit_mask)] // Explicit private Unix permission bits.
    fn open(path: &Path, identity: serde_json::Value, fee_budget_ou: u64) -> Result<Self> {
        use rustix::fs::{flock, open, openat, unlinkat, AtFlags, FlockOperation, Mode, OFlags};
        use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
        ensure!(
            fee_budget_ou != u64::MAX,
            "claim fee budget must be explicitly bounded"
        );
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => ensure!(
                metadata.is_dir() && !metadata.file_type().is_symlink(),
                "payment claim directory must be regular"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::DirBuilder::new().mode(0o700).create(path)?;
            }
            Err(error) => return Err(error.into()),
        }
        let directory: File = open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?
        .into();
        ensure!(
            directory.metadata()?.permissions().mode() & 0o077 == 0,
            "payment claim directory must be private"
        );
        let flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        let (writer, created): (File, bool) = match openat(
            &directory,
            "writer.lock",
            flags | OFlags::CREATE | OFlags::EXCL,
            Mode::from_bits_truncate(0o600),
        ) {
            Ok(file) => (file.into(), true),
            Err(rustix::io::Errno::EXIST) => (
                openat(&directory, "writer.lock", flags, Mode::empty())?.into(),
                false,
            ),
            Err(error) => return Err(error.into()),
        };
        let metadata = writer.metadata()?;
        ensure!(
            metadata.is_file()
                && metadata.nlink() == 1
                && metadata.permissions().mode() & 0o077 == 0
                && metadata.uid() == directory.metadata()?.uid(),
            "payment claim lease must be a private regular file"
        );
        flock(&writer, FlockOperation::NonBlockingLockExclusive)
            .context("payment claim journal already in use")?;
        let journal = match openat(
            &directory,
            "claims.json",
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(file) => {
                if created {
                    unlinkat(&directory, "writer.lock", AtFlags::empty())?;
                    anyhow::bail!("payment claim journal lost its writer lease file");
                }
                let mut file: File = file.into();
                let metadata = file.metadata()?;
                ensure!(
                    metadata.is_file()
                        && metadata.nlink() == 1
                        && metadata.permissions().mode() & 0o077 == 0
                        && metadata.uid() == directory.metadata()?.uid()
                        && metadata.len() <= MAX_JOURNAL,
                    "invalid payment claim journal file"
                );
                let mut raw = Vec::new();
                Read::by_ref(&mut file)
                    .take(MAX_JOURNAL + 1)
                    .read_to_end(&mut raw)?;
                ensure!(
                    u64::try_from(raw.len())? <= MAX_JOURNAL,
                    "claim journal exceeds bound"
                );
                let envelope: Envelope = serde_json::from_slice(&raw)?;
                ensure!(
                    hex::encode(Sha256::digest(serde_json::to_vec(&envelope.journal)?))
                        == envelope.sha256,
                    "claim journal checksum differs"
                );
                ensure!(
                    envelope.journal.version == 2 && envelope.journal.identity == identity,
                    "claim journal deployment or wallet identity differs"
                );
                ensure!(
                    envelope.journal.fee_budget_ou == fee_budget_ou
                        && envelope.journal.fees_reserved_ou <= fee_budget_ou
                        && envelope.journal.fees_reserved_ou.is_multiple_of(FEE_OU),
                    "claim journal fee budget differs or reservation is invalid"
                );
                envelope.journal
            }
            Err(rustix::io::Errno::NOENT) => {
                ensure!(created, "claim journal is missing; refusing queue reset");
                Journal {
                    version: 2,
                    identity,
                    fee_budget_ou,
                    fees_reserved_ou: 0,
                    last_submission_root: None,
                    slots: BTreeMap::new(),
                }
            }
            Err(error) => return Err(error.into()),
        };
        ensure!(
            journal.slots.len() <= MAX_SLOTS,
            "claim queue exceeds slot bound"
        );
        let mut retained_attempts = 0_u64;
        for (id, slot) in &journal.slots {
            ensure!(
                &slot_id(&slot.usage)? == id && slot.attempts.len() <= MAX_ATTEMPTS,
                "claim journal slot binding differs"
            );
            for attempt in &slot.attempts {
                retained_attempts = retained_attempts
                    .checked_add(1)
                    .context("claim count overflow")?;
                ensure!(
                    slot_id(&attempt.authorization)? == *id
                        && attempt.authorization.usage.total_bytes <= slot.usage.usage.total_bytes,
                    "claim attempt authorization differs"
                );
            }
        }
        ensure!(
            retained_attempts
                .checked_mul(FEE_OU)
                .context("claim fee overflow")?
                <= journal.fees_reserved_ou,
            "claim attempts exceed durable fee reservations"
        );
        let disk = Self {
            directory,
            _writer: writer,
            state: Mutex::new(journal),
            failed: AtomicBool::new(false),
        };
        // Also closes the initialization durability boundary for a fresh queue.
        {
            let journal = disk
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("claim journal poisoned"))?;
            disk.persist(&journal)?;
        }
        Ok(disk)
    }
    fn available(&self) -> Result<()> {
        ensure!(
            !self.failed.load(Ordering::Acquire),
            "claim journal failed; restart required"
        );
        Ok(())
    }
    fn slot(&self, id: &str) -> Result<Option<Slot>> {
        self.available()?;
        Ok(self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("claim journal poisoned"))?
            .slots
            .get(id)
            .cloned())
    }
    fn keys(&self) -> Result<Vec<String>> {
        self.available()?;
        Ok(self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("claim journal poisoned"))?
            .slots
            .keys()
            .cloned()
            .collect())
    }
    fn permits_new(&self, root: &str) -> Result<bool> {
        self.available()?;
        let journal = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("claim journal poisoned"))?;
        ensure!(
            journal.fee_budget_ou - journal.fees_reserved_ou >= FEE_OU,
            "claim fee budget exhausted; no new signed attempts allowed"
        );
        Ok(journal.last_submission_root.as_deref() != Some(root))
    }
    fn update<T>(&self, change: impl FnOnce(&mut Journal) -> Result<T>) -> Result<T> {
        self.available()?;
        let mut guard = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("claim journal poisoned"))?;
        self.available()?;
        let mut next = guard.clone();
        let result = change(&mut next)?;
        if let Err(error) = self.persist(&next) {
            self.failed.store(true, Ordering::Release);
            return Err(error);
        }
        *guard = next;
        Ok(result)
    }
    fn enqueue(&self, usage: SignedUsage) -> Result<String> {
        let id = slot_id(&usage)?;
        self.update(|journal| {
            if let Some(slot) = journal.slots.get_mut(&id) {
                if usage.usage.total_bytes > slot.usage.usage.total_bytes {
                    slot.usage = usage;
                }
            } else {
                ensure!(
                    journal.slots.len() < MAX_SLOTS,
                    "payment claim queue is full"
                );
                journal.slots.insert(
                    id.clone(),
                    Slot {
                        usage,
                        attempts: Vec::new(),
                    },
                );
            }
            Ok(id)
        })
    }
    fn reconcile(&self, id: &str, covered: u64) -> Result<()> {
        self.update(|journal| {
            if let Some(slot) = journal.slots.get_mut(id) {
                if slot.usage.usage.total_bytes <= covered {
                    journal.slots.remove(id);
                } else {
                    slot.attempts
                        .retain(|attempt| attempt.authorization.usage.total_bytes > covered);
                }
            }
            Ok(())
        })
    }
    fn attempt(&self, id: &str, attempt: Attempt, root: String) -> Result<bool> {
        self.update(|journal| {
            if journal.last_submission_root.as_deref() == Some(root.as_str()) {
                return Ok(false);
            }
            let Some(slot) = journal.slots.get_mut(id) else {
                return Ok(false);
            };
            if slot
                .attempts
                .iter()
                .any(|saved| saved.transaction == attempt.transaction)
            {
                return Ok(false);
            }
            ensure!(
                slot.attempts.len() < MAX_ATTEMPTS,
                "claim retry limit reached; operator recovery required"
            );
            ensure!(
                slot_id(&attempt.authorization)? == id,
                "claim slot changed before signing"
            );
            let reserved = journal
                .fees_reserved_ou
                .checked_add(FEE_OU)
                .context("claim fee reservation overflow")?;
            ensure!(
                reserved <= journal.fee_budget_ou,
                "claim fee budget exhausted"
            );
            slot.attempts.push(attempt);
            journal.fees_reserved_ou = reserved;
            journal.last_submission_root = Some(root);
            Ok(true)
        })
    }
    #[cfg(not(unix))]
    fn persist(&self, _: &Journal) -> Result<()> {
        anyhow::bail!("native payment settlement requires Unix storage")
    }
    #[cfg(unix)]
    fn persist(&self, journal: &Journal) -> Result<()> {
        use rustix::fs::{openat, renameat, unlinkat, AtFlags, Mode, OFlags};
        use std::os::unix::fs::MetadataExt;
        let sha256 = hex::encode(Sha256::digest(serde_json::to_vec(journal)?));
        let raw = serde_json::to_vec(&Envelope {
            journal: journal.clone(),
            sha256,
        })?;
        ensure!(
            u64::try_from(raw.len())? <= MAX_JOURNAL,
            "claim journal exceeds byte bound"
        );
        let name = format!(".claims-{:032x}.tmp", rand::random::<u128>());
        let mut temporary: File = openat(
            &self.directory,
            name.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_bits_truncate(0o600),
        )?
        .into();
        let result = (|| {
            ensure!(
                temporary.metadata()?.uid() == self.directory.metadata()?.uid(),
                "claim directory is not owned by the running user"
            );
            temporary.write_all(&raw)?;
            temporary.sync_all()?;
            renameat(
                &self.directory,
                name.as_str(),
                &self.directory,
                "claims.json",
            )?;
            self.directory.sync_all()?;
            Ok(())
        })();
        let _ = unlinkat(&self.directory, name.as_str(), AtFlags::empty());
        result
    }
}

pub(crate) struct Publisher {
    payments: Arc<Payments>,
    disk: Arc<Disk>,
    wake: Arc<Notify>,
    running: Arc<AtomicBool>,
    callers: Arc<Semaphore>,
}
pub(crate) struct Service {
    submission: Arc<Submission>,
    payments: Arc<Payments>,
    key: SigningKey,
    operator: Vec<u8>,
    operator_key: Vec<u8>,
    disk: Arc<Disk>,
    wake: Arc<Notify>,
    running: Arc<AtomicBool>,
}
async fn covered(payments: &Payments, usage: &SignedUsage) -> Result<(Plan, bool)> {
    let plan = payments.plan(usage.usage.plan).await?;
    plan.validate_usage(usage)?;
    let class = usize::from(usage.usage.traffic_class);
    let floor = plan.redeemed_bytes[class];
    let charge = plan
        .tariff
        .charge(usage.usage.traffic_class, usage.usage.total_bytes)?;
    let settled = counters_cover(
        floor,
        plan.redeemed_ou[class],
        usage.usage.total_bytes,
        charge,
    );
    ensure!(plan.live(), "canonical payment publication changed");
    Ok((plan, settled))
}
fn counters_cover(bytes: u64, paid_ou: u64, requested_bytes: u64, requested_ou: u64) -> bool {
    bytes >= requested_bytes || paid_ou >= requested_ou
}
impl Service {
    pub(crate) async fn open(
        submission: Arc<Submission>,
        payments: Arc<Payments>,
        key: SigningKey,
        directory: PathBuf,
        fee_budget_ou: u64,
    ) -> Result<(Arc<Publisher>, Self)> {
        let operator_key = STANDARD.encode(key.verifying_key().as_bytes()).into_bytes();
        let operator = transaction::address_from_public_key(&operator_key);
        ensure!(
            payments.operator.display().as_bytes() == operator
                && payments.history.chain() == submission.node.chain(),
            "claim wallet or canonical chain differs from payment deployment"
        );
        let identity = serde_json::json!({"chain":submission.node.chain(),
            "config":payments.config,"operator_public_key":STANDARD.encode(key.verifying_key().as_bytes())});
        let disk = Arc::new(
            tokio::task::spawn_blocking(move || Disk::open(&directory, identity, fee_budget_ou))
                .await??,
        );
        for id in disk.keys()? {
            let slot = disk.slot(&id)?.context("durable claim slot disappeared")?;
            validate_scope(&slot.usage, &payments)?;
            for attempt in slot.attempts {
                validate_scope(&attempt.authorization, &payments)?;
                check_transaction(
                    &decode_attempt(&attempt)?,
                    &attempt.authorization,
                    &operator_key,
                )?;
            }
        }
        let wake = Arc::new(Notify::new());
        let running = Arc::new(AtomicBool::new(true));
        let publisher = Arc::new(Publisher {
            payments: payments.clone(),
            disk: disk.clone(),
            wake: wake.clone(),
            running: running.clone(),
            callers: Arc::new(Semaphore::new(8)),
        });
        Ok((
            publisher,
            Self {
                submission,
                payments,
                key,
                operator,
                operator_key,
                disk,
                wake,
                running,
            },
        ))
    }
    async fn deliver(&self, id: &str) -> Result<()> {
        let Some(slot) = self.disk.slot(id)? else {
            return Ok(());
        };
        let (plan, complete) = covered(&self.payments, &slot.usage).await?;
        let floor = plan.redeemed_bytes[usize::from(slot.usage.usage.traffic_class)];
        if complete
            || slot
                .attempts
                .iter()
                .any(|attempt| attempt.authorization.usage.total_bytes <= floor)
        {
            // Economic coverage can exceed the raw canonical byte counter in
            // its rounding bucket. Remove this authorization, preserving any
            // concurrently enqueued larger voucher for its own recheck.
            let floor = if complete {
                floor.max(slot.usage.usage.total_bytes)
            } else {
                floor
            };
            let disk = self.disk.clone();
            let id = id.to_owned();
            tokio::task::spawn_blocking(move || disk.reconcile(&id, floor)).await??;
            self.wake.notify_waiters();
            if complete {
                return Ok(());
            }
        }
        let Some(slot) = self.disk.slot(id)? else {
            return Ok(());
        };
        plan.claim_increment(&slot.usage)?;
        let wallet = Arc::new(self.submission.executor.operator_wallet().await);
        let (plan, complete) = covered(&self.payments, &slot.usage).await?;
        if complete {
            return Ok(());
        }
        plan.claim_increment(&slot.usage)?;
        let view = self.submission.node.snapshot()?;
        let serving = self.payments.shared.current()?;
        ensure!(
            plan.live() && view.head() == serving.committed.head(),
            "claim wallet snapshot changed"
        );
        let ledger = account_store::ledger(&StateBatch::from_snapshot(view.state().clone()))?;
        let account = ledger
            .account(&self.operator)
            .context("claim operator wallet is unfunded")?;
        let now = clock()?;
        let mut candidate = None;
        for attempt in &slot.attempts {
            let tx = decode_attempt(attempt)?;
            check_transaction(&tx, &attempt.authorization, &self.operator_key)?;
            if account.nonce < tx.nonce && (-5.0..=300.0).contains(&(now - tx.timestamp)) {
                candidate = Some((tx, attempt.authorization.clone()));
            }
        }
        let (tx, authorization) = if let Some(candidate) = candidate {
            candidate
        } else {
            // Empty finalized epochs can share a state root. Bind throttling to
            // the complete canonical head, so an expired attempt can recover.
            let root = hex::encode(Sha256::digest(serde_json::to_vec(view.head())?));
            if !self.disk.permits_new(&root)? {
                return Ok(());
            }
            let nonce = self
                .submission
                .pending
                .inspect(|pool| pool.duty_nonce(&self.operator, account.nonce))?
                .context("operator wallet has another pending nonce")?;
            let mut tx = Transaction {
                from: self.operator.clone(),
                to: slot
                    .usage
                    .usage
                    .deployment
                    .program
                    .display()
                    .as_bytes()
                    .to_vec(),
                amount: 0.into(),
                nonce,
                ou: FEE_OU.into(),
                timestamp: now,
                signature: vec![],
                public_key: Some(self.operator_key.clone()),
                message: Some(serde_json::to_vec(&slot.usage.claim_params()?)?),
                encrypted_data: Some(b"claim".to_vec()),
                op_type: OpType::ContractCall,
            };
            ensure!(
                octra_node_protocol::transaction_policy::ou_cost(
                    &tx,
                    &self.submission.fees.stealth_minimum
                ) <= tx.ou,
                "configured claim fee is below native scheduled cost"
            );
            tx.signature = STANDARD
                .encode(self.key.sign(&tx.signing_bytes()?).to_bytes())
                .into_bytes();
            check_transaction(&tx, &slot.usage, &self.operator_key)?;
            let attempt = Attempt {
                authorization: slot.usage.clone(),
                transaction: String::from_utf8(tx.to_json_bytes()?)?,
            };
            let disk = self.disk.clone();
            let id = id.to_owned();
            let guard = wallet.clone();
            let saved = tokio::task::spawn_blocking(move || {
                let _wallet = guard;
                disk.attempt(&id, attempt, root)
            })
            .await??;
            if !saved {
                return Ok(());
            }
            (tx, slot.usage)
        };
        // Recheck after durable IO: no expired authorization is submitted just
        // because it was eligible when its file was first written.
        let (fresh, complete) = covered(&self.payments, &authorization).await?;
        if complete {
            return Ok(());
        }
        fresh.claim_increment(&authorization)?;
        self.submission.submit_operator(tx, now, wallet).await?;
        Ok(())
    }
    pub(crate) async fn run(self, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        let mut interval = tokio::time::interval(Duration::from_secs(2));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut cursor = 0_usize;
        loop {
            tokio::select! {
                biased;
                _ = shutdown.wait_for(|stopped| *stopped) => return Ok(()),
                () = self.wake.notified() => (),
                _ = interval.tick() => (),
            }
            let keys = self.disk.keys()?;
            if keys.is_empty() {
                continue;
            }
            for offset in 0..keys.len().min(8) {
                if *shutdown.borrow() {
                    return Ok(());
                }
                let id = &keys[(cursor + offset) % keys.len()];
                match tokio::time::timeout(Duration::from_secs(10), self.deliver(id)).await {
                    Ok(Ok(())) => (),
                    Ok(Err(error)) => {
                        eprintln!("Octranet claim remains durable slot={id}: {error:#}");
                    }
                    Err(_) => {
                        eprintln!("Octranet claim remains durable slot={id}: submission timed out");
                    }
                }
            }
            cursor = (cursor + 8) % keys.len();
        }
    }
}
impl Drop for Service {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Release);
        self.wake.notify_waiters();
    }
}
fn validate_scope(usage: &SignedUsage, payments: &Payments) -> Result<()> {
    usage.verify()?;
    ensure!(
        usage.usage.deployment == payments.deployment && usage.usage.offer == payments.config.offer,
        "claim authorization targets another payment deployment"
    );
    slot_id(usage)?;
    Ok(())
}
fn decode_attempt(attempt: &Attempt) -> Result<Transaction> {
    Ok(Transaction::from_document(&Document::parse(
        attempt.transaction.as_bytes(),
    )?)?)
}

#[async_trait::async_trait]
impl octravpn_node::payments::Settlement for Publisher {
    async fn confirm(&self, usage: SignedUsage) -> Result<()> {
        let _caller = self
            .callers
            .clone()
            .try_acquire_owned()
            .context("claim confirmation is busy")?;
        ensure!(
            self.running.load(Ordering::Acquire),
            "claim service stopped"
        );
        validate_scope(&usage, &self.payments)?;
        let (plan, complete) = covered(&self.payments, &usage).await?;
        if complete {
            return Ok(());
        }
        plan.claim_increment(&usage)?;
        let disk = self.disk.clone();
        let queued = usage.clone();
        tokio::task::spawn_blocking(move || disk.enqueue(queued)).await??;
        self.wake.notify_one();
        let deadline = tokio::time::Instant::now() + CONFIRM_WAIT;
        loop {
            ensure!(
                self.running.load(Ordering::Acquire),
                "claim service stopped; authorization remains durable"
            );
            let (plan, complete) = covered(&self.payments, &usage).await?;
            if complete {
                return Ok(());
            }
            plan.claim_increment(&usage)?;
            ensure!(
                tokio::time::Instant::now() < deadline,
                "claim confirmation pending; authorization remains durable"
            );
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use octra_node_protocol::transaction::Nonce;
    use octravpn_core::{
        payments::{Deployment, Usage},
        Address, KeyPair,
    };
    use std::os::unix::fs::{symlink, PermissionsExt};
    const TEST_BUDGET: u64 = FEE_OU * 10;

    fn usage(sequence: u64, total_bytes: u64) -> SignedUsage {
        SignedUsage::sign(
            Usage {
                deployment: Deployment {
                    domain: "ab".repeat(32),
                    program: Address::from_pubkey(&[2; 32]),
                },
                payer: Address::from_pubkey(&[3; 32]),
                generation: 1,
                plan: 8,
                offer: 4,
                manifest_hash: "cd".repeat(32),
                traffic_class: 0,
                sequence,
                total_bytes,
            },
            &KeyPair::from_secret_bytes(&[31; 32]),
        )
        .unwrap()
    }
    fn tx(signed: &SignedUsage) -> (Transaction, Vec<u8>) {
        let key = SigningKey::from_bytes(&[11; 32]);
        let public = STANDARD.encode(key.verifying_key().as_bytes()).into_bytes();
        let mut tx = Transaction {
            from: transaction::address_from_public_key(&public),
            to: signed
                .usage
                .deployment
                .program
                .display()
                .as_bytes()
                .to_vec(),
            amount: 0.into(),
            nonce: Nonce::new(1).unwrap(),
            ou: FEE_OU.into(),
            timestamp: 1_700_000_000.,
            signature: vec![],
            public_key: Some(public.clone()),
            message: Some(serde_json::to_vec(&signed.claim_params().unwrap()).unwrap()),
            encrypted_data: Some(b"claim".to_vec()),
            op_type: OpType::ContractCall,
        };
        tx.signature = STANDARD
            .encode(key.sign(&tx.signing_bytes().unwrap()).to_bytes())
            .into_bytes();
        (tx, public)
    }
    fn attempt(authorization: SignedUsage) -> Attempt {
        let (tx, _) = tx(&authorization);
        Attempt {
            authorization,
            transaction: String::from_utf8(tx.to_json_bytes().unwrap()).unwrap(),
        }
    }

    // These tests cover disk/encoding boundaries, not canonical grant or public
    // network qualification. Canonical API tests are in canonical_tests.rs.
    #[test]
    fn cumulative_queue_survives_lower_sequence_and_partial_progress() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("claims");
        let identity = serde_json::json!({"deployment":"fixture"});
        let disk = Disk::open(&path, identity.clone(), TEST_BUDGET).unwrap();
        let first = usage(100, 10);
        let id = disk.enqueue(first.clone()).unwrap();
        assert!(disk.attempt(&id, attempt(first), "head1".into()).unwrap());
        assert!(!disk.permits_new("head1").unwrap());
        let larger = usage(1, 200);
        assert_eq!(disk.enqueue(larger.clone()).unwrap(), id);
        disk.enqueue(usage(101, 20)).unwrap();
        assert_eq!(disk.slot(&id).unwrap().unwrap().usage, larger);
        disk.reconcile(&id, 10).unwrap();
        let pending = disk.slot(&id).unwrap().unwrap();
        assert!(pending.attempts.is_empty());
        assert_eq!(pending.usage.usage.total_bytes, 200);
        assert!(disk
            .attempt(&id, attempt(larger.clone()), "head2".into())
            .unwrap());
        drop(disk);
        let recovered = Disk::open(&path, identity, TEST_BUDGET).unwrap();
        let pending = recovered.slot(&id).unwrap().unwrap();
        assert_eq!(pending.usage, larger);
        assert_eq!(pending.attempts.len(), 1);
        recovered.reconcile(&id, 200).unwrap();
        assert!(recovered.keys().unwrap().is_empty());
    }

    #[test]
    fn signed_transaction_cannot_change_receipt_or_sender() {
        let signed = usage(1, 100);
        let (original, public) = tx(&signed);
        check_transaction(&original, &signed, &public).unwrap();
        let encoded = attempt(signed.clone());
        assert_eq!(decode_attempt(&encoded).unwrap(), original);
        assert!(check_transaction(&original, &usage(2, 101), &public).is_err());
        let key = SigningKey::from_bytes(&[11; 32]);
        for case in 0..4 {
            let mut forged = original.clone();
            match case {
                0 => forged.ou = (FEE_OU + 1).into(),
                1 => forged.from = b"forged factory sender".to_vec(),
                2 => forged.encrypted_data = Some(b"withdraw".to_vec()),
                _ => forged.to = Address::from_pubkey(&[9; 32]).display().as_bytes().to_vec(),
            }
            // Even a correctly signed ordinary transaction must match the exact
            // claim binding, fee and normalized key-derived sender.
            forged.signature = STANDARD
                .encode(key.sign(&forged.signing_bytes().unwrap()).to_bytes())
                .into_bytes();
            assert!(check_transaction(&forged, &signed, &public).is_err());
        }
    }

    #[test]
    fn exclusive_writer_missing_lease_and_queue_reset_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("claims");
        let identity = serde_json::json!({"deployment":"fixture"});
        let disk = Disk::open(&path, identity.clone(), TEST_BUDGET).unwrap();
        disk.enqueue(usage(1, 10)).unwrap();
        assert!(Disk::open(&path, identity.clone(), TEST_BUDGET).is_err());
        drop(disk);
        assert!(Disk::open(
            &path,
            serde_json::json!({"deployment":"other"}),
            TEST_BUDGET
        )
        .is_err());
        std::fs::remove_file(path.join("writer.lock")).unwrap();
        assert!(Disk::open(&path, identity.clone(), TEST_BUDGET).is_err());
        // Recover the deliberately removed lease for the missing-journal
        // negative case; neither mutation is a supported production recovery.
        let lock = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path.join("writer.lock"))
            .unwrap();
        lock.set_permissions(std::fs::Permissions::from_mode(0o600))
            .unwrap();
        drop(lock);
        std::fs::remove_file(path.join("claims.json")).unwrap();
        assert!(Disk::open(&path, identity, TEST_BUDGET).is_err());
    }

    #[test]
    fn directory_descriptor_remains_pinned_and_symlinks_are_refused() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("claims");
        let identity = serde_json::json!({"deployment":"fixture"});
        let disk = Disk::open(&path, identity.clone(), TEST_BUDGET).unwrap();
        let moved = root.path().join("moved");
        std::fs::rename(&path, &moved).unwrap();
        std::fs::create_dir(&path).unwrap();
        let id = disk.enqueue(usage(1, 10)).unwrap();
        assert!(!path.join("claims.json").exists());
        drop(disk);
        let disk = Disk::open(&moved, identity.clone(), TEST_BUDGET).unwrap();
        assert!(disk.slot(&id).unwrap().is_some());
        drop(disk);
        let external = root.path().join("external");
        std::fs::rename(moved.join("claims.json"), &external).unwrap();
        symlink(&external, moved.join("claims.json")).unwrap();
        assert!(Disk::open(&moved, identity, TEST_BUDGET).is_err());
    }

    #[test]
    fn fee_reservations_survive_rejection_progress_and_restart() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("claims");
        let identity = serde_json::json!({"deployment":"fixture"});
        let disk = Disk::open(&path, identity.clone(), FEE_OU).unwrap();
        let signed = usage(1, 10);
        let id = disk.enqueue(signed.clone()).unwrap();
        let signed_attempt = attempt(signed);
        assert!(disk
            .attempt(&id, signed_attempt.clone(), "head1".into())
            .unwrap());
        // Retrying the exact durable transaction neither signs anew nor spends
        // another reservation. Unknown admission outcomes release no credit.
        assert!(!disk.attempt(&id, signed_attempt, "head2".into()).unwrap());
        assert!(disk.permits_new("head2").is_err());
        assert_eq!(disk.state.lock().unwrap().fees_reserved_ou, FEE_OU);
        disk.reconcile(&id, 10).unwrap();
        let next = usage(2, 20);
        let id = disk.enqueue(next.clone()).unwrap();
        assert!(disk
            .attempt(&id, attempt(next.clone()), "head3".into())
            .is_err());
        drop(disk);
        assert!(Disk::open(&path, identity.clone(), FEE_OU * 2).is_err());
        let disk = Disk::open(&path, identity, FEE_OU).unwrap();
        assert_eq!(disk.state.lock().unwrap().fees_reserved_ou, FEE_OU);
        assert!(disk.attempt(&id, attempt(next), "head4".into()).is_err());
        assert!(disk.slot(&id).unwrap().unwrap().attempts.is_empty());
    }

    #[test]
    fn zero_fee_budget_disables_spending_and_unlimited_is_rejected() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("claims");
        let identity = serde_json::json!({"deployment":"fixture"});
        assert!(Disk::open(&path, identity.clone(), u64::MAX).is_err());
        let disk = Disk::open(&path, identity, 0).unwrap();
        let signed = usage(1, 10);
        let id = disk.enqueue(signed.clone()).unwrap();
        assert!(disk.permits_new("head1").is_err());
        assert!(disk.attempt(&id, attempt(signed), "head1".into()).is_err());
        assert_eq!(disk.state.lock().unwrap().fees_reserved_ou, 0);
    }

    #[test]
    fn canonical_economic_coverage_avoids_zero_increment_claims() {
        assert!(counters_cover(1, 1, 2, 1)); // Same prepaid rounding bucket.
        assert!(counters_cover(0, 0, 100, 0)); // Operator explicitly free class.
        assert!(!counters_cover(1, 1, 2, 2)); // Additional debt needs inclusion.
        assert!(counters_cover(2, 2, 2, 2)); // Exact prior byte redemption.
    }
}
