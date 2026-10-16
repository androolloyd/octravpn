//! Durable countersigned receipts become ordinary operator claim transactions.
//! Canonical application state, rather than intake acknowledgement, completes
//! delivery. Receipt and signed transaction files survive cancellation/restart.
use super::Pinned;
use crate::rpc::Context;
use anyhow::{ensure, Context as _, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use octra_node_protocol::{native_json::Document, transaction::Transaction};
use octra_node_runtime::{account_store, state_batch::StateBatch};
use octravpn_core::{
    control::AnnounceSessionRequest,
    receipt::{ReceiptContext, SignedReceipt},
    sig::PublicKey,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{mpsc, oneshot, watch};

const RECORDS: usize = 4096;
const ATTEMPTS: usize = 8;
const FILE_BYTES: u64 = 65_536;
const STORE_BYTES: u64 = 64 * 1024 * 1024;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    receipt: SignedReceipt,
    announcement: AnnounceSessionRequest,
}
struct Request {
    record: Record,
    reply: oneshot::Sender<Result<()>>,
}
pub(crate) struct Publisher {
    sender: mpsc::Sender<Request>,
    submission: Arc<Context>,
    pinned: Arc<Pinned>,
    directory: PathBuf,
    domain: ReceiptContext,
    receipt_key: PublicKey,
    lock: Arc<File>,
    publication: Arc<std::sync::Mutex<()>>,
}
pub(crate) struct Service {
    submission: Arc<Context>,
    pinned: Arc<Pinned>,
    domain: ReceiptContext,
    receipt_key: PublicKey,
    key: SigningKey,
    operator: Vec<u8>,
    directory: PathBuf,
    receiver: mpsc::Receiver<Request>,
    records: BTreeMap<String, Record>,
    writer_lease: Arc<File>,
}

fn read(path: &Path) -> Result<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(
            (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
        );
    }
    let mut file = options.open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() <= FILE_BYTES,
        "invalid native claim record"
    );
    let mut bytes = Vec::new();
    file.by_ref().take(FILE_BYTES + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= FILE_BYTES,
        "native claim record too large"
    );
    Ok(bytes)
}
fn valid(record: &Record, domain: &ReceiptContext, receipt_key: PublicKey) -> Result<()> {
    record.receipt.verify()?;
    let request = &record.announcement;
    octravpn_core::sig::verify(
        &request.client_pubkey,
        &octravpn_core::control::announce_signing_payload(
            &request.session_id,
            &request.client_pubkey,
            &request.client_wg_pubkey,
            &request.open_tx_hash,
        ),
        &request.client_sig,
    )?;
    octravpn_core::sig::verify(
        &request.opener_pubkey,
        &octravpn_core::control::announce_opener_binding_payload(
            &request.session_id,
            &request.client_pubkey,
            &request.client_wg_pubkey,
            &request.open_tx_hash,
        ),
        &request.opener_sig,
    )?;
    ensure!(
        &record.receipt.receipt.context == domain
            && record.receipt.node_pubkey == receipt_key
            && record.receipt.client_pubkey == record.announcement.client_pubkey
            && record.receipt.receipt.session_id == record.announcement.session_id,
        "native claim receipt binding differs"
    );
    Ok(())
}
fn same_claim(prior: &Record, record: &Record) -> Result<()> {
    ensure!(
        prior.receipt.receipt.bytes_used == record.receipt.receipt.bytes_used
            && prior.announcement.client_pubkey == record.announcement.client_pubkey
            && prior.announcement.open_tx_hash == record.announcement.open_tx_hash,
        "native claim already fixes another byte total or opening"
    );
    Ok(())
}
impl Service {
    pub(crate) async fn open(
        submission: Arc<Context>,
        pinned: Arc<Pinned>,
        domain: ReceiptContext,
        receipt_key: PublicKey,
        key: SigningKey,
        directory: PathBuf,
    ) -> Result<(Arc<Publisher>, Self)> {
        let operator = octra_node_protocol::transaction::address_from_public_key(
            STANDARD.encode(key.verifying_key().as_bytes()).as_bytes(),
        );
        pinned.validate_operator(&submission.node.snapshot()?, &operator)?;
        let path = directory.clone();
        let captured = domain.clone();
        let chain = submission.node.chain().clone();
        let identity_key = key.verifying_key();
        let (lock, records) = tokio::task::spawn_blocking(move || -> Result<_> {
            std::fs::create_dir_all(&path)?;
            let mut options = OpenOptions::new(); options.read(true).write(true).create(true).truncate(false);
            #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600).custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32); }
            let lock = options.open(path.join("writer.lock"))?;
            ensure!(lock.metadata()?.is_file(), "native claim lock must be regular");
            rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)?;
            crate::storage::publish(&path.join("identity.json"), &serde_json::to_vec(&serde_json::json!({"version":1,"chain":chain,"domain":captured,"operator":STANDARD.encode(identity_key.as_bytes()),"receipt_key":receipt_key}))?)?;
            let mut records = BTreeMap::new();let mut total_bytes=0_u64;
            for (count, entry) in std::fs::read_dir(&path)?.enumerate() {
                ensure!(count < RECORDS*(ATTEMPTS+1)+64, "native claim directory entry limit reached");
                let entry = entry?; let name = entry.file_name(); let name = name.to_str().context("invalid claim filename")?;
                if let Some(id) = name.strip_suffix(".receipt.json") {
                    ensure!(records.len() < RECORDS && id.len() == 64 && id.bytes().all(|v|v.is_ascii_digit() || (b'a'..=b'f').contains(&v)), "invalid native claim record identity/capacity");
                    let raw=read(&entry.path())?;total_bytes+=raw.len() as u64;
                    ensure!(total_bytes<=STORE_BYTES,"native claim receipt bytes exceed store bound");
                    let record: Record = serde_json::from_slice(&raw)?;
                    valid(&record, &captured, receipt_key)?;
                    ensure!(record.receipt.receipt.session_id.to_hex() == id, "claim filename binding differs");
                    records.insert(id.to_owned(), record);
                }
            }
            Ok((Arc::new(lock), records))
        }).await??;
        let (sender, receiver) = mpsc::channel(8);
        Ok((
            Arc::new(Publisher {
                sender,
                submission: submission.clone(),
                pinned: pinned.clone(),
                directory: directory.clone(),
                domain: domain.clone(),
                receipt_key,
                lock: lock.clone(),
                publication: Arc::new(std::sync::Mutex::new(())),
            }),
            Self {
                submission,
                pinned,
                domain,
                receipt_key,
                key,
                operator,
                directory,
                receiver,
                records,
                writer_lease: lock,
            },
        ))
    }
    async fn persist(&mut self, record: Record) -> Result<String> {
        valid(&record, &self.domain, self.receipt_key)?;
        let id = record.receipt.receipt.session_id.to_hex();
        if let Some(prior) = self.records.get(&id) {
            same_claim(prior, &record)?;
            return Ok(id);
        }
        ensure!(
            self.records.len() < RECORDS,
            "native claim record capacity reached"
        );
        let path = self.directory.join(format!("{id}.receipt.json"));
        let bytes = serde_json::to_vec(&record)?;
        let lock = self.writer_lease.clone();
        tokio::task::spawn_blocking(move || {
            let _writer_lease = lock;
            crate::storage::publish(&path, &bytes)
        })
        .await??;
        self.records.insert(id.clone(), record);
        Ok(id)
    }
    async fn deliver(&self, id: &str) -> Result<bool> {
        let record = &self.records[id];
        let receipt = &record.receipt.receipt;
        let view = self.submission.node.snapshot()?;
        let net = self
            .pinned
            .quote(&view, &record.announcement, receipt.bytes_used)
            .await?;
        if let Some(claim) = self
            .pinned
            .claim(&view, &receipt.session_id, &self.operator)?
        {
            ensure!(
                claim.bytes == receipt.bytes_used,
                "committed operator claim bytes differ"
            );
            if let Some(claim_net) = claim.net {
                ensure!(
                    claim_net == net,
                    "committed operator claim amount differs from the session tariff"
                );
                return Ok(true);
            }
        }
        ensure!(
            self.pinned.can_claim(&view, &receipt.session_id)?,
            "native receipt session is not canonically claimable"
        );
        let wallet = Arc::new(self.submission.executor.operator_wallet().await);
        let directory = self.directory.clone();
        let session = id.to_owned();
        let attempts = tokio::task::spawn_blocking(move || -> Result<Vec<Transaction>> {
            let mut attempts = Vec::new();
            let mut gap = false;
            for index in 0..ATTEMPTS {
                let path = directory.join(format!("{session}.tx-{index:04}.json"));
                match read(&path) {
                    Ok(raw) => {
                        ensure!(!gap, "native claim attempt sequence has a gap");
                        attempts.push(Transaction::from_document(&Document::parse(&raw)?)?);
                    }
                    Err(error)
                        if error
                            .downcast_ref::<std::io::Error>()
                            .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
                    {
                        gap = true;
                    }
                    Err(error) => return Err(error),
                }
            }
            Ok(attempts)
        })
        .await??;
        let fresh = self.submission.node.snapshot()?;
        if let Some(claim) = self
            .pinned
            .claim(&fresh, &receipt.session_id, &self.operator)?
        {
            ensure!(
                claim.bytes == receipt.bytes_used,
                "committed operator claim bytes differ"
            );
            if let Some(claim_net) = claim.net {
                ensure!(
                    claim_net == net,
                    "committed operator claim amount differs from the session tariff"
                );
                return Ok(true);
            }
        }
        ensure!(
            self.pinned.can_claim(&fresh, &receipt.session_id)?,
            "native receipt session is no longer canonically claimable"
        );
        let ledger = account_store::ledger(&StateBatch::from_snapshot(fresh.state().clone()))?;
        let account = ledger
            .account(&self.operator)
            .context("native operator wallet is unfunded")?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64();
        for tx in &attempts {
            self.check_transaction(tx, receipt, net)?;
        }
        let tx = if let Some(tx) = attempts
            .last()
            .filter(|tx| account.nonce < tx.nonce && now - tx.timestamp <= 300.)
        {
            tx.clone()
        } else {
            // A replacement preserves the exact authenticated claim amount.
            // Its prior nonce is already consumed in canonical state, or its
            // timestamp can no longer pass ordinary native HTTP admission.
            // All old signed attempts remain available for restart/audit.
            ensure!(
                attempts.len() < ATTEMPTS,
                "native claim attempt limit reached; operator recovery required"
            );
            let nonce = self
                .submission
                .pending
                .inspect(|pool| pool.duty_nonce(&self.operator, account.nonce))?
                .context("native operator nonce has a pending transaction")?;
            let mut tx = Transaction {
                from: self.operator.clone(),
                to: self.domain.program_addr.display().as_bytes().to_vec(),
                amount: 0.into(),
                nonce,
                ou: 1000.into(),
                timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64(),
                signature: vec![],
                public_key: Some(
                    STANDARD
                        .encode(self.key.verifying_key().as_bytes())
                        .into_bytes(),
                ),
                message: Some(serde_json::to_vec(&serde_json::json!([
                    receipt
                        .session_id
                        .as_u64()
                        .context("claim session is not uint")?,
                    receipt.bytes_used,
                    net
                ]))?),
                encrypted_data: Some(b"settle_claim".to_vec()),
                op_type: self.pinned.claim_op(),
            };
            tx.signature = STANDARD
                .encode(self.key.sign(&tx.signing_bytes()?).to_bytes())
                .into_bytes();
            let bytes = tx.to_json_bytes()?;
            let path = self
                .directory
                .join(format!("{id}.tx-{:04}.json", attempts.len()));
            let lock = self.writer_lease.clone();
            let lease = wallet.clone();
            tokio::task::spawn_blocking(move || {
                let _writer_lease = lock;
                let _wallet = lease;
                crate::storage::publish(&path, &bytes)
            })
            .await??;
            tx
        };
        self.check_transaction(&tx, receipt, net)?;
        self.submission.submit_operator(tx, now, wallet).await?;
        Ok(false)
    }
    fn check_transaction(
        &self,
        tx: &Transaction,
        receipt: &octravpn_core::receipt::Receipt,
        net: u64,
    ) -> Result<()> {
        let expected = serde_json::to_vec(&serde_json::json!([
            receipt
                .session_id
                .as_u64()
                .context("claim session is not uint")?,
            receipt.bytes_used,
            net
        ]))?;
        ensure!(
            tx.from == self.operator
                && tx.to == self.domain.program_addr.display().as_bytes()
                && tx.amount == 0.into()
                && tx.op_type == self.pinned.claim_op()
                && tx.encrypted_data.as_deref() == Some(b"settle_claim")
                && tx.message.as_deref() == Some(expected.as_slice())
                && tx.public_key.as_deref().is_some_and(|public| public
                    == STANDARD
                        .encode(self.key.verifying_key().as_bytes())
                        .as_bytes()
                    && tx.verify(public)),
            "saved native claim transaction binding differs"
        );
        Ok(())
    }
    pub(crate) async fn run(mut self, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        let mut completed = std::collections::BTreeSet::new();
        let mut recovery_cursor = 0;
        let mut timer = tokio::time::interval(Duration::from_secs(2));
        loop {
            tokio::select! {
                () = async {let _ = shutdown.wait_for(|v|*v).await;} => return Ok(()),
                request = self.receiver.recv() => {
                    let Some(request) = request else {return Ok(())};
                    let result = async {
                        let id = self.persist(request.record).await?;
                        let deadline = tokio::time::Instant::now()+Duration::from_secs(45);
                        loop {
                            match self.deliver(&id).await {
                                Ok(true) => {completed.insert(id);return Ok(())},
                                Ok(false) => (),
                                Err(error) => eprintln!("native claim remains durable and pending session={id}: {error:#}"),
                            }
                            ensure!(tokio::time::Instant::now()<deadline, "native claim confirmation pending");
                            tokio::time::sleep(Duration::from_millis(500)).await;
                        }
                    }.await;
                    let _ = request.reply.send(result);
                }
                _ = timer.tick() => {
                    // A handler may persist its intent then time out or find
                    // the bounded mailbox full. Recover those rows without
                    // depending on the caller or a process restart.
                    let directory=self.directory.clone();
                    let domain=self.domain.clone();let key=self.receipt_key;
                    let discovered=tokio::task::spawn_blocking(move || -> Result<Vec<Record>> {
                        let mut rows=Vec::new();let mut total_bytes=0_u64;
                        for (count,entry) in std::fs::read_dir(directory)?.enumerate() {
                            ensure!(count<RECORDS*(ATTEMPTS+1)+64,"native claim directory entry limit reached");
                            let entry=entry?;
                            if entry.file_name().to_str().is_some_and(|name|name.ends_with(".receipt.json")) {
                                ensure!(rows.len()<RECORDS,"native claim record capacity reached");
                                let raw=read(&entry.path())?;total_bytes+=raw.len() as u64;
                                ensure!(total_bytes<=STORE_BYTES,"native claim receipt bytes exceed store bound");
                                let record:Record=serde_json::from_slice(&raw)?;valid(&record,&domain,key)?;rows.push(record);
                            }
                        }
                        Ok(rows)
                    }).await??;
                    for record in discovered {let id=record.receipt.receipt.session_id.to_hex();self.records.entry(id).or_insert(record);}
                    let pending=self.records.keys().filter(|id|!completed.contains(*id)).cloned().collect::<Vec<_>>();
                    for offset in 0..pending.len().min(8) {
                        let id=pending[(recovery_cursor+offset)%pending.len()].clone();
                        match self.deliver(&id).await {Ok(true)=>{completed.insert(id);}, Ok(false)=>(),Err(error)=>eprintln!("native claim recovery pending session={id}: {error:#}")}
                        if *shutdown.borrow() {return Ok(())}
                    }
                    if !pending.is_empty() {recovery_cursor=(recovery_cursor+8)%pending.len();}
                }
            }
        }
    }
}
#[async_trait::async_trait]
impl octravpn_node::embedded::ReceiptSettlement for Publisher {
    async fn authorize_retry(
        &self,
        receipt: &SignedReceipt,
        announcement: &AnnounceSessionRequest,
    ) -> Result<()> {
        let candidate = Record {
            receipt: receipt.clone(),
            announcement: announcement.clone(),
        };
        valid(&candidate, &self.domain, self.receipt_key)?;
        // A saved claim record is not an admission proof: older versions could
        // persist one before the canonical claim check. Recheck the opening at
        // the current root on every retry, even after a restart.
        let view = self.submission.node.snapshot()?;
        self.pinned
            .quote(&view, announcement, receipt.receipt.bytes_used)
            .await?;
        Ok(())
    }

    async fn confirm(
        &self,
        receipt: SignedReceipt,
        announcement: AnnounceSessionRequest,
    ) -> Result<()> {
        let directory = self.directory.clone();
        let domain = self.domain.clone();
        let receipt_key = self.receipt_key;
        let lock = self.lock.clone();
        let publication = self.publication.clone();
        let record = tokio::task::spawn_blocking(move || -> Result<Record> {
            let _writer_lease = lock;
            let _publication = publication
                .lock()
                .map_err(|_| anyhow::anyhow!("claim publication lock poisoned"))?;
            let record = Record {
                receipt,
                announcement,
            };
            valid(&record, &domain, receipt_key)?;
            let path = directory.join(format!(
                "{}.receipt.json",
                record.receipt.receipt.session_id.to_hex()
            ));
            match read(&path) {
                Ok(bytes) => {
                    let prior: Record = serde_json::from_slice(&bytes)?;
                    valid(&prior, &domain, receipt_key)?;
                    same_claim(&prior, &record)?;
                    Ok(prior)
                }
                Err(error)
                    if error
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
                {
                    let mut receipts = 0;
                    let bytes = serde_json::to_vec(&record)?;
                    ensure!(
                        bytes.len() as u64 <= FILE_BYTES,
                        "native claim record too large"
                    );
                    let mut total_bytes = bytes.len() as u64;
                    for (count, entry) in std::fs::read_dir(&directory)?.enumerate() {
                        ensure!(
                            count < RECORDS * (ATTEMPTS + 1) + 64,
                            "native claim directory entry limit reached"
                        );
                        let entry = entry?;
                        if entry
                            .file_name()
                            .to_str()
                            .is_some_and(|name| name.ends_with(".receipt.json"))
                        {
                            receipts += 1;
                            total_bytes = total_bytes
                                .checked_add(entry.metadata()?.len())
                                .context("native claim byte accounting overflow")?;
                        }
                    }
                    ensure!(receipts < RECORDS, "native claim record capacity reached");
                    ensure!(
                        total_bytes <= STORE_BYTES,
                        "native claim receipt bytes exceed store bound"
                    );
                    crate::storage::publish(&path, &bytes)?;
                    Ok(record)
                }
                Err(error) => Err(error),
            }
        })
        .await??;
        let (reply, receive) = oneshot::channel();
        self.sender
            .try_send(Request { record, reply })
            .map_err(|_| anyhow::anyhow!("native claim publisher is busy or stopped"))?;
        tokio::time::timeout(Duration::from_secs(55), receive).await??
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use octravpn_core::{
        address::Address,
        receipt::Receipt,
        session::{Blind, SessionId},
        sig::KeyPair,
    };

    fn record() -> (Record, ReceiptContext, PublicKey) {
        let client = KeyPair::from_secret_bytes(&[11; 32]);
        let opener = KeyPair::from_secret_bytes(&[12; 32]);
        let node = KeyPair::from_secret_bytes(&[13; 32]);
        let domain = ReceiptContext::v2(
            Address::from_pubkey(&[31; 32]),
            9871,
            Address::from_pubkey(&[32; 32]),
        );
        let session = SessionId::from_u64(7);
        let wg = [14; 32];
        let opening = "ab".repeat(32);
        let client_sig = client.sign(&octravpn_core::control::announce_signing_payload(
            &session,
            &client.public,
            &wg,
            &opening,
        ));
        let opener_sig = opener.sign(&octravpn_core::control::announce_opener_binding_payload(
            &session,
            &client.public,
            &wg,
            &opening,
        ));
        let announcement = AnnounceSessionRequest {
            session_id: session.clone(),
            client_pubkey: client.public,
            client_wg_pubkey: wg,
            open_tx_hash: opening,
            client_sig,
            opener_pubkey: opener.public,
            opener_sig,
        };
        let receipt = SignedReceipt::build(
            Receipt::new(domain.clone(), session, 1, 1_200_000, Blind::new([15; 32])),
            &client,
            &node,
        );
        (
            Record {
                receipt,
                announcement,
            },
            domain,
            node.public,
        )
    }
    #[test]
    fn saved_claim_requires_original_wallet_announcement_and_receipt_domain() {
        let (record, domain, key) = record();
        valid(&record, &domain, key).unwrap();
        let mut wrong = record.clone();
        wrong.announcement.open_tx_hash = "cd".repeat(32);
        assert!(valid(&wrong, &domain, key).is_err());
        let mut wrong = record.clone();
        wrong.announcement.opener_pubkey = KeyPair::from_secret_bytes(&[16; 32]).public;
        assert!(valid(&wrong, &domain, key).is_err());
        let mut wrong_domain = domain;
        wrong_domain.chain_id += 1;
        assert!(valid(&record, &wrong_domain, key).is_err());
        assert!(valid(
            &record,
            &record.receipt.receipt.context,
            KeyPair::from_secret_bytes(&[17; 32]).public
        )
        .is_err());
    }
    #[test]
    fn saved_claim_reads_reject_unbounded_and_nonregular_paths() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("record");
        std::fs::write(&path, b"valid").unwrap();
        assert_eq!(read(&path).unwrap(), b"valid");
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(FILE_BYTES + 1)
            .unwrap();
        assert!(read(&path).is_err());
        assert!(read(directory.path()).is_err());
        #[cfg(unix)]
        {
            let link = directory.path().join("link");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            assert!(read(&link).is_err());
        }
    }
}
