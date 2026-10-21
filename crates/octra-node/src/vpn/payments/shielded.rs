//! Experimental canonical funding authority. A decrypted box or RPC receipt is
//! never payment: the received note must occupy a newly appended position in
//! an authenticated historical pool tree with active native value rules.
//! This does not credit a meter without a separate durable single-use journal.
use super::{
    application_domain, check_application, digest, Application, Fields, Payments, PLAN_MAX_AGE,
};
use crate::SnapshotLease;
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::transaction::RuleMode;
use octra_node_runtime::{
    account_store, circle_view,
    finality_queries::Range,
    state_batch::{Snapshot, StateBatch},
};
use octra_private_payments_experimental::{
    invoice::{Consent, Settlement, SignedInvoice},
    native_stealth,
    pool::{self, call::Call, envelope, Domain, Membership, Note, PoolIndex, SpendKey},
};
use octravpn_core::{parse_native_address, payments::Tariff};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
pub mod history;
pub mod index;
pub mod payer;
pub mod startup;
mod storage;
pub mod wallet;

/// Public immutable deployment pins. Supply a separately accepted ceremony VK;
/// an operator response must never choose this key on the payer's behalf.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub circle: String,
    pub factory: String,
    pub custody_cap_ou: u64,
    pub verification_key_b64: String,
    pub verification_key_sha256: String,
}

pub struct Pool {
    directory: Arc<Payments>,
    config: Config,
    origin: [u8; 32],
    address: [u8; 47],
    domain: Domain,
    code_hash: String,
    factory_hash: String,
}
struct Execution {
    lease: SnapshotLease,
    before: history::Projection,
    after: history::Projection,
    record: octra_node_protocol::consensus::CatchupEpochRecord,
    paid_at: u64,
    now: u64,
}
struct Historical {
    lease: SnapshotLease,
    before: Snapshot,
    after: Snapshot,
    record: octra_node_protocol::consensus::CatchupEpochRecord,
    paid_at: u64,
    now: u64,
}
impl From<Execution> for Historical {
    fn from(value: Execution) -> Self {
        Self {
            lease: value.lease,
            before: value.before.snapshot().clone(),
            after: value.after.snapshot().clone(),
            record: value.record,
            paid_at: value.paid_at,
            now: value.now,
        }
    }
}

/// Explicit local consent, separate from the operator's signed private terms.
pub struct Limits {
    pub receipt_key: [u8; 32],
    pub traffic_class: u8,
    pub max_bytes: u64,
    pub max_cost_ou: u64,
}

/// All inclusion material is untrusted until confirm() returns. It also works
/// for notes produced by nested Circle calls; no VM event text is trusted.
pub struct Inclusion<'a> {
    pub epoch: u64,
    pub commitment: [u8; 32],
    pub membership: &'a Membership,
    pub call: &'a Call,
    pub relayer: [u8; 47],
    pub invoice: &'a SignedInvoice,
    pub tariff: &'a Tariff,
    pub limits: &'a Limits,
    pub spend_key: &'a SpendKey,
    pub view_secret: &'a [u8; 32],
}

// These records contain the private payer/operator relationship. Deliberately
// no Debug or generic serialization; the wallet journal must encrypt them.
pub struct Funding {
    pub credit_id: [u8; 32],
    pub quote: [u8; 32],
    pub commitment: [u8; 32],
    pub receipt_key: [u8; 32],
    pub operator_generation: u64,
    pub offer: u64,
    pub traffic_class: u8,
    pub bytes: u64,
    pub amount_ou: u64,
    pub epoch: u64,
    pub purchased_ms: u64,
    pub observed_ms: u64,
}
pub struct FundedPurchase {
    funding: Funding,
    note: Note,
    eligible: bool,
    lease: SnapshotLease,
}
impl std::ops::Deref for FundedPurchase {
    type Target = Funding;
    fn deref(&self) -> &Self::Target {
        &self.funding
    }
}
impl FundedPurchase {
    pub fn note(&self) -> &Note {
        &self.note
    }
    pub fn admissible(&self) -> bool {
        self.eligible && self.lease.is_live(PLAN_MAX_AGE)
    }
    /// Durable wallet/credit work must precede this final nonblocking operation.
    pub fn with_current<T>(&self, action: impl FnOnce(&Funding) -> Result<T>) -> Result<T> {
        self.lease.with_current(PLAN_MAX_AGE, || {
            ensure!(
                self.eligible,
                "private payment operator is no longer eligible"
            );
            action(&self.funding)
        })
    }
}

struct State {
    notes: [u8; 32],
    spent: [u8; 32],
    count: u64,
}
struct Placement {
    lease: SnapshotLease,
    before: Snapshot,
    paid_at: u64,
    now: u64,
}

impl Pool {
    fn credit_id(&self, commitment: [u8; 32]) -> [u8; 32] {
        let mut id = Sha256::new();
        id.update(b"Octranet shielded capacity v1\0");
        id.update(self.origin);
        id.update(self.address);
        id.update(commitment);
        id.finalize().into()
    }
    fn same_custody(&self, other: &Self) -> bool {
        self.origin == other.origin
            && self.address == other.address
            && self.domain.digest() == other.domain.digest()
            && self.code_hash == other.code_hash
            && self.factory_hash == other.factory_hash
            && self.config.factory == other.config.factory
            && self.config.custody_cap_ou == other.config.custody_cap_ou
            && Arc::ptr_eq(&self.directory.shared, &other.directory.shared)
    }
    /// Constructed from a Node-minted directory reader, never an arbitrary RPC.
    pub fn new(directory: Arc<Payments>, config: Config) -> Result<Self> {
        ensure!(
            directory.config.application == Application::Circle,
            "private payments require a canonical Circle directory"
        );
        ensure!(
            directory.config.domain
                == application_domain(directory.history.chain(), Application::Circle),
            "private payment directory network differs"
        );
        let address = native(&config.circle)?;
        native(&config.factory)?;
        digest(&config.verification_key_sha256)?;
        let key = STANDARD.decode(&config.verification_key_b64)?;
        ensure!(
            STANDARD.encode(&key) == config.verification_key_b64
                && hex::encode(Sha256::digest(&key)) == config.verification_key_sha256,
            "private payment verification key pin differs"
        );
        let origin = hash(&directory.config.domain)?;
        let domain = Domain::new(&origin, &address)?;
        let source = pool::app::source(&origin, &key, config.custody_cap_ou)?;
        let code_hash = compiled_hash(&source)?;
        let factory_hash = compiled_hash(pool::app::FACTORY)?;
        Ok(Self {
            directory,
            config,
            origin,
            address,
            domain,
            code_hash,
            factory_hash,
        })
    }

    pub fn domain(&self) -> Domain {
        self.domain
    }
    pub fn origin(&self) -> [u8; 32] {
        self.origin
    }
    pub fn circle(&self) -> &str {
        &self.config.circle
    }
    /// Canonical directory terms for independent payer consent. Reading an
    /// offer establishes neither private funding nor forwarding capacity.
    pub async fn offer(&self, offer: u64) -> Result<super::Offer> {
        self.directory.offer(offer).await
    }

    async fn current_index(&self, index: &PoolIndex) -> Result<(SnapshotLease, u64)> {
        let lease = SnapshotLease::capture(self.directory.shared.clone())?;
        lease.with_current(PLAN_MAX_AGE, || Ok(()))?;
        self.directory
            .check_value_effects(lease.committed())
            .await?;
        let (graph, history) = self
            .directory
            .circle_authority
            .as_ref()
            .context("shielded pool execution authority missing")?;
        let profile =
            circle_view::canonical_with_graph(&lease.committed().assets, graph, history.as_ref())
                .await?;
        ensure!(
            profile.math,
            "shielded pool requires active native math rules"
        );
        let now = self.directory.canonical_time(lease.committed()).await?;
        let state = self.state(lease.committed().state())?;
        ensure!(
            index.roots()
                == (
                    pool::decode_field(&state.notes)?,
                    pool::decode_field(&state.spent)?,
                    state.count,
                ),
            "public index does not match canonical shielded pool roots"
        );
        lease.with_current(PLAN_MAX_AGE, || Ok(()))?;
        Ok((lease, now))
    }

    // Ownership witness only: this establishes neither original purchase time
    // nor traffic entitlement. Callers still open their own authenticated note.
    async fn current_member(
        &self,
        index: &PoolIndex,
        position: u32,
        commitment: [u8; 32],
    ) -> Result<SnapshotLease> {
        let (lease, _) = self.current_index(index).await?;
        let (root, _, count) = index.roots();
        index
            .membership(position)?
            .verify(root, count, pool::decode_field(&commitment)?)?;
        lease.with_current(PLAN_MAX_AGE, || Ok(()))?;
        Ok(lease)
    }

    fn code(&self, snapshot: &Snapshot) -> Result<()> {
        check_application(
            Application::Circle,
            snapshot,
            &self.config.circle,
            &self.code_hash,
            Some(self.config.factory.as_bytes()),
        )?;
        check_application(
            Application::Circle,
            snapshot,
            &self.config.factory,
            &self.factory_hash,
            None,
        )?;
        ensure!(
            snapshot.get(&[b"circles", &self.address, b"origin", b"owner_mode"])
                == Some(b"parent".as_slice()),
            "private pool must be parent-owned"
        );
        Ok(())
    }
    fn state(&self, snapshot: &Snapshot) -> Result<State> {
        self.code(snapshot)?;
        let fields = Fields {
            snapshot,
            program: &self.address,
            application: Application::Circle,
        };
        ensure!(
            fields.uint(b"initialized", &[])? == 1,
            "private pool is not initialized"
        );
        ensure!(
            hash(&fields.text(b"domain", &[])?)? == self.domain.digest(),
            "private pool domain differs"
        );
        let notes = hash(&fields.text(b"notes", &[])?)?;
        pool::decode_field(&notes)?;
        let spent = hash(&fields.text(b"spent", &[])?)?;
        pool::decode_field(&spent)?;
        let count = fields.uint(b"count", &[])?;
        let locked = fields.uint(b"locked", &[])?;
        ensure!(
            count <= 1_u64 << pool::NOTE_DEPTH && locked <= self.config.custody_cap_ou,
            "private pool accounting differs"
        );
        let account =
            account_store::load(&StateBatch::from_snapshot(snapshot.clone()), &self.address)?;
        ensure!(
            account.map_or(locked == 0, |account| account.balance >= locked.into()),
            "private pool native custody is insufficient"
        );
        Ok(State {
            notes,
            spent,
            count,
        })
    }

    async fn record(&self, epoch: u64) -> Result<Execution> {
        let lease = SnapshotLease::capture(self.directory.shared.clone())?;
        lease.with_current(PLAN_MAX_AGE, || Ok(()))?;
        let committed = lease.committed();
        self.directory.check_value_effects(committed).await?;
        let now = self.directory.canonical_time(committed).await?;
        let current_pool = self.state(committed.state())?;
        ensure!(
            epoch > 0 && epoch <= committed.head().cursor.epoch.0,
            "private note epoch is not canonically published"
        );
        let after_head = self.directory.history.head_for_epoch(epoch).await?;
        let before_head = self.directory.history.head_for_epoch(epoch - 1).await?;
        let (graph, history) = self
            .directory
            .circle_authority
            .as_ref()
            .context("private payment historical authority is missing")?;
        let before = history::Projection::at(self, before_head.clone()).await?;
        let after = history::Projection::at(self, after_head.clone()).await?;
        let view_epoch = circle_view::epoch(
            before.snapshot().get(&[b"meta", b"last_epoch"]),
            circle_view::ReadKind::View,
        )?;
        let profile = circle_view::anchored(
            graph,
            view_epoch,
            before.head().cursor.epoch.0,
            history.as_ref(),
        )
        .await?;
        ensure!(
            profile.epoch == i64::try_from(epoch)?
                && profile.math
                && profile.proof_exec == RuleMode::Active,
            "private payment historical value rules are inactive"
        );
        let Range::Found { mut records, .. } = history.range(i64::try_from(epoch)?, 1).await?
        else {
            anyhow::bail!("private payment canonical finality record is unavailable");
        };
        ensure!(
            records.len() == 1,
            "private payment historical epoch count differs"
        );
        let record = records.pop().expect("one checked historical record");
        ensure!(
            record.epoch_id == i64::try_from(epoch)?
                && record.state_root == after_head.cursor.state_root.0
                && record.prev_state_root == before_head.cursor.state_root.0,
            "private payment historical finality differs"
        );
        let paid_at = u64::try_from(octra_node_protocol::consensus::policy::time_of_seconds(
            record.epoch_ts,
        )?)?;
        ensure!(
            paid_at <= now
                && self.directory.history.epoch_time_ms(&after_head).await?
                    == Some(i64::try_from(paid_at)?),
            "private payment historical epoch clock differs"
        );
        let paid_pool = self.state(after.snapshot())?;
        ensure!(
            paid_pool.count <= current_pool.count,
            "private pool history regressed"
        );
        lease.with_current(PLAN_MAX_AGE, || Ok(()))?;
        Ok(Execution {
            lease,
            before,
            after,
            record,
            paid_at,
            now,
        })
    }

    async fn epoch(&self, epoch: u64) -> Result<Execution> {
        let execution = self.record(epoch).await?;
        self.state(execution.before.snapshot())?;
        self.state(execution.after.snapshot())?;
        Ok(execution)
    }

    async fn locate(
        &self,
        epoch: u64,
        commitment: [u8; 32],
        membership: &Membership,
    ) -> Result<Placement> {
        self.locate_from(epoch, commitment, membership, None).await
    }
    async fn historical(&self, epoch: u64, proof: Option<&history::Proof>) -> Result<Historical> {
        if epoch > self.directory.history.anchor().epoch.0 {
            return Ok(self.epoch(epoch).await?.into());
        }
        let proof = proof.context("portable evidence missing below retained history floor")?;
        ensure!(proof.epoch() == epoch, "portable payment epoch differs");
        proof.verify(self).await
    }
    async fn locate_from(
        &self,
        epoch: u64,
        commitment: [u8; 32],
        membership: &Membership,
        proof: Option<&history::Proof>,
    ) -> Result<Placement> {
        let Historical {
            lease,
            before,
            after,
            paid_at,
            now,
            ..
        } = self.historical(epoch, proof).await?;
        let current_pool = self.state(lease.committed().state())?;
        let prior_pool = self.state(&before)?;
        let paid_pool = self.state(&after)?;
        ensure!(
            u64::from(membership.index) >= prior_pool.count
                && paid_pool.count <= current_pool.count,
            "private note was not created in the claimed epoch"
        );
        let commitment = pool::decode_field(&commitment)?;
        membership.verify(
            pool::decode_field(&paid_pool.notes)?,
            paid_pool.count,
            commitment,
        )?;

        lease.with_current(PLAN_MAX_AGE, || Ok(()))?;
        Ok(Placement {
            lease,
            before,
            paid_at,
            now,
        })
    }

    /// Native deposits and full withdrawals require the exact successful
    /// exchange with its accepted native value. Rejected calls are
    /// carried separately in receipts_json and are never accepted here.
    async fn confirmed_exchange(
        &self,
        epoch: u64,
        parameters: &serde_json::Value,
        relayer: &[u8; 47],
        deposit_ou: u64,
        expected: Option<&octra_node_protocol::transaction::Transaction>,
    ) -> Result<Historical> {
        self.confirmed_exchange_from(epoch, parameters, relayer, deposit_ou, expected, None)
            .await
    }
    async fn confirmed_exchange_from(
        &self,
        epoch: u64,
        parameters: &serde_json::Value,
        relayer: &[u8; 47],
        deposit_ou: u64,
        expected: Option<&octra_node_protocol::transaction::Transaction>,
        proof: Option<&history::Proof>,
    ) -> Result<Historical> {
        let execution = self.historical(epoch, proof).await?;
        self.check_exchange(&execution.record, parameters, relayer, deposit_ou, expected)?;
        execution.lease.with_current(PLAN_MAX_AGE, || Ok(()))?;
        Ok(execution)
    }

    fn check_exchange(
        &self,
        record: &octra_node_protocol::consensus::CatchupEpochRecord,
        parameters: &serde_json::Value,
        relayer: &[u8; 47],
        deposit_ou: u64,
        expected: Option<&octra_node_protocol::transaction::Transaction>,
    ) -> Result<()> {
        use octra_node_protocol::{
            native_json::Document,
            transaction::{self, OpType, Transaction},
        };
        ensure!(
            i64::try_from(deposit_ou).is_ok(),
            "private native value differs"
        );
        let mut found = false;
        for raw in &record.txs_json {
            let tx = Transaction::from_document(&Document::parse(raw)?)?;
            if tx.from == relayer
                && tx.to == self.address
                && tx.op_type == OpType::CircleCall
                && tx.encrypted_data.as_deref() == Some(b"exchange")
                && tx.amount == deposit_ou.into()
                && expected.is_none_or(|expected| expected == &tx)
                && tx
                    .message
                    .as_deref()
                    .map(serde_json::from_slice::<serde_json::Value>)
                    .transpose()?
                    .as_ref()
                    == Some(parameters)
            {
                let key = tx
                    .public_key
                    .as_deref()
                    .context("private exchange signer missing")?;
                ensure!(
                    transaction::address_from_public_key(key) == tx.from
                        && tx.verify(key)
                        && transaction::normalize_envelope(&tx, Some(key))? == tx,
                    "private exchange signature differs"
                );
                ensure!(!found, "duplicate successful private exchange");
                found = true;
            }
        }
        ensure!(found, "private exchange is not canonically confirmed");
        Ok(())
    }

    /// Verify actual canonical receipt of one signed prepaid purchase. Repeated
    /// reads return the same credit_id; a wallet must durably consume it once.
    pub async fn confirm(&self, input: Inclusion<'_>) -> Result<FundedPurchase> {
        self.confirm_from(input, None).await
    }
    pub async fn confirm_recovered(
        &self,
        input: Inclusion<'_>,
        proof: &history::Proof,
    ) -> Result<FundedPurchase> {
        self.confirm_from(input, Some(proof)).await
    }
    async fn confirm_from(
        &self,
        input: Inclusion<'_>,
        proof: Option<&history::Proof>,
    ) -> Result<FundedPurchase> {
        let Placement {
            lease,
            before,
            paid_at,
            now,
        } = self
            .locate_from(input.epoch, input.commitment, input.membership, proof)
            .await?;
        let committed = lease.committed();

        let q = &input.invoice.invoice;
        let historical = self.directory.offer_fields(
            &self.directory.directory(&before)?,
            q.offer,
            paid_at,
            Some(input.tariff.clone()),
        )?;
        ensure!(
            historical.liquid && historical.provider_available && historical.purchase_open,
            "private purchase operator or rate was unavailable"
        );
        let current = self.directory.offer_fields(
            &self.directory.directory(committed.state())?,
            q.offer,
            now,
            Some(input.tariff.clone()),
        )?;
        let key = historical
            .data
            .receipt_key
            .context("private purchase operator key is missing")?;
        let class = historical
            .data
            .tariff
            .classes()
            .get(usize::from(input.limits.traffic_class))
            .context("private purchase traffic class is missing")?;
        let consent = Consent {
            chain_origin: self.origin,
            directory_circle: native(&self.directory.config.program)?,
            operator_key: key.0,
            bond_generation: historical.data.operator_generation,
            offer: historical.data.offer,
            tariff_hash: hash(&historical.data.manifest_hash)?,
            receipt_key: input.limits.receipt_key,
            settlement: Settlement::ShieldedPool {
                circle: self.address,
                note_owner: pool::encode_field(input.spend_key.owner(self.domain)),
            },
            traffic_class: input.limits.traffic_class,
            rate_ou_per_mib: class.rate_ou_per_mib,
            max_bytes: input.limits.max_bytes,
            max_cost_ou: input.limits.max_cost_ou,
            canonical_ms: paid_at,
            active_from_ms: historical.data.offer_start_ms,
            purchase_deadline_ms: (historical.data.offer_end_ms != 0)
                .then_some(historical.data.offer_end_ms),
        };
        let quote = input.invoice.verify(&consent)?;
        ensure!(
            input.call.quote == quote
                && input.call.valid_from_ms == q.valid_from_ms
                && input.call.expires_ms == q.expires_ms
                && paid_at >= q.valid_from_ms
                && paid_at < q.expires_ms,
            "private purchase call differs from the signed invoice"
        );
        ensure!(
            input.call.deposit_ou == 0 && input.call.withdraw_ou == 0,
            "private purchase must be an internal shielded transfer"
        );
        ensure!(
            native_stealth::view_public(input.view_secret) == q.recipient_view_public()?,
            "private purchase claimant view differs"
        );
        let context = input
            .call
            .context(&self.origin, &self.address, &input.relayer)?;
        let commitment = pool::decode_field(&input.commitment)?;
        let note = envelope::open(
            self.domain,
            input.spend_key.owner(self.domain),
            input.view_secret,
            &input.call.boxes[0],
            &context,
            commitment,
        )?;
        ensure!(
            note.value() == q.amount_ou()?,
            "private purchase note price differs"
        );
        let funding = Funding {
            credit_id: self.credit_id(input.commitment),
            quote,
            commitment: input.commitment,
            receipt_key: q.receipt_key,
            operator_generation: historical.data.operator_generation,
            offer: q.offer,
            traffic_class: q.traffic_class,
            bytes: q.bytes,
            amount_ou: note.value(),
            epoch: input.epoch,
            purchased_ms: paid_at,
            observed_ms: now,
        };
        lease.with_current(PLAN_MAX_AGE, || Ok(()))?;
        Ok(FundedPurchase {
            funding,
            note,
            eligible: current.liquid && current.provider_available && current.quote_started,
            lease,
        })
    }
}

fn native(text: &str) -> Result<[u8; 47]> {
    parse_native_address(text)?;
    Ok(text.as_bytes().try_into()?)
}
fn hash(text: &str) -> Result<[u8; 32]> {
    digest(text)?;
    hex::decode(text)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("private digest size differs"))
}
fn compiled_hash(source: &str) -> Result<String> {
    let compiled = octra_node_runtime::program::build::legacy(source.as_bytes(), true, true)?;
    let bytes = STANDARD.decode(
        compiled["bytecode"]
            .as_str()
            .context("private pool bytecode missing")?,
    )?;
    Ok(hex::encode(Sha256::digest(bytes)))
}
