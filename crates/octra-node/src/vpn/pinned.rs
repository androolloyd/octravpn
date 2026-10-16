//! V5 settlement state over a pinned public Circle or deployed Program.
//! Receipts identify the opening event; committed application state establishes
//! the remaining escrow, eligibility and session lifetime.
use super::{
    async_trait, AnnounceSessionRequest, Committed, FundedSession, ReceiptContext, RelayLifecycle,
    Result, SessionId, Settlement,
};
mod policy;
use anyhow::{bail, ensure, Context};
use base64::{engine::general_purpose::STANDARD, Engine};
use num_bigint::BigInt;
use octra_exex::{native_history::ArchiveProof, Cursor};
use octra_node_protocol::{
    aml::emit::internal_key,
    native_json::{Document, Value},
    transaction::{decode_base64, OpType, Transaction},
};
use octra_node_runtime::{
    account_store,
    canonical::{Head, Reader},
    circle_store,
    program::store,
    state_batch::{Snapshot, StateBatch},
};
use octravpn_core::{
    address::Address,
    control::{announce_opener_binding_payload, announce_signing_payload},
    sig::{verify, PublicKey},
};
use octravpn_node::admission::RelayArmedState;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::Mutex,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Application {
    Circle,
    Program,
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Layout {
    Source,
    Protocol,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub chain: String,
    pub receipt_chain_id: u32,
    pub application: Application,
    pub program: String,
    pub code_hash: String,
    pub operator_circle: String,
    pub layout: Layout,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_tunnel: Option<octravpn_node::embedded::IpTunnelConfig>,
}
pub(crate) struct Claim {
    pub bytes: u64,
    pub net: Option<u64>,
}
impl Config {
    pub fn domain(&self) -> Result<ReceiptContext> {
        ensure!(
            self.receipt_chain_id != 0,
            "VPN receipt chain identifier must be nonzero"
        );
        Ok(ReceiptContext::v2(
            octravpn_core::parse_native_address(&self.program)?,
            self.receipt_chain_id,
            octravpn_core::parse_native_address(&self.operator_circle)?,
        ))
    }
}
pub struct Pinned {
    config: Config,
    history: Reader,
    domain: ReceiptContext,
    receipt_key: Vec<u8>,
    openings: Mutex<OpeningCache>,
    checked_code: Mutex<Option<Cursor>>,
}
#[derive(Clone, PartialEq, Eq)]
struct OpeningBinding {
    session: [u8; 32],
    hash: String,
    opener: Vec<u8>,
    tailnet: u64,
    circle: Vec<u8>,
    deposit: u64,
    opened: u64,
    treasury: bool,
}
struct VerifiedOpening {
    binding: OpeningBinding,
    head: Head,
}
#[derive(Default)]
struct OpeningCache {
    rows: BTreeMap<[u8; 32], VerifiedOpening>,
    order: VecDeque<[u8; 32]>,
}
impl OpeningCache {
    fn get(&self, binding: &OpeningBinding, sequence: u64) -> Option<Head> {
        self.rows
            .get(&binding.session)
            .filter(|saved| saved.head.cursor.sequence.0 <= sequence && saved.binding == *binding)
            .map(|saved| saved.head.clone())
    }
    fn remember(&mut self, binding: OpeningBinding, head: Head) {
        if !self.rows.contains_key(&binding.session) {
            while self.rows.len() >= 4096 {
                if let Some(oldest) = self.order.pop_front() {
                    self.rows.remove(&oldest);
                } else {
                    self.rows.clear();
                }
            }
            self.order.push_back(binding.session);
        }
        self.rows
            .insert(binding.session, VerifiedOpening { binding, head });
    }
}
impl Pinned {
    pub(crate) fn application(&self) -> Application {
        self.config.application
    }
    pub fn new(config: Config, history: Reader, receipt_key: PublicKey) -> Result<Self> {
        ensure!(
            config.chain == history.chain().chain_id,
            "VPN settlement chain differs from canonical history"
        );
        ensure!(
            config.code_hash.len() == 64
                && config
                    .code_hash
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "invalid VPN application code pin"
        );
        let domain = config.domain()?;
        Ok(Self {
            config,
            history,
            domain,
            receipt_key: STANDARD.encode(receipt_key.0).into_bytes(),
            openings: Mutex::new(OpeningCache::default()),
            checked_code: Mutex::new(None),
        })
    }
    pub(crate) fn validate(&self, view: &Committed) -> Result<()> {
        self.check(view, &self.domain)
    }
    pub(crate) fn validate_operator(&self, view: &Committed, operator: &[u8]) -> Result<()> {
        self.check(view, &self.domain)?;
        ensure!(
            self.required(
                view.state(),
                b"circle_owner",
                Some(self.config.operator_circle.as_bytes())
            )? == operator,
            "native claim signer differs from registered operator"
        );
        Ok(())
    }
    pub(crate) fn claim(
        &self,
        view: &Committed,
        session: &SessionId,
        operator: &[u8],
    ) -> Result<Option<Claim>> {
        self.validate_operator(view, operator)?;
        let (key, _) = self.session_identity(view, session)?;
        match self.uint(view.state(), b"operator_claim_set", Some(&key))? {
            0 => return Ok(None),
            1 => (),
            _ => bail!("VPN operator claim flag differs"),
        }
        Ok(Some(Claim {
            bytes: self.uint(view.state(), b"operator_claim_bytes", Some(&key))?,
            net: match self.uint(view.state(), b"operator_claim_net_set", Some(&key))? {
                1 => Some(self.uint(view.state(), b"operator_claim_net", Some(&key))?),
                0 => None,
                _ => bail!("VPN operator claim amount flag differs"),
            },
        }))
    }
    pub(crate) fn claim_op(&self) -> OpType {
        match self.config.application {
            Application::Program => OpType::ContractCall,
            Application::Circle => OpType::CircleCall,
        }
    }
    pub(crate) fn can_claim(&self, view: &Committed, session: &SessionId) -> Result<bool> {
        self.check(view, &self.domain)?;
        let (key, status) = self.session_identity(view, session)?;
        // Admission pause and the traffic lease do not cancel obligations
        // already incurred. The application keeps these claims recoverable.
        Ok(status == 0 && self.active(view.state())? && self.escrow(view, &key)?.is_some())
    }
    fn value(
        &self,
        state: &Snapshot,
        field: &[u8],
        index: Option<&[u8]>,
    ) -> Result<Option<Vec<u8>>> {
        let key = match index {
            None => field.to_vec(),
            Some(index) => match self.config.layout {
                Layout::Protocol => [field, b":", index].concat(),
                Layout::Source => [
                    internal_key(b"map", field),
                    b"/".to_vec(),
                    index.len().to_string().into_bytes(),
                    b"#".to_vec(),
                    index.to_vec(),
                ]
                .concat(),
            },
        };
        match self.config.application {
            Application::Circle => {
                circle_store::inline(state, self.config.program.as_bytes(), &key)
                    .map_err(Into::into)
            }
            Application::Program => Ok(state
                .get(&[
                    b"contracts",
                    self.config.program.as_bytes(),
                    b"storage",
                    &key,
                ])
                .map(<[u8]>::to_vec)),
        }
    }
    fn uint(&self, state: &Snapshot, field: &[u8], index: Option<&[u8]>) -> Result<u64> {
        let Some(value) = self.value(state, field, index)? else {
            return Ok(0);
        };
        let number = std::str::from_utf8(&value)?.parse::<u64>()?;
        ensure!(
            number.to_string().as_bytes() == value,
            "noncanonical VPN numeric state"
        );
        Ok(number)
    }
    fn required(&self, state: &Snapshot, field: &[u8], index: Option<&[u8]>) -> Result<Vec<u8>> {
        self.value(state, field, index)?
            .context("VPN application state missing")
    }
    fn check(&self, view: &Committed, domain: &ReceiptContext) -> Result<()> {
        ensure!(
            domain == &self.domain,
            "VPN receipt deployment domain differs"
        );
        let octra_browser::Provenance::Canonical(identity) = view.provenance() else {
            bail!("VPN settlement requires a canonical snapshot");
        };
        let head = view.head();
        ensure!(
            identity.chain_id == self.history.chain().chain_id
                && identity.origin == self.history.chain().origin
                && identity.epoch == head.cursor.epoch.0
                && identity.state_root == hex::encode(head.cursor.state_root.0)
                && identity.ledger_root == head.ledger_root
                && identity.irmin_commit == head.irmin_commit,
            "VPN settlement snapshot identity differs"
        );
        self.check_code(view)?;
        let state = view.state();
        ensure!(
            self.uint(state, b"protocol_fee_bps", None)? == 0,
            "VPN protocol commission must be zero"
        );
        let circle = Some(self.config.operator_circle.as_bytes());
        ensure!(
            self.required(state, b"circle_receipt_pk", circle)? == self.receipt_key,
            "VPN operator receipt key differs"
        );
        Ok(())
    }
    fn check_code(&self, view: &Committed) -> Result<()> {
        let cursor = view.head().cursor;
        if self
            .checked_code
            .lock()
            .map_err(|_| anyhow::anyhow!("VPN code cache poisoned"))?
            .as_ref()
            == Some(&cursor)
        {
            return Ok(());
        }
        let state = view.state();
        let address = self.config.program.as_bytes();
        let (hash, encoded) = match self.config.application {
            Application::Program => {
                let meta = store::meta(state, address)?.context("VPN application not deployed")?;
                ensure!(
                    meta.address == address,
                    "VPN application metadata address differs"
                );
                (
                    meta.code_hash,
                    store::bytecode(state, address)
                        .context("VPN application bytecode missing")?
                        .to_vec(),
                )
            }
            Application::Circle => {
                let program = circle_store::public_program(state, address)?;
                ensure!(
                    program.runtime == b"octb"
                        && program.privacy_class == b"public"
                        && program.resource_mode == b"public_resources",
                    "VPN Circle must expose public OCTB settlement state"
                );
                (program.code_hash.to_vec(), program.code_b64.to_vec())
            }
        };
        let code = decode_base64(&encoded)?;
        ensure!(
            hash == self.config.code_hash.as_bytes()
                && hex::encode(Sha256::digest(code)) == self.config.code_hash,
            "VPN application code pin differs"
        );
        *self
            .checked_code
            .lock()
            .map_err(|_| anyhow::anyhow!("VPN code cache poisoned"))? = Some(cursor);
        Ok(())
    }
    fn session_identity(&self, view: &Committed, id: &SessionId) -> Result<(Vec<u8>, u64)> {
        let sid = id
            .as_u64()
            .context("VPN application requires integer session identifiers")?;
        ensure!(
            sid < self.uint(view.state(), b"session_count", None)?,
            "VPN session not found"
        );
        let key = sid.to_string().into_bytes();
        ensure!(
            self.required(view.state(), b"session_exit", Some(&key))?
                == self.config.operator_circle.as_bytes(),
            "VPN session operator differs"
        );
        let status = self.uint(view.state(), b"session_status", Some(&key))?;
        Ok((key, status))
    }
    fn expiry(&self, view: &Committed, key: &[u8]) -> Result<u64> {
        let opened = self.uint(view.state(), b"session_opened_at", Some(key))?;
        let grace = self.uint(view.state(), b"session_grace_epochs", None)?;
        ensure!(grace > 0, "VPN session grace is unavailable");
        opened
            .checked_add(grace)
            .context("VPN session expiry overflow")
    }
    fn active(&self, state: &Snapshot) -> Result<bool> {
        let circle = Some(self.config.operator_circle.as_bytes());
        let minimum = self.uint(state, b"min_circle_stake", None)?;
        // V5's constructor and private-admin set_params both enforce this floor.
        Ok(minimum >= 100_000_000
            && self.uint(state, b"circle_slashed", circle)? == 0
            && self.uint(state, b"circle_active", circle)? == 1
            && self.uint(state, b"circle_unbonding", circle)? == 0
            && self.uint(state, b"circle_bond", circle)? >= minimum)
    }
    fn eligible(&self, state: &Snapshot) -> Result<bool> {
        Ok(self.uint(state, b"paused", None)? == 0 && self.active(state)?)
    }
    fn escrow(&self, view: &Committed, key: &[u8]) -> Result<Option<u64>> {
        let minimum = self.uint(view.state(), b"min_session_deposit", None)?;
        ensure!(minimum > 0, "VPN minimum session deposit is unavailable");
        let deposit = self.uint(view.state(), b"session_deposit", Some(key))?;
        // Governance may raise the opening minimum after an existing session
        // was funded. The pinned application keeps that older escrow valid.
        if deposit == 0 {
            return Ok(None);
        }
        let batch = StateBatch::from_snapshot(view.state().clone());
        if account_store::load(&batch, self.config.program.as_bytes())?
            .is_none_or(|account| account.balance < BigInt::from(deposit))
        {
            return Ok(None);
        }
        Ok(Some(deposit))
    }
    async fn opening(
        &self,
        view: &Committed,
        request: &AnnounceSessionRequest,
        key: &[u8],
        opener: &Address,
        deposit: u64,
    ) -> Result<()> {
        ensure!(
            self.history.head_at(view.head().cursor.sequence).await? == *view.head(),
            "VPN opening history differs from the committed snapshot"
        );
        let treasury = match self.uint(view.state(), b"session_treasury_funded", Some(key))? {
            0 => false,
            1 => true,
            _ => bail!("VPN session funding source differs"),
        };
        let binding = OpeningBinding {
            session: *request.session_id.as_bytes(),
            hash: request.open_tx_hash.clone(),
            opener: opener.to_string().into_bytes(),
            tailnet: self.uint(view.state(), b"session_tailnet", Some(key))?,
            circle: self.config.operator_circle.as_bytes().to_vec(),
            deposit,
            opened: self.uint(view.state(), b"session_opened_at", Some(key))?,
            treasury,
        };
        let saved = {
            self.openings
                .lock()
                .map_err(|_| anyhow::anyhow!("VPN opening cache poisoned"))?
                .get(&binding, view.head().cursor.sequence.0)
        };
        if let Some(saved) = saved {
            // Reuse parsed proof work only while its exact containing head is
            // still retained by this reader. A sequence alone cannot identify
            // an ancestor across another store, rollback or fork.
            ensure!(
                self.history.head_at(saved.cursor.sequence).await? == saved,
                "VPN cached opening history differs"
            );
            return Ok(());
        }
        let (head, record) = self
            .history
            .transaction(
                view.head(),
                request.open_tx_hash.as_bytes(),
                16 * 1024 * 1024,
            )
            .await?
            .context("VPN opening transaction is outside retained history")?;
        ensure!(
            record.proof == ArchiveProof::Exact,
            "VPN opening transaction lacks exact call identity"
        );
        let tx = Transaction::from_document(&Document::parse(&record.transaction)?)?;
        ensure!(
            tx.from == binding.opener && tx.to == self.config.program.as_bytes(),
            "VPN opening transaction sender or target differs"
        );
        ensure!(
            match self.config.application {
                Application::Circle => tx.op_type == OpType::CircleCall,
                Application::Program =>
                    matches!(tx.op_type, OpType::ContractCall | OpType::ProgramExec),
            },
            "VPN opening transaction operation differs"
        );
        let method = tx
            .encrypted_data
            .as_deref()
            .context("VPN opening method missing")?;
        ensure!(
            matches!(method, b"open_session" | b"open_session_from_treasury"),
            "VPN opening method differs"
        );
        let params = Document::parse(
            tx.message
                .as_deref()
                .context("VPN opening parameters missing")?,
        )?;
        let Value::List(values) = params.root() else {
            bail!("VPN opening parameters must be a list");
        };
        ensure!(values.len() == 3, "VPN opening parameter count differs");
        let tailnet = binding.tailnet;
        ensure!(
            json_uint(
                params
                    .get(values[0])
                    .context("VPN tailnet parameter missing")?
            )? == tailnet,
            "VPN opening tailnet differs"
        );
        ensure!(
            matches!(params.get(values[1]),Some(Value::String(circle)) if circle==self.config.operator_circle.as_bytes()),
            "VPN opening operator differs"
        );
        let max_pay = json_uint(
            params
                .get(values[2])
                .context("VPN payment parameter missing")?,
        )?;
        ensure!(
            treasury == (method == b"open_session_from_treasury"),
            "VPN session funding source differs"
        );
        ensure!(
            if treasury {
                tx.amount == BigInt::from(0_u8) && max_pay == deposit
            } else {
                tx.amount == BigInt::from(deposit) && max_pay <= deposit
            },
            "VPN opening escrow differs"
        );
        let opened = binding.opened;
        ensure!(head.cursor.epoch.0 == opened, "VPN opening epoch differs");
        let receipt = Document::parse(
            record
                .receipt
                .as_deref()
                .context("VPN opening execution receipt missing")?,
        )?;
        ensure!(
            matches!(
                receipt.field(receipt.root(), b"success"),
                Some(Value::Bool(true))
            ),
            "VPN opening call did not succeed"
        );
        ensure!(
            matches!(receipt.field(receipt.root(),b"contract"),Some(Value::String(address)) if address==self.config.program.as_bytes()),
            "VPN opening receipt target differs"
        );
        ensure!(
            matches!(receipt.field(receipt.root(),b"method"),Some(Value::String(value)) if value==method),
            "VPN opening receipt method differs"
        );
        ensure!(
            matches!(receipt.field(receipt.root(), b"error"), Some(Value::Null)),
            "VPN opening receipt contains an error"
        );
        ensure!(
            json_uint(
                receipt
                    .field(receipt.root(), b"epoch")
                    .context("VPN opening receipt epoch missing")?
            )? == opened,
            "VPN opening receipt epoch differs"
        );
        let Some(Value::List(events)) = receipt.field(receipt.root(), b"events") else {
            bail!("VPN opening events missing");
        };
        let expected = [
            key.to_vec(),
            tailnet.to_string().into_bytes(),
            self.config.operator_circle.as_bytes().to_vec(),
            deposit.to_string().into_bytes(),
            opened.to_string().into_bytes(),
        ];
        let mut found = 0;
        for event in events {
            let event = receipt.get(*event).context("VPN opening event missing")?;
            if !matches!(receipt.field(event,b"event"),Some(Value::String(name)) if name==b"SessionOpened")
            {
                continue;
            }
            if !matches!(receipt.field(event,b"contract"),Some(Value::String(address)) if address==self.config.program.as_bytes())
            {
                continue;
            }
            if !matches!(receipt.field(event,b"depth"),Some(Value::Int(depth)) if depth.get()==0) {
                continue;
            }
            let Some(Value::List(values)) = receipt.field(event, b"values") else {
                continue;
            };
            if values.len()==expected.len() && values.iter().zip(&expected).all(|(value,expected)|matches!(receipt.get(*value),Some(Value::String(value)) if value==expected)) {found+=1;}
        }
        ensure!(found == 1, "VPN session opening event differs");
        self.openings
            .lock()
            .map_err(|_| anyhow::anyhow!("VPN opening cache poisoned"))?
            .remember(binding, head);
        Ok(())
    }
}
fn json_uint(value: &Value) -> Result<u64> {
    match value {
        Value::Int(value) => u64::try_from(value.get()).map_err(Into::into),
        Value::String(raw) | Value::IntLiteral(raw) => Ok(std::str::from_utf8(raw)?.parse()?),
        _ => bail!("VPN integer parameter differs"),
    }
}
#[async_trait]
impl Settlement for Pinned {
    async fn session(
        &self,
        view: &Committed,
        request: &AnnounceSessionRequest,
        domain: &ReceiptContext,
    ) -> Result<Option<FundedSession>> {
        if request.client_wg_pubkey == [0; 32]
            || verify(
                &request.client_pubkey,
                &announce_signing_payload(
                    &request.session_id,
                    &request.client_pubkey,
                    &request.client_wg_pubkey,
                    &request.open_tx_hash,
                ),
                &request.client_sig,
            )
            .is_err()
            || verify(
                &request.opener_pubkey,
                &announce_opener_binding_payload(
                    &request.session_id,
                    &request.client_pubkey,
                    &request.client_wg_pubkey,
                    &request.open_tx_hash,
                ),
                &request.opener_sig,
            )
            .is_err()
        {
            return Ok(None);
        }
        self.check(view, domain)?;
        let (key, status) = self.session_identity(view, &request.session_id)?;
        if status != 0
            || self.uint(view.state(), b"operator_claim_set", Some(&key))? != 0
            || !self.eligible(view.state())?
        {
            return Ok(None);
        }
        let expiry = self.expiry(view, &key)?;
        if view.head().cursor.epoch.0 >= expiry {
            return Ok(None);
        }
        let Some(deposit) = self.escrow(view, &key)? else {
            return Ok(None);
        };
        let opener = Address::try_from_display(std::str::from_utf8(&self.required(
            view.state(),
            b"session_opener",
            Some(&key),
        )?)?)?;
        if opener != Address::from_pubkey(&request.opener_pubkey.0) {
            return Ok(None);
        }
        self.opening(view, request, &key, &opener, deposit).await?;
        Ok(Some(FundedSession {
            domain: domain.clone(),
            session_id: request.session_id.clone(),
            opener,
            client_pubkey: request.client_pubkey,
            client_wg_pubkey: request.client_wg_pubkey,
            open_tx_hash: request.open_tx_hash.clone(),
            current_epoch: view.head().cursor.epoch.0,
            expires_epoch: expiry,
            escrow_ou: deposit,
            open: true,
        }))
    }
    async fn lifecycle(
        &self,
        view: &Committed,
        id: &SessionId,
        domain: &ReceiptContext,
    ) -> Result<RelayLifecycle> {
        self.check(view, domain)?;
        let (key, status) = self.session_identity(view, id)?;
        Ok(match status {
            0 => {
                ensure!(self.eligible(view.state())?, "VPN operator is ineligible");
                ensure!(
                    self.escrow(view, &key)?.is_some(),
                    "VPN session escrow is unavailable"
                );
                ensure!(
                    view.head().cursor.epoch.0 < self.expiry(view, &key)?,
                    "VPN session funding lease expired"
                );
                RelayLifecycle::Open
            }
            3 => {
                let hash = self.required(view.state(), b"session_settlement_hash", Some(&key))?;
                ensure!(
                    hash.len() == 64
                        && hash
                            .iter()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)),
                    "VPN armed receipt hash differs"
                );
                let deadline = self.uint(view.state(), b"session_relay_deadline", Some(&key))?;
                let opened = self.uint(view.state(), b"session_opened_at", Some(&key))?;
                let deposit = self.uint(view.state(), b"session_deposit", Some(&key))?;
                let net = self.uint(view.state(), b"session_relay_net", Some(&key))?;
                ensure!(
                    deadline > opened && net > 0 && net <= deposit,
                    "VPN armed escrow or deadline differs"
                );
                RelayLifecycle::Armed(RelayArmedState {
                    deadline,
                    settlement_hash: String::from_utf8(hash)?,
                })
            }
            1 | 2 | 4 | 5 => RelayLifecycle::Terminal(status),
            _ => bail!("VPN session status differs"),
        })
    }
}
