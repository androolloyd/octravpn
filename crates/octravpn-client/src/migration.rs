//! Offline, evidence-bound migration of legacy wallet-only settlement stores.
mod evidence;
mod files;

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail, Context, Result};
use octravpn_core::{
    address::Address,
    receipt::{ReceiptContext, SignedReceipt},
    receipt_vault::VaultRecord,
    session::SessionId,
    sig::{verify, KeyPair, PublicKey, Signature},
    v3_calls::Application,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    config::ClientConfig,
    settle_state::{SettleStatePaths, SettleStateStore},
    wallet,
};

#[derive(clap::Args, Clone, Debug)]
pub(crate) struct Args {
    /// JSON v1 bundle: sessions[{session_id,opening_transaction,announce}].
    #[arg(long)]
    evidence: Option<PathBuf>,
    /// Print per-record diagnostics without creating or opening any store.
    #[arg(long, conflicts_with = "apply")]
    inspect: bool,
    /// Copy only when every record has authenticated deployment ownership.
    /// Legacy source files are preserved.
    #[arg(long, requires = "evidence", conflicts_with = "inspect")]
    apply: bool,
}

#[derive(Serialize)]
struct Report {
    source: PathBuf,
    destination: PathBuf,
    eligible: bool,
    errors: Vec<String>,
    records: Vec<Diagnostic>,
}

#[derive(Default, Serialize)]
struct Diagnostic {
    session_id: String,
    state: Option<u64>,
    net: Option<u64>,
    receipt_records: usize,
    errors: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordPin {
    session_id: SessionId,
    state: u64,
    net: Option<u64>,
    receipt_hash: String,
    receipt_seq: u64,
    client_pubkey: PublicKey,
    node_pubkey: PublicKey,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestBody {
    version: u32,
    application: Application,
    context: ReceiptContext,
    wallet: Address,
    files: Vec<files::Pin>,
    evidence_hash: String,
    records: Vec<RecordPin>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    body: ManifestBody,
    public_key: PublicKey,
    signature: Signature,
}

pub(crate) fn scope_root(
    root: &Path,
    application: Application,
    context: &ReceiptContext,
) -> PathBuf {
    let mut hash = Sha256::new();
    hash.update(b"octravpn:client-settlement:v2\0");
    hash.update(application.operation().as_bytes());
    hash.update(context.program_addr.as_bytes());
    hash.update(context.chain_id.to_be_bytes());
    hash.update(context.circle_id_canonical_bytes());
    root.join("deployments").join(hex::encode(hash.finalize()))
}

fn context(cfg: &ClientConfig) -> Result<(Address, ReceiptContext)> {
    let wallet = Address::try_from_display(&cfg.wallet.addr).context("migration wallet address")?;
    let program = octravpn_core::parse_native_address(&cfg.chain.program_addr)
        .context("migration settlement address")?;
    let circle = octravpn_core::parse_native_address(&cfg.v3.circle_id)
        .context("migration operator Circle address")?;
    if cfg.chain.chain_id == 0 {
        bail!("migration receipt chain id must be nonzero");
    }
    Ok((
        wallet,
        ReceiptContext::v2(program, cfg.chain.chain_id, circle),
    ))
}

pub(crate) fn run(cfg: &ClientConfig, args: &Args) -> Result<()> {
    let (wallet_address, context) = context(cfg)?;
    let application = cfg.v3.application;
    let root = Path::new(&cfg.v3.relay.state_dir);
    let source_path = SettleStatePaths::for_wallet(root, &wallet_address).wallet_dir;
    let destination =
        SettleStatePaths::for_wallet(scope_root(root, application, &context), &wallet_address)
            .wallet_dir;
    let source = files::Snapshot::read(&source_path)?;
    let mut report = Report {
        source: source_path,
        destination: destination.clone(),
        eligible: false,
        errors: Vec::new(),
        records: Vec::new(),
    };
    let evidence_raw = match &args.evidence {
        Some(path) => files::read_optional(path, 16 * 1024 * 1024)?,
        None => Vec::new(),
    };
    let bundle = if evidence_raw.is_empty() {
        None
    } else {
        match serde_json::from_slice::<evidence::Bundle>(&evidence_raw) {
            Ok(bundle) if bundle.version == 1 => Some(bundle),
            Ok(_) => {
                report
                    .errors
                    .push("unsupported evidence bundle version".to_owned());
                None
            }
            Err(error) => {
                report.errors.push(format!("evidence bundle: {error}"));
                None
            }
        }
    };
    let records = inspect(
        &source,
        bundle.as_ref(),
        application,
        &context,
        &wallet_address,
        &mut report,
    );
    if destination.try_exists()? {
        report.errors.push(
            "destination already exists; refusing to replace, merge or resume a partial/stale copy"
                .to_owned(),
        );
    }
    report.eligible = report.errors.is_empty()
        && !report.records.is_empty()
        && report.records.iter().all(|record| record.errors.is_empty());
    println!("{}", serde_json::to_string_pretty(&report)?);
    if !args.apply {
        return Ok(());
    }
    if !report.eligible {
        bail!("migration refused; resolve the reported evidence gaps using the original deployment or client");
    }
    let key = wallet::load_keypair(
        cfg.v3
            .wallet_key_path
            .as_deref()
            .unwrap_or(&cfg.wallet.secret_path),
    )
    .context("load migration manifest signing wallet")?;
    if Address::from_pubkey(&key.public.0) != wallet_address {
        bail!("migration signing key does not own the configured wallet");
    }
    let body = ManifestBody {
        version: 1,
        application,
        context,
        wallet: wallet_address,
        files: source.pins.clone(),
        evidence_hash: hex::encode(Sha256::digest(&evidence_raw)),
        records,
    };
    let signature = key.sign(&manifest_payload(&body)?);
    let manifest = Manifest {
        body,
        public_key: key.public,
        signature,
    };
    files::install(
        &source,
        &destination,
        &serde_json::to_vec_pretty(&manifest)?,
    )?;
    println!(
        "migration published at {}; legacy files preserved",
        destination.display()
    );
    Ok(())
}

fn inspect(
    source: &files::Snapshot,
    bundle: Option<&evidence::Bundle>,
    application: Application,
    context: &ReceiptContext,
    wallet: &Address,
    report: &mut Report,
) -> Vec<RecordPin> {
    let mut diagnostics = BTreeMap::<SessionId, Diagnostic>::new();
    let state = journal(&source.files[0], files::NAMES[0], &mut report.errors);
    let nets = journal(&source.files[1], files::NAMES[1], &mut report.errors);
    for (id, floor) in &state {
        let record = diagnostic(&mut diagnostics, id);
        record.state = Some(*floor);
        if !(1..=7).contains(floor) {
            record
                .errors
                .push(format!("unknown legacy settlement state {floor}"));
        }
    }
    for (id, floor) in &nets {
        let record = diagnostic(&mut diagnostics, id);
        record.net = floor.checked_sub(1);
        if *floor == 0 {
            record
                .errors
                .push("invalid zero encoded arm-net floor".to_owned());
        }
    }
    let mut bindings = BTreeMap::new();
    let mut duplicate = BTreeSet::new();
    if let Some(bundle) = bundle {
        for binding in &bundle.sessions {
            if bindings
                .insert(binding.session_id.clone(), binding)
                .is_some()
            {
                duplicate.insert(binding.session_id.clone());
            }
        }
    }
    let vault = match octravpn_core::receipt_vault::inspect(&source.files[2]) {
        Ok(records) => records,
        Err(error) => {
            report.errors.push(format!("{}: {error}", files::NAMES[2]));
            Vec::new()
        }
    };
    let mut latest = BTreeMap::<SessionId, SignedReceipt>::new();
    for record in vault {
        match record {
            VaultRecord::Receipt {
                session_id,
                receipt,
            } => {
                let diagnostic = diagnostic(&mut diagnostics, &session_id);
                diagnostic.receipt_records += 1;
                if receipt.receipt.context != *context {
                    diagnostic.errors.push(format!(
                        "receipt sequence {} belongs to another deployment domain",
                        receipt.receipt.seq
                    ));
                }
                if let Some(binding) = bindings.get(&session_id) {
                    if let Err(error) =
                        evidence::authenticate(binding, &receipt, application, context, wallet)
                    {
                        diagnostic.errors.push(format!(
                            "receipt sequence {}: {error:#}",
                            receipt.receipt.seq
                        ));
                    }
                } else if let Err(error) = receipt.verify() {
                    diagnostic.errors.push(format!(
                        "receipt sequence {} signatures: {error}",
                        receipt.receipt.seq
                    ));
                }
                if latest
                    .get(&session_id)
                    .is_none_or(|previous| previous.receipt.seq < receipt.receipt.seq)
                {
                    latest.insert(session_id, receipt);
                }
            }
            VaultRecord::Lifecycle { session_id, .. } => {
                diagnostic(&mut diagnostics, &session_id);
            }
        }
    }
    let mut pins = Vec::new();
    for (id, diagnostic) in &mut diagnostics {
        if diagnostic.state.is_none() {
            diagnostic
                .errors
                .push("session has no settlement-state record".to_owned());
        }
        if diagnostic.receipt_records == 0 {
            diagnostic.errors.push(
                "missing signed receipt; receipt deployment domain is not established".to_owned(),
            );
        }
        if !bindings.contains_key(id) {
            diagnostic.errors.push("missing original signed opening transaction and wallet/client announcement evidence; application kind cannot be inferred".to_owned());
        }
        if duplicate.contains(id) {
            diagnostic
                .errors
                .push("duplicate evidence bindings are ambiguous".to_owned());
        }
        if diagnostic.state.is_some_and(|state| state >= 2) && diagnostic.net.is_none() {
            diagnostic
                .errors
                .push("recoverable settlement state has no arm-net material".to_owned());
        }
        if let Some(receipt) = latest.get(id) {
            match serde_json::to_vec(receipt) {
                Ok(raw) => pins.push(RecordPin {
                    session_id: id.clone(),
                    state: diagnostic.state.unwrap_or(0),
                    net: diagnostic.net,
                    receipt_hash: hex::encode(Sha256::digest(raw)),
                    receipt_seq: receipt.receipt.seq,
                    client_pubkey: receipt.client_pubkey,
                    node_pubkey: receipt.node_pubkey,
                }),
                Err(error) => diagnostic.errors.push(format!("receipt pin: {error}")),
            }
        }
    }
    if diagnostics.is_empty() {
        report
            .errors
            .push("legacy source has no attributable session records".to_owned());
    }
    if diagnostics.len() > 100_000 {
        report
            .errors
            .push("legacy source exceeds the supported session count".to_owned());
    }
    for id in bindings.keys() {
        if !diagnostics.contains_key(id) {
            report.errors.push(format!(
                "evidence session {} has no legacy record",
                id.to_hex()
            ));
        }
    }
    report.records = diagnostics.into_values().collect();
    pins
}

fn diagnostic<'a>(
    records: &'a mut BTreeMap<SessionId, Diagnostic>,
    id: &SessionId,
) -> &'a mut Diagnostic {
    records.entry(id.clone()).or_insert_with(|| Diagnostic {
        session_id: id.to_hex(),
        ..Diagnostic::default()
    })
}

fn journal(raw: &[u8], name: &str, errors: &mut Vec<String>) -> BTreeMap<SessionId, u64> {
    match octravpn_core::receipt_journal::inspect(raw) {
        Ok(entries) => entries,
        Err(error) => {
            errors.push(format!("{name}: {error}"));
            BTreeMap::new()
        }
    }
}

fn manifest_payload(body: &ManifestBody) -> Result<Vec<u8>> {
    let mut payload = b"octravpn:client-settlement-migration:v1\0".to_vec();
    payload.extend_from_slice(&serde_json::to_vec(body)?);
    Ok(payload)
}

/// Legacy files can remain beside a migrated store. Their exact source pins
/// and the destination's original floors are authenticated by the wallet.
pub(crate) fn open_store(
    root: &Path,
    wallet: &Address,
    application: Application,
    context: &ReceiptContext,
    key: &KeyPair,
) -> Result<SettleStateStore> {
    let source = files::Snapshot::read(&SettleStatePaths::for_wallet(root, wallet).wallet_dir)?;
    let scoped = scope_root(root, application, context);
    let destination = SettleStatePaths::for_wallet(&scoped, wallet).wallet_dir;
    let raw = files::read_optional(&destination.join("migration.json"), 16 * 1024 * 1024)?;
    let manifest = if raw.is_empty() {
        if source.has_data() {
            bail!("legacy unscoped settlement records require `settle migrate --inspect --evidence <bundle>` before recovery");
        }
        None
    } else {
        let manifest: Manifest =
            serde_json::from_slice(&raw).context("decode settlement migration manifest")?;
        if manifest.body.version != 1
            || manifest.body.application != application
            || manifest.body.context != *context
            || manifest.body.wallet != *wallet
            || manifest.public_key != key.public
            || Address::from_pubkey(&manifest.public_key.0) != *wallet
        {
            bail!("settlement migration manifest belongs to another deployment or wallet");
        }
        verify(
            &manifest.public_key,
            &manifest_payload(&manifest.body)?,
            &manifest.signature,
        )
        .context("migration manifest signature invalid")?;
        if source.has_data() && source.pins != manifest.body.files {
            bail!("legacy settlement source changed after migration; refusing stale recovery");
        }
        for name in files::NAMES {
            let metadata = std::fs::symlink_metadata(destination.join(name))
                .with_context(|| format!("migrated store is incomplete: {name}"))?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                bail!("migrated store contains an invalid {name}");
            }
        }
        Some(manifest)
    };
    let store = SettleStateStore::open(scoped, wallet)?;
    if let Some(manifest) = manifest {
        for record in manifest.body.records {
            if store
                .state(&record.session_id)?
                .map_or(0, |state| state as u64)
                < record.state
            {
                bail!(
                    "migrated state regressed for session {}",
                    record.session_id.to_hex()
                );
            }
            if record.net.is_some() && store.migration_net(&record.session_id) != record.net {
                bail!(
                    "migrated arm net differs for session {}",
                    record.session_id.to_hex()
                );
            }
            let receipt = store.migration_receipt(&record.session_id).ok_or_else(|| {
                anyhow!(
                    "migrated receipt missing for session {}",
                    record.session_id.to_hex()
                )
            })?;
            let receipt_hash = hex::encode(Sha256::digest(serde_json::to_vec(&receipt)?));
            if receipt.receipt.context != *context
                || receipt.receipt.session_id != record.session_id
                || receipt.client_pubkey != record.client_pubkey
                || receipt.node_pubkey != record.node_pubkey
                || receipt.receipt.seq < record.receipt_seq
                || ((record.state >= 2 || receipt.receipt.seq == record.receipt_seq)
                    && receipt_hash != record.receipt_hash)
            {
                bail!(
                    "migrated receipt differs for session {}",
                    record.session_id.to_hex()
                );
            }
            receipt
                .verify()
                .context("migrated receipt signatures invalid")?;
        }
    }
    Ok(store)
}
