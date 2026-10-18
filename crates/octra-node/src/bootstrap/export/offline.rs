//! Offline snapshot administration over explicit trust and verified source bytes.
//! Native physical stores use the separately pinned original native backend;
//! portable snapshots keep full finalized authority and ledger verification here.
use super::{codec, package, Authority};
use anyhow::{ensure, Context, Result};
use clap::Args;
use octra_node_protocol::{
    consensus::ValidatorSet,
    state_sync::{anchor, checkpoint, head, manifest},
};
use octra_node_runtime::ledger_image::Limits;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug)]
pub enum Action {
    Seal,
    Build,
    SignCheckpoint,
    SignManifest,
    Verify,
    AssembleQuorum,
    AssembleFinalized,
}
impl Action {
    fn name(self) -> &'static str {
        match self {
            Self::Seal => "seal",
            Self::Build => "build",
            Self::SignCheckpoint => "sign-checkpoint",
            Self::SignManifest => "sign-manifest",
            Self::Verify => "verify",
            Self::AssembleQuorum => "assemble",
            Self::AssembleFinalized => "assemble-finalized",
        }
    }
}

// A portable native checkpoint signer reads a stable HEAD, while every physical
// or historical form must retain the actual native chaindata and journal owner.
pub(crate) enum NativeSourceOwner {
    Portable {
        _directory: crate::native_tools::NativeDirectoryOwner,
    },
    Physical {
        _directory: crate::native_tools::NativeDirectoryOwner,
        _journal: octra_node_protocol::consensus::journal::JournalOwner,
    },
}
fn missing_native_marker(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error.into()),
    }
}
pub(crate) fn native_source_owner(
    source: &Path,
    action: Action,
    historical: bool,
) -> Result<NativeSourceOwner> {
    use crate::native_tools::NativeDirectoryOwner;
    use octra_node_protocol::consensus::journal::JournalOwner;
    ensure!(
        missing_native_marker(&source.join("canonical.sqlite"))?,
        "native backend refuses Rust canonical storage"
    );
    let mut physical = false;
    for name in ["chaindata", "irmin_store"] {
        match fs::symlink_metadata(source.join(name)) {
            Ok(metadata) => {
                ensure!(
                    metadata.is_dir() && !metadata.file_type().is_symlink(),
                    "native physical marker is not an unlinked directory"
                );
                physical = true;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
    }
    if matches!(action, Action::SignCheckpoint) && !historical && !physical {
        let directory = NativeDirectoryOwner::acquire(source)?;
        // Missing is exclusively NotFound. Recheck after acquiring the actual
        // source inode so no marker error/symlink can select the portable path.
        for name in ["chaindata", "irmin_store", "canonical.sqlite"] {
            ensure!(
                missing_native_marker(&source.join(name))?,
                "native source classification changed"
            );
        }
        for name in ["HEAD.json", "ledger.dat"] {
            let metadata = fs::symlink_metadata(source.join(name))?;
            ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink(),
                "portable native source input is not a regular file"
            );
        }
        let raw = super::super::read_limited(&source.join("HEAD.json"), head::MAX_BYTES)?;
        // A logical commit identifier is portable metadata, not proof that
        // physical Irmin/chaindata directories exist. Native signing checks
        // the complete matching/stable HEAD after this strict parse.
        head::Head::parse(&raw)?;
        Ok(NativeSourceOwner::Portable {
            _directory: directory,
        })
    } else {
        let directory = NativeDirectoryOwner::acquire(&source.join("chaindata"))?;
        let journal = JournalOwner::open(source)?;
        Ok(NativeSourceOwner::Physical {
            _directory: directory,
            _journal: journal,
        })
    }
}

#[derive(Args)]
pub struct Options {
    /// Independently trusted Rust bootstrap config for portable/canonical sources.
    #[arg(long, allow_hyphen_values = true)]
    pub config: Option<PathBuf>,
    #[arg(long, alias = "directory", allow_hyphen_values = true)]
    pub source: Option<PathBuf>,
    #[arg(long, allow_hyphen_values = true)]
    pub output: Option<PathBuf>,
    #[arg(long, allow_hyphen_values = true)]
    pub draft: Option<PathBuf>,
    #[arg(long, allow_hyphen_values = true)]
    pub certificate: Option<PathBuf>,
    /// Existing native JSON wallet; never generated or copied to output.
    #[arg(long, allow_hyphen_values = true)]
    pub wallet: Option<PathBuf>,
    /// Independently authenticated anchor for canonical signing/export or finalized assembly.
    #[arg(long, allow_hyphen_values = true)]
    pub finality: Option<PathBuf>,
    #[arg(long, default_value_t = 16_777_216, allow_hyphen_values = true, value_parser = native_int_arg)]
    pub chunk_size: i64,
    #[arg(long, default_value_t = 604_800, allow_hyphen_values = true, value_parser = native_int64_arg)]
    pub validity: i64,
    #[arg(long)]
    pub historical: bool,
    #[arg(long, allow_hyphen_values = true)]
    pub chain_id: Option<String>,
    #[arg(long, allow_hyphen_values = true)]
    pub config_hash: Option<String>,
    /// Explicit role entries for the original native physical-store backend.
    #[arg(long, allow_hyphen_values = true)]
    pub validator: Vec<String>,
    #[arg(long, allow_hyphen_values = true)]
    pub exporter: Vec<String>,
    /// Verified native-tool artifact map. Required only for an OCaml physical store.
    #[arg(
        long = "native-tool",
        alias = "native-backend",
        allow_hyphen_values = true
    )]
    pub native_backend: Option<PathBuf>,
    #[arg(long, allow_hyphen_values = true)]
    pub checkpoint_signature: Vec<PathBuf>,
    #[arg(long, allow_hyphen_values = true)]
    pub exporter_signature: Vec<PathBuf>,
}

fn native_int_arg(value: &str) -> std::result::Result<i64, String> {
    octra_node_protocol::native_integer::parse_int63(value.as_bytes())
        .ok_or_else(|| "invalid native machine integer".to_owned())
}
fn native_int64_arg(value: &str) -> std::result::Result<i64, String> {
    octra_node_protocol::native_integer::parse_int64(value.as_bytes())
        .ok_or_else(|| "invalid native int64".to_owned())
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Ready {
    version: String,
    head_epoch: i64,
    state_root: String,
    commit_id: String,
    created_at: f64,
}

struct Source {
    draft: manifest::Draft,
    anchor: anchor::VerifiedAnchor,
    // Pinned descriptors remain live until the command has finished reading.
    files: BTreeMap<Vec<u8>, fs::File>,
}

fn finality(path: &Path) -> Result<Vec<u8>> {
    use octra_node_protocol::consensus::{codec::Wire, Finalize, ValidatorSet};
    #[derive(Deserialize)]
    struct Journal {
        finalize: String,
        validator_set: String,
    }
    let raw = super::super::read_limited(path, manifest::MANIFEST_LIMIT)?;
    let encoded = match serde_json::from_slice::<serde_json::Value>(&raw) {
        Ok(serde_json::Value::String(value)) => value.into_bytes(),
        Ok(serde_json::Value::Object(_)) => {
            let journal: Journal = serde_json::from_slice(&raw)?;
            let finalize = Finalize::decode(&octra_node_protocol::native_base64::decode(
                journal.finalize.as_bytes(),
            )?)?;
            let validator_set = ValidatorSet::decode(&octra_node_protocol::native_base64::decode(
                journal.validator_set.as_bytes(),
            )?)?;
            anchor::Anchor {
                steps: Vec::new(),
                finalize,
                validator_set,
            }
            .encode()?
        }
        Ok(_) => anyhow::bail!("finality input is invalid"),
        Err(_) => std::str::from_utf8(&raw)?.trim().as_bytes().to_vec(),
    };
    anchor::Anchor::decode(&encoded)?;
    Ok(encoded)
}

fn path<'a>(value: Option<&'a Path>, flag: &str) -> Result<&'a Path> {
    value.with_context(|| format!("--{flag} is required"))
}
fn signature_json(signature: &checkpoint::Signature) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec_pretty(&json!({
        "signer":std::str::from_utf8(&signature.signer)?,
        "signature":std::str::from_utf8(&signature.signature)?
    }))?)
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = fs::canonicalize(
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )?;
    let destination = parent.join(path.file_name().context("output filename missing")?);
    ensure!(
        fs::symlink_metadata(&destination).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "output already exists or is inaccessible"
    );
    let mut stage = tempfile::NamedTempFile::new_in(&parent)?;
    stage.write_all(bytes)?;
    stage.write_all(b"\n")?;
    stage.as_file().sync_all()?;
    stage.persist_noclobber(destination)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}
fn network(authority: &Authority, body: &checkpoint::Body) -> Result<()> {
    ensure!(
        body.chain_id == authority.network().identity.chain_id.as_bytes()
            && body.config_hash == authority.network().config_hash.as_bytes()
            && body.epoch >= authority.network().minimum_epoch,
        "checkpoint differs from configured network authority"
    );
    Ok(())
}
fn fresh(body: &checkpoint::Body, now: i64) -> Result<()> {
    ensure!(
        now.saturating_add(300) >= body.created_at && now <= body.valid_until,
        "checkpoint is outside its validity window"
    );
    Ok(())
}
fn ready(root: &Path, checkpoint: &checkpoint::Body) -> Result<()> {
    let raw = package::read(root, ".ready.json", 16_384)?;
    let head_raw = package::read(root, "HEAD.json", head::MAX_BYTES)?;
    let head = head::Head::parse(&head_raw)?;
    ensure!(
        head.matches_checkpoint(checkpoint),
        "snapshot ready HEAD differs from checkpoint"
    );
    // The automatic archive publishes a second closed format: the exact
    // schema3 HEAD bytes. Source/Anchor/files have already been authenticated
    // before readiness is checked. Do not rewrite the immutable archive marker.
    if raw == head_raw {
        ensure!(
            head.schema_version == 3,
            "unsupported archive ready HEAD schema"
        );
        return Ok(());
    }
    // The standalone native SDK marker retains its original strict five-field
    // format. A different/malformed HEAD marker cannot fall back by field alias.
    let marker: Ready = serde_json::from_slice(&raw)?;
    ensure!(
        marker.version == "octra-state-sync-snapshot-ready"
            && marker.head_epoch == checkpoint.epoch
            && marker.state_root.as_bytes() == checkpoint.state_root
            && marker.commit_id.as_bytes() == head.commit_id
            && marker.created_at.is_finite()
            && marker.created_at >= 0.,
        "snapshot ready marker differs from checkpoint/HEAD"
    );
    Ok(())
}
fn listed(root: &Path) -> Result<BTreeSet<Vec<u8>>> {
    fn walk(root: &Path, relative: &Path, paths: &mut BTreeSet<Vec<u8>>) -> Result<()> {
        for entry in fs::read_dir(root.join(relative))? {
            let entry = entry?;
            let child = relative.join(entry.file_name());
            let text = child.to_str().context("snapshot path is not UTF-8")?;
            ensure!(
                child.components().count() <= 16 && text.len() <= 4096,
                "snapshot path exceeds portable limits"
            );
            // The portable scope is closed; unrelated config/keys/control files
            // are not inputs. Symlinks in an included subtree are always refused.
            let relevant = manifest::reference_file(text.as_bytes())
                || text == "pvac"
                || text.starts_with("pvac/");
            if !relevant {
                continue;
            }
            let meta = fs::symlink_metadata(entry.path())?;
            ensure!(!meta.file_type().is_symlink(), "snapshot path is a symlink");
            if meta.is_dir() {
                walk(root, &child, paths)?;
            } else {
                ensure!(meta.is_file(), "snapshot path is not a regular file");
                ensure!(
                    paths.len() < manifest::FILE_LIMIT,
                    "snapshot file count exceeds limit"
                );
                paths.insert(text.as_bytes().to_vec());
            }
        }
        Ok(())
    }
    let mut paths = BTreeSet::new();
    walk(root, Path::new(""), &mut paths)?;
    Ok(paths)
}
fn source(
    authority: &Authority,
    root: &Path,
    draft: manifest::Draft,
    limits: Limits,
    require_ready: bool,
) -> Result<Source> {
    network(authority, &draft.checkpoint)?;
    let finality = package::read(root, "snapshot.finality", manifest::MANIFEST_LIMIT)?;
    let anchor = anchor::verify(authority.trust().validators, &draft.checkpoint, &finality)?;
    ensure!(
        listed(root)?
            == draft
                .manifest
                .files
                .iter()
                .map(|f| f.path.clone())
                .collect(),
        "snapshot file set differs from manifest"
    );
    let files = package::verify_files(authority, root, &draft, &anchor, limits)?;
    if require_ready {
        ready(root, &draft.checkpoint)?;
    }
    Ok(Source {
        draft,
        anchor,
        files,
    })
}
fn draft(root: &Path, explicit: Option<&Path>) -> Result<manifest::Draft> {
    let raw = if let Some(path) = explicit {
        super::super::read_limited(path, manifest::MANIFEST_LIMIT)?
    } else {
        package::read(root, "snapshot.draft.json", manifest::MANIFEST_LIMIT)?
    };
    codec::parse_draft(&raw)
}
fn seal(root: &Path, verified: &Source) -> Result<()> {
    let head = head::Head::parse(&package::read(root, "HEAD.json", head::MAX_BYTES)?)?;
    ensure!(
        head.matches_checkpoint(&verified.draft.checkpoint),
        "snapshot HEAD changed before sealing"
    );
    let marker = Ready {
        version: "octra-state-sync-snapshot-ready".into(),
        head_epoch: head.epoch_id,
        state_root: String::from_utf8(head.state_root)?,
        commit_id: String::from_utf8(head.commit_id)?,
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs_f64(),
    };
    if root.join(".ready.json").try_exists()? {
        return ready(root, &verified.draft.checkpoint);
    }
    write_new(
        &root.join(".ready.json"),
        &serde_json::to_vec_pretty(&marker)?,
    )
}
// Finalized checkpoints bind the raw consensus set. The original standalone
// native legacy-quorum CLI instead binds its encoded role-entry set; that
// distinct legacy form is handled by detached assembly or the native backend.
fn finalized_signer_hash(signers: &ValidatorSet) -> Result<Vec<u8>> {
    let raw = anchor::raw_validator_set(signers)?;
    Ok(
        hex::encode(octra_node_protocol::consensus::hash::validator_set_hash(
            &raw,
        )?)
        .into_bytes(),
    )
}

fn active_signers(verified: &Source) -> Result<ValidatorSet> {
    Ok(anchor::encoded_validator_set(
        &verified.anchor.anchor().validator_set,
    )?)
}

// Match the real host writer and consensus-journal leases. These are not
// advisory lookalike lock paths and must outlive every stopped-store read.
fn canonical_owner(
    root: &Path,
) -> Result<(
    fs::File,
    octra_node_protocol::consensus::journal::JournalOwner,
)> {
    ensure!(
        !root.join("irmin_store").try_exists()? && !root.join("chaindata").try_exists()?,
        "canonical source contains native storage"
    );
    ensure!(
        fs::symlink_metadata(root.join("canonical.sqlite"))?
            .file_type()
            .is_file(),
        "canonical database is missing or linked"
    );
    Ok((
        crate::single::writer_lock(&root.join("canonical.sqlite"))?,
        octra_node_protocol::consensus::journal::JournalOwner::open(root)?,
    ))
}
async fn retained_finality(
    store: &octra_node_runtime::canonical::OfflineStore,
    authority: &Authority,
    epoch: u64,
) -> Result<octra_node_protocol::consensus::Finalize> {
    use octra_node_protocol::consensus::{codec::Wire, Finalize};
    let floor = store.anchor().cursor.epoch.0;
    if epoch > floor {
        let sequence = store
            .sequence_for_epoch(epoch)
            .await?
            .context("epoch is not retained")?;
        let head = store.retained_head(sequence).await?;
        ensure!(
            store.reader().record_lengths(&head).await?.certificate <= 4_000_000,
            "retained finality exceeds native limit"
        );
        let finality = Finalize::decode(&store.certificate(sequence).await?)?;
        ensure!(
            finality.epoch_id == i64::try_from(epoch)?
                && finality.header.epoch_id == i64::try_from(epoch)?
                && finality.chain_id == authority.network().identity.chain_id.as_bytes()
                && finality.header.chain_id == finality.chain_id
                && finality.header.proposed_state_root == head.cursor.state_root.0
                && finality.header.txid_hi == head.txid_hi,
            "retained finality/head differs"
        );
        return Ok(finality);
    }
    let raw = store
        .checkpoint_certificate()
        .await?
        .context("genesis has no finalized certificate; no finality is synthesized")?;
    let certificate = authority.trust().verify_persisted(&raw)?;
    let finalized = certificate.anchor().context("floor finality missing")?;
    ensure!(
        certificate.draft().checkpoint.epoch == i64::try_from(floor)?
            && certificate.draft().checkpoint.state_root
                == hex::encode(store.anchor().cursor.state_root.0).as_bytes()
            && certificate.draft().checkpoint.ledger_state_root
                == store.anchor().ledger_root.as_bytes()
            && certificate.draft().checkpoint.txid_hi == store.anchor().txid_hi
            && certificate.draft().checkpoint.epoch_index_hash.as_deref()
                == store.anchor().index_hash.as_deref().map(str::as_bytes)
            && certificate.draft().checkpoint.epoch_index_root.as_deref()
                == Some(store.anchor().index_root.as_bytes()),
        "stored floor certificate differs from canonical anchor"
    );
    if epoch == floor {
        return Ok(finalized.anchor().finalize.clone());
    }
    let window = store
        .checkpoint_window()
        .await?
        .context("retained root window missing")?;
    octra_node_protocol::state_sync::roots::verify_snapshot(finalized, &window)?;
    octra_node_protocol::state_sync::roots::decode(&window)?
        .into_iter()
        .find(|value| value.epoch_id == epoch as i64)
        .context("required root is outside authenticated retained window")
}

impl Options {
    pub async fn run(self, action: Action) -> Result<()> {
        if self.native_backend.is_some() {
            return self.native(action).await;
        }
        ensure!(
            self.exporter.is_empty(),
            "portable exporter authority comes from --config"
        );
        ensure!(
            self.validator.is_empty() || matches!(action, Action::SignCheckpoint),
            "portable --validator selects only a checkpoint signing role, never network trust"
        );
        let config = super::super::read(path(self.config.as_deref(), "config")?)?;
        let limits = Limits {
            bytes: config.max_bytes,
            records: config.max_records,
            string_bytes: config.max_string_bytes,
        };
        let authority = Authority::new(config.network)?;
        if let Some(chain) = &self.chain_id {
            ensure!(
                chain == &authority.network().identity.chain_id,
                "chain id differs from configured authority"
            );
        }
        if let Some(hash) = &self.config_hash {
            ensure!(
                hash == &authority.network().config_hash,
                "config hash differs from configured authority"
            );
        }
        if matches!(action, Action::Seal)
            && self
                .source
                .as_ref()
                .is_some_and(|p| p.join("canonical.sqlite").is_file())
        {
            return self.canonical_seal(authority, limits).await;
        }
        if matches!(action, Action::SignCheckpoint)
            && self
                .source
                .as_ref()
                .is_some_and(|p| p.join("canonical.sqlite").is_file())
        {
            return self.canonical_checkpoint(authority).await;
        }
        tokio::task::spawn_blocking(move || self.portable(action, &authority, limits)).await?
    }

    async fn canonical_seal(self, authority: Authority, limits: Limits) -> Result<()> {
        use octra_node_protocol::{
            consensus::{codec::Wire, hash},
            state_sync::roots,
        };
        ensure!(
            (manifest::CHUNK_MIN..=manifest::CHUNK_MAX).contains(&self.chunk_size),
            "invalid snapshot chunk size"
        );
        ensure!(
            (1..=2_678_400).contains(&self.validity),
            "invalid snapshot validity"
        );
        let directory = fs::canonicalize(path(self.source.as_deref(), "source")?)?;
        let owner = canonical_owner(&directory)?;
        let store =
            octra_node_runtime::canonical::OfflineStore::open(&directory.join("canonical.sqlite"))
                .await?;
        let captured = async {
            ensure!(
                store.chain() == &authority.network().identity,
                "canonical chain identity differs"
            );
            let encoded = finality(path(self.finality.as_deref(), "finality")?)?;
            let finalized = anchor::Anchor::decode(&encoded)?;
            let active = finalized.derive(authority.trust().validators)?;
            let head = store.head().clone();
            let epoch = head.cursor.epoch.0;
            ensure!(
                finalized.finalize.encode()?
                    == retained_finality(&store, &authority, epoch)
                        .await?
                        .encode()?,
                "supplied finality differs from current canonical head"
            );
            let now = super::super::now()?;
            let checkpoint = checkpoint::Body {
                chain_id: authority.network().identity.chain_id.as_bytes().to_vec(),
                epoch: i64::try_from(epoch)?,
                state_root: hex::encode(head.cursor.state_root.0).into_bytes(),
                ledger_state_root: head.ledger_root.as_bytes().to_vec(),
                txid_hi: head.txid_hi,
                config_hash: authority.network().config_hash.as_bytes().to_vec(),
                validator_set_hash: hex::encode(hash::validator_set_hash(&active)?).into_bytes(),
                quorum_cert_hash: Some(anchor::finalize_hash(&finalized.finalize)?),
                epoch_index_hash: Some(
                    head.index_hash
                        .as_ref()
                        .context("canonical index hash missing")?
                        .as_bytes()
                        .to_vec(),
                ),
                epoch_index_root: Some(head.index_root.as_bytes().to_vec()),
                created_at: now,
                valid_until: now
                    .checked_add(self.validity)
                    .context("snapshot expiry overflow")?,
            };
            network(&authority, &checkpoint)?;
            let verified = anchor::verify(authority.trust().validators, &checkpoint, &encoded)?;
            let mut prior = Vec::with_capacity(roots::WIDTH);
            for offset in 1..=epoch.min(roots::WIDTH as u64) {
                prior.push(retained_finality(&store, &authority, epoch - offset).await?);
            }
            let window = roots::encode(&prior)?;
            roots::verify_snapshot(&verified, &window)?;
            let state = store.snapshot_at(&head).await?;
            let migration = if authority.network().migration_root.is_some() {
                let raw = package::read(
                    &directory,
                    "pvac/migration_state.json",
                    octra_node_protocol::state_sync::migration::MAX_BYTES,
                )?;
                package::verify_migration(&raw, authority.network(), checkpoint.epoch)?;
                Some(raw)
            } else {
                None
            };
            Ok::<_, anyhow::Error>(package::Capture {
                head,
                checkpoint,
                finality: encoded,
                window,
                state,
                migration,
            })
        }
        .await;
        store.close().await;
        let captured = captured?;
        let output = path(self.output.as_deref(), "output")?.to_path_buf();
        let parent = fs::canonicalize(
            output
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )?;
        ensure!(
            !parent
                .join(output.file_name().context("output filename missing")?)
                .starts_with(&directory),
            "snapshot output must be outside its canonical source"
        );
        // The blocking file-copy worker owns the exact store leases even if its
        // async caller is cancelled, until all source descriptors are closed.
        tokio::task::spawn_blocking(move || {
            let _owner = owner;
            let report = package::publish_capture(
                &directory,
                &output,
                captured,
                u64::try_from(self.chunk_size)?,
                limits,
            )?;
            let verified = source(&authority, &output, draft(&output, None)?, limits, false)?;
            seal(&output, &verified)?;
            println!("{}", serde_json::to_string(&report)?);
            Ok(())
        })
        .await?
    }

    fn portable(self, action: Action, authority: &Authority, limits: Limits) -> Result<()> {
        if matches!(action, Action::Verify) {
            return self.verify(authority, limits);
        }
        if matches!(action, Action::AssembleQuorum | Action::AssembleFinalized) {
            return self.assemble(action, authority, limits);
        }
        let root = fs::canonicalize(path(self.source.as_deref(), "source")?)?;
        ensure!(
            !root.join("irmin_store").exists() && !root.join("chaindata").exists(),
            "native physical store requires an explicit pinned --native-backend"
        );
        let require_ready = !matches!(action, Action::Seal | Action::SignCheckpoint);
        let verified = source(
            authority,
            &root,
            draft(&root, self.draft.as_deref())?,
            limits,
            require_ready,
        )?;
        let now = super::super::now()?;
        match action {
            Action::Seal => {
                ensure!(self.output.is_none(), "portable seal marks its supplied immutable snapshot; canonical export uses --output");
                seal(&root, &verified)?;
            }
            Action::Build => {
                ensure!(
                    (1..=2_678_400).contains(&self.validity),
                    "validity must be in 1..2678400 seconds"
                );
                ensure!(
                    (manifest::CHUNK_MIN..=manifest::CHUNK_MAX).contains(&self.chunk_size),
                    "invalid chunk size"
                );
                let mut checkpoint = verified.draft.checkpoint.clone();
                checkpoint.created_at = now;
                checkpoint.valid_until = now
                    .checked_add(self.validity)
                    .context("snapshot validity overflow")?;
                let hash = hex::encode(checkpoint.hash()?).into_bytes();
                let files = verified
                    .draft
                    .manifest
                    .files
                    .iter()
                    .map(|file| {
                        package::file_manifest(
                            &root,
                            std::str::from_utf8(&file.path)?,
                            u64::try_from(self.chunk_size)?,
                        )
                    })
                    .collect::<Result<Vec<_>>>()?;
                let total = files.iter().try_fold(0i64, |n, f| {
                    n.checked_add(f.size)
                        .context("snapshot total size overflow")
                })?;
                let body = manifest::Body {
                    checkpoint_hash: hash.clone(),
                    snapshot_id: hash.clone(),
                    irmin_commit: verified.draft.manifest.irmin_commit.clone(),
                    chunk_size: self.chunk_size,
                    total_size: total,
                    file_count: i64::try_from(files.len())?,
                    chunk_count: i64::try_from(
                        files.iter().map(|f| f.chunks.len()).sum::<usize>(),
                    )?,
                    chunks_root: hex::encode(manifest::chunks_root(&files)?).into_bytes(),
                    files,
                };
                let draft = manifest::Draft {
                    checkpoint,
                    checkpoint_hash: hash,
                    manifest_hash: hex::encode(body.hash()?).into_bytes(),
                    manifest: body,
                };
                // Recheck complete contents under the new commitments before publishing.
                let _current = source(authority, &root, draft.clone(), limits, true)?;
                write_new(
                    path(self.output.as_deref(), "output")?,
                    &codec::draft(&draft)?,
                )?;
            }
            Action::SignCheckpoint => {
                fresh(&verified.draft.checkpoint, now)?;
                let active = active_signers(&verified)?;
                let signers = self.signers(authority, Some(&active))?;
                ensure!(
                    finalized_signer_hash(&signers)?
                        == verified.draft.checkpoint.validator_set_hash,
                    "checkpoint validator set hash mismatch"
                );
                let signature = crate::validator_cli::transaction::sign_message(
                    path(self.wallet.as_deref(), "wallet")?,
                    &signers,
                    &verified.draft.checkpoint.hash()?,
                )?;
                write_new(
                    path(self.output.as_deref(), "output")?,
                    &signature_json(&signature)?,
                )?;
            }
            Action::SignManifest => {
                let signature = crate::validator_cli::transaction::sign_message(
                    path(self.wallet.as_deref(), "wallet")?,
                    authority.trust().exporters,
                    &verified.draft.manifest.hash()?,
                )?;
                write_new(
                    path(self.output.as_deref(), "output")?,
                    &signature_json(&signature)?,
                )?;
            }
            Action::Verify | Action::AssembleQuorum | Action::AssembleFinalized => {
                unreachable!("handled above")
            }
        }
        // Retaining these descriptors through the operation is deliberate.
        drop(verified.files);
        println!(
            "{}",
            serde_json::to_string(&json!({"event":action.name(),
            "epoch":verified.draft.checkpoint.epoch,"checkpoint":std::str::from_utf8(&verified.draft.checkpoint_hash)?,
            "manifest":std::str::from_utf8(&verified.draft.manifest_hash)?,"backend":"rust-portable"}))?
        );
        Ok(())
    }

    fn verify(&self, authority: &Authority, limits: Limits) -> Result<()> {
        let raw = super::super::read_limited(
            path(self.certificate.as_deref(), "certificate")?,
            manifest::MANIFEST_LIMIT,
        )?;
        let certificate = manifest::Certificate::parse(&raw)?;
        let verified =
            certificate.verify(authority.trust().validators, authority.trust().exporters)?;
        network(authority, &verified.draft().checkpoint)?;
        fresh(&verified.draft().checkpoint, super::super::now()?)?;
        if let Some(root) = &self.source {
            let _source = source(authority, root, verified.draft().clone(), limits, true)?;
        }
        println!(
            "{}",
            serde_json::to_string(&json!({"event":"certificate_verified",
            "checkpoint":std::str::from_utf8(&verified.draft().checkpoint_hash)?,
            "manifest":std::str::from_utf8(&verified.draft().manifest_hash)?,
            "epoch":verified.draft().checkpoint.epoch,"source_verified":self.source.is_some()}))?
        );
        Ok(())
    }

    async fn canonical_checkpoint(self, authority: Authority) -> Result<()> {
        use octra_node_protocol::consensus::codec::Wire;
        let raw = super::super::read_limited(
            path(self.draft.as_deref(), "draft")?,
            manifest::MANIFEST_LIMIT,
        )?;
        let draft = codec::parse_draft(&raw)?;
        network(&authority, &draft.checkpoint)?;
        fresh(&draft.checkpoint, super::super::now()?)?;
        // A locally consistent database is not a signing authority. Verify the
        // supplied finalized anchor independently against configured trust and
        // the exact checkpoint body, including every validator transition.
        let encoded = finality(path(self.finality.as_deref(), "finality")?)?;
        let verified_anchor =
            anchor::verify(authority.trust().validators, &draft.checkpoint, &encoded)?;
        let active = anchor::encoded_validator_set(&verified_anchor.anchor().validator_set)?;
        if !self.validator.is_empty() {
            let selected = self.signers(&authority, None)?;
            ensure!(
                selected.validators == active.validators,
                "selected signer roles differ from authenticated active validators"
            );
        }
        let directory = fs::canonicalize(path(self.source.as_deref(), "source")?)?;
        let _owner = canonical_owner(&directory)?;
        let store =
            octra_node_runtime::canonical::OfflineStore::open(&directory.join("canonical.sqlite"))
                .await?;
        let result = async {
            ensure!(store.chain() == &authority.network().identity, "canonical chain identity differs");
            let current = store.head().clone();
            let epoch = u64::try_from(draft.checkpoint.epoch)?;
            ensure!(epoch <= current.cursor.epoch.0 && current.cursor.epoch.0 - epoch <= 500_000,
                    "historical checkpoint is ahead or outside verification range");
            ensure!(self.historical || epoch == current.cursor.epoch.0,
                    "checkpoint differs from current head; historical verification requires --historical");
            let sequence = store.sequence_for_epoch(epoch).await?.context("historical epoch is not retained")?;
            let head = store.retained_head(sequence).await?;
            let finality = retained_finality(&store, &authority, epoch).await?;
            ensure!(finality.encode()? == verified_anchor.anchor().finalize.encode()?,
                "supplied finalized anchor differs from retained canonical certificate");
            ensure!(hex::encode(head.cursor.state_root.0).as_bytes() == draft.checkpoint.state_root
                    && head.ledger_root.as_bytes() == draft.checkpoint.ledger_state_root
                    && head.txid_hi == draft.checkpoint.txid_hi
                    && head.index_root.as_bytes() == draft.checkpoint.epoch_index_root.as_deref().context("checkpoint index root missing")?
                    && head.index_hash.as_deref().map(str::as_bytes) == draft.checkpoint.epoch_index_hash.as_deref(),
                    "historical canonical checkpoint differs");
            if let Some(hash) = &draft.checkpoint.quorum_cert_hash {
                ensure!(anchor::finalize_hash(&finality)? == *hash, "historical quorum certificate differs");
            }
            let signers = &active;
            ensure!(finalized_signer_hash(signers)? == draft.checkpoint.validator_set_hash,
                    "checkpoint validator set hash mismatch");
            ensure!(self.historical || store.retained_head(current.cursor.sequence).await? == current,
                    "canonical head changed before checkpoint signing");
            let signature = crate::validator_cli::transaction::sign_message(
                path(self.wallet.as_deref(), "wallet")?, signers,
                &draft.checkpoint.hash()?)?;
            write_new(path(self.output.as_deref(), "output")?, &signature_json(&signature)?)
        }.await;
        store.close().await;
        result
    }

    fn assemble(&self, action: Action, authority: &Authority, limits: Limits) -> Result<()> {
        let raw = super::super::read_limited(
            path(self.draft.as_deref(), "draft")?,
            manifest::MANIFEST_LIMIT,
        )?;
        let draft = codec::parse_draft(&raw)?;
        network(authority, &draft.checkpoint)?;
        let _source = self
            .source
            .as_ref()
            .map(|root| source(authority, root, draft.clone(), limits, true))
            .transpose()?;
        let load = |paths: &[PathBuf]| -> Result<Vec<checkpoint::Signature>> {
            ensure!(paths.len() <= 1024, "too many signature inputs");
            let mut signatures = Vec::new();
            for path in paths {
                signatures.extend(codec::signatures(&super::super::read_limited(
                    path, 16_384,
                )?)?);
                ensure!(signatures.len() <= 1024, "too many signatures");
            }
            signatures.sort_by(|left, right| left.signer.cmp(&right.signer));
            Ok(signatures)
        };
        let exporters = load(&self.exporter_signature)?;
        let raw = if matches!(action, Action::AssembleQuorum) {
            ensure!(
                exporters.len() == 1,
                "checkpoint certificate requires one exporter signature"
            );
            codec::quorum_certificate(&draft, &load(&self.checkpoint_signature)?, &exporters[0])?
        } else {
            ensure!(
                self.checkpoint_signature.is_empty(),
                "finalized assembly takes finality, not checkpoint signatures"
            );
            let encoded = finality(path(self.finality.as_deref(), "finality")?)?;
            codec::certificate(&draft, &encoded, &exporters)?
        };
        let certificate = manifest::Certificate::parse(&raw)?
            .verify(authority.trust().validators, authority.trust().exporters)?;
        network(authority, &certificate.draft().checkpoint)?;
        write_new(path(self.output.as_deref(), "output")?, &raw)?;
        println!(
            "{}",
            serde_json::to_string(&json!({"event":"certificate_assembled",
            "checkpoint":std::str::from_utf8(&draft.checkpoint_hash)?,
            "manifest":std::str::from_utf8(&draft.manifest_hash)?,
            "finalized":matches!(action, Action::AssembleFinalized)}))?
        );
        Ok(())
    }

    fn signers(
        &self,
        authority: &Authority,
        active: Option<&ValidatorSet>,
    ) -> Result<ValidatorSet> {
        if self.validator.is_empty() {
            return Ok(active.unwrap_or(authority.trust().validators).clone());
        }
        Ok(manifest::signer_set(
            &self
                .validator
                .iter()
                .map(|v| v.as_bytes().to_vec())
                .collect::<Vec<_>>(),
        )?)
    }

    async fn native(self, action: Action) -> Result<()> {
        use crate::native_tools::{
            Bounds, NativeBackend, NativeBackendOptions, NativeDirectoryOwner, NativeTool, Policy,
        };
        use std::ffi::OsString;
        ensure!(
            self.config.is_none(),
            "native physical mode takes native chain/config/signer flags, not portable config"
        );
        ensure!(
            self.finality.is_none() || matches!(action, Action::AssembleFinalized),
            "--finality applies to finalized assembly in native mode"
        );
        let options =
            NativeBackendOptions::read(path(self.native_backend.as_deref(), "native-tool")?)?;
        let backend = NativeBackend::verified(NativeTool::StateSyncManifest, &options)?;
        let mut args = vec![OsString::from("--command"), OsString::from(action.name())];
        let mut field = |name: &str, value: &std::ffi::OsStr| {
            args.push(OsString::from(name));
            args.push(value.to_os_string());
        };
        if let Some(source) = &self.source {
            field("--source", source.as_os_str());
        }
        if let Some(value) = &self.output {
            ensure!(
                fs::symlink_metadata(value)
                    .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
                "native output already exists or is inaccessible"
            );
            if let Some(source) = &self.source {
                let parent = value
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or(Path::new("."));
                let destination = fs::canonicalize(parent)?
                    .join(value.file_name().context("output filename missing")?);
                ensure!(
                    !destination.starts_with(fs::canonicalize(source)?),
                    "native output must be outside its input store/snapshot"
                );
            }
            field("--output", value.as_os_str());
        }
        for (name, value) in [
            ("--draft", self.draft.as_deref()),
            ("--certificate", self.certificate.as_deref()),
            ("--wallet", self.wallet.as_deref()),
            ("--finality", self.finality.as_deref()),
        ] {
            if let Some(value) = value {
                field(name, value.as_os_str());
            }
        }
        for (name, value) in [
            ("--chain-id", self.chain_id.as_deref()),
            ("--config-hash", self.config_hash.as_deref()),
        ] {
            if let Some(value) = value {
                field(name, value.as_ref());
            }
        }
        for value in &self.validator {
            field("--validator", value.as_ref());
        }
        for value in &self.exporter {
            field("--exporter", value.as_ref());
        }
        if matches!(action, Action::Build | Action::Seal) {
            field("--validity", self.validity.to_string().as_ref());
        }
        if matches!(action, Action::Build) {
            field("--chunk-size", self.chunk_size.to_string().as_ref());
        }
        for value in &self.checkpoint_signature {
            field("--checkpoint-signature", value.as_os_str());
        }
        for value in &self.exporter_signature {
            field("--exporter-signature", value.as_os_str());
        }
        if self.historical {
            args.push(OsString::from("--historical"));
        }
        let bounds = Bounds {
            timeout: std::time::Duration::from_secs(3600),
            ..Bounds::default()
        };
        let output = if matches!(action, Action::Verify) {
            backend.run(args, Policy::ReadOnly, (), bounds).await?
        } else if matches!(action, Action::AssembleQuorum | Action::AssembleFinalized)
            && self.source.is_none()
        {
            // Detached native assembly mutates only the explicit output. Hold
            // its actual parent inode; there is no invented source-store lease.
            let output = path(self.output.as_deref(), "output")?;
            let parent = output
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            let owner = NativeDirectoryOwner::acquire(&fs::canonicalize(parent)?)?;
            backend
                .run(args, Policy::StoppedOwner, owner, bounds)
                .await?
        } else {
            let source = path(self.source.as_deref(), "source")?;
            let owner = native_source_owner(source, action, self.historical)?;
            backend
                .run(args, Policy::StoppedOwner, owner, bounds)
                .await?
        };
        ensure!(
            output.status.success(),
            "native snapshot command refused with status {:?}",
            output.status.code()
        );
        std::io::stdout().write_all(&output.stdout)?;
        Ok(())
    }
}
