//! Authenticated public-network bootstrap into a new, atomically published data
//! directory. A download never enables voting or replaces an existing database.
mod download;
pub mod export;
mod resume;
use anyhow::{ensure, Context, Result};
use download::{Candidate, Client, Source};
use futures::{stream, StreamExt, TryStreamExt};
use octra_exex::ChainIdentity;
use octra_node_protocol::{
    consensus::ValidatorSet,
    native_base64,
    state_sync::{
        head,
        manifest::{self, Trust},
        migration, roots,
    },
};
use octra_node_runtime::{canonical::CanonicalStore, ledger_image};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{BufReader, Read},
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    pub identity: ChainIdentity,
    pub config_hash: String,
    pub validators: Vec<String>,
    pub exporters: Vec<String>,
    pub minimum_epoch: i64,
    pub migration_root: Option<String>,
}
pub struct Authority {
    network: Network,
    validators: ValidatorSet,
    exporters: ValidatorSet,
}
impl Authority {
    pub fn new(network: Network) -> Result<Self> {
        network.identity.validate().map_err(anyhow::Error::msg)?;
        ensure!(
            lower_hash(network.config_hash.as_bytes()),
            "invalid consensus configuration hash"
        );
        ensure!(network.minimum_epoch >= 0, "negative snapshot floor");
        ensure!(
            network.minimum_epoch as u64 >= network.identity.origin.epoch(),
            "snapshot floor precedes configured checkpoint origin"
        );
        if let Some(root) = &network.migration_root {
            ensure!(lower_hash(root.as_bytes()), "invalid migration root");
        }
        let parse = |entries: &[String]| {
            manifest::signer_set(
                &entries
                    .iter()
                    .map(|s| s.as_bytes().to_vec())
                    .collect::<Vec<_>>(),
            )
        };
        let validators = parse(&network.validators)?;
        let exporters = parse(&network.exporters)?;
        Ok(Self {
            network,
            validators,
            exporters,
        })
    }
    pub fn trust(&self) -> Trust<'_> {
        Trust {
            validators: &self.validators,
            exporters: &self.exporters,
            chain_id: self.network.identity.chain_id.as_bytes(),
            config_hash: self.network.config_hash.as_bytes(),
            minimum_epoch: self.network.minimum_epoch,
        }
    }
    pub fn network(&self) -> &Network {
        &self.network
    }
    pub async fn reopen(&self, directory: &Path) -> Result<CanonicalStore> {
        self.reopen_with_migration(directory)
            .await
            .map(|(store, _)| store)
    }
    pub async fn reopen_with_migration(
        &self,
        directory: &Path,
    ) -> Result<(CanonicalStore, Option<migration::Admission>)> {
        // Startup uses retained evidence and the caller's current trust, never
        // the network.json copied alongside the downloaded data as authority.
        let store = CanonicalStore::open_from_checkpoint(
            &directory.join("canonical.sqlite"),
            &self.network.identity,
            &self.trust(),
        )
        .await?;
        let checkpoint = store.anchor().cursor.epoch.0;
        let migration = verify_migration(directory, &self.network, i64::try_from(checkpoint)?)?;
        if let Some(admission) = &migration {
            let epoch = u64::try_from(admission.snapshot_epoch())?;
            let head = store.head().await?;
            if (checkpoint..=head.cursor.epoch.0).contains(&epoch) {
                let bound = store.reader().head_for_epoch(epoch).await?;
                admission.bind_snapshot(hex::encode(bound.cursor.state_root.0).as_bytes())?;
            }
        }
        Ok((store, migration))
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub network: Network,
    pub sources: Vec<String>,
    #[serde(default)]
    pub allow_private_http: bool,
    #[serde(default = "default_bytes")]
    pub max_bytes: u64,
    #[serde(default = "default_records")]
    pub max_records: u64,
    #[serde(default = "default_string_bytes")]
    pub max_string_bytes: u64,
}
fn default_bytes() -> u64 {
    ledger_image::Limits::default().bytes
}
fn default_records() -> u64 {
    ledger_image::Limits::default().records
}
fn default_string_bytes() -> u64 {
    ledger_image::Limits::default().string_bytes
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub directory: PathBuf,
    pub chain_id: String,
    pub epoch: u64,
    pub state_root: String,
    pub manifest_hash: String,
    pub ledger_records: u64,
    pub downloaded_bytes: u64,
    pub reused_bytes: u64,
}
pub fn read(path: &Path) -> Result<Config> {
    Ok(serde_json::from_slice(&read_limited(path, 1024 * 1024)?)?)
}
fn now() -> Result<i64> {
    Ok(i64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    )?)
}
fn lower_hash(bytes: &[u8]) -> bool {
    bytes.len() == 64
        && bytes
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
}

fn candidates(values: Vec<Candidate>) -> Result<Vec<Candidate>> {
    let mut by_epoch = BTreeMap::new();
    let mut groups = BTreeMap::<Vec<u8>, Candidate>::new();
    for candidate in values {
        let draft = candidate.certificate.draft();
        let checkpoint = &draft.checkpoint;
        if let Some(prior) = by_epoch.get(&checkpoint.epoch) {
            ensure!(
                checkpoint.same_finalized_state(prior),
                "conflicting quorum checkpoints at the same snapshot epoch"
            );
        } else {
            by_epoch.insert(checkpoint.epoch, checkpoint.clone());
        }
        if let Some(group) = groups.get_mut(&draft.manifest_hash) {
            ensure!(
                group.certificate.draft() == draft,
                "conflicting snapshot manifest"
            );
            for source in candidate.sources {
                if !group
                    .sources
                    .iter()
                    .any(|prior| prior.identity() == source.identity())
                {
                    group.sources.push(source);
                }
            }
        } else {
            groups.insert(draft.manifest_hash.clone(), candidate);
        }
    }
    let mut values = groups.into_values().collect::<Vec<_>>();
    values.sort_by(|a, b| {
        let a_draft = a.certificate.draft();
        let b_draft = b.certificate.draft();
        b_draft
            .checkpoint
            .epoch
            .cmp(&a_draft.checkpoint.epoch)
            .then(a_draft.checkpoint_hash.cmp(&b_draft.checkpoint_hash))
            .then(b.sources.len().cmp(&a.sources.len()))
            .then(a_draft.manifest_hash.cmp(&b_draft.manifest_hash))
    });
    Ok(values)
}

/// Install only after finality, exporter, network, chunk, image, HEAD, recent
/// roots and configured migration checks all bind to the same checkpoint.
pub async fn install(config: Config, destination: &Path) -> Result<Report> {
    ensure!(
        !config.sources.is_empty() && config.sources.len() <= 64,
        "snapshot requires 1 to 64 sources"
    );
    ensure!(
        config.max_bytes > 0 && config.max_records > 0 && config.max_string_bytes > 0,
        "snapshot resource limits must be positive"
    );
    ensure!(
        !destination.try_exists()?,
        "snapshot destination already exists"
    );
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = fs::canonicalize(parent).context("snapshot destination parent must exist")?;
    let destination = parent.join(
        destination
            .file_name()
            .context("snapshot destination has no name")?,
    );
    let authority = Authority::new(config.network.clone())?;
    let mut identities = BTreeSet::new();
    let mut sources = Vec::new();
    for raw in &config.sources {
        let source = Source::new(raw, config.allow_private_http)?;
        ensure!(
            identities.insert(source.identity().to_owned()),
            "duplicate state sync source"
        );
        sources.push(source);
    }
    let client = Client::new()?;
    let workspace = Arc::new(resume::Workspace::open(
        &destination,
        &config.network.identity,
    )?);
    let trust = authority.trust();
    let timestamp = now()?;
    let cached = workspace.candidate(&trust, &sources, timestamp)?;
    let results = stream::iter(
        sources
            .into_iter()
            .map(|source| client.manifest(source, &trust, timestamp)),
    )
    .buffer_unordered(8)
    .collect::<Vec<_>>()
    .await;
    let mut valid = Vec::new();
    valid.extend(cached);
    let mut failures = Vec::new();
    for result in results {
        match result {
            Ok(candidate) => valid.push(candidate),
            Err(error) => failures.push(error.to_string()),
        }
    }
    ensure!(
        !valid.is_empty(),
        "no authenticated snapshot source: {}",
        failures.join("; ")
    );
    for candidate in candidates(valid)? {
        let draft = candidate.certificate.draft();
        if draft.manifest.total_size as u64 > config.max_bytes {
            failures.push("snapshot exceeds local byte limit".into());
            continue;
        }
        let stage = Arc::new(
            tempfile::Builder::new()
                .prefix(".install-")
                .tempdir_in(workspace.path())?,
        );
        let owned = workspace.clone();
        let cached_candidate = candidate.clone();
        let cache =
            tokio::task::spawn_blocking(move || owned.remember(&cached_candidate)).await??;
        let attempt = install_candidate(
            &client,
            &candidate,
            &config,
            &authority,
            &cache,
            stage.clone(),
        )
        .await;
        match attempt {
            Err(error) => failures.push(error.to_string()),
            Ok(mut report) => {
                sync_tree(stage.path())?;
                publish_directory(stage.path(), &destination)?;
                fs::File::open(&parent)?.sync_all()?;
                fs::File::open(workspace.path())?.sync_all()?;
                report.directory = destination;
                return Ok(report);
            }
        }
    }
    anyhow::bail!("no snapshot could be installed: {}", failures.join("; "))
}

async fn install_candidate(
    client: &Client,
    candidate: &Candidate,
    config: &Config,
    authority: &Authority,
    cache: &resume::Cache,
    stage: Arc<tempfile::TempDir>,
) -> Result<Report> {
    let draft = candidate.certificate.draft();
    let checkpoint = &draft.checkpoint;
    require_space(stage.path(), draft.manifest.total_size as u64)?;
    let downloaded = stream::iter(
        draft
            .manifest
            .files
            .iter()
            .map(|file| client.file(candidate, file, cache)),
    )
    .buffer_unordered(8)
    .try_collect::<Vec<_>>()
    .await?
    .into_iter()
    .try_fold(0u64, |total, bytes| {
        total
            .checked_add(bytes)
            .context("snapshot download counter overflow")
    })?;
    // Imported state lives in a fresh directory. Verified cached files are
    // immutable, and hard links avoid copying the complete ledger a second time.
    let paths = draft
        .manifest
        .files
        .iter()
        .map(|file| Ok(std::str::from_utf8(&file.path)?.to_owned()))
        .collect::<Result<Vec<_>>>()?;
    let owned = stage.clone();
    let cached = cache.clone();
    tokio::task::spawn_blocking(move || {
        for relative in paths {
            let path = owned.path().join(&relative);
            fs::create_dir_all(path.parent().context("snapshot file parent missing")?)?;
            fs::hard_link(cached.path().join(relative), &path)?;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    let source_head = head::Head::parse(&read_limited(
        &stage.path().join("HEAD.json"),
        head::MAX_BYTES,
    )?)?;
    ensure!(
        source_head.matches_checkpoint(checkpoint),
        "restored HEAD.json does not match checkpoint"
    );
    if let Some(commit) = &draft.manifest.irmin_commit {
        ensure!(
            source_head.irmin_commit.as_ref() == Some(commit),
            "source HEAD Irmin commit differs from manifest"
        );
    }
    ensure!(
        read_limited(&stage.path().join("state_root"), 256)? == checkpoint.state_root,
        "snapshot state_root differs from checkpoint"
    );
    let window = read_limited(&stage.path().join("ready_roots"), roots::MAX_FILE)?;
    roots::verify_snapshot(
        candidate
            .certificate
            .anchor()
            .context("reference finality missing")?,
        &window,
    )?;
    verify_migration(stage.path(), &config.network, checkpoint.epoch)?;
    let ledger_root = String::from_utf8(checkpoint.ledger_state_root.clone())?;
    let limits = ledger_image::Limits {
        bytes: config.max_bytes,
        records: config.max_records,
        string_bytes: config.max_string_bytes,
    };
    let owned = stage.clone();
    let restored = tokio::task::spawn_blocking(move || {
        let path = owned.path().join("ledger.dat");
        let file = regular(&path)?;
        let size = file.metadata()?.len();
        Ok::<_, anyhow::Error>(ledger_image::restore(
            BufReader::new(file),
            size,
            &ledger_root,
            limits,
        )?)
    })
    .await??;
    // Every external public-key blob referenced by the authenticated tree must
    // exist and its content hash must equal the ledger's blob identifier.
    let files = draft
        .manifest
        .files
        .iter()
        .map(|f| (f.path.as_slice(), f))
        .collect::<BTreeMap<_, _>>();
    for (_, hash) in restored.state.entries(&[b"pvac_hashes"]) {
        if lower_hash(hash) {
            let name = format!("pvac/blobs/{}.pk", std::str::from_utf8(hash)?);
            let file = files
                .get(name.as_bytes())
                .context("referenced PVAC blob missing from snapshot")?;
            ensure!(
                file.sha256 == hash,
                "PVAC blob content hash differs from ledger"
            );
        }
    }
    let records = restored.records;
    let store = CanonicalStore::create_from_checkpoint(
        &stage.path().join("canonical.sqlite"),
        config.network.identity.clone(),
        restored.state,
        &candidate.raw,
        &window,
        &authority.trust(),
        now()?,
    )
    .await?;
    store.close().await;
    // Keep original certificate/HEAD/roots for recovery and native interchange.
    crate::storage::publish(
        &stage.path().join("snapshot.certificate.json"),
        &candidate.raw,
    )?;
    crate::storage::publish(
        &stage.path().join("network.json"),
        &serde_json::to_vec_pretty(&config.network)?,
    )?;
    fs::rename(
        stage.path().join("HEAD.json"),
        stage.path().join("HEAD.source.json"),
    )?;
    fs::remove_file(stage.path().join("ledger.dat"))?;
    Ok(Report {
        directory: PathBuf::new(),
        chain_id: config.network.identity.chain_id.clone(),
        epoch: u64::try_from(checkpoint.epoch)?,
        state_root: String::from_utf8(checkpoint.state_root.clone())?,
        manifest_hash: String::from_utf8(draft.manifest_hash.clone())?,
        ledger_records: records,
        downloaded_bytes: downloaded,
        reused_bytes: (draft.manifest.total_size as u64)
            .checked_sub(downloaded)
            .context("snapshot download counter exceeds manifest")?,
    })
}

pub fn verify_migration(
    directory: &Path,
    network: &Network,
    floor: i64,
) -> Result<Option<migration::Admission>> {
    let path = directory.join("pvac/migration_state.json");
    let Some(root) = &network.migration_root else {
        ensure!(!path.try_exists()?, "unexpected migration admission state");
        return Ok(None);
    };
    let raw = read_limited(&path, migration::MAX_BYTES)?;
    let admission = migration::Admission::parse(
        &raw,
        network.identity.chain_id.as_bytes(),
        root.as_bytes(),
        |encoded| {
            native_base64::decode(encoded)
                .ok()
                .and_then(|raw| <[u8; 32]>::try_from(raw).ok())
                .is_some_and(|point| octra_hfhe::proof::generators::point_valid(&point))
        },
    )?;
    admission.bind_floor(
        network.config_hash.as_bytes(),
        network.config_hash.as_bytes(),
        floor,
    )?;
    Ok(Some(admission))
}
fn regular(path: &Path) -> Result<fs::File> {
    let before = fs::symlink_metadata(path)?;
    ensure!(before.is_file(), "snapshot artifact must be a regular file");
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(
            rustix::fs::OFlags::NOFOLLOW.bits() as i32 | rustix::fs::OFlags::NONBLOCK.bits() as i32,
        );
    }
    let file = options.open(path)?;
    let after = file.metadata()?;
    ensure!(after.is_file(), "snapshot artifact changed type");
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            before.dev() == after.dev() && before.ino() == after.ino(),
            "snapshot artifact identity changed"
        );
    }
    Ok(file)
}
pub(crate) fn read_limited(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let file = regular(path)?;
    ensure!(
        file.metadata()?.len() <= limit as u64,
        "snapshot artifact exceeds size limit"
    );
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "snapshot artifact exceeds size limit");
    Ok(bytes)
}
fn require_space(path: &Path, bytes: u64) -> Result<()> {
    #[cfg(unix)]
    {
        let stat = rustix::fs::statvfs(path)?;
        let free = (stat.f_bavail as u128) * (stat.f_frsize as u128);
        let needed = u128::from(bytes) * 4 + 1024 * 1024 * 1024;
        ensure!(
            free >= needed,
            "insufficient space for snapshot staging and canonical import"
        );
    }
    #[cfg(not(unix))]
    {
        let _ = (path, bytes);
    }
    Ok(())
}
fn sync_tree(root: &Path) -> Result<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_dir() {
            sync_tree(&entry.path())?;
        } else {
            ensure!(kind.is_file(), "unexpected staged file type");
            fs::File::open(entry.path())?.sync_all()?;
        }
    }
    fs::File::open(root)?.sync_all()?;
    Ok(())
}
fn publish_directory(source: &Path, destination: &Path) -> Result<()> {
    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    {
        rustix::fs::renameat_with(
            rustix::fs::CWD,
            source,
            rustix::fs::CWD,
            destination,
            rustix::fs::RenameFlags::NOREPLACE,
        )?;
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
    {
        let _ = (source, destination);
        anyhow::bail!("atomic snapshot directory publication is unsupported on this platform")
    }
}
