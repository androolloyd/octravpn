//! Immutable native snapshot drafts and separately authorized certificates.
use super::{codec, Authority};
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::Signer;
use octra_node_protocol::{
    consensus::{codec::Wire, hash, Finalize},
    state_sync::{anchor, checkpoint, head, manifest, roots},
};
use octra_node_runtime::{
    canonical::{CanonicalStore, Head},
    ledger_image::{self, Limits},
    state_batch::Snapshot,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

pub struct Prepare {
    /// Canonical base64 native finalized anchor, supplied by the operator.
    pub finality: PathBuf,
    pub chunk_size: u64,
    pub valid_for: u64,
    pub limits: Limits,
}
pub struct Assemble {
    pub exporter_key: Option<PathBuf>,
    /// Files containing native arrays of exporter signatures over manifest hash.
    pub exporter_signatures: Vec<PathBuf>,
    /// Optional independent quorum attestation over checkpoint hash. These are
    /// checked if supplied; they never replace native finalized authority.
    pub checkpoint_signatures: Vec<PathBuf>,
    pub limits: Limits,
}
#[derive(Debug, Serialize)]
pub struct PackageReport {
    pub directory: PathBuf,
    pub epoch: i64,
    pub state_root: String,
    pub checkpoint_hash: String,
    pub manifest_hash: String,
    pub bytes: i64,
    pub signed: bool,
}
pub(crate) struct VerifiedPackage {
    pub certificate: manifest::VerifiedCertificate,
    pub raw: Vec<u8>,
    pub files: BTreeMap<Vec<u8>, fs::File>,
}
const DRAFT: &str = "snapshot.draft.json";
const FINALITY: &str = "snapshot.finality";
const CERTIFICATE: &str = "snapshot.certificate.json";

pub async fn prepare(
    authority: &Authority,
    directory: &Path,
    target: &Path,
    options: Prepare,
) -> Result<PackageReport> {
    ensure!(
        (manifest::CHUNK_MIN as u64..=manifest::CHUNK_MAX as u64).contains(&options.chunk_size),
        "invalid snapshot chunk size"
    );
    ensure!(
        (1..=2_678_400).contains(&options.valid_for),
        "invalid snapshot validity interval"
    );
    let raw = super::super::read_limited(&options.finality, manifest::MANIFEST_LIMIT)?;
    let encoded = std::str::from_utf8(&raw)?.trim().as_bytes().to_vec();
    let finality = anchor::Anchor::decode(&encoded)?;
    let active = finality.derive(authority.trust().validators)?;
    let epoch = u64::try_from(finality.finalize.epoch_id)?;
    let (store, migration) = authority.reopen_with_migration(directory).await?;
    let capture = async {
        let sequence = store
            .sequence_for_epoch(epoch)
            .await?
            .context("finality epoch is not retained")?;
        let head = store.retained_head(sequence).await?;
        let retained = finalize_at(&store, authority, epoch).await?;
        ensure!(
            retained.encode()? == finality.finalize.encode()?,
            "finality is not the retained head certificate"
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
            quorum_cert_hash: Some(anchor::finalize_hash(&finality.finalize)?),
            epoch_index_hash: Some(
                head.index_hash
                    .as_ref()
                    .context("retained head has no epoch index hash")?
                    .as_bytes()
                    .to_vec(),
            ),
            epoch_index_root: Some(head.index_root.as_bytes().to_vec()),
            created_at: now,
            valid_until: now
                .checked_add(i64::try_from(options.valid_for)?)
                .context("snapshot expiry overflow")?,
        };
        let verified = anchor::verify(authority.trust().validators, &checkpoint, &encoded)?;
        ensure!(
            checkpoint.epoch >= authority.network().minimum_epoch,
            "snapshot precedes configured floor"
        );
        let mut prior = Vec::with_capacity(roots::WIDTH);
        for offset in 1..=epoch.min(roots::WIDTH as u64) {
            prior.push(finalize_at(&store, authority, epoch - offset).await?);
        }
        let window = roots::encode(&prior)?;
        roots::verify_snapshot(&verified, &window)?;
        let state = store.reader().snapshot_at(&head).await?;
        Ok::<_, anyhow::Error>((head, checkpoint, window, state))
    }
    .await;
    store.close().await;
    let (head, checkpoint, window, state) = capture?;
    let migration_bytes = if migration.is_some() {
        let raw = super::super::read_limited(
            &directory.join("pvac/migration_state.json"),
            octra_node_protocol::state_sync::migration::MAX_BYTES,
        )?;
        verify_migration(&raw, authority.network(), checkpoint.epoch)?;
        Some(raw)
    } else {
        None
    };
    let source = directory.to_path_buf();
    let target = target.to_path_buf();
    tokio::task::spawn_blocking(move || {
        prepare_files(
            &source,
            &target,
            Image {
                chunk_size: options.chunk_size,
                limits: options.limits,
            },
            &head,
            checkpoint,
            &encoded,
            &window,
            &state,
            migration_bytes.as_deref(),
        )
    })
    .await?
}

pub(crate) async fn finalize_at(
    store: &CanonicalStore,
    authority: &Authority,
    epoch: u64,
) -> Result<Finalize> {
    let floor = store.anchor().cursor.epoch.0;
    if epoch > floor {
        let sequence = store
            .sequence_for_epoch(epoch)
            .await?
            .context("root window epoch is not retained")?;
        return Ok(Finalize::decode(&store.certificate(sequence).await?)?);
    }
    if epoch == floor {
        let raw = store.checkpoint_certificate().await?.context(
            "retained genesis has no finalized certificate; supply an authenticated checkpoint",
        )?;
        let certificate = authority.trust().verify_persisted(&raw)?;
        return Ok(certificate
            .anchor()
            .context("retained floor finality missing")?
            .anchor()
            .finalize
            .clone());
    }
    roots::decode(
        store
            .checkpoint_window()
            .context("retained root window is missing")?,
    )?
    .into_iter()
    .find(|value| value.epoch_id == epoch as i64)
    .context("required finalized root is outside retained window")
}

fn prepare_files(
    source: &Path,
    target: &Path,
    options: Image,
    head: &Head,
    checkpoint: checkpoint::Body,
    finality: &[u8],
    window: &[u8],
    state: &Snapshot,
    migration: Option<&[u8]>,
) -> Result<PackageReport> {
    let (parent, target) = output(target)?;
    super::super::require_space(&parent, options.limits.bytes.min(1 << 30))?;
    let stage = tempfile::Builder::new()
        .prefix(".octra-snapshot-")
        .tempdir_in(&parent)?;
    let root = stage.path();
    let draft = write_image(
        source, root, options, head, checkpoint, finality, window, state, migration,
    )?;
    super::super::sync_tree(root)?;
    super::super::publish_directory(root, &target)?;
    fs::File::open(&parent)?.sync_all()?;
    report(&target, &draft, false)
}
#[allow(clippy::too_many_arguments)] // One immutable captured image, shared with manual prepare.
fn write_image(
    source: &Path,
    root: &Path,
    options: Image,
    head: &Head,
    checkpoint: checkpoint::Body,
    finality: &[u8],
    window: &[u8],
    state: &Snapshot,
    migration: Option<&[u8]>,
) -> Result<manifest::Draft> {
    let finalized = anchor::Anchor::decode(finality)?.finalize;
    let head_json = serde_json::to_vec_pretty(&serde_json::json!({
        "schema_version":3,"generation":checkpoint.epoch,"epoch_id":checkpoint.epoch,
        "state_root":std::str::from_utf8(&checkpoint.state_root)?,"ledger_state_root":head.ledger_root,
        "irmin_commit":head.irmin_commit,"txid_hi":head.txid_hi.to_string(),
        "txlog_seg":null,"txlog_off":null,"epochlog_off":null,"commit_id":std::str::from_utf8(&anchor::finalize_hash(&finalized)?)?,
        "ts":finalized.header.ts,"quorum_cert_hash":checkpoint.quorum_cert_hash.as_deref().map(std::str::from_utf8).transpose()?,
        "epoch_index_hash":head.index_hash,"epoch_index_root":head.index_root
    }))?;
    ensure!(
        head::Head::parse(&head_json)?.matches_checkpoint(&checkpoint),
        "portable HEAD differs from authenticated head"
    );
    write(root, "HEAD.json", &head_json)?;
    write(root, "state_root", &checkpoint.state_root)?;
    write(root, "ready_roots", window)?;
    let mut ledger = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(root.join("ledger.dat"))?;
    let written = {
        let mut out = BufWriter::with_capacity(4 * 1024 * 1024, &mut ledger);
        let value = ledger_image::write(state, &mut out, options.limits)?;
        out.flush()?;
        value
    };
    ensure!(
        written.root == head.ledger_root,
        "snapshot ledger differs from authenticated head"
    );
    ledger.sync_all()?;
    let mut paths = BTreeSet::from([
        "HEAD.json".to_owned(),
        "state_root".into(),
        "ready_roots".into(),
        "ledger.dat".into(),
    ]);
    if let Some(raw) = migration {
        write(root, "pvac/migration_state.json", raw)?;
        paths.insert("pvac/migration_state.json".into());
    }
    for (_, hash) in state.entries(&[b"pvac_hashes"]) {
        ensure!(
            super::super::lower_hash(hash),
            "ledger contains invalid public-key blob hash"
        );
        let name = format!("pvac/blobs/{}.pk", std::str::from_utf8(hash)?);
        if !paths.insert(name.clone()) {
            continue;
        }
        ensure!(
            paths.len() <= manifest::FILE_LIMIT,
            "snapshot file count exceeds limit"
        );
        let mut input = open(source, &name)?;
        let length = input.metadata()?.len();
        ensure!(
            length <= options.limits.bytes,
            "public-key blob exceeds local size limit"
        );
        let destination = root.join(&name);
        fs::create_dir_all(destination.parent().context("blob parent missing")?)?;
        let mut out = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)?;
        let bound = length
            .checked_add(1)
            .context("public-key blob length overflow")?;
        let count = std::io::copy(&mut Read::by_ref(&mut input).take(bound), &mut out)?;
        ensure!(count == length, "public-key blob changed length");
        out.sync_all()?;
        ensure!(
            file_manifest(root, &name, options.chunk_size)?.sha256 == hash,
            "public-key blob hash differs from ledger"
        );
    }
    let checkpoint_hash = hex::encode(checkpoint.hash()?).into_bytes();
    let files = paths
        .iter()
        .map(|path| file_manifest(root, path, options.chunk_size))
        .collect::<Result<Vec<_>>>()?;
    let total_size = files.iter().try_fold(0i64, |sum, file| {
        sum.checked_add(file.size).context("snapshot size overflow")
    })?;
    ensure!(
        total_size as u64 <= options.limits.bytes,
        "snapshot exceeds local byte limit"
    );
    let chunk_count = files.iter().try_fold(0usize, |sum, file| {
        sum.checked_add(file.chunks.len())
            .context("snapshot chunk count overflow")
    })?;
    ensure!(
        chunk_count <= manifest::CHUNK_LIMIT,
        "snapshot chunk count exceeds limit"
    );
    let body = manifest::Body {
        checkpoint_hash: checkpoint_hash.clone(),
        snapshot_id: checkpoint_hash.clone(),
        irmin_commit: Some(head.irmin_commit.as_bytes().to_vec()),
        chunk_size: i64::try_from(options.chunk_size)?,
        total_size,
        file_count: i64::try_from(files.len())?,
        chunk_count: i64::try_from(chunk_count)?,
        chunks_root: hex::encode(manifest::chunks_root(&files)?).into_bytes(),
        files,
    };
    body.validate_reference()?;
    let draft = manifest::Draft {
        checkpoint,
        checkpoint_hash,
        manifest_hash: hex::encode(body.hash()?).into_bytes(),
        manifest: body,
    };
    write(root, DRAFT, &codec::draft(&draft)?)?;
    write(root, FINALITY, finality)?;
    Ok(draft)
}

pub fn assemble(
    authority: &Authority,
    directory: &Path,
    options: Assemble,
) -> Result<PackageReport> {
    let Assemble {
        exporter_key,
        exporter_signatures,
        checkpoint_signatures,
        limits,
    } = options;
    let root = fs::canonicalize(directory)?;
    ensure!(
        !root.join(CERTIFICATE).try_exists()?,
        "snapshot certificate already exists"
    );
    let draft = codec::parse_draft(&read(&root, DRAFT, manifest::MANIFEST_LIMIT)?)?;
    let finality = read(&root, FINALITY, manifest::MANIFEST_LIMIT)?;
    let anchor = anchor::verify(authority.trust().validators, &draft.checkpoint, &finality)?;
    let files = verify_files(authority, &root, &draft, &anchor, limits)?;
    let mut quorum = load_signatures(&checkpoint_signatures)?;
    if quorum.is_empty() {
        ensure!(
            checkpoint_signatures.is_empty(),
            "checkpoint signature inputs contain no signatures"
        );
    } else {
        quorum.sort_by(|a, b| a.signer.cmp(&b.signer));
        draft.checkpoint.verify_quorum(
            &anchor::encoded_validator_set(&anchor.anchor().validator_set)?,
            &quorum,
        )?;
    }
    let mut signatures = load_signatures(&exporter_signatures)?;
    if let Some(path) = &exporter_key {
        let key = crate::identity::read(path)?;
        let public = STANDARD.encode(key.verifying_key().as_bytes());
        let signer = octra_node_protocol::transaction::address_from_public_key(public.as_bytes());
        signatures.push(checkpoint::Signature {
            signer,
            signature: STANDARD
                .encode(key.sign(&draft.manifest.hash()?).to_bytes())
                .into_bytes(),
        });
    }
    signatures.sort_by(|a, b| a.signer.cmp(&b.signer));
    manifest::verify_exporters(
        authority.trust().exporters,
        1,
        &draft.manifest.hash()?,
        &signatures,
    )?;
    let raw = codec::certificate(&draft, &finality, &signatures)?;
    authority.trust().verify(&raw, super::super::now()?)?;
    // Keep pinned verified files through publication. Nothing in the package
    // contains the signing key, local database, or node configuration.
    drop(files);
    let mut staged = tempfile::NamedTempFile::new_in(&root)?;
    staged.write_all(&raw)?;
    staged.as_file().sync_all()?;
    staged.persist_noclobber(root.join(CERTIFICATE))?;
    fs::File::open(&root)?.sync_all()?;
    report(&root, &draft, true)
}

pub(crate) fn verify(
    authority: &Authority,
    directory: &Path,
    limits: Limits,
) -> Result<VerifiedPackage> {
    let raw = read(directory, CERTIFICATE, manifest::MANIFEST_LIMIT)?;
    let certificate = authority.trust().verify(&raw, super::super::now()?)?;
    let files = verify_files(
        authority,
        directory,
        certificate.draft(),
        certificate.anchor().context("snapshot finality missing")?,
        limits,
    )?;
    Ok(VerifiedPackage {
        certificate,
        raw,
        files,
    })
}
fn verify_files(
    authority: &Authority,
    root: &Path,
    draft: &manifest::Draft,
    anchor: &anchor::VerifiedAnchor,
    limits: Limits,
) -> Result<BTreeMap<Vec<u8>, fs::File>> {
    draft.verify()?;
    draft.manifest.validate_reference()?;
    let network = authority.network();
    ensure!(
        draft.checkpoint.chain_id == network.identity.chain_id.as_bytes()
            && draft.checkpoint.config_hash == network.config_hash.as_bytes()
            && draft.checkpoint.epoch >= network.minimum_epoch,
        "snapshot checkpoint differs from configured network authority"
    );
    ensure!(
        draft.manifest.total_size as u64 <= limits.bytes,
        "snapshot exceeds local byte limit"
    );
    let mut files = BTreeMap::new();
    for file in &draft.manifest.files {
        let name = std::str::from_utf8(&file.path)?;
        let mut input = open(root, name)?;
        ensure!(
            input.metadata()?.len() == file.size as u64,
            "snapshot file length differs: {name}"
        );
        let actual = hash_file(&mut input, name, draft.manifest.chunk_size as u64)?;
        ensure!(actual == *file, "snapshot file bytes differ: {name}");
        files.insert(file.path.clone(), input);
    }
    let source_head = head::Head::parse(&read_pinned(&mut files, "HEAD.json", head::MAX_BYTES)?)?;
    ensure!(
        source_head.matches_checkpoint(&draft.checkpoint),
        "snapshot HEAD differs from checkpoint"
    );
    ensure!(
        source_head.irmin_commit == draft.manifest.irmin_commit,
        "snapshot HEAD commit differs from manifest"
    );
    ensure!(
        read_pinned(&mut files, "state_root", 256)? == draft.checkpoint.state_root,
        "snapshot state root differs"
    );
    roots::verify_snapshot(
        anchor,
        &read_pinned(&mut files, "ready_roots", roots::MAX_FILE)?,
    )?;
    let listed = draft
        .manifest
        .files
        .iter()
        .any(|file| file.path == b"pvac/migration_state.json");
    ensure!(
        listed == authority.network().migration_root.is_some(),
        "migration artifact is not committed by manifest"
    );
    if listed {
        verify_migration(
            &read_pinned(
                &mut files,
                "pvac/migration_state.json",
                octra_node_protocol::state_sync::migration::MAX_BYTES,
            )?,
            authority.network(),
            draft.checkpoint.epoch,
        )?;
    }
    let ledger = files
        .get_mut(b"ledger.dat".as_slice())
        .context("snapshot ledger missing")?;
    ledger.seek(SeekFrom::Start(0))?;
    let restored = ledger_image::restore(
        BufReader::new(ledger.try_clone()?),
        ledger.metadata()?.len(),
        std::str::from_utf8(&draft.checkpoint.ledger_state_root)?,
        limits,
    )?;
    for (_, hash) in restored.state.entries(&[b"pvac_hashes"]) {
        ensure!(
            super::super::lower_hash(hash),
            "ledger public-key blob hash is invalid"
        );
        let name = format!("pvac/blobs/{}.pk", std::str::from_utf8(hash)?);
        let file = draft
            .manifest
            .files
            .iter()
            .find(|file| file.path == name.as_bytes())
            .context("ledger public-key blob missing from snapshot")?;
        ensure!(
            file.sha256 == hash,
            "ledger public-key blob hash differs from manifest"
        );
    }
    Ok(files)
}
fn read_pinned(
    files: &mut BTreeMap<Vec<u8>, fs::File>,
    name: &str,
    limit: usize,
) -> Result<Vec<u8>> {
    let file = files
        .get_mut(name.as_bytes())
        .context("required snapshot artifact is absent")?;
    ensure!(
        file.metadata()?.len() <= limit as u64,
        "snapshot artifact exceeds limit"
    );
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    Read::by_ref(file)
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "snapshot artifact grew past limit");
    Ok(bytes)
}
fn verify_migration(raw: &[u8], network: &super::super::Network, floor: i64) -> Result<()> {
    use octra_node_protocol::{native_base64, state_sync::migration};
    let expected = network
        .migration_root
        .as_deref()
        .context("unexpected migration admission artifact")?;
    let admission = migration::Admission::parse(
        raw,
        network.identity.chain_id.as_bytes(),
        expected.as_bytes(),
        |encoded| {
            native_base64::decode(encoded)
                .ok()
                .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                .is_some_and(|point| octra_hfhe::proof::generators::point_valid(&point))
        },
    )?;
    admission.bind_floor(
        network.config_hash.as_bytes(),
        network.config_hash.as_bytes(),
        floor,
    )?;
    Ok(())
}
fn load_signatures(paths: &[PathBuf]) -> Result<Vec<checkpoint::Signature>> {
    ensure!(paths.len() <= 1024, "too many signature inputs");
    let mut all = Vec::new();
    for path in paths {
        all.extend(codec::signatures(&super::super::read_limited(
            path,
            1024 * 1024,
        )?)?);
        ensure!(all.len() <= 1024, "too many signatures");
    }
    Ok(all)
}
fn output(target: &Path) -> Result<(PathBuf, PathBuf)> {
    let parent = fs::canonicalize(
        target
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )?;
    let target = parent.join(target.file_name().context("snapshot output name missing")?);
    ensure!(
        fs::symlink_metadata(&target)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound),
        "snapshot output already exists or is inaccessible"
    );
    Ok((parent, target))
}
fn write(root: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let path = root.join(name);
    fs::create_dir_all(path.parent().context("snapshot file parent missing")?)?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
pub(crate) fn open(root: &Path, name: &str) -> Result<fs::File> {
    ensure!(
        manifest::valid_path(name.as_bytes()),
        "invalid snapshot relative path"
    );
    #[cfg(unix)]
    {
        use rustix::fs::{open, openat, Mode, OFlags};
        let directory_flags =
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let mut directory = open(root, directory_flags, Mode::empty())?;
        let mut parts = name.split('/').peekable();
        while let Some(part) = parts.next() {
            if parts.peek().is_some() {
                directory = openat(&directory, part, directory_flags, Mode::empty())?;
            } else {
                let file: fs::File = openat(
                    &directory,
                    part,
                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                    Mode::empty(),
                )?
                .into();
                ensure!(
                    file.metadata()?.is_file(),
                    "snapshot artifact is not a regular file"
                );
                return Ok(file);
            }
        }
        anyhow::bail!("snapshot path is empty")
    }
    #[cfg(not(unix))]
    {
        let _ = root;
        anyhow::bail!("safe snapshot file access requires Unix")
    }
}
fn read(root: &Path, name: &str, limit: usize) -> Result<Vec<u8>> {
    let file = open(root, name)?;
    ensure!(
        file.metadata()?.len() <= limit as u64,
        "snapshot artifact exceeds limit"
    );
    let mut raw = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut raw)?;
    ensure!(raw.len() <= limit, "snapshot artifact grew past limit");
    Ok(raw)
}
fn file_manifest(root: &Path, name: &str, chunk_size: u64) -> Result<manifest::File> {
    hash_file(&mut open(root, name)?, name, chunk_size)
}
fn hash_file(file: &mut fs::File, name: &str, chunk_size: u64) -> Result<manifest::File> {
    file.seek(SeekFrom::Start(0))?;
    let length = file.metadata()?.len();
    ensure!(
        i64::try_from(length).is_ok(),
        "snapshot artifact length exceeds protocol range"
    );
    let count = length.div_ceil(chunk_size);
    ensure!(
        count <= manifest::CHUNK_LIMIT as u64,
        "snapshot file chunk count exceeds limit"
    );
    let mut whole = Sha256::new();
    let mut chunks = Vec::new();
    let mut buffer = vec![0; usize::try_from(chunk_size)?];
    let mut offset = 0u64;
    while offset < length {
        let size = usize::try_from((length - offset).min(chunk_size))?;
        file.read_exact(&mut buffer[..size])?;
        whole.update(&buffer[..size]);
        chunks.push(manifest::Chunk {
            index: i64::try_from(chunks.len())?,
            offset: i64::try_from(offset)?,
            size: i64::try_from(size)?,
            sha256: hex::encode(Sha256::digest(&buffer[..size])).into_bytes(),
        });
        offset += size as u64;
    }
    let mut extra = [0];
    ensure!(
        file.read(&mut extra)? == 0 && file.metadata()?.len() == length,
        "snapshot file changed length"
    );
    file.seek(SeekFrom::Start(0))?;
    Ok(manifest::File {
        path: name.as_bytes().to_vec(),
        size: i64::try_from(length)?,
        sha256: hex::encode(whole.finalize()).into_bytes(),
        chunks,
    })
}
fn report(directory: &Path, draft: &manifest::Draft, signed: bool) -> Result<PackageReport> {
    Ok(PackageReport {
        directory: directory.to_path_buf(),
        epoch: draft.checkpoint.epoch,
        state_root: String::from_utf8(draft.checkpoint.state_root.clone())?,
        checkpoint_hash: String::from_utf8(draft.checkpoint_hash.clone())?,
        manifest_hash: String::from_utf8(draft.manifest_hash.clone())?,
        bytes: draft.manifest.total_size,
        signed,
    })
}

/// A retained immutable capture. The live node owns its store; exporting never
/// reopens its writer or consults downloaded configuration for trust.
pub(crate) struct Capture {
    head: Head,
    checkpoint: checkpoint::Body,
    finality: Vec<u8>,
    window: Vec<u8>,
    state: Snapshot,
    migration: Option<Vec<u8>>,
}
impl Capture {
    pub(crate) fn snapshot_id(&self) -> Result<String> {
        Ok(hex::encode(self.checkpoint.hash()?))
    }
}
#[derive(Clone, Copy)]
struct Image {
    chunk_size: u64,
    limits: Limits,
}

pub(crate) async fn capture(
    authority: &Authority,
    store: &CanonicalStore,
    source: &Path,
    head: Head,
    finality: anchor::Anchor,
) -> Result<Capture> {
    ensure!(
        store.chain() == &authority.network().identity,
        "snapshot store identity differs"
    );
    ensure!(
        store.retained_head(head.cursor.sequence).await? == head,
        "snapshot retained head differs"
    );
    let epoch = head.cursor.epoch.0;
    ensure!(
        finalize_at(store, authority, epoch).await?.encode()? == finality.finalize.encode()?,
        "snapshot finality differs from retained certificate"
    );
    let active = finality.derive(authority.trust().validators)?;
    let timestamp = finality.finalize.header.ts;
    ensure!(
        timestamp.is_finite() && (0. ..9_223_372_036_854_775_808.).contains(&timestamp),
        "snapshot finality timestamp is invalid"
    );
    let created_at = timestamp as i64;
    let checkpoint = checkpoint::Body {
        chain_id: authority.network().identity.chain_id.as_bytes().to_vec(),
        epoch: i64::try_from(epoch)?,
        state_root: hex::encode(head.cursor.state_root.0).into_bytes(),
        ledger_state_root: head.ledger_root.as_bytes().to_vec(),
        txid_hi: head.txid_hi,
        config_hash: authority.network().config_hash.as_bytes().to_vec(),
        validator_set_hash: hex::encode(hash::validator_set_hash(&active)?).into_bytes(),
        quorum_cert_hash: Some(anchor::finalize_hash(&finality.finalize)?),
        epoch_index_hash: Some(
            head.index_hash
                .as_ref()
                .context("snapshot index hash missing")?
                .as_bytes()
                .to_vec(),
        ),
        epoch_index_root: Some(head.index_root.as_bytes().to_vec()),
        created_at,
        valid_until: created_at
            .checked_add(octra_node_protocol::state_sync::cycle::VALID_FOR_SECONDS)
            .context("snapshot expiry overflow")?,
    };
    ensure!(
        checkpoint.epoch >= authority.network().minimum_epoch,
        "snapshot precedes configured floor"
    );
    let finality = finality.encode()?;
    let verified = anchor::verify(authority.trust().validators, &checkpoint, &finality)?;
    let mut prior = Vec::with_capacity(roots::WIDTH);
    for offset in 1..=epoch.min(roots::WIDTH as u64) {
        prior.push(finalize_at(store, authority, epoch - offset).await?);
    }
    let window = roots::encode(&prior)?;
    roots::verify_snapshot(&verified, &window)?;
    let state = store.reader().snapshot_at(&head).await?;
    let migration = if authority.network().migration_root.is_some() {
        let path = source.join("pvac/migration_state.json");
        let raw = tokio::task::spawn_blocking(move || {
            super::super::read_limited(&path, octra_node_protocol::state_sync::migration::MAX_BYTES)
        })
        .await??;
        verify_migration(&raw, authority.network(), checkpoint.epoch)?;
        Some(raw)
    } else {
        None
    };
    Ok(Capture {
        head,
        checkpoint,
        finality,
        window,
        state,
        migration,
    })
}

pub(crate) fn prepare_capture(
    source: &Path,
    target: &Path,
    captured: Capture,
    chunk_size: u64,
    limits: Limits,
) -> Result<PackageReport> {
    ensure!(
        (manifest::CHUNK_MIN as u64..=manifest::CHUNK_MAX as u64).contains(&chunk_size),
        "invalid snapshot chunk size"
    );
    super::super::require_space(target, limits.bytes.min(1 << 30))?;
    let draft = write_image(
        source,
        target,
        Image { chunk_size, limits },
        &captured.head,
        captured.checkpoint,
        &captured.finality,
        &captured.window,
        &captured.state,
        captured.migration.as_deref(),
    )?;
    super::super::sync_tree(target)?;
    report(target, &draft, false)
}

/// The automatic publisher signs with its already loaded identity. No key path
/// or private key material is introduced into the snapshot archive.
pub(crate) fn sign_capture(
    authority: &Authority,
    directory: &Path,
    key: &ed25519_dalek::SigningKey,
    limits: Limits,
) -> Result<Vec<u8>> {
    let draft = codec::parse_draft(&read(directory, DRAFT, manifest::MANIFEST_LIMIT)?)?;
    let finality = read(directory, FINALITY, manifest::MANIFEST_LIMIT)?;
    let verified = anchor::verify(authority.trust().validators, &draft.checkpoint, &finality)?;
    let _files = verify_files(authority, directory, &draft, &verified, limits)?;
    let public = STANDARD.encode(key.verifying_key().as_bytes());
    let signatures = [checkpoint::Signature {
        signer: octra_node_protocol::transaction::address_from_public_key(public.as_bytes()),
        signature: STANDARD
            .encode(key.sign(&draft.manifest.hash()?).to_bytes())
            .into_bytes(),
    }];
    manifest::verify_exporters(
        authority.trust().exporters,
        1,
        &draft.manifest.hash()?,
        &signatures,
    )?;
    let raw = codec::certificate(&draft, &finality, &signatures)?;
    authority.trust().verify(&raw, super::super::now()?)?;
    write(directory, CERTIFICATE, &raw)?;
    fs::File::open(directory)?.sync_all()?;
    Ok(raw)
}
