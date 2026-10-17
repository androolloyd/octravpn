//! Authenticated non-genesis history floors. The retained snapshot does not
//! create synthetic transactions or replay events preceding its checkpoint.
use super::{
    connect, error, hex_hash, irmin, reader, Arc, CanonicalStore, ChainIdentity, Cursor, EpochId,
    Head, HeadCache, Path, Result, Row, Sequence, Snapshot, SqliteEpochSource, StateRoot,
};
use octra_node_protocol::{
    consensus::ParentCommit,
    state_sync::{
        manifest::{Trust, VerifiedCertificate},
        roots,
    },
};

pub(super) struct Bootstrap {
    pub(super) raw: Vec<u8>,
    pub(super) window: Vec<u8>,
    certificate: VerifiedCertificate,
    roots: Vec<(i64, Vec<u8>)>,
}
impl Bootstrap {
    fn new(raw: &[u8], window: &[u8], certificate: VerifiedCertificate) -> Result<Self> {
        let anchor = certificate
            .anchor()
            .ok_or_else(|| error("bootstrap requires finalized authority"))?;
        let roots = roots::verify_snapshot(anchor, window).map_err(error)?;
        Ok(Self {
            raw: raw.to_vec(),
            window: window.to_vec(),
            certificate,
            roots,
        })
    }
}

fn checkpoint_head(certificate: &VerifiedCertificate) -> Result<Head> {
    let checkpoint = &certificate.draft().checkpoint;
    if certificate.anchor().is_none() {
        return Err(error("bootstrap requires finalized authority"));
    }
    let ledger_root = String::from_utf8(checkpoint.ledger_state_root.clone()).map_err(error)?;
    let index_root = String::from_utf8(
        checkpoint
            .epoch_index_root
            .clone()
            .ok_or_else(|| error("missing checkpoint index root"))?,
    )
    .map_err(error)?;
    let index_hash = String::from_utf8(
        checkpoint
            .epoch_index_hash
            .clone()
            .ok_or_else(|| error("missing checkpoint index hash"))?,
    )
    .map_err(error)?;
    let message = b"state sync".to_vec();
    let date = checkpoint.created_at;
    let head = Head {
        cursor: Cursor {
            sequence: Sequence(0),
            epoch: EpochId(u64::try_from(checkpoint.epoch).map_err(error)?),
            state_root: StateRoot(hex_hash(
                std::str::from_utf8(&checkpoint.state_root).map_err(error)?,
            )?),
        },
        irmin_commit: hex::encode(irmin::commit_hash(
            &hex_hash(&ledger_root)?,
            &[],
            date,
            b"octra",
            &message,
        )),
        ledger_root,
        parent_commit: None,
        index_root,
        index_hash: Some(index_hash),
        txid_hi: checkpoint.txid_hi,
        date,
        message,
    };
    head.validate()?;
    Ok(head)
}

impl CanonicalStore {
    /// Only an authenticated, fresh reference certificate can install a remote
    /// snapshot. `chain` retains its independently configured genesis or pinned
    /// checkpoint origin; a downloaded snapshot never selects that identity.
    /// Call on a private staging path, then close and publish the whole directory.
    pub async fn create_from_checkpoint(
        path: &Path,
        chain: ChainIdentity,
        state: Snapshot,
        raw_certificate: &[u8],
        root_window: &[u8],
        trust: &Trust<'_>,
        now: i64,
    ) -> Result<Self> {
        let certificate = trust.verify(raw_certificate, now).map_err(error)?;
        if chain.chain_id.as_bytes() != trust.chain_id {
            return Err(error("bootstrap chain identity differs"));
        }
        bind_origin(&chain, &certificate)?;
        let head = checkpoint_head(&certificate)?;
        if hex::encode(state.root().map_err(error)?) != head.ledger_root {
            return Err(error("snapshot differs from authenticated checkpoint"));
        }
        let bootstrap = Bootstrap::new(raw_certificate, root_window, certificate)?;
        Self::initialize(path, chain, state, head, Some(bootstrap)).await
    }

    /// Reauthenticate a snapshot floor before restoring its canonical suffix.
    /// Expired download certificates remain valid historical finality evidence.
    /// This does not fall back to trusting locally edited HEAD metadata.
    pub async fn open_from_checkpoint(
        path: &Path,
        expected_chain: &ChainIdentity,
        trust: &Trust<'_>,
    ) -> Result<Self> {
        expected_chain.validate().map_err(error)?;
        if expected_chain.chain_id.as_bytes() != trust.chain_id {
            return Err(error("bootstrap chain identity differs"));
        }
        let pool = connect(path).await?;
        let row = sqlx::query("SELECT chain,anchor FROM node_identity WHERE id=0")
            .fetch_one(&pool)
            .await
            .map_err(error)?;
        let chain: ChainIdentity =
            serde_json::from_slice(row.try_get::<&[u8], _>("chain").map_err(error)?)
                .map_err(error)?;
        let anchor: Head =
            serde_json::from_slice(row.try_get::<&[u8], _>("anchor").map_err(error)?)
                .map_err(error)?;
        if &chain != expected_chain {
            return Err(error("canonical chain identity differs"));
        }
        let row = sqlx::query("SELECT certificate,roots FROM node_bootstrap WHERE id=0")
            .fetch_one(&pool)
            .await
            .map_err(error)?;
        let raw: Vec<u8> = row.try_get("certificate").map_err(error)?;
        let window: Vec<u8> = row.try_get("roots").map_err(error)?;
        let certificate = trust.verify_persisted(&raw).map_err(error)?;
        bind_origin(&chain, &certificate)?;
        if checkpoint_head(&certificate)? != anchor {
            return Err(error("persisted checkpoint anchor differs"));
        }
        let source = Arc::new(
            SqliteEpochSource::open_existing(pool.clone(), chain.clone(), anchor.cursor)
                .await
                .map_err(error)?,
        );
        let bootstrap = Some(Bootstrap::new(&raw, &window, certificate)?);
        let head_cache = Arc::new(HeadCache::new(anchor.clone()));
        let store = Self {
            pool,
            chain,
            anchor,
            bootstrap,
            source,
            head_cache,
            snapshots: Arc::default(),
        };
        store.verify_history().await?;
        let head = store.head().await?;
        let restored = reader::restore(&store.pool, &store.anchor).await?;
        if hex::encode(restored.root().map_err(error)?) != store.anchor.ledger_root {
            return Err(error("checkpoint state differs"));
        }
        if head == store.anchor {
            store.snapshots.remember(&store.anchor, restored)?;
        } else {
            // Authenticate the floor even when only the suffix is served, but
            // release its independent tree before restoring the current head.
            drop(restored);
        }
        store.snapshot().await?;
        store.index_vm_receipts().await?;
        store.index_transactions().await?;
        Ok(store)
    }

    pub fn checkpoint_parent(&self) -> Option<ParentCommit> {
        let anchor = self.bootstrap.as_ref()?.certificate.anchor()?.anchor();
        Some(ParentCommit {
            certificate: anchor.finalize.certificate(),
            validator_set: anchor.validator_set.clone(),
        })
    }
    pub fn checkpoint_root(&self, epoch: i64) -> Option<Vec<u8>> {
        let bootstrap = self.bootstrap.as_ref()?;
        if let Some((_, root)) = bootstrap.roots.iter().find(|(e, _)| *e == epoch) {
            return hex::decode(root).ok();
        }
        // Native Rule_graph permits its hard-coded activation anchors below an
        // authenticated history floor; arbitrary historical roots stay absent.
        octra_node_protocol::rules::root_after_floor(
            self.chain.chain_id.as_bytes(),
            self.anchor.cursor.epoch.0 as i64,
            epoch,
        )
        .and_then(|root| hex::decode(root).ok())
    }

    /// The finalized floor is retained separately from epoch events so extension
    /// consumers cannot mistake a snapshot for a complete pre-floor history.
    pub async fn checkpoint_certificate(&self) -> Result<Option<Vec<u8>>> {
        let present:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='node_bootstrap')")
            .fetch_one(&self.pool).await.map_err(error)?;
        if !present {
            return Ok(None);
        }
        sqlx::query_scalar("SELECT certificate FROM node_bootstrap WHERE id=0")
            .fetch_optional(&self.pool)
            .await
            .map_err(error)
    }
}

/// The native certificate remains the authority for imported state. This
/// additional local binding prevents mislabelling the configured history origin.
fn bind_origin(chain: &ChainIdentity, certificate: &VerifiedCertificate) -> Result<()> {
    let checkpoint = &certificate.draft().checkpoint;
    chain
        .bind_checkpoint(
            u64::try_from(checkpoint.epoch).map_err(error)?,
            StateRoot(hex_hash(
                std::str::from_utf8(&checkpoint.state_root).map_err(error)?,
            )?),
        )
        .map_err(error)
}
