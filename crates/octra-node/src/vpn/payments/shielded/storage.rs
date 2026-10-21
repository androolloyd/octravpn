//! Shared operator/payer storage. SQLite sees only scoped pseudorandom tags and authenticated ciphertext.
//! Every financial update is one FULL-synchronous SQLite transaction. The
//! exclusive directory lease prevents independent writers sharing this book.
use anyhow::{ensure, Context, Result};
use octravpn_core::sealed::{Key, Protection};
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
    Sqlite, SqlitePool, Transaction,
};
use std::{
    fs::File,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use zeroize::Zeroizing;

pub(super) struct Disk {
    pub(super) pool: SqlitePool,
    key: Key,
    scope: [u8; 32],
    directory: File,
    _lease: File,
    database: File,
    path: PathBuf,
    failed: AtomicBool,
}
impl Disk {
    /// Keep acquisition failures attributable without logging book paths,
    /// encrypted record identities or financial contents.
    #[track_caller]
    pub(super) fn begin(
        &self,
    ) -> impl std::future::Future<Output = Result<Transaction<'_, Sqlite>>> + Send {
        let caller = std::panic::Location::caller();
        async move {
            self.pool.begin().await.with_context(|| {
                format!(
                    "open private book transaction at {}:{}",
                    caller.file(),
                    caller.line()
                )
            })
        }
    }
    pub(super) fn path(&self) -> &Path {
        &self.path
    }
    #[cfg(unix)]
    #[expect(
        clippy::verbose_bit_mask,
        reason = "Explicit POSIX private-file permission masks."
    )]
    pub(super) async fn open(path: &Path, key: Key, scope: [u8; 32], create: bool) -> Result<Self> {
        use rustix::fs::{flock, open, openat, FlockOperation, Mode, OFlags};
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        if create {
            std::fs::DirBuilder::new().mode(0o700).create(path)?;
        }
        let directory: File = open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?
        .into();
        ensure!(
            directory.metadata()?.permissions().mode() & 0o077 == 0,
            "private wallet directory permissions differ"
        );
        let flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        let create_flags = if create {
            OFlags::CREATE | OFlags::EXCL
        } else {
            OFlags::empty()
        };
        let lease: File = openat(
            &directory,
            "wallet.lock",
            flags | create_flags,
            Mode::from_bits_truncate(0o600),
        )?
        .into();
        Self::private_file(&lease, &directory)?;
        flock(&lease, FlockOperation::NonBlockingLockExclusive)
            .context("private wallet already in use")?;
        let database: File = openat(
            &directory,
            "wallet.sqlite",
            flags | create_flags,
            Mode::from_bits_truncate(0o600),
        )?
        .into();
        Self::private_file(&database, &directory)?;
        for name in ["wallet.sqlite-wal", "wallet.sqlite-shm"] {
            match openat(&directory, name, flags, Mode::empty()) {
                Ok(file) => Self::sidecar(&File::from(file), &directory)
                    .with_context(|| format!("invalid private wallet {name}"))?,
                Err(rustix::io::Errno::NOENT) => {}
                Err(error) => return Err(error.into()),
            }
        }
        let path = std::fs::canonicalize(path)?.join("wallet.sqlite");
        let options = SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(false)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Full)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(5));
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await?;
        let key = key.derive(b"wallet database", &scope)?;
        let result = Self {
            pool,
            key,
            scope,
            directory,
            _lease: lease,
            database,
            path,
            failed: AtomicBool::new(false),
        };
        result.check()?;
        if create {
            sqlx::query("CREATE TABLE wallet_records(kind INTEGER NOT NULL,tag BLOB NOT NULL CHECK(length(tag)=32),bucket BLOB NOT NULL CHECK(length(bucket)=32),value BLOB NOT NULL,PRIMARY KEY(kind,tag)) WITHOUT ROWID")
                .execute(&result.pool).await?;
            result.database.sync_all()?;
            result.directory.sync_all()?;
        }
        Ok(result)
    }
    #[cfg(unix)]
    fn private_file(file: &File, directory: &File) -> Result<()> {
        Self::private_metadata(&file.metadata()?, directory)
    }
    #[cfg(unix)]
    #[expect(
        clippy::verbose_bit_mask,
        reason = "Explicit POSIX private-file permission masks."
    )]
    fn private_metadata(meta: &std::fs::Metadata, directory: &File) -> Result<()> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        ensure!(
            meta.is_file()
                && meta.permissions().mode() & 0o077 == 0
                && meta.nlink() == 1
                && meta.uid() == directory.metadata()?.uid(),
            "private wallet file permissions differ"
        );
        Ok(())
    }
    #[cfg(unix)]
    fn sidecar(file: &File, directory: &File) -> Result<()> {
        use std::os::unix::fs::MetadataExt;
        // SQLite removes old WAL/SHM files on its worker's final close. If that
        // happens after preflight opens one, its descriptor has no pathname and
        // is equivalent to NOENT. Named sidecars still need every strict check.
        let meta = file.metadata()?;
        if meta.nlink() == 0 {
            return Ok(());
        }
        Self::private_metadata(&meta, directory)
    }
    #[cfg(not(unix))]
    pub(super) async fn open(_: &Path, _: Key, _: [u8; 32], _: bool) -> Result<Self> {
        anyhow::bail!("private wallets require Unix directory locking")
    }
    #[expect(
        clippy::verbose_bit_mask,
        reason = "Explicit POSIX private-file permission masks."
    )]
    pub(super) fn check(&self) -> Result<()> {
        ensure!(
            !self.failed.load(Ordering::Acquire),
            "private wallet requires recovery after an ambiguous write"
        );
        let meta = std::fs::symlink_metadata(&self.path)?;
        ensure!(
            meta.is_file() && !meta.file_type().is_symlink(),
            "private wallet database path changed"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let pinned = self.database.metadata()?;
            ensure!(
                meta.dev() == pinned.dev()
                    && meta.ino() == pinned.ino()
                    && meta.nlink() == 1
                    && meta.uid() == self.directory.metadata()?.uid()
                    && meta.permissions().mode() & 0o077 == 0,
                "private wallet database identity changed"
            );
        }
        Ok(())
    }
    pub(super) fn tag(&self, kind: u8, id: &[u8]) -> Result<[u8; 32]> {
        Ok(*self
            .key
            .derive_bytes(&[b"wallet tag ".as_slice(), &[kind]].concat(), id)?)
    }
    fn protection(&self, kind: u8, tag: &[u8; 32]) -> Result<Protection> {
        let mut hash = Sha256::new();
        hash.update(self.scope);
        hash.update([kind]);
        hash.update(tag);
        let scope: [u8; 32] = hash.finalize().into();
        Ok(Protection::new(
            self.key.derive(b"wallet row", &scope)?,
            scope,
        ))
    }
    pub(super) fn encode<T: Serialize>(
        &self,
        kind: u8,
        tag: &[u8; 32],
        record: &T,
    ) -> Result<Vec<u8>> {
        let plain = Zeroizing::new(serde_json::to_vec(record)?);
        ensure!(plain.len() <= 131_072, "private wallet row exceeds bound");
        self.protection(kind, tag)?.seal(&plain)
    }
    pub(super) fn decode<T: DeserializeOwned>(
        &self,
        kind: u8,
        tag: &[u8; 32],
        raw: &[u8],
    ) -> Result<T> {
        ensure!(
            raw.len() <= 131_072 + octravpn_core::sealed::OVERHEAD,
            "private wallet row exceeds bound"
        );
        let plain = self.protection(kind, tag)?.open(raw)?;
        serde_json::from_slice(&plain).map_err(|_| anyhow::anyhow!("invalid private wallet record"))
    }
    pub(super) async fn load<T: DeserializeOwned>(
        &self,
        tx: &mut Transaction<'_, Sqlite>,
        kind: u8,
        tag: &[u8; 32],
    ) -> Result<Option<T>> {
        let raw: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT value FROM wallet_records WHERE kind=? AND tag=?")
                .bind(i64::from(kind))
                .bind(tag.as_slice())
                .fetch_optional(&mut **tx)
                .await?;
        raw.map(|raw| self.decode(kind, tag, &raw)).transpose()
    }
    pub(super) async fn insert<T: Serialize>(
        &self,
        tx: &mut Transaction<'_, Sqlite>,
        kind: u8,
        tag: &[u8; 32],
        bucket: &[u8; 32],
        record: &T,
    ) -> Result<()> {
        let value = self.encode(kind, tag, record)?;
        sqlx::query("INSERT INTO wallet_records VALUES(?,?,?,?)")
            .bind(i64::from(kind))
            .bind(tag.as_slice())
            .bind(bucket.as_slice())
            .bind(value)
            .execute(&mut **tx)
            .await?;
        Ok(())
    }
    pub(super) async fn replace<T: Serialize>(
        &self,
        tx: &mut Transaction<'_, Sqlite>,
        kind: u8,
        tag: &[u8; 32],
        record: &T,
    ) -> Result<()> {
        let value = self.encode(kind, tag, record)?;
        ensure!(
            sqlx::query("UPDATE wallet_records SET value=? WHERE kind=? AND tag=?")
                .bind(value)
                .bind(i64::from(kind))
                .bind(tag.as_slice())
                .execute(&mut **tx)
                .await?
                .rows_affected()
                == 1,
            "private wallet record disappeared"
        );
        Ok(())
    }
    pub(super) async fn commit(&self, tx: Transaction<'_, Sqlite>) -> Result<()> {
        if let Err(error) = tx.commit().await {
            self.failed.store(true, Ordering::Release);
            return Err(error.into());
        }
        if let Err(error) = self.check() {
            self.failed.store(true, Ordering::Release);
            return Err(error);
        }
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    #[test]
    fn sidecar_cleanup_race_does_not_accept_insecure_named_files() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let directory = File::open(root.path()).unwrap();
        let path = root.path().join("wallet.sqlite-wal");
        let file = File::create(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        Disk::sidecar(&file, &directory).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Disk::sidecar(&file, &directory).is_err());
        std::fs::hard_link(&path, root.path().join("linked")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(Disk::sidecar(&file, &directory).is_err());
        std::fs::remove_file(root.path().join("linked")).unwrap();
        std::fs::remove_file(&path).unwrap();
        Disk::sidecar(&file, &directory).unwrap();
        assert!(
            Disk::private_file(&file, &directory).is_err(),
            "database and lease must never accept an unlinked descriptor"
        );
    }
    #[tokio::test]
    async fn private_rows_refuse_wrong_key_scope_row_swaps_and_corruption() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("wallet");
        let key = Key::from_bytes([6; 32]);
        let disk = Disk::open(&path, key.clone(), [7; 32], true).await.unwrap();
        assert!(Disk::open(&path, key.clone(), [7; 32], false)
            .await
            .is_err());
        let message = "relationship, invoice and purchased byte counters".to_owned();
        let first = disk.encode(1, &[8; 32], &message).unwrap();
        assert_ne!(first, disk.encode(1, &[8; 32], &message).unwrap());
        assert!(!first
            .windows(message.len())
            .any(|v| v == message.as_bytes()));
        assert!(disk.decode::<String>(2, &[8; 32], &first).is_err());
        assert!(disk.decode::<String>(1, &[9; 32], &first).is_err());
        let mut tx = disk.pool.begin().await.unwrap();
        disk.insert(&mut tx, 0, &[0; 32], &[0; 32], &message)
            .await
            .unwrap();
        disk.commit(tx).await.unwrap();
        disk.pool.close().await;
        drop(disk);
        for (key, scope) in [(Key::from_bytes([5; 32]), [7; 32]), (key.clone(), [6; 32])] {
            let wrong = Disk::open(&path, key, scope, false).await.unwrap();
            let mut tx = wrong.pool.begin().await.unwrap();
            assert!(wrong.load::<String>(&mut tx, 0, &[0; 32]).await.is_err());
            tx.rollback().await.unwrap();
            wrong.pool.close().await;
        }
        let disk = Disk::open(&path, key, [7; 32], false).await.unwrap();
        let mut tx = disk.pool.begin().await.unwrap();
        assert_eq!(
            disk.load::<String>(&mut tx, 0, &[0; 32]).await.unwrap(),
            Some(message)
        );
        tx.rollback().await.unwrap();
        let mut corrupt = first;
        corrupt[40] ^= 1;
        assert!(disk.decode::<String>(1, &[8; 32], &corrupt).is_err());
        disk.pool.close().await;
    }

    #[tokio::test]
    async fn missing_lease_and_replaced_database_refuse_counter_reset() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("wallet");
        let key = Key::from_bytes([6; 32]);
        assert!(Disk::open(&path, key.clone(), [7; 32], false)
            .await
            .is_err());
        assert!(!path.exists());
        let disk = Disk::open(&path, key.clone(), [7; 32], true).await.unwrap();
        disk.pool.close().await;
        drop(disk);
        std::fs::remove_file(path.join("wallet.lock")).unwrap();
        assert!(Disk::open(&path, key.clone(), [7; 32], false)
            .await
            .is_err());
        assert!(!path.join("wallet.lock").exists());
        let linked = root.path().join("linked");
        symlink(&path, &linked).unwrap();
        assert!(Disk::open(&linked, key.clone(), [7; 32], false)
            .await
            .is_err());
        let other = root.path().join("other");
        let disk = Disk::open(&other, key, [7; 32], true).await.unwrap();
        let original = other.join("wallet.sqlite");
        std::fs::rename(&original, other.join("retained.sqlite")).unwrap();
        std::fs::write(&original, b"replacement").unwrap();
        assert!(disk.check().is_err());
        disk.pool.close().await;
    }
}
