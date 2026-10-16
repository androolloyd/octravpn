//! Durable address ownership prevents old kernel/NAT replies from crossing a
//! session boundary after process restart. Never clear this file while NAT
//! state for the dedicated interface can survive.
use anyhow::{ensure, Context, Result};
use octravpn_core::{ip_tunnel, session::SessionId};
use parking_lot::{Mutex, RwLock};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    net::Ipv4Addr,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

const MAGIC: &[u8; 8] = b"OVIPOWN1";
const HEADER: u64 = 40;
const RECORD: usize = 100;
const CAP: usize = 131_069;
type Owner = ([u8; 32], [u8; 32]);
struct State {
    file: File,
    tail: [u8; 32],
}
pub(super) struct Book {
    writer: Mutex<State>,
    rows: RwLock<BTreeMap<Ipv4Addr, Owner>>,
    failed: AtomicBool,
}
impl Book {
    #[cfg(not(unix))]
    pub(super) fn open(_: &Path, _: &[u8; 32]) -> Result<Self> {
        anyhow::bail!("durable VPN address ownership requires Unix writer locking")
    }
    #[cfg(unix)]
    #[expect(
        clippy::verbose_bit_mask,
        reason = "Keep explicit POSIX permission masks at the private-file security boundary."
    )]
    pub(super) fn open(path: &Path, server: &[u8; 32]) -> Result<Self> {
        let parent = path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent)?;
        let mut file: File = {
            use std::os::unix::fs::PermissionsExt;
            ensure!(
                std::fs::metadata(parent)?.permissions().mode() & 0o022 == 0,
                "VPN address-book parent is writable by another user"
            );
            let fd = rustix::fs::open(
                path,
                rustix::fs::OFlags::RDWR
                    | rustix::fs::OFlags::CREATE
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC
                    | rustix::fs::OFlags::NONBLOCK,
                rustix::fs::Mode::from_bits_truncate(0o600),
            )?;
            let file: File = fd.into();
            ensure!(
                file.metadata()?.is_file() && file.metadata()?.permissions().mode() & 0o077 == 0,
                "VPN address book must be a private regular file"
            );
            rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
                .context("VPN address book already in use")?;
            file
        };
        let size = file.metadata()?.len();
        ensure!(
            size <= HEADER + CAP as u64 * RECORD as u64,
            "VPN address book exceeds the address pool"
        );
        let mut header = [0; HEADER as usize];
        header[..8].copy_from_slice(MAGIC);
        header[8..].copy_from_slice(server);
        if size == 0 {
            file.write_all(&header)?;
            file.sync_all()?;
            File::open(parent)?.sync_all()?;
        } else {
            let mut saved = [0; HEADER as usize];
            file.read_exact(&mut saved)?;
            ensure!(
                saved == header,
                "VPN address book belongs to another server key or version"
            );
        }
        let mut rows = BTreeMap::new();
        let mut tail: [u8; 32] = Sha256::digest(header).into();
        let count = size.saturating_sub(HEADER) / RECORD as u64;
        for _ in 0..count {
            let mut record = [0; RECORD];
            file.read_exact(&mut record)?;
            let digest = Sha256::digest([tail.as_slice(), &record[..68]].concat());
            ensure!(
                record[68..] == digest[..],
                "VPN address-book checksum differs"
            );
            let address = Ipv4Addr::from(<[u8; 4]>::try_from(&record[..4])?);
            let session = <[u8; 32]>::try_from(&record[4..36])?;
            let key = <[u8; 32]>::try_from(&record[36..68])?;
            ensure!(
                address == ip_tunnel::address(&SessionId::new(session), &key),
                "VPN address-book binding differs"
            );
            ensure!(
                rows.insert(address, (session, key)).is_none(),
                "VPN address book contains a duplicate owner"
            );
            tail = digest.into();
        }
        let complete = HEADER + count * RECORD as u64;
        if size > 0 && size != complete {
            // A partial append cannot have returned fsync success and therefore
            // cannot have released a first packet to the kernel.
            file.set_len(complete)?;
            file.sync_all()?;
        }
        file.seek(SeekFrom::End(0))?;
        Ok(Self {
            writer: Mutex::new(State { file, tail }),
            rows: RwLock::new(rows),
            failed: AtomicBool::new(false),
        })
    }
    fn known(&self, address: Ipv4Addr, owner: Owner) -> Result<bool> {
        ensure!(
            !self.failed.load(Ordering::Acquire),
            "VPN address book unavailable after persistence failure"
        );
        let rows = self.rows.read();
        if let Some(previous) = rows.get(&address) {
            ensure!(*previous == owner, "VPN IP address collision");
            return Ok(true);
        }
        ensure!(rows.len() < CAP, "VPN address pool exhausted");
        Ok(false)
    }
    pub(super) async fn claim(
        self: &Arc<Self>,
        address: Ipv4Addr,
        session: &SessionId,
        key: &[u8; 32],
    ) -> Result<()> {
        let owner = (*session.as_bytes(), *key);
        // Existing packet paths never wait on another session's disk flush.
        if self.known(address, owner)? {
            return Ok(());
        }
        let book = self.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut state = book.writer.lock();
            if book.known(address, owner)? {
                return Ok(());
            }
            let mut record = [0; RECORD];
            record[..4].copy_from_slice(&address.octets());
            record[4..36].copy_from_slice(&owner.0);
            record[36..68].copy_from_slice(&owner.1);
            let digest: [u8; 32] =
                Sha256::digest([state.tail.as_slice(), &record[..68]].concat()).into();
            record[68..].copy_from_slice(&digest);
            if let Err(error) = state
                .file
                .write_all(&record)
                .and_then(|()| state.file.sync_all())
            {
                book.failed.store(true, Ordering::Release);
                return Err(error.into());
            }
            state.tail = digest;
            book.rows.write().insert(address, owner);
            Ok(())
        })
        .await?
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn private_directory() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }
    fn owner(n: u64) -> (SessionId, [u8; 32], Ipv4Addr) {
        let session = SessionId::from_u64(n);
        let key = [23; 32];
        let address = ip_tunnel::address(&session, &key);
        (session, key, address)
    }

    #[tokio::test]
    async fn restart_retains_ownership_and_refuses_a_real_pool_collision() {
        let directory = private_directory();
        let path = directory.path().join("owners.bin");
        let server = [11; 32];
        let mut seen = BTreeMap::new();
        let (a, b) = (0..=CAP as u64)
            .find_map(|n| {
                let (_, _, address) = owner(n);
                seen.insert(address, n).map(|old| (old, n))
            })
            .expect("finite pool must collide");
        let (session, key, address) = owner(a);
        let book = Arc::new(Book::open(&path, &server).unwrap());
        book.claim(address, &session, &key).await.unwrap();
        book.claim(address, &session, &key).await.unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            HEADER + RECORD as u64
        );
        assert!(
            Book::open(&path, &server).is_err(),
            "only one writer owns the transport"
        );
        drop(book);
        let book = Arc::new(Book::open(&path, &server).unwrap());
        let (collision, key, same_address) = owner(b);
        assert_eq!(same_address, address);
        assert!(book.claim(address, &collision, &key).await.is_err());
        book.claim(address, &session, &key).await.unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            HEADER + RECORD as u64
        );
    }

    #[tokio::test]
    async fn unused_partial_tail_recovers_but_a_complete_corrupt_record_never_does() {
        let directory = private_directory();
        let path = directory.path().join("owners.bin");
        let server = [11; 32];
        let (session, key, address) = owner(1);
        let book = Arc::new(Book::open(&path, &server).unwrap());
        book.claim(address, &session, &key).await.unwrap();
        drop(book);
        let complete = std::fs::read(&path).unwrap();
        {
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap();
            file.write_all(&[0x55; RECORD - 1]).unwrap();
            file.sync_all().unwrap();
        }
        drop(Book::open(&path, &server).unwrap());
        assert_eq!(std::fs::read(&path).unwrap(), complete);
        let mut corrupt = complete;
        corrupt[HEADER as usize + RECORD - 1] ^= 1;
        std::fs::write(&path, &corrupt).unwrap();
        assert!(Book::open(&path, &server).is_err());
        assert_eq!(
            std::fs::read(&path).unwrap(),
            corrupt,
            "corruption cannot reset ownership"
        );
    }

    #[test]
    fn server_identity_private_file_and_symlink_boundaries_are_preserved() {
        let directory = private_directory();
        let path = directory.path().join("owners.bin");
        drop(Book::open(&path, &[11; 32]).unwrap());
        let original = std::fs::read(&path).unwrap();
        assert!(Book::open(&path, &[12; 32]).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), original);
        let alias = directory.path().join("alias.bin");
        symlink(&path, &alias).unwrap();
        assert!(Book::open(&alias, &[11; 32]).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Book::open(&path, &[11; 32]).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(Book::open(&path, &[11; 32]).is_err());
    }
}
