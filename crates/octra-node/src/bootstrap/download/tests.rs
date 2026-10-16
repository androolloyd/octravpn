//! Download-cache mechanics only. The manifest trust boundary is qualified
//! separately; an unauthenticated cache never authorizes canonical state.
use super::*;
use crate::bootstrap::resume::{Cache, Workspace};
use octra_exex::{ChainIdentity, StateRoot};
use std::{fs, path::PathBuf};

const PART: usize = 1024 * 1024;
struct Fixture {
    directory: tempfile::TempDir,
    destination: PathBuf,
    chain: ChainIdentity,
    workspace: Arc<Workspace>,
    cache: Cache,
    descriptor: File,
    bytes: Vec<u8>,
}
fn fixture() -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let destination = directory.path().join("state");
    let chain = ChainIdentity::genesis("download-cache-test", StateRoot([7; 32]));
    let workspace = Arc::new(Workspace::open(&destination, &chain).unwrap());
    let cache = workspace.test_cache().unwrap();
    let bytes = [vec![1; PART], vec![2; PART]].concat();
    let digest = |bytes: &[u8]| hex::encode(Sha256::digest(bytes)).into_bytes();
    let descriptor = File {
        path: b"ledger.dat".to_vec(),
        size: bytes.len() as i64,
        sha256: digest(&bytes),
        chunks: bytes
            .chunks(PART)
            .enumerate()
            .map(|(index, bytes)| Chunk {
                index: index as i64,
                offset: (index * PART) as i64,
                size: bytes.len() as i64,
                sha256: digest(bytes),
            })
            .collect(),
    };
    Fixture {
        directory,
        destination,
        chain,
        workspace,
        cache,
        descriptor,
        bytes,
    }
}

#[test]
fn resume_rehashes_chunks_truncates_torn_tail_and_refuses_corrupt_completed_file() {
    let fixture = fixture();
    let writer = Writer::open(&fixture.descriptor, fixture.cache.clone())
        .unwrap()
        .unwrap();
    let writer = writer.append(fixture.bytes[..PART].to_vec()).unwrap();
    let part = writer.part.clone();
    drop(writer);
    fs::OpenOptions::new()
        .append(true)
        .open(&part)
        .unwrap()
        .write_all(b"torn unverified tail")
        .unwrap();
    let writer = Writer::open(&fixture.descriptor, fixture.cache.clone())
        .unwrap()
        .unwrap();
    assert_eq!(writer.offset, PART as i64);
    assert_eq!(fs::metadata(&part).unwrap().len(), PART as u64);
    assert_eq!(
        writer
            .append(fixture.bytes[PART..].to_vec())
            .unwrap()
            .finish()
            .unwrap(),
        PART as u64
    );
    let complete = fixture.cache.path().join("ledger.dat");
    assert_eq!(fs::read(&complete).unwrap(), fixture.bytes);
    assert!(Writer::open(&fixture.descriptor, fixture.cache.clone())
        .unwrap()
        .is_none());
    let mut corrupted = fixture.bytes.clone();
    corrupted[PART] ^= 1;
    fs::write(&complete, corrupted).unwrap();
    let writer = Writer::open(&fixture.descriptor, fixture.cache.clone())
        .unwrap()
        .unwrap();
    assert_eq!(writer.offset, 0);
    assert!(
        !complete.exists(),
        "a corrupt completed file cannot be reused"
    );
    assert!(writer
        .append(vec![0; fixture.bytes.len()])
        .unwrap()
        .finish()
        .is_err());
    assert!(
        !complete.exists(),
        "a wrong final digest cannot publish a cache file"
    );
}

#[cfg(unix)]
#[test]
fn partial_file_symlinks_hardlinks_and_public_permissions_fail_before_mutation() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    for mode in ["symlink", "hardlink", "permissions"] {
        let fixture = fixture();
        let target = fixture.directory.path().join("outside");
        fs::write(&target, b"preserve outside bytes").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        let part = fixture.cache.path().join("ledger.dat.part");
        match mode {
            "symlink" => symlink(&target, &part).unwrap(),
            "hardlink" => fs::hard_link(&target, &part).unwrap(),
            _ => {
                fs::write(&part, b"unverified prefix").unwrap();
                fs::set_permissions(&part, fs::Permissions::from_mode(0o644)).unwrap();
            }
        }
        assert!(
            Writer::open(&fixture.descriptor, fixture.cache.clone()).is_err(),
            "{mode}"
        );
        assert_eq!(fs::read(&target).unwrap(), b"preserve outside bytes");
    }
}

#[cfg(unix)]
#[tokio::test]
async fn cancelling_download_keeps_workspace_locked_until_owned_disk_write_finishes() {
    let fixture = fixture();
    let writer = Writer::open(&fixture.descriptor, fixture.cache.clone())
        .unwrap()
        .unwrap();
    let bytes = fixture.bytes[..PART].to_vec();
    let (entered, ready) = tokio::sync::oneshot::channel();
    let (release, waiting) = std::sync::mpsc::channel();
    let caller = tokio::spawn(async move {
        disk(move || {
            entered.send(()).unwrap();
            waiting.recv().unwrap();
            writer.append(bytes).map(drop)
        })
        .await
    });
    ready.await.unwrap();
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    let Fixture {
        directory: _directory,
        destination,
        chain,
        workspace,
        cache,
        descriptor,
        ..
    } = fixture;
    drop(cache);
    drop(workspace);
    assert!(Workspace::open(&destination, &chain).is_err());
    release.send(()).unwrap();
    let workspace = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(workspace) = Workspace::open(&destination, &chain) {
                break Arc::new(workspace);
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let writer = Writer::open(&descriptor, workspace.test_cache().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(
        writer.offset, PART as i64,
        "restart authenticates the completed chunk"
    );
}
