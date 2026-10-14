#![cfg(unix)]
use octra_node_protocol::consensus::journal::JournalOwner;
use std::{
    fs,
    path::PathBuf,
    process::Command,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Barrier,
    },
};

static SERIAL: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "octra-journal-owner-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn probe(&self, busy: bool) {
        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "lock_probe_child", "--nocapture"])
            .env("OCTRA_JOURNAL_LOCK_PROBE", &self.0)
            .env("OCTRA_JOURNAL_LOCK_BUSY", busy.to_string())
            .status()
            .unwrap();
        assert!(status.success());
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn lock_probe_child() {
    let Some(path) = std::env::var_os("OCTRA_JOURNAL_LOCK_PROBE") else {
        return;
    };
    if std::env::var("OCTRA_JOURNAL_LOCK_BUSY").unwrap() == "true" {
        let error = JournalOwner::open(path).err().expect("lock must be held");
        assert_eq!(error.to_string(), "validator journal is already owned");
    } else {
        JournalOwner::open(path).expect("lock must be released");
    }
}

#[test]
fn exclusive_across_processes_and_until_workers_drain() {
    let dir = Temp::new();
    let owner = JournalOwner::open(&dir.0).unwrap();
    owner.set_floor(7).unwrap();
    assert!(JournalOwner::open(&dir.0).is_err());
    dir.probe(true);

    let barrier = Arc::new(Barrier::new(2));
    let worker_barrier = Arc::clone(&barrier);
    let worker_owner = owner.clone();
    let worker = std::thread::spawn(move || {
        worker_barrier.wait();
        worker_owner.set_floor(8).unwrap();
        // worker_owner retains the process lock through the fsync above.
    });
    drop(owner);
    dir.probe(true);
    barrier.wait();
    worker.join().unwrap();
    dir.probe(false);
    assert_eq!(
        JournalOwner::open(&dir.0).unwrap().floor().unwrap(),
        Some(8)
    );
}

#[test]
fn concurrent_floor_advancement_never_regresses() {
    let dir = Temp::new();
    let owner = JournalOwner::open(&dir.0).unwrap();
    owner.set_floor(0).unwrap();
    let worker_owner = owner.clone();
    let worker = std::thread::spawn(move || worker_owner.set_floor(100));
    let _ = owner.set_floor(50);
    worker.join().unwrap().unwrap();
    assert_eq!(owner.floor().unwrap(), Some(100));
    let pruned = owner.prune_finalized(100).unwrap();
    pruned.votes.unwrap();
    pruned.syncs.unwrap();
    assert_eq!(owner.floor().unwrap(), Some(100));
}

#[test]
fn refuses_symlinked_lock() {
    let dir = Temp::new();
    let target = dir.0.join("other");
    fs::write(&target, b"keep").unwrap();
    std::os::unix::fs::symlink(&target, dir.0.join("validator_journal.lock")).unwrap();
    assert!(JournalOwner::open(&dir.0).is_err());
    assert_eq!(fs::read(target).unwrap(), b"keep");
}
