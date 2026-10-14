//! Exclusive validator journal ownership shared by all persistence workers.
//!
//! Clone the owner into a worker before spawning it. The lock remains held until
//! the last worker exits, even when its caller is cancelled or the driver stops.
use super::{
    journal_io as io,
    pending_log::{PendingCommit, PendingLog},
    relief::Mark,
    relief_log::ReliefLog,
    sync_log::SyncLog,
    vote_log::{Position, VoteLog},
    Error, RoundSync, Vote,
};
use std::{
    fs::File,
    path::Path,
    sync::{Arc, Mutex, MutexGuard},
};

struct Journals {
    votes: VoteLog,
    syncs: SyncLog,
    relief: ReliefLog,
    pending: PendingLog,
}
struct Owned {
    journals: Mutex<Journals>,
    // Drop after the journal state. Never unlink: the inode identifies the lock.
    _lock: File,
}

#[derive(Clone)]
pub struct JournalOwner(Arc<Owned>);

pub struct Pruned {
    /// Failure blocks local voting until the durable floor is repaired.
    pub votes: Result<(), Error>,
    /// Native round-sync cleanup failures are reported independently.
    pub syncs: Result<(), Error>,
    /// Relief retention failures are independent of the local voting floor.
    pub relief: Result<(), Error>,
}

impl JournalOwner {
    /// Acquire the process lock before opening any signing or recovery journal.
    #[cfg(unix)]
    pub fn open(data_dir: impl AsRef<Path>) -> Result<Self, Error> {
        use rustix::fs::{flock, open, FlockOperation, Mode, OFlags};
        let path = data_dir.as_ref();
        io::directory(path, "validator journal")?;
        let lock: File = open(
            path.join("validator_journal.lock"),
            OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|e| io::io_error(e.into()))?
        .into();
        if !lock.metadata().map_err(io::io_error)?.is_file() {
            return Err("validator journal lock is not regular".into());
        }
        flock(&lock, FlockOperation::NonBlockingLockExclusive).map_err(|e| {
            if e == rustix::io::Errno::WOULDBLOCK {
                Error::from("validator journal is already owned")
            } else {
                io::io_error(e.into())
            }
        })?;
        io::sync_directory(path)?;
        Ok(Self(Arc::new(Owned {
            journals: Mutex::new(Journals {
                votes: VoteLog::disk(path),
                syncs: SyncLog::disk(path),
                relief: ReliefLog::disk(path),
                pending: PendingLog::disk(path),
            }),
            _lock: lock,
        })))
    }

    #[cfg(not(unix))]
    pub fn open(_data_dir: impl AsRef<Path>) -> Result<Self, Error> {
        Err("validator journal locking requires a supported Unix host".into())
    }

    fn state(&self) -> Result<MutexGuard<'_, Journals>, Error> {
        self.0
            .journals
            .lock()
            .map_err(|_| Error::from("validator journal worker panicked"))
    }

    pub fn floor(&self) -> Result<Option<i64>, Error> {
        self.state()?.votes.floor()
    }
    pub fn set_floor(&self, epoch: i64) -> Result<(), Error> {
        self.state()?.votes.set_floor(epoch)
    }
    pub fn round_mark(&self) -> Result<Option<Position>, Error> {
        self.state()?.votes.round_mark()
    }
    pub fn set_round_mark(&self, epoch: i64, round: i64) -> Result<(), Error> {
        self.state()?.votes.set_round_mark(epoch, round)
    }
    pub fn check_vote(&self, vote: &Vote) -> Result<(), Error> {
        self.state()?.votes.check(vote)
    }
    pub fn keep_vote(&self, vote: Vote) -> Result<Vote, Error> {
        self.state()?.votes.keep(vote)
    }
    pub fn find_vote(&self, expected: &Vote) -> Result<Option<Vote>, Error> {
        self.state()?.votes.find_statement(expected)
    }
    pub fn max_round(
        &self,
        chain: &[u8],
        validator: &[u8],
        epoch: i64,
    ) -> Result<Option<i64>, Error> {
        self.state()?.votes.max_round(chain, validator, epoch)
    }
    pub fn keep_sync(&self, sync: RoundSync, public: &[u8]) -> Result<RoundSync, Error> {
        self.state()?.syncs.keep(sync, public)
    }
    pub fn load_syncs(
        &self,
        chain: &[u8],
        validator: &[u8],
        epoch: i64,
        public: &[u8],
    ) -> Result<Vec<RoundSync>, Error> {
        self.state()?.syncs.load(chain, validator, epoch, public)
    }

    /// The consensus host authenticates the plan before keep and after restore.
    pub fn keep_relief(&self, mark: Mark) -> Result<Mark, Error> {
        self.state()?.relief.keep(mark)
    }
    pub fn latest_relief(&self, through_height: i64) -> Result<Option<Mark>, Error> {
        self.state()?.relief.latest(through_height)
    }

    /// Speculative recovery data must be durable before publishing a precommit.
    pub fn keep_pending(&self, record: &PendingCommit) -> Result<(), Error> {
        self.state()?.pending.keep(record)
    }
    pub fn pending(&self) -> Result<Vec<PendingCommit>, Error> {
        self.state()?.pending.read()
    }
    pub fn delete_pending(&self, epoch: i64, round: i64) -> Result<(), Error> {
        self.state()?.pending.delete(epoch, round)
    }
    /// The host calls this only after the canonical epoch effects are durable.
    pub fn delete_pending_epoch(&self, epoch: i64) -> Result<(), Error> {
        self.state()?.pending.delete_epoch(epoch)
    }

    /// Preserve the finalized epoch's votes for parent certificates, and remove
    /// its round-sync witnesses. Advance the floor before deleting any votes.
    pub fn prune_finalized(&self, finalized: i64) -> Result<Pruned, Error> {
        let mut state = self.state()?;
        let votes = state
            .votes
            .set_floor(finalized)
            .and_then(|()| state.votes.prune(finalized.wrapping_sub(1)));
        let syncs = state.syncs.prune(finalized);
        let relief = state.relief.prune(finalized);
        Ok(Pruned {
            votes,
            syncs,
            relief,
        })
    }
}
