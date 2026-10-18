//! The adopted Vote_floor plan, using the shared durable anti-equivocation log.
//! The offline command additionally holds the launcher's store ownership lock.
use super::{canonical_owner, directory, existing_file, NativeDirectoryOwner};
use anyhow::{bail, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::Args;
use octra_node_protocol::{
    consensus::{
        codec::{self, Wire},
        hash,
        journal::JournalOwner,
        pending_log::PendingCommit,
        vote_log::VoteLog,
        RoundSync, Vote, VoteType,
    },
    native_integer, oce1,
    state_sync::head::Head,
    transaction::address_from_public_key,
};
use octra_node_runtime::canonical::OfflineStore;
use std::{fs, io::Read, path::PathBuf};

#[derive(Args)]
pub struct VoteFloor {
    #[arg(long, allow_hyphen_values = true)]
    pub data_dir: PathBuf,
    #[arg(long, allow_hyphen_values = true)]
    pub chain_id: String,
    #[arg(long, allow_hyphen_values = true)]
    pub validator: String,
    #[arg(long, allow_hyphen_values = true)]
    pub validator_pub: String,
    #[arg(long, allow_hyphen_values = true)]
    pub head_epoch: String,
    #[arg(long, allow_hyphen_values = true)]
    pub round: Option<String>,
    #[arg(long, allow_hyphen_values = true)]
    pub round_min: Option<String>,
    #[arg(long, allow_hyphen_values = true)]
    pub round_sync: Option<String>,
    #[arg(long)]
    pub check: bool,
    #[arg(long)]
    pub staged: bool,
    #[arg(long)]
    pub prepared: bool,
    /// Use current canonical.sqlite instead of the native HEAD.json layout.
    #[arg(long)]
    pub canonical: bool,
}
struct Request {
    epoch: i64,
    round: i64,
    public: Vec<u8>,
}
impl VoteFloor {
    pub async fn run(&self) -> Result<i32> {
        match self.execute().await {
            Ok(marked) => {
                println!(
                    "status = {} head_epoch = {} round = {marked}",
                    if self.check {
                        "vote_floor_checked"
                    } else {
                        "vote_floor_ready"
                    },
                    self.head_epoch_number()?
                );
                Ok(0)
            }
            Err(error) => {
                eprintln!("status = refused reason = {error}");
                Ok(1)
            }
        }
    }
    fn head_epoch_number(&self) -> Result<i64> {
        native_integer::parse_int64(self.head_epoch.as_bytes())
            .context("vote floor arguments are invalid")
    }
    fn request(&self) -> Result<Request> {
        ensure!(!self.data_dir.as_os_str().is_empty(), "empty --data-dir");
        for (key, value) in [
            ("--chain-id", self.chain_id.as_str()),
            ("--validator", self.validator.as_str()),
            ("--validator-pub", self.validator_pub.as_str()),
            ("--head-epoch", self.head_epoch.as_str()),
        ] {
            ensure!(!value.is_empty(), "empty {key}");
        }
        let minimum = match &self.round_min {
            None => 0,
            Some(raw) => native_integer::parse_int63(raw.as_bytes())
                .filter(|v| (0..=codec::MAX_ROUND).contains(v))
                .context("round minimum is invalid")?,
        };
        let source = match (&self.round, &self.round_sync) {
            (Some(raw), None) if !raw.is_empty() => Ok(Some(raw)),
            (None, Some(raw)) if !raw.is_empty() => Ok(None),
            (Some(_), Some(_)) => Err(anyhow::anyhow!("round source is ambiguous")),
            _ => Err(anyhow::anyhow!("missing round source")),
        }?;
        let epoch = self.head_epoch_number()?;
        let public = STANDARD
            .decode(&self.validator_pub)
            .map_err(|_| anyhow::anyhow!("vote floor arguments are invalid"))?;
        ensure!(
            !(self.staged && self.prepared),
            "staged and prepared checks are exclusive"
        );
        if self.staged {
            ensure!(self.check, "staged check requires --check");
            ensure!(source.is_some(), "staged check requires round");
        }
        if self.prepared {
            ensure!(self.check, "prepared check requires --check");
            ensure!(source.is_some(), "prepared check requires round");
        }
        let round = if let Some(raw) = source {
            native_integer::parse_int63(raw.as_bytes())
                .context("vote floor arguments are invalid")?
        } else {
            sync_round(self, &public, epoch.wrapping_add(1))?.max(minimum)
        };
        ensure!(
            epoch >= 0 && epoch != i64::MAX,
            "vote floor epoch is invalid"
        );
        ensure!(
            (0..=codec::MAX_ROUND).contains(&round),
            "vote floor round is invalid"
        );
        Ok(Request {
            epoch,
            round,
            public,
        })
    }
    async fn execute(&self) -> Result<i64> {
        let request = self.request()?;
        let path = directory(&self.data_dir)?;
        if self.canonical {
            let owner = canonical_owner(&path)?;
            let store = OfflineStore::open(&path.join("canonical.sqlite")).await?;
            let result = (|| {
                ensure!(
                    store.chain().chain_id == self.chain_id,
                    "vote floor chain does not match local canonical chain"
                );
                ensure!(
                    i64::try_from(store.head().cursor.epoch.0)? == request.epoch,
                    "head epoch does not match local finalized head"
                );
                plan(self, &request, &owner.journal)
            })();
            store.close().await;
            result
        } else {
            ensure!(
                !path.join("canonical.sqlite").try_exists()?,
                "native vote floor refuses current canonical storage"
            );
            // This is the exact directory inode locked by native Store_chaindata.
            // Retain both owners until all fsynced journal operations finish.
            let _native_owner = NativeDirectoryOwner::acquire(&path.join("chaindata"))?;
            let journal = JournalOwner::open(&path)?;
            let head = path.join("HEAD.json");
            match fs::symlink_metadata(&head) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    bail!("local finalized head is missing")
                }
                Err(error) => return Err(error.into()),
                Ok(_) => (),
            }
            existing_file(&head)?;
            let mut bytes = Vec::new();
            fs::File::open(&head)?
                .take(octra_node_protocol::state_sync::head::MAX_BYTES as u64 + 1)
                .read_to_end(&mut bytes)?;
            let head = Head::parse(&bytes)
                .map_err(|_| anyhow::anyhow!("local finalized head is invalid"))?;
            ensure!(
                head.epoch_id == request.epoch,
                "head epoch does not match local finalized head"
            );
            plan(self, &request, &journal)
        }
    }
}
fn sync_round(options: &VoteFloor, public: &[u8], epoch: i64) -> Result<i64> {
    let encoded = options
        .round_sync
        .as_ref()
        .context("missing round source")?;
    let wire = STANDARD
        .decode(encoded)
        .map_err(|_| anyhow::anyhow!("round sync base64 decode failed"))?;
    let sync =
        RoundSync::decode(&wire).map_err(|_| anyhow::anyhow!("round sync wire decode failed"))?;
    ensure!(sync.encode()? == wire, "round sync wire is not exact");
    ensure!(
        sync.chain_id == options.chain_id.as_bytes(),
        "round sync chain does not match"
    );
    ensure!(sync.epoch_id == epoch, "round sync epoch does not match");
    ensure!(!sync.request, "round sync is a request");
    ensure!(
        sync.validator == options.validator.as_bytes(),
        "round sync validator does not match"
    );
    ensure!(
        hash::verify_round_sync(public, &sync)?,
        "round sync signature is invalid"
    );
    Ok(sync.round)
}
fn current_vote(
    options: &VoteFloor,
    request: &Request,
    entry: PendingCommit,
) -> Result<Option<Vote>> {
    ensure!(entry.epoch_id >= 0, "pending vote epoch is invalid");
    let epoch = request.epoch + 1;
    ensure!(
        entry.epoch_id <= epoch,
        "pending consensus vote exceeds current epoch"
    );
    if entry.epoch_id != epoch {
        return Ok(None);
    }
    ensure!(
        entry.validator_addr == options.validator.as_bytes(),
        "pending vote validator does not match"
    );
    ensure!(
        (0..=codec::MAX_ROUND).contains(&entry.round),
        "pending vote round is invalid"
    );
    let encoded = entry
        .vote_b64
        .context("pending vote has no stored precommit")?;
    let wire = STANDARD
        .decode(encoded)
        .map_err(|_| anyhow::anyhow!("pending vote base64 decode failed"))?;
    let vote =
        Vote::decode(&wire).map_err(|_| anyhow::anyhow!("pending vote wire decode failed"))?;
    ensure!(vote.encode()? == wire, "pending vote wire is not exact");
    ensure!(
        vote.chain_id == options.chain_id.as_bytes(),
        "pending vote chain does not match"
    );
    ensure!(
        vote.validator == options.validator.as_bytes(),
        "pending vote signer does not match"
    );
    ensure!(vote.epoch_id == epoch, "pending vote epoch does not match");
    ensure!(
        vote.round == entry.round,
        "pending vote round does not match"
    );
    ensure!(
        vote.vote_type == VoteType::Precommit,
        "pending vote type is invalid"
    );
    ensure!(
        hex::encode(oce1::hash32_bytes(&vote.proposal_id)?)
            == std::str::from_utf8(&entry.proposal_id)?,
        "pending vote proposal does not match"
    );
    ensure!(
        hash::verify_vote(&request.public, &vote)?,
        "pending vote signature is invalid"
    );
    Ok(Some(vote))
}
fn plan(options: &VoteFloor, request: &Request, journal: &JournalOwner) -> Result<i64> {
    ensure!(
        request.public.len() == 32,
        "validator public key is invalid"
    );
    ensure!(
        address_from_public_key(STANDARD.encode(&request.public).as_bytes())
            == options.validator.as_bytes(),
        "validator public key does not match address"
    );
    let mut memory = VoteLog::memory();
    let mut votes = Vec::new();
    for entry in journal.pending()? {
        if let Some(vote) = current_vote(options, request, entry)? {
            memory.keep(vote.clone())?;
            // Native fold prepends; preserve its later disk-check/write order.
            votes.insert(0, vote);
        }
    }
    for vote in &votes {
        journal.check_vote(vote)?;
    }
    let epoch = request.epoch + 1;
    let prior = journal.max_round(
        options.chain_id.as_bytes(),
        options.validator.as_bytes(),
        epoch,
    )?;
    let marked = votes.iter().fold(
        prior.unwrap_or(request.round).max(request.round),
        |highest, vote| highest.max(vote.round),
    );
    if options.prepared || options.staged {
        ensure!(
            marked == request.round,
            "vote floor round does not match staged round"
        );
        ensure!(
            journal
                .round_mark()?
                .is_some_and(|m| m.epoch_id == epoch && m.round == request.round),
            "vote floor round is not prepared"
        );
        if options.staged {
            ensure!(
                journal.floor()? == Some(request.epoch),
                "vote floor is not staged"
            );
        }
    } else if !options.check {
        for vote in votes {
            journal.keep_vote(vote)?;
        }
        journal.set_round_mark(epoch, marked)?;
        journal.set_floor(request.epoch)?;
    }
    Ok(marked)
}
