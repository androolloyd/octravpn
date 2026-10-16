//! Observational legacy Tree lifecycle, independent of canonical commitments.
use anyhow::{ensure, Context, Result};
use octra_node_protocol::{
    consensus::{codec::Wire, Finalize},
    legacy_tree::{self, Tree},
    native_integer::parse_int63,
    native_json::Document,
    transaction::{Nonce, Transaction},
};
use octra_node_runtime::{canonical::Head, state_batch::Snapshot};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    pub epoch: i64,
    pub roots: i64,
}
struct Pending {
    head: Head,
    digest: Option<Vec<u8>>,
}
pub(crate) struct State {
    head: Head,
    tree: Tree,
    pending: Option<Pending>,
    unavailable: Option<String>,
    metrics: octra_node_protocol::metrics::Stats,
}
fn next(head: &Head) -> Result<Nonce> {
    Ok(Nonce::new(i64::try_from(head.cursor.epoch.0)?)?.successor())
}
impl State {
    pub(crate) fn boot(head: Head, state: &Snapshot, genesis_parent: bool) -> Result<Self> {
        let epoch = if let Some(raw) = state.get(&[b"meta", b"last_epoch"]) {
            Nonce::new(parse_int63(raw).context("invalid legacy startup epoch")?)?.successor()
        } else if head.cursor.sequence.0 > 0 {
            next(&head)?
        } else {
            Nonce::default()
        };
        // Startup_runtime_boot_shell uses GENESIS only when neither a retained
        // epoch nor a history floor exists. Older Rust histories did not retain
        // the legacy JSON digest; a checkpoint QC is a separate commitment.
        let tree = if genesis_parent {
            Tree::create(epoch, b"GENESIS".to_vec())
        } else {
            Tree::unbound(epoch)
        };
        Ok(Self {
            head,
            tree,
            pending: None,
            unavailable: None,
            metrics: octra_node_protocol::metrics::Stats::default(),
        })
    }
    fn reconcile(&mut self, head: &Head) -> Result<()> {
        if &self.head == head {
            return Ok(());
        }
        if self
            .pending
            .as_ref()
            .is_some_and(|pending| &pending.head == head)
        {
            self.committed(head);
        }
        ensure!(&self.head == head, "legacy observation head differs");
        Ok(())
    }
    pub(crate) fn status(&mut self, head: &Head) -> Result<Status> {
        self.reconcile(head)?;
        if let Some(error) = &self.unavailable {
            anyhow::bail!("{error}")
        }
        Ok(Status {
            epoch: self.tree.epoch_id.get(),
            roots: self.tree.root_count().get(),
        })
    }
    pub(crate) fn prepare(
        &mut self,
        base: &Head,
        head: Head,
        certificate: &[u8],
        raws: &[Vec<u8>],
    ) {
        let result = (|| -> Result<Option<Vec<u8>>> {
            if let Some(reason) = &self.unavailable {
                anyhow::bail!("{reason}");
            }
            self.reconcile(base)?;
            let finalized = Finalize::decode(certificate)?;
            ensure!(
                finalized.epoch_id as u64 == head.cursor.epoch.0,
                "legacy observation epoch differs"
            );
            let transactions = raws
                .iter()
                .map(|raw| {
                    Transaction::from_document(&Document::parse(raw)?).map_err(anyhow::Error::from)
                })
                .collect::<Result<Vec<_>>>()?;
            match self.tree.finalize_epoch(
                Nonce::new(finalized.epoch_id)?,
                &finalized.header.creator_addr,
                base.ledger_root.as_bytes().to_vec(),
                finalized.header.ts,
                &transactions,
            ) {
                Ok(digest) => Ok(Some(digest)),
                Err(legacy_tree::Error::ParentUnavailable) => Ok(None),
                Err(error) => Err(error.into()),
            }
        })();
        let digest = match result {
            Ok(digest) => {
                self.unavailable = None;
                digest
            }
            Err(error) => {
                self.unavailable = Some(error.to_string());
                None
            }
        };
        self.pending = Some(Pending { head, digest });
    }

    pub(crate) fn pending_digest(&self, head: &Head) -> Option<Vec<u8>> {
        self.pending
            .as_ref()
            .filter(|pending| pending.head == *head)
            .and_then(|pending| pending.digest.clone())
    }

    /// Restore only a digest retained by the matching canonical epoch journal.
    pub(crate) fn restore_parent(&mut self, head: &Head, digest: &[u8]) -> Result<()> {
        ensure!(
            self.head == *head && self.pending.is_none(),
            "legacy restart head differs"
        );
        ensure!(
            digest.len() == 64
                && digest
                    .iter()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)),
            "invalid legacy restart digest"
        );
        self.tree = Tree::create(self.tree.epoch_id, digest.to_vec());
        Ok(())
    }
    /// Native cleanup runs only after the commit returns successfully. Failures
    /// abort the storage batch and schedule exit; they never reset Tree here.
    pub(crate) fn committed(&mut self, head: &Head) {
        if head.cursor.sequence.0 < self.head.cursor.sequence.0 || &self.head == head {
            return;
        }
        let digest = self
            .pending
            .take()
            .filter(|pending| pending.head == *head)
            .and_then(|pending| pending.digest);
        match next(head) {
            Ok(epoch) => {
                self.tree = match digest {
                    Some(digest) => Tree::create(epoch, digest),
                    None => Tree::unbound(epoch),
                };
                self.head = head.clone();
                self.unavailable = None;
            }
            Err(error) => self.unavailable = Some(error.to_string()),
        }
    }
    pub(crate) fn failed(&mut self, error: String) {
        self.pending = None;
        self.tree = Tree::unbound(self.tree.epoch_id);
        self.unavailable = Some(error);
    }
    pub(crate) fn observe_metrics(&mut self, epoch: &octra_node_protocol::metrics::Epoch) {
        self.metrics.observe(epoch, || {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|v| v.as_secs_f64())
                .unwrap_or_default()
        });
    }
    pub(crate) fn metrics(&self) -> Result<Vec<u8>> {
        Ok(self.metrics.to_json()?)
    }
}
