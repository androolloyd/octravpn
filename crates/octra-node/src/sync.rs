//! Consecutive certificate-based recovery. Peer head advertisements select
//! sources only: every epoch still passes historical QC and execution checks.
use crate::{import::Executor, Host, Node};
use anyhow::{Context, Result};
use octra_node_protocol::consensus::{codec::Wire, driver_policy};
use octra_node_runtime::{
    bundle_queries::{self, Bundles},
    canonical::Head,
    epoch_roots::{self, EpochRoots, WaitFor},
    finality_queries::{self, Finality},
};
use std::time::Duration;
use tokio::time::Instant;

pub struct Peers<'a, R, F, B> {
    pub roots: &'a EpochRoots<R>,
    pub finality: &'a Finality<F>,
    pub bundles: &'a Bundles<B>,
}
pub struct Progress {
    pub head: Head,
    pub reached: bool,
}

impl<A: Host> Node<A> {
    /// Recover using native weighted range agreement and shared prefixes. Each
    /// record is executed against its actual parent; a later failure retains
    /// the committed prefix and leaves application/VPN admission suspended.
    pub async fn catch_up_range<F: finality_queries::Host>(
        &self,
        target: u64,
        peers: &Finality<F>,
        executor: &impl Executor,
        network_seconds: f64,
    ) -> Result<Progress> {
        use octra_node_protocol::{
            consensus::catchup, native_json::Document, transaction::Transaction,
        };
        anyhow::ensure!(
            target < (1_u64 << 62),
            "catch-up target exceeds canonical epoch range"
        );
        let _sync = self.syncing.lock().await;
        let mut head = self.head().await?;
        if head.cursor.epoch.0 >= target {
            return Ok(Progress {
                head,
                reached: true,
            });
        }
        self.suspend("catching up canonical history");
        while head.cursor.epoch.0 < target {
            let from = (head.cursor.epoch.0 + 1) as i64;
            let max = (target - head.cursor.epoch.0).min(catchup::RANGE_EPOCHS as u64) as i64;
            let response = peers
                .query_range(from, max, network_seconds, |response| {
                    // Native peer range validation checks payload commitments and
                    // continuity here; QCs and historical rules are checked at
                    // actual execution time, before any state can be published.
                    if !catchup::valid_chunk_first_epoch(&response.status, &response.records, from)
                        || catchup::verify_chain_continuity(
                            &response.records,
                            from,
                            &head.cursor.state_root.0,
                        )
                        .is_err()
                    {
                        return Ok(false);
                    }
                    for record in &response.records {
                        let hashes = record
                            .txs_json
                            .iter()
                            .map(|bytes| {
                                let doc = Document::parse(bytes).map_err(|e| e.to_string())?;
                                Transaction::from_document(&doc)
                                    .and_then(|tx| tx.hash())
                                    .map(|hash| hash.to_vec())
                                    .map_err(|e| e.to_string())
                            })
                            .collect::<Result<Vec<_>, _>>();
                        let Ok(hashes) = hashes else { return Ok(false) };
                        if catchup::verify_record_hashes(record, &hashes).is_err()
                            || catchup::verify_record_receipts(record).is_err()
                        {
                            return Ok(false);
                        }
                    }
                    Ok(true)
                })
                .await
                .context("acquire agreed catch-up range")?;
            let Some(response) = response else {
                return Ok(Progress {
                    head: self.head().await?,
                    reached: false,
                });
            };
            for record in response.records {
                self.import_record(&record, executor).await?;
            }
            head = self.head().await?;
        }
        Ok(Progress {
            head,
            reached: true,
        })
    }

    /// Recover up to a caller-selected target, with a network budget per epoch.
    /// Execution and durable publication are outside that budget. Unavailable
    /// data returns the last committed head; invalid execution returns an error.
    /// Actual recovery leaves services suspended, including on cancellation.
    /// An already-reached target leaves admission unchanged. The driver must
    /// decide that recovery has caught up before explicitly calling `resume`.
    ///
    /// This path acquires individual native finality proofs. It is not the
    /// native driver's bulk range agreement or active-validator voting loop.
    pub async fn catch_up<
        R: epoch_roots::Host,
        F: finality_queries::Host,
        B: bundle_queries::Host,
    >(
        &self,
        target: u64,
        peers: &Peers<'_, R, F, B>,
        executor: &impl Executor,
        network_seconds: f64,
    ) -> Result<Progress> {
        anyhow::ensure!(
            target < (1_u64 << 62),
            "catch-up target exceeds canonical epoch range"
        );
        let _sync = self.syncing.lock().await;
        let head = self.head().await?;
        if head.cursor.epoch.0 >= target {
            return Ok(Progress {
                head,
                reached: true,
            });
        }
        self.suspend("catching up canonical history");
        let budget = Duration::from_secs_f64(driver_policy::bounded_timeout(network_seconds));
        loop {
            let head = self.head().await?;
            if head.cursor.epoch.0 >= target {
                return Ok(Progress {
                    head,
                    reached: true,
                });
            }
            let epoch = i64::try_from(head.cursor.epoch.0 + 1)?;
            let deadline = Instant::now() + budget;
            let roots = peers
                .roots
                .query(
                    epoch,
                    (budget.as_secs_f64() / 3.).min(0.5),
                    WaitFor::SourceAgreement,
                    false,
                )
                .await
                .context("discover finalized epoch sources")?;
            let remaining = || {
                deadline
                    .saturating_duration_since(Instant::now())
                    .as_secs_f64()
            };
            let Some(certificate) = peers
                .finality
                .query_proof(epoch, &roots, remaining() / 2., |certificate| {
                    let head = &head;
                    async move {
                        match self
                            .publisher
                            .verify_certificate(head, &certificate.encode()?)
                            .await
                        {
                            Ok(_) => Ok(true),
                            Err(octra_node_runtime::finality::Error::Invalid(_)) => Ok(false),
                            Err(error) => Err(error.to_string().into()),
                        }
                    }
                })
                .await
                .context("acquire finalized epoch certificate")?
            else {
                return Ok(Progress {
                    head: self.head().await?,
                    reached: false,
                });
            };
            if self
                .import_finalized(&certificate.encode()?, peers.bundles, executor, remaining())
                .await?
                .is_none()
            {
                return Ok(Progress {
                    head: self.head().await?,
                    reached: false,
                });
            }
        }
    }
}
