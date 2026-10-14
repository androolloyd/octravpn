// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Range readers share authentication with single-certificate queries, while
//! owning separate windows and collecting one response per validator.
use super::{Finality, Host, Inner};
use crate::query_peers;
use octra_node_protocol::{
    consensus::{
        catchup_agreement::{self, Agreement},
        codec::Wire,
        driver_policy::{self, QueryWindow},
        hash, Bytes, CatchupQuery, CatchupResponse, Error, ValidatorSet,
    },
    network::{domain_hash, frame::Frame},
};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::Instant;

/// A trusted snapshot of the driver's current stake set and scheduled change.
/// The request cannot cross that activation; quorum policy still applies at
/// each prefix's last epoch.
pub struct RangePlan {
    pub stake: ValidatorSet,
    pub scheduled: Option<(i64, ValidatorSet)>,
}
impl RangePlan {
    fn validators(&self, chain: &[u8], epoch: i64) -> Result<ValidatorSet, Error> {
        self.scheduled
            .as_ref()
            .filter(|(activation, _)| epoch >= *activation)
            .map_or(&self.stake, |(_, set)| set)
            .for_epoch(chain, epoch)
    }
}
pub(super) struct Slot {
    pub id: Bytes,
    pub window: QueryWindow,
    pub owner: Arc<()>,
    pub responses: Vec<Arc<CatchupResponse>>,
}
struct Reader<H> {
    inner: Arc<Inner<H>>,
    owner: Arc<()>,
}
impl<H> Drop for Reader<H> {
    fn drop(&mut self) {
        let mut windows = self.inner.windows.lock().expect("finality windows");
        if windows
            .range
            .as_ref()
            .is_some_and(|slot| Arc::ptr_eq(&slot.owner, &self.owner))
        {
            windows.range = None;
        }
    }
}
impl<H: Host> Finality<H> {
    /// Agree on a full range or native-selected shared prefix. `validate`
    /// checks payloads and continuity against the local head. The caller must
    /// authenticate each certificate and its execution before publication.
    /// The timeout includes waiting behind another range reader and host I/O.
    pub async fn query_range(
        &self,
        from_epoch: i64,
        max_epochs: i64,
        timeout: f64,
        mut validate: impl FnMut(&CatchupResponse) -> Result<bool, Error>,
    ) -> Result<Option<CatchupResponse>, Error> {
        let budget = driver_policy::bounded_timeout(timeout);
        if budget == 0.0 {
            return Ok(None);
        }
        let deadline = Instant::now() + Duration::from_secs_f64(budget);
        tokio::time::timeout_at(deadline, async {
            let _serial = self.0.ranges.lock().await;
            let plan = self.0.host.range_plan().await?;
            let max_epochs = catchup_agreement::limit(
                from_epoch,
                max_epochs,
                plan.scheduled.as_ref().map(|(e, _)| *e),
            );
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| Error::from(e.to_string()))?
                .as_secs_f64();
            let suffix = format!(":{from_epoch}:{max_epochs}:{nonce:.6}:range");
            let id = hash::mark_complete_catchup_request(&domain_hash(
                b"octra:catchup_range_request_id:v1",
                &[self.0.address.as_slice(), suffix.as_bytes()].concat(),
            ))?;
            let reader = Reader {
                inner: self.0.clone(),
                owner: Arc::new(()),
            };
            self.0.windows.lock().expect("finality windows").range = Some(Slot {
                id: id.clone(),
                window: QueryWindow {
                    from_epoch,
                    max_epochs,
                },
                owner: reader.owner.clone(),
                responses: vec![],
            });
            let frame = Frame {
                message: 0x3a,
                payload: CatchupQuery {
                    chain_id: self.0.chain.clone(),
                    request_id: id.clone(),
                    from_epoch,
                    max_epochs,
                }
                .encode()?,
            };
            let connected = self
                .0
                .swarm
                .peers()
                .iter()
                .map(|p| p.hello().node_id.clone())
                .collect::<Vec<_>>();
            let waves = catchup_agreement::waves(
                &plan.validators(&self.0.chain, from_epoch)?,
                query_peers::ordered(&self.0.host.active_validators()?, &id, &connected),
            );
            let delay = Duration::from_secs_f64(catchup_agreement::wave_delay(budget, waves.len()));
            let mut agreement = Agreement::default();
            // An empty peer plan still waits on the registered window, as the
            // native driver does. Newly connected unsolicited peers cannot
            // contribute without a signed response for this request ID.
            if waves.is_empty() {
                return self
                    .wait_range(
                        &reader,
                        from_epoch,
                        deadline,
                        &plan,
                        &mut agreement,
                        &mut validate,
                    )
                    .await;
            }
            for (index, wave) in waves.iter().enumerate() {
                if Instant::now() >= deadline {
                    return Ok(None);
                }
                futures::future::join_all(
                    wave.iter()
                        .map(|peer| self.0.swarm.send_to(peer, frame.clone())),
                )
                .await;
                let until = if index + 1 == waves.len() {
                    deadline
                } else {
                    deadline.min(Instant::now() + delay)
                };
                if let Some(response) = self
                    .wait_range(
                        &reader,
                        from_epoch,
                        until,
                        &plan,
                        &mut agreement,
                        &mut validate,
                    )
                    .await?
                {
                    return Ok(Some(response));
                }
            }
            Ok(None)
        })
        .await
        .unwrap_or(Ok(None))
    }
    async fn wait_range(
        &self,
        reader: &Reader<H>,
        from_epoch: i64,
        deadline: Instant,
        plan: &RangePlan,
        agreement: &mut Agreement,
        validate: &mut impl FnMut(&CatchupResponse) -> Result<bool, Error>,
    ) -> Result<Option<CatchupResponse>, Error> {
        while Instant::now() < deadline {
            let responses = {
                let windows = self.0.windows.lock().expect("finality windows");
                let Some(slot) = windows
                    .range
                    .as_ref()
                    .filter(|slot| Arc::ptr_eq(&slot.owner, &reader.owner))
                else {
                    return Ok(None);
                };
                slot.responses.clone()
            };
            if let Some(response) = agreement.select(
                &self.0.chain,
                from_epoch,
                responses.iter().map(AsRef::as_ref),
                |epoch| plan.validators(&self.0.chain, epoch),
                &mut *validate,
            )? {
                return Ok(Some(response));
            }
            tokio::time::sleep_until(deadline.min(Instant::now() + Duration::from_millis(100)))
                .await;
        }
        Ok(None)
    }
}
