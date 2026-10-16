//! Native HTTP join sources supply catch-up bytes only. Head advertisements,
//! embedded validator sets and readiness markers cannot introduce authority.
mod ready;
pub use ready::read_verified;

use crate::{import::Executor, Host, Node};
use anyhow::{ensure, Context, Result};
use ed25519_dalek::SigningKey;
use octra_node_protocol::{
    consensus::{catchup, hash, CatchupEpochRecord},
    native_json::Document,
    state_sync::{http, range_part},
};
use octra_node_runtime::{canonical::Head, validator_history::CanonicalValidators};
use reqwest::Url;
use std::{path::Path, time::Duration};
use tokio::time::Instant;

#[derive(Clone)]
pub struct Client {
    sources: Vec<Url>,
    http: reqwest::Client,
}
pub struct Report {
    pub synced: bool,
    pub records_verified: i64,
    pub source: Option<String>,
    pub error: Option<String>,
}
impl Client {
    /// Capture both native source lists once, preserving source precedence.
    /// Credentials and redirect forwarding are deliberately unsupported.
    pub fn capture(mut setting: impl FnMut(&str) -> Option<Vec<u8>>) -> Result<Self> {
        let mut sources = Vec::new();
        for name in ["OCTRA_JOIN_RPC", "OCTRA_STATE_SYNC_SOURCES"] {
            let Some(raw) = setting(name) else { continue };
            for raw in std::str::from_utf8(&raw)?
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                ensure!(raw.len() <= 4096, "join source URL exceeds limit");
                let url = Url::parse(raw.trim_end_matches('/'))?;
                ensure!(
                    matches!(url.scheme(), "http" | "https") && url.host_str().is_some(),
                    "join source must be HTTP(S)"
                );
                ensure!(
                    url.username().is_empty()
                        && url.password().is_none()
                        && url.query().is_none()
                        && url.fragment().is_none(),
                    "join source cannot contain credentials, query or fragment"
                );
                if !sources.contains(&url) {
                    sources.push(url);
                }
                ensure!(sources.len() <= 32, "too many join sources");
            }
        }
        Ok(Self {
            sources,
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(10))
                .timeout(Duration::from_secs(20))
                .build()?,
        })
    }
    pub fn configured(&self) -> bool {
        !self.sources.is_empty()
    }
    /// Reserve a share of the caller's remaining time for later sources. The
    /// last source retains the full deadline, including multipart transfers.
    fn source_deadline(deadline: Instant, remaining_sources: usize) -> Instant {
        if remaining_sources <= 1 {
            return deadline;
        }
        let now = Instant::now();
        now + (deadline.saturating_duration_since(now) / remaining_sources as u32)
            .min(Duration::from_secs(20))
    }
    fn route(source: &Url, path: &str) -> Result<Url> {
        Ok(Url::parse(&format!(
            "{}{path}",
            source.as_str().trim_end_matches('/')
        ))?)
    }
    async fn get(&self, url: Url, deadline: Instant) -> Result<Vec<u8>> {
        let request = async {
            let mut response = self.http.get(url).send().await?;
            ensure!(
                response.status().is_success(),
                "join HTTP response {}",
                response.status()
            );
            ensure!(
                response
                    .content_length()
                    .is_none_or(|n| n <= range_part::BODY_MAX as u64),
                "join response exceeds byte limit"
            );
            let mut raw = Vec::new();
            while let Some(chunk) = response.chunk().await? {
                ensure!(
                    chunk.len() <= range_part::BODY_MAX.saturating_sub(raw.len()),
                    "join response exceeds byte limit"
                );
                raw.extend_from_slice(&chunk);
            }
            Ok::<_, anyhow::Error>(raw)
        };
        tokio::time::timeout_at(deadline, request)
            .await
            .context("join deadline elapsed")?
    }
    async fn advertised(&self, source: &Url, deadline: Instant) -> Result<http::Head> {
        let raw = self
            .get(Self::route(source, "/state-sync/head")?, deadline)
            .await?;
        http::Head::parse_response(&raw)?.context("join source has no committed head")
    }
    async fn range(
        &self,
        source: &Url,
        from: i64,
        max: i64,
        deadline: Instant,
    ) -> Result<Vec<CatchupEpochRecord>> {
        ensure!(
            from >= 0 && (1..=catchup::RANGE_EPOCHS).contains(&max),
            "invalid join range request"
        );
        let url = |part: Option<i64>, digest: Option<&[u8]>| -> Result<Url> {
            let mut url = Self::route(source, "/state-sync/range")?;
            {
                let mut query = url.query_pairs_mut();
                query
                    .append_pair("from_epoch", &from.to_string())
                    .append_pair("max_epochs", &max.to_string());
                if let Some(part) = part {
                    query.append_pair("part", &part.to_string());
                }
                if let Some(hash) = digest {
                    query.append_pair("sha256", std::str::from_utf8(hash)?);
                }
            }
            Ok(url)
        };
        let first = self.get(url(None, None)?, deadline).await?;
        let document = match range_part::view(&first)? {
            range_part::View::Full(doc) => doc,
            range_part::View::Part(first) => {
                ensure!(first.index == 0, "join first range part is not zero");
                ensure!(
                    first.count > 1
                        && first.count as u64
                            <= range_part::FULL_MAX.div_ceil(range_part::RAW_MAX) as u64,
                    "join range part count exceeds limit"
                );
                let mut parts = Vec::with_capacity(first.count as usize);
                let count = first.count;
                let digest = first.sha256.clone();
                parts.push(first);
                for index in 1..count {
                    let raw = self.get(url(Some(index), Some(&digest))?, deadline).await?;
                    let range_part::View::Part(part) = range_part::view(&raw)? else {
                        anyhow::bail!("join range part changed to full response")
                    };
                    ensure!(
                        part.index == index && part.count == count && part.sha256 == digest,
                        "join range part identity differs"
                    );
                    parts.push(part);
                }
                Document::parse(&range_part::join(&parts)?)?
            }
        };
        let http::RangeResult::Records { records, .. } = http::parse_range(&document)? else {
            anyhow::bail!("join source has no signed range")
        };
        ensure!(
            !records.is_empty() && records.len() <= max as usize && records[0].epoch_id == from,
            "join source has no complete requested range"
        );
        Ok(records)
    }
    /// A far head is usable only when its QC is signed by independently known
    /// canonical membership. A consecutive range beside the retained head is
    /// an availability target only; every record is authenticated on import.
    async fn proves<A: Host>(
        &self,
        node: &Node<A>,
        membership: &CanonicalValidators,
        base: &Head,
        record: &CatchupEpochRecord,
    ) -> Result<bool> {
        let set = membership
            .expected_set(base, record.epoch_id, None, &|_| Ok(None))
            .await?;
        let Some(proof) = record.finality.as_ref() else {
            return Ok(false);
        };
        let Some(next_txid) = proof.finalize.header.txid_hi.checked_add(1) else {
            return Ok(false);
        };
        Ok(catchup::verify_record_finality(
            node.store.chain().chain_id.as_bytes(),
            &hash::validator_set_hash(&set)?,
            next_txid,
            record,
        )
        .is_ok())
    }
    pub async fn proved_target<A: Host>(
        &self,
        node: &Node<A>,
        membership: &CanonicalValidators,
        executor: &impl Executor,
        deadline: Instant,
    ) -> Result<Option<u64>> {
        let base = node.head().await?;
        let mut best = None;
        for (index, source) in self.sources.iter().enumerate() {
            if Instant::now() >= deadline {
                break;
            }
            let source_deadline = Self::source_deadline(deadline, self.sources.len() - index);
            let candidate = async {
                let advertised = self.advertised(source, source_deadline).await?;
                if advertised.epoch <= base.cursor.epoch.0 as i64 {
                    return Ok(None);
                }
                let from = i64::try_from(base.cursor.epoch.0)?
                    .checked_add(1)
                    .context("join epoch overflow")?;
                if let Ok(records) = self
                    .range(
                        source,
                        from,
                        (advertised.epoch - from + 1).min(catchup::RANGE_EPOCHS),
                        source_deadline,
                    )
                    .await
                {
                    catchup::verify_chain_continuity(&records, from, &base.cursor.state_root.0)?;
                    for record in &records {
                        catchup::verify_record_receipts(record)?;
                    }
                    // Authenticate the first successor against local rules.
                    // Later range entries remain hints until sequential import.
                    node.publisher
                        .verify_record(&base, &records[0], &executor.graph())
                        .await?;
                    return Ok::<_, anyhow::Error>(Some(
                        records.last().context("join range is empty")?.epoch_id as u64,
                    ));
                }
                if let Ok(records) = self
                    .range(source, advertised.epoch, 1, source_deadline)
                    .await
                {
                    let record = &records[0];
                    if hex::encode(&record.state_root).as_bytes() == advertised.state_root
                        && self
                            .proves(node, membership, &base, record)
                            .await
                            .unwrap_or(false)
                    {
                        return Ok(Some(record.epoch_id as u64));
                    }
                }
                Ok(None)
            }
            .await;
            match candidate {
                Ok(Some(epoch)) => best = Some(best.map_or(epoch, |old: u64| old.max(epoch))),
                Ok(None) => (),
                Err(error) => eprintln!("join head unavailable source={source} error={error:#}"),
            }
        }
        Ok(best)
    }
    /// Recover a previously proved target with native multi-source range
    /// fallback. The caller must explicitly resume serving after recovery.
    pub async fn catch_up<A: Host>(
        &self,
        node: &Node<A>,
        target: u64,
        executor: &impl Executor,
        deadline: Instant,
    ) -> Result<crate::sync::Progress> {
        ensure!(
            target < (1_u64 << 62),
            "HTTP catch-up target exceeds canonical epoch range"
        );
        let _sync = node.syncing.lock().await;
        loop {
            let head = node.head().await?;
            if head.cursor.epoch.0 >= target {
                return Ok(crate::sync::Progress {
                    head,
                    reached: true,
                });
            }
            node.suspend("catching up authenticated HTTP history");
            if Instant::now() >= deadline {
                return Ok(crate::sync::Progress {
                    head,
                    reached: false,
                });
            }
            let from = (head.cursor.epoch.0 + 1) as i64;
            let max = (target - head.cursor.epoch.0).min(catchup::RANGE_EPOCHS as u64) as i64;
            let mut selected = None;
            for (index, source) in self.sources.iter().enumerate() {
                let source_deadline = Self::source_deadline(deadline, self.sources.len() - index);
                let candidate = async {
                    let records = self.range(source, from, max, source_deadline).await?;
                    catchup::verify_chain_continuity(&records, from, &head.cursor.state_root.0)?;
                    node.publisher
                        .verify_record(&head, &records[0], &executor.graph())
                        .await?;
                    Ok::<_, anyhow::Error>(records)
                }
                .await;
                match candidate {
                    Ok(records) => {
                        selected = Some(records);
                        break;
                    }
                    Err(error) => eprintln!(
                        "join range unavailable source={source} from={from} error={error:#}"
                    ),
                }
            }
            let Some(records) = selected else {
                return Ok(crate::sync::Progress {
                    head: node.head().await?,
                    reached: false,
                });
            };
            for record in records {
                if Instant::now() >= deadline {
                    return Ok(crate::sync::Progress {
                        head: node.head().await?,
                        reached: false,
                    });
                }
                // Every subsequent epoch resolves authority again against its
                // actual committed parent, including validator transitions.
                node.import_record(&record, executor).await?;
            }
        }
    }
    /// Continue bounded startup windows while each durably advances. Services
    /// remain suspended; the launcher owns cancellation of the complete startup.
    pub async fn catch_up_windows<A: Host>(
        &self,
        node: &Node<A>,
        target: u64,
        executor: &impl Executor,
        budget: Duration,
    ) -> Result<crate::sync::Progress> {
        ensure!(!budget.is_zero(), "HTTP catch-up window is empty");
        loop {
            let before = node.head().await?.cursor.epoch.0;
            let deadline = Instant::now()
                .checked_add(budget)
                .context("HTTP catch-up window exceeds monotonic range")?;
            let progress = self.catch_up(node, target, executor, deadline).await?;
            if progress.reached || progress.head.cursor.epoch.0 <= before {
                return Ok(progress);
            }
            eprintln!(
                "HTTP catch-up advanced epoch={} target={target}; continuing startup",
                progress.head.cursor.epoch.0
            );
        }
    }

    /// Native startup recovery tries sources in configured order. Failure keeps
    /// any authenticated committed prefix and returns an unattested report so
    /// the launcher can continue its independent P2P recovery path.
    pub async fn synchronize<A: Host>(
        &self,
        node: &Node<A>,
        executor: &impl Executor,
        data: &Path,
        key: &SigningKey,
        voting: bool,
        deadline: Instant,
    ) -> Result<Report> {
        let _sync = node.syncing.lock().await;
        let mut verified = 0_i64;
        let mut last_error = None;
        for (index, source) in self.sources.iter().enumerate() {
            if Instant::now() >= deadline {
                break;
            }
            let mut source_deadline = Self::source_deadline(deadline, self.sources.len() - index);
            let mut failures = 0;
            while failures < 3 && Instant::now() < source_deadline {
                let attempt = async {
                    let advertised = self.advertised(source, source_deadline).await?;
                    let head = node.head().await?;
                    let local = i64::try_from(head.cursor.epoch.0)?;
                    if local > advertised.epoch {
                        anyhow::bail!("join source is behind canonical history")
                    }
                    if local == advertised.epoch {
                        ensure!(
                            hex::encode(head.cursor.state_root.0).as_bytes()
                                == advertised.state_root,
                            "join source disagrees with canonical head"
                        );
                        return Ok(true);
                    }
                    let records = self
                        .range(
                            source,
                            local + 1,
                            (advertised.epoch - local).min(catchup::RANGE_EPOCHS),
                            source_deadline,
                        )
                        .await?;
                    catchup::verify_chain_continuity(
                        &records,
                        local + 1,
                        &head.cursor.state_root.0,
                    )?;
                    node.suspend("joining authenticated HTTP history");
                    for record in records {
                        ensure!(
                            Instant::now() < source_deadline,
                            "join deadline elapsed before next epoch"
                        );
                        node.import_record(&record, executor).await?;
                        verified = verified
                            .checked_add(1)
                            .context("join record count overflow")?;
                    }
                    Ok::<_, anyhow::Error>(false)
                }
                .await;
                match attempt {
                    Ok(true) => {
                        if verified > 0 {
                            ready::write(data, node, key, source.as_str(), voting, verified)
                                .await?;
                        }
                        return Ok(Report {
                            synced: true,
                            records_verified: verified,
                            source: Some(source.to_string()),
                            error: None,
                        });
                    }
                    Ok(false) => {
                        failures = 0;
                        // Authenticated progress earns another bounded window
                        // without consuming the later sources' reserve.
                        source_deadline =
                            Self::source_deadline(deadline, self.sources.len() - index);
                    }
                    Err(error) => {
                        eprintln!("join source unavailable source={source} error={error:#}");
                        last_error = Some(format!("{error:#}"));
                        failures += 1;
                        if failures < 3 {
                            let wake = (Instant::now() + Duration::from_secs(1 << (failures - 1)))
                                .min(source_deadline);
                            tokio::time::sleep_until(wake).await;
                        }
                    }
                }
            }
        }
        Ok(Report {
            synced: false,
            records_verified: verified,
            source: None,
            error: last_error,
        })
    }
}
