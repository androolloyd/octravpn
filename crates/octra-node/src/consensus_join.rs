//! Native HTTP join sources supply catch-up bytes only. Head advertisements,
//! embedded validator sets and readiness markers cannot introduce authority.
mod ready;
pub use ready::read_verified;

use crate::{import::Executor, Host, Node};
use anyhow::{bail, ensure, Context, Result};
use ed25519_dalek::SigningKey;
use octra_node_protocol::{
    consensus::{catchup, hash, CatchupEpochRecord},
    native_json::Document,
    state_sync::{http, range_part},
    transaction::Transaction,
};
use octra_node_runtime::{canonical::Head, validator_history::CanonicalValidators};
use reqwest::{header::RETRY_AFTER, StatusCode, Url};
use std::{collections::HashMap, path::Path, sync::Arc, time::Duration};
use tokio::{sync::Mutex, time::Instant};

#[derive(Clone)]
pub struct Client {
    sources: Vec<Url>,
    http: reqwest::Client,
    rate_limits: Arc<Mutex<HashMap<String, Instant>>>,
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
            rate_limits: Arc::new(Mutex::new(HashMap::new())),
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
        let origin = url.origin().ascii_serialization();
        {
            let mut limits = self.rate_limits.lock().await;
            if limits
                .get(&origin)
                .is_some_and(|until| *until > Instant::now())
            {
                bail!("join source cooling down after HTTP 429");
            }
            limits.remove(&origin);
        }
        let request = async {
            let mut response = self.http.get(url).send().await?;
            if response.status() == StatusCode::TOO_MANY_REQUESTS {
                let seconds = response
                    .headers()
                    .get(RETRY_AFTER)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<u64>().ok())
                    .unwrap_or(60)
                    .clamp(30, 300);
                self.rate_limits
                    .lock()
                    .await
                    .insert(origin, Instant::now() + Duration::from_secs(seconds));
                bail!("join HTTP response {}", response.status());
            }
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
    // Native response_payload_error rejects malformed payload/continuity for
    // the whole response before selecting a QC-valid prefix.
    fn payload(records: &[CatchupEpochRecord], from: i64, parent: &Head) -> Result<()> {
        catchup::verify_chain_continuity(records, from, &parent.cursor.state_root.0)?;
        for record in records {
            let hashes = record
                .txs_json
                .iter()
                .map(|raw| {
                    let document = Document::parse(raw)?;
                    Ok(Transaction::from_document(&document)?.hash()?.to_vec())
                })
                .collect::<Result<Vec<_>>>()?;
            catchup::verify_record_hashes(record, &hashes)?;
            catchup::verify_record_receipts(record)?;
        }
        Ok(())
    }

    // Only certificate/record finality belongs to native check_qcs. Reward,
    // execution-rule, execution and publication checks stay in import_record;
    // their errors must never be interpreted as a harmless invalid-QC suffix.
    async fn record_qc<A: Host>(
        node: &Node<A>,
        parent: &Head,
        record: &CatchupEpochRecord,
    ) -> Result<bool> {
        if u64::try_from(record.epoch_id).ok() != parent.cursor.epoch.0.checked_add(1)
            || record.prev_state_root != parent.cursor.state_root.0
        {
            return Ok(false);
        }
        let relief = node.store.reader().relief_after(parent).await?;
        let Ok(authority) = node
            .host
            .resolve(parent, record.epoch_id as u64, relief)
            .await
        else {
            // Native check_qcs truncates when locally selected membership is
            // unavailable; untrusted advertised sets never supply the gap.
            return Ok(false);
        };
        let next_txid = parent
            .txid_hi
            .checked_add(1)
            .and_then(|first| {
                i64::try_from(record.tx_hashes.len())
                    .ok()
                    .and_then(|count| first.checked_add(count))
            })
            .context("catch-up transaction index exhausted")?;
        Ok(catchup::verify_record_finality(
            node.store.chain().chain_id.as_bytes(),
            &hash::validator_set_hash(&authority.validators)?,
            next_txid,
            record,
        )
        .is_ok())
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
                let from = i64::try_from(base.cursor.epoch.0)?
                    .checked_add(1)
                    .context("join epoch overflow")?;
                // The head advertisement can lag the source's range backend,
                // or be unavailable while signed successors remain readable.
                // Probe the bounded consecutive range independently; only its
                // locally authenticated first record may select a target.
                if let Ok(records) = self
                    .range(source, from, catchup::RANGE_EPOCHS, source_deadline)
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
                    // Later records have not resolved their actual parent
                    // rules yet. An unproved suffix cannot become a persistent
                    // recovery obligation or stop an otherwise healthy driver.
                    return Ok::<_, anyhow::Error>(Some(records[0].epoch_id as u64));
                }
                let advertised = self.advertised(source, source_deadline).await?;
                if advertised.epoch <= base.cursor.epoch.0 as i64 {
                    return Ok(None);
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
    /// Recover a previously proved target with native multi-source HTTP
    /// fallback. Each response may advance through its bounded sixteen-record
    /// QC-valid prefix, beyond the target (a minimum, never a suffix obligation).
    /// The caller must explicitly resume serving after the complete prefix.
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
            // Native HTTP fallback requests a complete bounded chunk even
            // when the independently proved target is only the next epoch.
            let max = catchup::RANGE_EPOCHS;
            let mut selected = None;
            for (index, source) in self.sources.iter().enumerate() {
                let source_deadline = Self::source_deadline(deadline, self.sources.len() - index);
                let candidate = async {
                    let records = self.range(source, from, max, source_deadline).await?;
                    Self::payload(&records, from, &head)?;
                    ensure!(
                        Self::record_qc(node, &head, &records[0]).await?,
                        "join range has no QC-valid prefix"
                    );
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
                // Native check_qcs accepts only the contiguous QC-valid
                // prefix. Resolve against the actual committed parent, so an
                // earlier epoch's validator transition is not guessed.
                let parent = node.head().await?;
                if !Self::record_qc(node, &parent, &record).await? {
                    return Ok(crate::sync::Progress {
                        reached: parent.cursor.epoch.0 >= target,
                        head: parent,
                    });
                }
                // A trusted authority read can itself exhaust the caller's
                // absolute budget. Do not start another execution afterward.
                if Instant::now() >= deadline {
                    return Ok(crate::sync::Progress {
                        head: parent,
                        reached: false,
                    });
                }
                // Full reward/rules/execution/publication failures stay hard.
                // They do not become QC-prefix truncation or restore services.
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn rate_limited_source_cools_down_across_client_clones() {
        let requests = Arc::new(AtomicUsize::new(0));
        let seen = requests.clone();
        let router = axum::Router::new().route(
            "/state-sync/range",
            axum::routing::get(move || {
                let seen = seen.clone();
                async move {
                    seen.fetch_add(1, Ordering::SeqCst);
                    (StatusCode::TOO_MANY_REQUESTS, [(RETRY_AFTER, "120")])
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = Client::capture(|name| {
            (name == "OCTRA_JOIN_RPC").then(|| endpoint.as_bytes().to_vec())
        })
        .unwrap();
        let url = Client::route(&client.sources[0], "/state-sync/range").unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);

        assert!(client.get(url.clone(), deadline).await.is_err());
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        let error = client.clone().get(url.clone(), deadline).await.unwrap_err();
        assert!(error.to_string().contains("cooling down"));
        assert_eq!(requests.load(Ordering::SeqCst), 1);

        client.rate_limits.lock().await.insert(
            url.origin().ascii_serialization(),
            Instant::now() - Duration::from_millis(1),
        );
        assert!(client.get(url, deadline).await.is_err());
        assert_eq!(requests.load(Ordering::SeqCst), 2);
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
    }
}
