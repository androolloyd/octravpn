//! Bounded snapshot transport. Sources can supply bytes only for an already
//! authenticated manifest; redirects and automatic credential forwarding are off.
use anyhow::{ensure, Context, Result};
use octra_node_protocol::state_sync::manifest::{self, Chunk, File, Trust, VerifiedCertificate};
use reqwest::{header::HeaderMap, StatusCode, Url};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Seek, Write},
    net::IpAddr,
    sync::Arc,
    time::Duration,
};
use tokio::sync::Semaphore;
#[cfg(test)]
mod tests;

#[derive(Clone)]
pub(super) struct Source {
    url: Url,
    capacity: Arc<Semaphore>,
}
impl Source {
    pub(super) fn new(raw: &str, allow_private_http: bool) -> Result<Self> {
        let url = Url::parse(raw.trim().trim_end_matches('/'))?;
        ensure!(
            url.username().is_empty() && url.password().is_none(),
            "state sync source must not contain credentials"
        );
        ensure!(
            url.query().is_none() && url.fragment().is_none(),
            "state sync source must not contain a query or fragment"
        );
        let host = url
            .host_str()
            .context("state sync source requires a host")?
            .trim_matches(['[', ']']);
        let ip = host.parse::<IpAddr>().ok();
        let loopback = host == "localhost" || ip.is_some_and(|i| i.is_loopback());
        let private = match ip {
            Some(IpAddr::V4(ip)) => ip.is_private() || ip.is_link_local(),
            Some(IpAddr::V6(ip)) => {
                (ip.segments()[0] & 0xfe00) == 0xfc00 || (ip.segments()[0] & 0xffc0) == 0xfe80
            }
            None => false,
        };
        ensure!(
            url.scheme() == "https"
                || (url.scheme() == "http" && (loopback || (allow_private_http && private))),
            "plain HTTP state sync requires loopback or explicit private transport approval"
        );
        Ok(Self {
            url,
            capacity: Arc::new(Semaphore::new(2)),
        })
    }
    pub(super) fn identity(&self) -> &str {
        self.url.as_str()
    }
    fn route(&self, path: &str) -> Result<Url> {
        Ok(Url::parse(&format!(
            "{}{path}",
            self.url.as_str().trim_end_matches('/')
        ))?)
    }
}
#[derive(Clone)]
pub(super) struct Client {
    client: reqwest::Client,
    capacity: Arc<Semaphore>,
}
#[derive(Clone)]
pub(super) struct Candidate {
    pub raw: Vec<u8>,
    pub certificate: VerifiedCertificate,
    pub sources: Vec<Source>,
}
enum FetchError {
    Busy(Duration),
    Expired,
    Other(anyhow::Error),
}
impl Client {
    pub(super) fn new() -> Result<Self> {
        Ok(Self {
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(15))
                .timeout(Duration::from_secs(30))
                .build()?,
            capacity: Arc::new(Semaphore::new(8)),
        })
    }
    async fn once(
        &self,
        source: &Source,
        url: Url,
        limit: usize,
    ) -> std::result::Result<(HeaderMap, Vec<u8>), FetchError> {
        let request = async {
            let _global = self.capacity.acquire().await?;
            let _source = source.capacity.acquire().await?;
            let mut response = self.client.get(url).send().await?;
            let status = response.status();
            let headers = response.headers().clone();
            let bound = if status.is_success() { limit } else { 65_536 };
            if let Some(length) = response.content_length() {
                ensure!(length <= bound as u64, "response body exceeds size limit");
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await? {
                ensure!(
                    chunk.len() <= bound - bytes.len(),
                    "response body exceeds size limit"
                );
                bytes.extend_from_slice(&chunk);
            }
            Ok::<_, anyhow::Error>((status, headers, bytes))
        }
        .await;
        let (status, headers, bytes) = request.map_err(FetchError::Other)?;
        if status == StatusCode::GONE {
            return Err(FetchError::Expired);
        }
        if status == StatusCode::TOO_MANY_REQUESTS {
            let seconds = headers
                .get("retry-after")
                .and_then(|h| h.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(3)
                .clamp(1, 30);
            return Err(FetchError::Busy(Duration::from_secs(seconds)));
        }
        if !status.is_success() {
            return Err(FetchError::Other(anyhow::anyhow!(
                "snapshot source returned HTTP {status}"
            )));
        }
        Ok((headers, bytes))
    }
    async fn fetch(&self, source: &Source, url: Url, limit: usize) -> Result<(HeaderMap, Vec<u8>)> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(240);
        let mut attempts = 0u32;
        loop {
            match self.once(source, url.clone(), limit).await {
                Ok(value) => return Ok(value),
                Err(FetchError::Expired) => anyhow::bail!("state sync snapshot expired"),
                Err(FetchError::Busy(delay)) => {
                    ensure!(
                        tokio::time::Instant::now() + delay <= deadline,
                        "snapshot source busy wait budget exhausted"
                    );
                    tokio::time::sleep(delay).await;
                }
                Err(FetchError::Other(error)) => {
                    attempts += 1;
                    if attempts >= 3 {
                        return Err(error);
                    }
                    tokio::time::sleep(Duration::from_secs(u64::from(attempts))).await;
                }
            }
        }
    }
    pub(super) async fn manifest(
        &self,
        source: Source,
        trust: &Trust<'_>,
        now: i64,
    ) -> Result<Candidate> {
        let (headers, raw) = self
            .fetch(
                &source,
                source.route("/state-sync/manifest")?,
                manifest::MANIFEST_LIMIT,
            )
            .await?;
        let certificate = trust.verify(&raw, now)?;
        header(
            &headers,
            "x-octra-manifest-sha256",
            &certificate.draft().manifest_hash,
        )?;
        Ok(Candidate {
            raw,
            certificate,
            sources: vec![source],
        })
    }
    async fn chunk(&self, candidate: &Candidate, file: &File, chunk: &Chunk) -> Result<Vec<u8>> {
        let draft = candidate.certificate.draft();
        let mut failure = None;
        for source in &candidate.sources {
            let run = async {
                let mut url = source.route("/state-sync/chunk")?;
                url.query_pairs_mut()
                    .append_pair(
                        "snapshot",
                        std::str::from_utf8(&draft.manifest.snapshot_id)?,
                    )
                    .append_pair("path", std::str::from_utf8(&file.path)?)
                    .append_pair("index", &chunk.index.to_string())
                    .append_pair("sha256", std::str::from_utf8(&chunk.sha256)?);
                let (headers, bytes) = self
                    .fetch(source, url, usize::try_from(chunk.size)?)
                    .await?;
                for (name, value) in [
                    ("x-octra-chunk-sha256", chunk.sha256.as_slice()),
                    ("x-octra-manifest-sha256", &draft.manifest_hash),
                    ("x-octra-snapshot", &draft.manifest.snapshot_id),
                    ("x-octra-chunk-index", chunk.index.to_string().as_bytes()),
                ] {
                    header(&headers, name, value)?;
                }
                ensure!(bytes.len() as i64 == chunk.size, "chunk length mismatch");
                ensure!(
                    hex::encode(Sha256::digest(&bytes)).as_bytes() == chunk.sha256,
                    "chunk hash mismatch"
                );
                Ok::<_, anyhow::Error>(bytes)
            }
            .await;
            match run {
                Ok(bytes) => return Ok(bytes),
                Err(error) => failure = Some(error),
            }
        }
        Err(failure.unwrap_or_else(|| anyhow::anyhow!("snapshot has no source")))
    }
    pub(super) async fn file(
        &self,
        candidate: &Candidate,
        file: &File,
        cache: &super::resume::Cache,
    ) -> Result<u64> {
        let descriptor = file.clone();
        let cache = cache.clone();
        let Some(mut writer) = disk(move || Writer::open(&descriptor, cache)).await? else {
            return Ok(0);
        };
        let resumed = writer.offset;
        for chunk in file.chunks.iter().filter(|chunk| chunk.offset >= resumed) {
            ensure!(writer.offset == chunk.offset, "noncontiguous file chunk");
            let bytes = self.chunk(candidate, file, chunk).await?;
            writer = disk(move || writer.append(bytes)).await?;
        }
        disk(move || writer.finish()).await
    }
}

/// Every disk task owns the workspace lease until its last write/fsync has
/// completed, even if its async caller is cancelled and drops the join handle.
async fn disk<T: Send + 'static>(work: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(work).await?
}
struct Writer {
    output: std::fs::File,
    part: std::path::PathBuf,
    path: std::path::PathBuf,
    hash: Sha256,
    offset: i64,
    size: i64,
    expected: Vec<u8>,
    downloaded: u64,
    _cache: super::resume::Cache,
}
impl Writer {
    #[allow(clippy::verbose_bit_mask)] // The octal mask directly expresses private Unix permission bits.
    fn open(file: &File, cache: super::resume::Cache) -> Result<Option<Self>> {
        ensure!(
            manifest::reference_file(&file.path) && manifest::valid_path(&file.path),
            "unsafe snapshot path"
        );
        let path = cache.path().join(std::str::from_utf8(&file.path)?);
        super::resume::parents(
            cache.path(),
            path.parent().context("snapshot file parent missing")?,
        )?;
        match std::fs::symlink_metadata(&path) {
            Ok(_) => {
                let mut cached = super::regular(&path)?;
                let (offset, hash) = prefix(&mut cached, file)?;
                if offset == file.size
                    && cached.metadata()?.len() == file.size as u64
                    && hex::encode(hash.finalize()).as_bytes() == file.sha256
                {
                    return Ok(None);
                }
                drop(cached);
                std::fs::remove_file(&path)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
        let part = path.with_file_name(format!(
            "{}.part",
            path.file_name()
                .context("snapshot file name missing")?
                .to_str()
                .context("snapshot file name is not UTF-8")?
        ));
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(
                rustix::fs::OFlags::NOFOLLOW.bits() as i32
                    | rustix::fs::OFlags::NONBLOCK.bits() as i32,
            );
        }
        let mut output = options.open(&part)?;
        let meta = output.metadata()?;
        ensure!(
            meta.is_file(),
            "partial snapshot artifact must be a regular file"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            ensure!(
                meta.permissions().mode() & 0o077 == 0 && meta.nlink() == 1,
                "partial snapshot artifact must be private and have one link"
            );
        }
        let (offset, hash) = prefix(&mut output, file)?;
        output.set_len(offset as u64)?;
        output.seek(std::io::SeekFrom::Start(offset as u64))?;
        Ok(Some(Self {
            output,
            part,
            path,
            hash,
            offset,
            size: file.size,
            expected: file.sha256.clone(),
            downloaded: 0,
            _cache: cache,
        }))
    }
    #[allow(clippy::needless_pass_by_value)] // The physical write owns its chunk buffer through write and fsync.
    fn append(mut self, bytes: Vec<u8>) -> Result<Self> {
        self.output.write_all(&bytes)?;
        self.output.sync_all()?;
        self.hash.update(&bytes);
        self.offset = self
            .offset
            .checked_add(i64::try_from(bytes.len())?)
            .context("file size overflow")?;
        self.downloaded = self
            .downloaded
            .checked_add(bytes.len() as u64)
            .context("snapshot download counter overflow")?;
        Ok(self)
    }
    fn finish(self) -> Result<u64> {
        ensure!(
            self.offset == self.size
                && hex::encode(self.hash.finalize()).as_bytes() == self.expected,
            "snapshot file hash mismatch"
        );
        self.output.sync_all()?;
        drop(self.output);
        std::fs::rename(&self.part, &self.path)?;
        std::fs::File::open(self.path.parent().context("snapshot file parent missing")?)?
            .sync_all()?;
        Ok(self.downloaded)
    }
}

/// Reconstruct a verified contiguous prefix rather than trusting a progress
/// counter. A torn or changed chunk and all later bytes are downloaded again.
fn prefix(input: &mut std::fs::File, file: &File) -> Result<(i64, Sha256)> {
    let size = input.metadata()?.len();
    input.seek(std::io::SeekFrom::Start(0))?;
    let mut offset = 0i64;
    let mut hash = Sha256::new();
    for chunk in &file.chunks {
        ensure!(chunk.offset == offset, "noncontiguous file chunk");
        let end = offset
            .checked_add(chunk.size)
            .context("file size overflow")?;
        if end as u64 > size {
            break;
        }
        let mut bytes = vec![0; usize::try_from(chunk.size)?];
        input.read_exact(&mut bytes)?;
        if hex::encode(Sha256::digest(&bytes)).as_bytes() != chunk.sha256 {
            break;
        }
        hash.update(&bytes);
        offset = end;
    }
    Ok((offset, hash))
}
fn header(headers: &HeaderMap, name: &str, expected: &[u8]) -> Result<()> {
    let values = headers.get_all(name).iter().collect::<Vec<_>>();
    ensure!(
        values.len() == 1 && values[0].as_bytes() == expected,
        "response header mismatch: {name}"
    );
    Ok(())
}
