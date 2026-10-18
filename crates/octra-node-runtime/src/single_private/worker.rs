//! Owned, bounded native-style speculative range workers. The helper is trusted
//! code in this very executable, not a proof supplied by a peer or caller.
mod session;
use super::CacheBinding;
use crate::{
    private_balance::{self, Profile},
    private_crypto::ResultPolicy,
};
use octra_hfhe::scalar::ScalarRule;
use octra_node_protocol::{
    native_json::Document,
    state::{Account, Ledger},
    transaction::{RuleMode, Transaction},
};
use serde::{Deserialize, Serialize};
pub(crate) use session::Session;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    path::PathBuf,
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, OnceLock,
    },
    time::{Duration, Instant},
};
const MAX_INPUT: usize = 128 * 1024 * 1024;
const MAX_OUTPUT: usize = 64 * 1024;
const DOMAIN: &[u8] = b"octra:single-range-worker:v1\n";
/// Native environment is captured once for the process. No worker path override.
#[derive(Clone, Debug)]
pub struct Limits {
    pub capacity: usize,
    pub timeout_seconds: f64,
    pub rss_mb: u64,
}
impl Limits {
    pub fn capture() -> Self {
        Self::of_getenv(|name| std::env::var(name).ok())
    }
    /// Capture a configured environment without falling back to process values.
    pub fn from_values(get: impl Fn(&str) -> Option<Vec<u8>>) -> Self {
        Self::of_getenv(|name| get(name).and_then(|raw| String::from_utf8(raw).ok()))
    }
    fn of_getenv(get: impl Fn(&str) -> Option<String>) -> Self {
        fn int(
            get: &impl Fn(&str) -> Option<String>,
            name: &str,
            default: u64,
            low: u64,
            high: u64,
        ) -> u64 {
            get(name)
                .and_then(|v| octra_node_protocol::native_integer::parse_integer(v.as_bytes()))
                .and_then(|v| u64::try_from(v).ok())
                .filter(|v| (low..=high).contains(v))
                .unwrap_or(default)
        }
        let timeout = get("OCTRA_PVAC_VERIFY_TIMEOUT_SEC")
            .and_then(|v| native_float(&v))
            .filter(|v| v.is_finite() && (1.0..=1800.0).contains(v))
            .unwrap_or(600.);
        Self {
            capacity: usize::try_from(int(&get, "OCTRA_PVAC_VERIFY_WORKERS", 1, 1, 2)).unwrap_or(1),
            timeout_seconds: timeout,
            rss_mb: int(&get, "OCTRA_PVAC_VERIFY_MAX_RSS_MB", 9216, 64, 32768),
        }
    }
}
// OCaml float_of_string removes underscores and accepts C hexadecimal
// significands. Keep exact integer rounding before a power-of-two scale; this
// parser is only for finite worker configuration, never consensus arithmetic.
fn native_float(raw: &str) -> Option<f64> {
    use num_traits::ToPrimitive as _;
    let raw = raw.replace('_', "");
    let raw = raw.trim_start_matches(|c: char| c.is_ascii_whitespace());
    if raw.ends_with(|c: char| c.is_ascii_whitespace()) {
        return None;
    }
    let (negative, body) = raw.strip_prefix('-').map_or_else(
        || (false, raw.strip_prefix('+').unwrap_or(raw)),
        |s| (true, s),
    );
    let Some(hex) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) else {
        return raw.parse().ok();
    };
    let (significand, exponent) = if let Some(index) = hex.find(['p', 'P']) {
        (&hex[..index], hex[index + 1..].parse::<i64>().ok()?)
    } else {
        (hex, 0)
    };
    let mut seen_dot = false;
    let mut fractional = 0_i64;
    let mut digits = Vec::new();
    for c in significand.bytes() {
        if c == b'.' && !seen_dot {
            seen_dot = true;
        } else {
            if !c.is_ascii_hexdigit() {
                return None;
            }
            digits.push(c);
            if seen_dot {
                fractional = fractional.checked_add(1)?;
            }
        }
    }
    if digits.is_empty() {
        return None;
    }
    let number = num_bigint::BigUint::parse_bytes(&digits, 16)?;
    let bits = number.bits();
    let shift = bits.saturating_sub(53);
    let mut rounded = (&number >> usize::try_from(shift).ok()?).to_u64()?;
    if shift > 0 {
        let half = num_bigint::BigUint::from(1_u8) << usize::try_from(shift - 1).ok()?;
        let remainder =
            &number - ((num_bigint::BigUint::from(rounded)) << usize::try_from(shift).ok()?);
        if remainder > half || (remainder == half && rounded & 1 == 1) {
            rounded = rounded.checked_add(1)?;
        }
    }
    let power = exponent
        .checked_sub(fractional.checked_mul(4)?)?
        .checked_add(i64::try_from(shift).ok()?)?;
    let scale = if power > 1023 {
        f64::INFINITY
    } else if power < -1074 {
        0.
    } else {
        2_f64.powi(i32::try_from(power).ok()?)
    };
    #[allow(clippy::cast_precision_loss)]
    let value = rounded as f64 * scale;
    Some(if negative { -value } else { value })
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    #[serde(with = "bytes")]
    transaction: Vec<u8>,
    #[serde(with = "bytes")]
    current: Vec<u8>,
    #[serde(with = "bytes")]
    key: Vec<u8>,
    profile: [u8; 4],
}
mod bytes {
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};
    pub(super) fn serialize<S: Serializer>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&base64::engine::general_purpose::STANDARD.encode(value))
    }
    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        let value = String::deserialize(deserializer)?;
        if value.len() > super::MAX_INPUT {
            return Err(serde::de::Error::custom("worker field too large"));
        }
        base64::engine::general_purpose::STANDARD
            .decode(value)
            .map_err(serde::de::Error::custom)
    }
}
impl Input {
    fn profile(&self) -> Result<Profile, String> {
        let fields = match self.profile[0] {
            0 => RuleMode::Prior,
            1 => RuleMode::Active,
            _ => return Err("worker fields invalid".into()),
        };
        let strict = match self.profile[1] {
            0 => false,
            1 => true,
            _ => return Err("worker strict invalid".into()),
        };
        let math = match self.profile[2] {
            0 => ScalarRule::Prior,
            1 => ScalarRule::Wide,
            _ => return Err("worker math invalid".into()),
        };
        let result = match self.profile[3] {
            0 => ResultPolicy::Legacy,
            1 => ResultPolicy::Recoverable,
            _ => return Err("worker result invalid".into()),
        };
        Ok(Profile {
            fields,
            strict,
            math,
            result,
        })
    }
    fn tx(&self) -> Result<Transaction, String> {
        Transaction::from_document(&Document::parse(&self.transaction).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())
    }
    fn ledger(&self, tx: &Transaction) -> Result<Ledger, String> {
        Ledger::from_accounts(BTreeMap::from([(
            tx.from.clone(),
            Account {
                encrypted_balance: Some(self.current.clone()),
                ..Account::default()
            },
        )]))
        .map_err(|e| e.to_string())
    }
}
/// Opaque public-input job. Construction loads the actual sender snapshot and
/// complete profile/key binding; it carries no proof verdict or authority.
pub struct Task {
    input: Input,
    digest: [u8; 32],
}
impl Task {
    pub fn new(
        ledger: &Ledger,
        tx: &Transaction,
        profile: Profile,
        key: &[u8],
    ) -> Result<Self, String> {
        let input = Input {
            transaction: tx.to_json_bytes().map_err(|e| e.to_string())?,
            current: ledger
                .account(&tx.from)
                .and_then(|a| a.encrypted_balance.clone())
                .unwrap_or_default(),
            key: key.to_vec(),
            profile: [
                u8::from(profile.fields == RuleMode::Active),
                u8::from(profile.strict),
                u8::from(profile.math == ScalarRule::Wide),
                u8::from(profile.result == ResultPolicy::Recoverable),
            ],
        };
        if input.key.len() > 8 * 1024 * 1024 || input.current.len() > 16 * 1024 * 1024 {
            return Err("worker public key/value exceeds native transport limit".into());
        }
        let body = serde_json::to_vec(&input).map_err(|e| e.to_string())?;
        if body.len() > MAX_INPUT {
            return Err("Single range public input exceeds local worker limit".into());
        }
        let mut hash = Sha256::new();
        hash.update(DOMAIN);
        hash.update(&body);
        Ok(Self {
            input,
            digest: hash.finalize().into(),
        })
    }
    pub fn same_input(&self, other: &Self) -> bool {
        self.digest == other.digest
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    attempt: u8,
    balance: bool,
    generation: u64,
    digest: [u8; 32],
    input: Input,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    attempt: u8,
    balance: bool,
    generation: u64,
    digest: [u8; 32],
    outcome: Outcome,
}
#[derive(Serialize, Deserialize)]
enum Outcome {
    Checked(bool),
    Unavailable(String),
}
#[derive(Debug)]
pub(crate) enum Failure {
    Cancelled,
    QueueBusy,
    TimedOut,
    MemoryExceeded,
    Unavailable(String),
    Failed(String),
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => f.write_str("proof worker unavailable: worker_cancelled"),
            Self::QueueBusy => f.write_str("proof queue remained full"),
            Self::TimedOut => f.write_str("proof worker timed out"),
            Self::MemoryExceeded => f.write_str("proof worker memory limit exceeded"),
            Self::Unavailable(reason) => write!(f, "proof worker unavailable: {reason}"),
            Self::Failed(reason) => write!(f, "proof worker failed: {reason}"),
        }
    }
}
impl From<String> for Failure {
    fn from(reason: String) -> Self {
        Self::Failed(reason)
    }
}
impl From<&str> for Failure {
    fn from(reason: &str) -> Self {
        Self::Failed(reason.into())
    }
}
/// Trusted executable, capacity and OS child ownership are sealed in Runtime.
/// Neither its path nor its limits can be supplied by a request.
pub struct Worker {
    executable: PathBuf,
    executable_sha: [u8; 32],
    limits: Limits,
    proofs: crate::compute::Pool,
}
impl Worker {
    /// Explicit trusted helper capability for libraries and embedded runtimes.
    /// The executable must implement the worker commands used by its caller.
    pub fn open(executable: &std::path::Path, limits: Limits) -> Result<Arc<Self>, String> {
        if !(1..=2).contains(&limits.capacity)
            || !limits.timeout_seconds.is_finite()
            || !(1.0..=1800.0).contains(&limits.timeout_seconds)
            || !(64..=32768).contains(&limits.rss_mb)
        {
            return Err("invalid captured worker limits".into());
        }
        let executable = std::fs::canonicalize(executable).map_err(|e| e.to_string())?;
        if !std::fs::metadata(&executable)
            .map_err(|e| e.to_string())?
            .is_file()
        {
            return Err("worker executable is not a regular file".into());
        }
        let executable_sha = file_hash(&executable)?;
        Ok(Arc::new(Self {
            executable,
            executable_sha,
            proofs: crate::compute::Pool::new_sync(crate::compute::Limits::proof(limits.capacity))?,
            limits,
        }))
    }
    pub fn capture() -> Result<Arc<Self>, String> {
        static WORKER: OnceLock<Result<Arc<Worker>, String>> = OnceLock::new();
        WORKER
            .get_or_init(|| {
                let executable = std::env::current_exe()
                    .and_then(std::fs::canonicalize)
                    .map_err(|e| e.to_string())?;
                let executable_sha = file_hash(&executable)?;
                let limits = Limits::capture();
                Ok(Arc::new(Self {
                    executable,
                    executable_sha,
                    proofs: crate::compute::Pool::new_sync(crate::compute::Limits::proof(
                        limits.capacity,
                    ))?,
                    limits,
                }))
            })
            .clone()
    }
    pub fn limits(&self) -> &Limits {
        &self.limits
    }
    pub(crate) fn proofs(&self) -> &crate::compute::Pool {
        &self.proofs
    }
    /// This synchronous runner belongs on an owned OS worker. Dropping a caller
    /// future never drops its child. Cancellation is explicit and always reaps.
    pub fn run(
        &self,
        task: &Task,
        generation: u64,
        cancelled: &AtomicBool,
    ) -> Result<CacheBinding, String> {
        self.run_inner(task, generation, cancelled)
            .map_err(|failure| failure.to_string())
    }
    fn run_inner(
        &self,
        task: &Task,
        generation: u64,
        cancelled: &AtomicBool,
    ) -> Result<CacheBinding, Failure> {
        let delta = self.phase(task, generation, cancelled, false)?;
        let balance = self.phase(task, generation, cancelled, true)?;
        Ok(CacheBinding {
            current: task.input.current.clone(),
            profile: task.input.profile()?,
            key_sha256: Sha256::digest(&task.input.key).into(),
            transaction: task.input.tx()?.hash().map_err(|e| e.to_string())?,
            ranges: (delta, balance),
        })
    }
    #[cfg(test)]
    fn acquire(
        &self,
        cancelled: &AtomicBool,
        queue_waits: &mut u8,
    ) -> Result<crate::compute::Permit, Failure> {
        self.acquire_check(&|| cancelled.load(Ordering::Acquire), queue_waits)
    }
    fn acquire_check(
        &self,
        cancelled: &impl Fn() -> bool,
        queue_waits: &mut u8,
    ) -> Result<crate::compute::Permit, Failure> {
        loop {
            if cancelled() {
                return Err(Failure::Cancelled);
            }
            if let Some(permit) = self
                .proofs
                .acquire_sync(crate::compute::Priority::Speculative, false)
            {
                return Ok(permit);
            }
            if *queue_waits == 40 {
                return Err(Failure::QueueBusy);
            }
            *queue_waits += 1;
            // Match the native retry interval while allowing explicit local
            // cancellation to release a waiting job without another 50ms delay.
            let started = Instant::now();
            while started.elapsed() < Duration::from_millis(50) {
                if cancelled() {
                    return Err(Failure::Cancelled);
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }
    fn phase(
        &self,
        task: &Task,
        generation: u64,
        cancelled: &AtomicBool,
        balance: bool,
    ) -> Result<bool, Failure> {
        let mut queue_waits = 0;
        let first = self.run_child(task, generation, cancelled, balance, 0, &mut queue_waits);
        if matches!(&first, Err(Failure::Failed(_))) {
            // tx_view.preverify_range retries only Worker_failed, exactly once.
            // The child and capacity slot were already reaped/released.
            let started = Instant::now();
            while started.elapsed() < Duration::from_millis(250) {
                if cancelled.load(Ordering::Acquire) {
                    return Err(Failure::Cancelled);
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            self.run_child(task, generation, cancelled, balance, 1, &mut queue_waits)
        } else {
            first
        }
    }
    fn run_child(
        &self,
        task: &Task,
        generation: u64,
        cancelled: &AtomicBool,
        balance: bool,
        attempt: u8,
        queue_waits: &mut u8,
    ) -> Result<bool, Failure> {
        let input = Request {
            attempt,
            balance,
            generation,
            digest: task.digest,
            input: Input {
                transaction: task.input.transaction.clone(),
                current: task.input.current.clone(),
                key: task.input.key.clone(),
                profile: task.input.profile,
            },
        };
        let bytes = serde_json::to_vec(&input).map_err(|e| e.to_string())?;
        if bytes.len() > MAX_INPUT + 1024 {
            return Err("worker request exceeds local limit".into());
        }
        let _proof = self.acquire_check(&|| cancelled.load(Ordering::Acquire), queue_waits)?;
        let deadline = Instant::now() + Duration::from_secs_f64(self.limits.timeout_seconds);
        let output = self.exchange("single-range-worker", &bytes, MAX_OUTPUT, deadline, || {
            cancelled.load(Ordering::Acquire)
        })?;
        let response: Response = serde_json::from_slice(&output)
            .map_err(|e| format!("worker response malformed: {e}"))?;
        if response.generation != generation
            || response.digest != task.digest
            || response.balance != balance
            || response.attempt != attempt
        {
            return Err("worker completion binding differs".into());
        }
        match response.outcome {
            Outcome::Checked(valid) => Ok(valid),
            Outcome::Unavailable(reason) => Err(Failure::Unavailable(reason)),
        }
    }
    /// Owned native process runner. The caller holds either a proof-channel
    /// permit or native FHE actor admission; independent lanes can coexist.
    pub(crate) fn exchange(
        &self,
        command: &str,
        bytes: &[u8],
        output_limit: usize,
        deadline: Instant,
        cancelled: impl Fn() -> bool,
    ) -> Result<Vec<u8>, Failure> {
        if cancelled() {
            return Err(Failure::Cancelled);
        }
        let timeout = deadline.saturating_duration_since(Instant::now());
        if timeout.is_zero() {
            return Err(Failure::TimedOut);
        }
        if file_hash(&self.executable)? != self.executable_sha {
            return Err(Failure::Unavailable(
                "worker executable changed; restart required".into(),
            ));
        }
        let mut child = Command::new(&self.executable)
            .arg(command)
            .arg("--parent-pid")
            .arg(std::process::id().to_string())
            .env(
                "OCTRA_PVAC_VERIFY_TIMEOUT_SEC",
                timeout.as_secs_f64().max(1.0).to_string(),
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| e.to_string())?;
        // From here every return path kills/reaps, including pipe and thread errors.
        let result = (|| {
            if file_hash(&self.executable)? != self.executable_sha {
                return Err(Failure::Unavailable(
                    "worker executable changed during spawn".into(),
                ));
            }
            let mut stdin = child.stdin.take().ok_or("worker stdin missing")?;
            let stdout = child.stdout.take().ok_or("worker stdout missing")?;
            let stderr = child.stderr.take().ok_or("worker stderr missing")?;
            let io_failed = Arc::new(AtomicBool::new(false));
            std::thread::scope(|scope| {
                // Kill/reap before scoped threads are joined on every error or
                // unwind, so a blocked pipe writer cannot deadlock cancellation.
                struct ChildGuard<'a>(&'a mut std::process::Child);
                impl Drop for ChildGuard<'_> {
                    fn drop(&mut self) {
                        let _ = self.0.kill();
                        let _ = self.0.wait();
                    }
                }
                let owned = ChildGuard(&mut child);
                let input_thread = scope.spawn(|| {
                    let r = stdin.write_all(bytes);
                    drop(stdin);
                    if r.is_err() {
                        io_failed.store(true, Ordering::Release);
                    }
                    r
                });
                let output_thread = scope.spawn(|| bounded_read(stdout, output_limit, &io_failed));
                let error_thread = scope.spawn(|| bounded_read(stderr, MAX_OUTPUT, &io_failed));
                let status = loop {
                    let why = if cancelled() {
                        Some(Failure::Cancelled)
                    } else if Instant::now() >= deadline {
                        Some(Failure::TimedOut)
                    } else if io_failed.load(Ordering::Acquire) {
                        Some(Failure::Failed(
                            "worker pipe failure or oversized response".into(),
                        ))
                    } else if rss_mb(owned.0.id()).is_some_and(|rss| rss > self.limits.rss_mb) {
                        Some(Failure::MemoryExceeded)
                    } else {
                        None
                    };
                    if let Some(why) = why {
                        let _ = owned.0.kill();
                        let _ = owned.0.wait();
                        return Err(why);
                    }
                    match owned.0.try_wait() {
                        Ok(Some(status)) => break status,
                        Ok(None) => std::thread::sleep(Duration::from_millis(10)),
                        Err(e) => {
                            let _ = owned.0.kill();
                            let _ = owned.0.wait();
                            return Err(Failure::Failed(e.to_string()));
                        }
                    }
                };
                let written = input_thread
                    .join()
                    .map_err(|_| "worker writer panicked")?
                    .map_err(|e| e.to_string());
                let output = output_thread
                    .join()
                    .map_err(|_| "worker stdout reader panicked")??;
                error_thread
                    .join()
                    .map_err(|_| "worker stderr reader panicked")??;
                written?;
                if !status.success() {
                    return Err(Failure::Failed(format!("worker exited {status}")));
                }
                if cancelled() {
                    return Err(Failure::Cancelled);
                }
                Ok(output)
            })
        })();
        let _ = child.kill();
        let _ = child.wait();
        result
    }
}
fn file_hash(path: &std::path::Path) -> Result<[u8; 32], String> {
    let mut f = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut h = Sha256::new();
    let mut chunk = [0u8; 16 * 1024];
    loop {
        let n = f.read(&mut chunk).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        h.update(&chunk[..n]);
    }
    Ok(h.finalize().into())
}
pub(crate) fn bounded_read(
    mut pipe: impl Read,
    maximum: usize,
    failed: &AtomicBool,
) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = match pipe.read(&mut buf) {
            Ok(n) => n,
            Err(e) => {
                failed.store(true, Ordering::Release);
                return Err(e.to_string());
            }
        };
        if n == 0 {
            return Ok(out);
        }
        if out.len() + n > maximum {
            failed.store(true, Ordering::Release);
            return Err("worker pipe exceeds local limit".into());
        }
        out.extend_from_slice(&buf[..n]);
    }
}
fn rss_mb(pid: u32) -> Option<u64> {
    // Native /proc monitoring is unavailable on macOS too. Do not claim an
    // RLIMIT_AS substitute is an RSS cap. Timeout/cancellation still apply.
    let text = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let raw = text
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))?
        .split_ascii_whitespace()
        .next()?
        .parse::<u64>()
        .ok()?;
    Some(raw.div_ceil(1024))
}
pub(crate) struct Watchdog(Arc<AtomicBool>);
impl Watchdog {
    pub(crate) fn start(parent: u32) -> Result<Self, String> {
        Self::start_inner(parent, Some(Limits::capture().timeout_seconds + 0.1))
    }
    pub(crate) fn start_session(parent: u32) -> Result<Self, String> {
        Self::start_inner(parent, None)
    }
    fn start_inner(parent: u32, deadline: Option<f64>) -> Result<Self, String> {
        #[cfg(not(unix))]
        return Err("Single range helper requires Unix parent ownership".into());
        #[cfg(unix)]
        {
            let is_parent = move || {
                rustix::process::getppid().and_then(|p| u32::try_from(p.as_raw_pid()).ok())
                    == Some(parent)
            };
            if !is_parent() {
                return Err("worker parent changed".into());
            }
            let stopped = Arc::new(AtomicBool::new(false));
            let stop = stopped.clone();
            let started = Instant::now();
            std::thread::Builder::new()
                .name("octra-range-watchdog".into())
                .spawn(move || {
                    while !stop.load(Ordering::Acquire) {
                        if !is_parent()
                            || deadline
                                .is_some_and(|deadline| started.elapsed().as_secs_f64() >= deadline)
                        {
                            std::process::exit(74)
                        }
                        std::thread::sleep(Duration::from_millis(50));
                    }
                })
                .map_err(|e| e.to_string())?;
            Ok(Self(stopped))
        }
    }
}
impl Drop for Watchdog {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}
/// Hidden executable entrypoint. It reads only bounded public inputs and runs
/// actual range checks; no wallet, store, launch configuration or network opens.
pub fn helper(parent_pid: u32) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    rustix::process::set_parent_process_death_signal(Some(rustix::process::Signal::KILL))
        .map_err(|e| e.to_string())?;
    let _watchdog = Watchdog::start(parent_pid)?;
    let bytes = bounded_read(
        std::io::stdin().lock(),
        MAX_INPUT + 1024,
        &AtomicBool::new(false),
    )?;
    let request: Request = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    let body = serde_json::to_vec(&request.input).map_err(|e| e.to_string())?;
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash.update(&body);
    if <[u8; 32]>::from(hash.finalize()) != request.digest {
        return Err("worker input binding differs".into());
    }
    #[cfg(feature = "test-helpers")]
    test_fault(request.attempt)?;
    let tx = request.input.tx()?;
    let outcome = match crate::private_transfer::single_range(
        &request.input.ledger(&tx)?,
        &tx,
        request.input.profile()?,
        &request.input.key,
        request.balance,
    ) {
        Ok(valid) => Outcome::Checked(valid),
        Err(private_balance::Error::Rejected(_)) => Outcome::Checked(false),
        Err(private_balance::Error::Unavailable(reason)) => Outcome::Unavailable(reason),
    };
    let response = serde_json::to_vec(&Response {
        attempt: request.attempt,
        balance: request.balance,
        generation: request.generation,
        digest: request.digest,
        outcome,
    })
    .map_err(|e| e.to_string())?;
    std::io::stdout()
        .lock()
        .write_all(&response)
        .map_err(|e| e.to_string())
}
#[cfg(feature = "test-helpers")]
fn test_fault(attempt: u8) -> Result<(), String> {
    match std::env::var("OCTRA_TEST_SINGLE_RANGE_FAULT")
        .ok()
        .as_deref()
    {
        Some("delay") => std::thread::sleep(Duration::from_secs(3)),
        Some("death") => std::process::exit(71),
        Some("death-once") if attempt == 0 => std::process::exit(71),
        Some("death-once") | None => {}
        Some("rss") => {
            let mut pages = vec![0u8; 128 * 1024 * 1024];
            for p in pages.chunks_mut(4096) {
                p[0] = 7;
            }
            std::hint::black_box(&pages);
            std::thread::sleep(Duration::from_secs(3));
        }
        Some(_) => return Err("invalid test-only worker fault".into()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn capacity_queue_is_bounded_and_cancelled_without_minting_a_verdict() {
        let worker = Worker {
            executable: PathBuf::new(),
            executable_sha: [0; 32],
            limits: Limits {
                capacity: 1,
                timeout_seconds: 600.,
                rss_mb: 9216,
            },
            proofs: crate::compute::Pool::new_sync(crate::compute::Limits::proof(1)).unwrap(),
        };
        let held = worker
            .proofs
            .acquire_sync(crate::compute::Priority::Required, false)
            .unwrap();
        let cancelled = AtomicBool::new(false);
        let mut waits = 0;
        let started = Instant::now();
        assert!(matches!(
            worker.acquire(&cancelled, &mut waits),
            Err(Failure::QueueBusy)
        ));
        assert_eq!(waits, 40);
        assert!(started.elapsed() >= Duration::from_secs(2));
        // A failed-child retry keeps its phase's exhausted queue budget.
        assert!(matches!(
            worker.acquire(&cancelled, &mut waits),
            Err(Failure::QueueBusy)
        ));
        assert_eq!(waits, 40);
        cancelled.store(true, Ordering::Release);
        assert!(matches!(
            worker.acquire(&cancelled, &mut waits),
            Err(Failure::Cancelled)
        ));
        drop(held);
        cancelled.store(false, Ordering::Release);
        let slot = worker.acquire(&cancelled, &mut waits).unwrap();
        assert_eq!(worker.proofs.stats().active, 1);
        drop(slot);
        assert_eq!(worker.proofs.stats().active, 0);
    }
    #[test]
    fn pristine_native_worker_environment_limits() {
        let fixture: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../tests/fixtures/single-worker-limits.json"
        ))
        .unwrap();
        assert_eq!(
            fixture["upstream_commit"],
            "7f9be4489870645cfcc95439638cde40f5da9f50"
        );
        assert_eq!(fixture["instrumentation"], serde_json::json!({}));
        let map: serde_json::Value =
            serde_json::from_slice(include_bytes!("../../../../docs/rust-node/source-map.json"))
                .unwrap();
        assert_eq!(fixture["source_sha256"], map["files"]);
        assert_eq!(
            fixture["oracle_sha256"],
            hex::encode(Sha256::digest(include_bytes!(
                "../../../../scripts/node-port/single-worker-limits-oracle.ml"
            )))
        );
        assert_eq!(
            fixture["runner_sha256"],
            hex::encode(Sha256::digest(include_bytes!(
                "../../../../scripts/node-port/resource-native-oracle.py"
            )))
        );
        let cases = fixture["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 102);
        for case in cases {
            let name = case["input"]["name"].as_str().unwrap();
            let value = case["input"]["value"].as_str();
            let limits = Limits::of_getenv(|key| {
                if key == name {
                    value.map(str::to_owned)
                } else {
                    None
                }
            });
            assert_eq!(
                limits.capacity as u64,
                case["expected"]["capacity"].as_u64().unwrap(),
                "{case}"
            );
            assert_eq!(
                limits.rss_mb,
                case["expected"]["rss"].as_u64().unwrap(),
                "{case}"
            );
            assert_eq!(
                format!("{:016x}", limits.timeout_seconds.to_bits()),
                case["expected"]["timeout_bits"].as_str().unwrap(),
                "{case}"
            );
        }
    }
    #[test]
    fn configured_values_keep_absence_and_native_worker_bounds_authoritative() {
        let limits = Limits::from_values(|name| match name {
            "OCTRA_PVAC_VERIFY_WORKERS" => Some(b"0x2".to_vec()),
            "OCTRA_PVAC_VERIFY_TIMEOUT_SEC" => Some(b"0x1p0".to_vec()),
            "OCTRA_PVAC_VERIFY_MAX_RSS_MB" => Some(b"64".to_vec()),
            _ => None,
        });
        assert_eq!(limits.capacity, 2);
        assert_eq!(limits.timeout_seconds.to_bits(), 1_f64.to_bits());
        assert_eq!(limits.rss_mb, 64);
        for values in [None, Some(b"invalid".to_vec()), Some(vec![0xff])] {
            let limits = Limits::from_values(|_| values.clone());
            assert_eq!(limits.capacity, 1);
            assert_eq!(limits.timeout_seconds.to_bits(), 600_f64.to_bits());
            assert_eq!(limits.rss_mb, 9216);
        }
    }
}
