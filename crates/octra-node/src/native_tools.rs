//! Explicit, source-bound native-format maintenance tools. The executable hash
//! is the operator's trust anchor; the build certificate records its provenance.
//! Native store formats remain behind this boundary rather than being decoded
//! by an approximate storage implementation.
use anyhow::{ensure, Context, Result};
use serde::{de::Error as _, Deserialize, Deserializer};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs::{self, File},
    io::{self, Read},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

const UPSTREAM: &str = "7f9be4489870645cfcc95439638cde40f5da9f50";
const SOURCE_MAP: &str = "ddefd67b70c877129f1678655715abf6a6a0a1b652c0394be552a4eb8c31e141";
const ARCHIVE_MAP: &str = "1bd5faff11bea372a0e1bd9abd78d9a1a9a3889907ec1fb19d88b9db83a30858";
const MAX_JSON: u64 = 4 * 1024 * 1024;
const POLL: Duration = Duration::from_millis(5);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeTool {
    CheckStore,
    FheAudit,
    VoteFloor,
    StateSyncManifest,
}
impl NativeTool {
    fn target(self) -> &'static str {
        match self {
            Self::CheckStore => "_build/default/bin/check_store.exe",
            Self::FheAudit => "_build/default/bin/fhe_audit.exe",
            Self::VoteFloor => "_build/default/bin/vote_floor.exe",
            Self::StateSyncManifest => "_build/default/bin/octra_state_sync_manifest.exe",
        }
    }
    fn check_policy(self, args: &[OsString], policy: Policy) -> Result<()> {
        let readonly = match self {
            Self::CheckStore | Self::FheAudit => true,
            Self::VoteFloor => {
                let parsed = native_options(
                    args,
                    &[
                        "--data-dir",
                        "--chain-id",
                        "--validator",
                        "--validator-pub",
                        "--head-epoch",
                        "--round",
                        "--round-min",
                        "--round-sync",
                    ],
                    &["--check", "--staged", "--prepared"],
                )?;
                let mut fields = BTreeMap::new();
                for (key, value) in parsed {
                    ensure!(
                        fields.insert(key, value).is_none(),
                        "duplicate native vote-floor option"
                    );
                }
                for key in [
                    "--data-dir",
                    "--chain-id",
                    "--validator",
                    "--validator-pub",
                    "--head-epoch",
                ] {
                    ensure!(
                        fields.contains_key(key),
                        "required native vote-floor option is missing"
                    );
                }
                let round = fields.contains_key("--round");
                let sync = fields.contains_key("--round-sync");
                let checking = fields.contains_key("--check");
                let staged = fields.contains_key("--staged");
                let prepared = fields.contains_key("--prepared");
                ensure!(
                    round != sync,
                    "native vote-floor round source is ambiguous or missing"
                );
                ensure!(
                    !(staged && prepared),
                    "native vote-floor checks are exclusive"
                );
                ensure!(
                    !(staged || prepared) || checking,
                    "native vote-floor check requires --check"
                );
                checking
            }
            Self::StateSyncManifest => {
                let parsed = native_options(
                    args,
                    &[
                        "--command",
                        "--source",
                        "--chain-id",
                        "--config-hash",
                        "--chunk-size",
                        "--validity",
                        "--output",
                        "--draft",
                        "--certificate",
                        "--wallet",
                        "--checkpoint-signature",
                        "--exporter-signature",
                        "--finality",
                        "--validator",
                        "--exporter",
                    ],
                    &["--historical"],
                )?;
                let mut command = None;
                for (key, value) in parsed {
                    if key == "--command" {
                        ensure!(
                            command
                                .replace(value.context("native snapshot command is missing")?)
                                .is_none(),
                            "native snapshot requires one explicit command"
                        );
                    }
                }
                let command = command
                    .context("native snapshot requires one explicit command")?
                    .to_str()
                    .context("native snapshot command is not UTF-8")?;
                ensure!(
                    matches!(
                        command,
                        "seal"
                            | "build"
                            | "sign-checkpoint"
                            | "sign-manifest"
                            | "assemble"
                            | "assemble-finalized"
                            | "verify"
                    ),
                    "unsupported native snapshot command"
                );
                command == "verify"
            }
        };
        ensure!(
            policy
                == if readonly {
                    Policy::ReadOnly
                } else {
                    Policy::StoppedOwner
                },
            "native tool ownership policy does not match command"
        );
        Ok(())
    }
}

// Mirror each original tool's option arity before choosing ownership policy.
// Values are consumed once, even when their bytes spell another option name.
fn native_options<'a>(
    args: &'a [OsString],
    valued: &[&str],
    flags: &[&str],
) -> Result<Vec<(&'a str, Option<&'a OsString>)>> {
    let mut fields = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let key = args[index]
            .to_str()
            .context("native option name is not UTF-8")?;
        if flags.contains(&key) {
            fields.push((key, None));
            index += 1;
        } else {
            ensure!(valued.contains(&key), "unsupported native option");
            let value = args
                .get(index + 1)
                .context("native option value is missing")?;
            fields.push((key, Some(value)));
            index += 2;
        }
    }
    Ok(fields)
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBackendOptions {
    pub executable: PathBuf,
    pub sha256: String,
    pub certificate: PathBuf,
}
impl NativeBackendOptions {
    /// Binding paths are relative to the binding file, never the process cwd.
    pub fn read(path: &Path) -> Result<Self> {
        let mut result: Self = json(path)?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        if result.executable.is_relative() {
            result.executable = parent.join(result.executable);
        }
        if result.certificate.is_relative() {
            result.certificate = parent.join(result.certificate);
        }
        Ok(result)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    ReadOnly,
    StoppedOwner,
}

#[derive(Clone, Copy)]
pub struct Bounds {
    pub timeout: Duration,
    /// Combined stdout and stderr bytes; callers decide which public output to expose.
    pub max_output: usize,
}
impl Default for Bounds {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(300),
            max_output: 1024 * 1024,
        }
    }
}

#[derive(Clone)]
pub struct NativeBackend {
    tool: NativeTool,
    image: Arc<tempfile::TempDir>,
}

#[derive(Deserialize)]
struct Certificate {
    schema: String,
    native_pin: String,
    #[serde(deserialize_with = "unique_map")]
    native_sources: BTreeMap<String, String>,
    #[serde(deserialize_with = "unique_map")]
    native_archive_inputs: BTreeMap<String, String>,
    native_production_bodies_changed: bool,
    native_sources_rechecked_after_build: bool,
    native_archive_rechecked_after_build: bool,
    #[serde(deserialize_with = "unique_map")]
    artifacts: BTreeMap<String, Artifact>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    sha256: String,
    bytes: u64,
}

fn unique_map<'de, D, V>(deserializer: D) -> std::result::Result<BTreeMap<String, V>, D::Error>
where
    D: Deserializer<'de>,
    V: Deserialize<'de>,
{
    struct Unique<V>(std::marker::PhantomData<V>);
    impl<'de, V: Deserialize<'de>> serde::de::Visitor<'de> for Unique<V> {
        type Value = BTreeMap<String, V>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a map with unique string keys")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut map: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            let mut result = BTreeMap::new();
            while let Some((key, value)) = map.next_entry::<String, V>()? {
                ensure_unique(&mut result, key, value).map_err(A::Error::custom)?;
            }
            Ok(result)
        }
    }
    deserializer.deserialize_map(Unique(std::marker::PhantomData))
}
fn ensure_unique<V>(map: &mut BTreeMap<String, V>, key: String, value: V) -> Result<()> {
    ensure!(
        map.insert(key, value).is_none(),
        "duplicate certificate map key"
    );
    Ok(())
}

fn regular(path: &Path) -> Result<File> {
    #[cfg(unix)]
    {
        use rustix::fs::{open, Mode, OFlags};
        let file: File = open(
            path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )?
        .into();
        ensure!(
            file.metadata()?.is_file(),
            "native tool input is not a regular file"
        );
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        anyhow::bail!("native-format maintenance requires Unix")
    }
}
fn json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let input = regular(path)?;
    ensure!(
        input.metadata()?.len() <= MAX_JSON,
        "native tool JSON exceeds bound"
    );
    let mut bytes = vec![];
    input.take(MAX_JSON + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_JSON,
        "native tool JSON grew beyond bound"
    );
    serde_json::from_slice(&bytes).context("invalid native tool JSON")
}

impl NativeBackend {
    pub fn verified(tool: NativeTool, options: &NativeBackendOptions) -> Result<Self> {
        let certificate: Certificate = json(&options.certificate)?;
        ensure!(
            matches!(
                certificate.schema.as_str(),
                "octra_shared_native_modules_artifacts_v1"
                    | "octra_native_tools_build_artifacts_v1"
            ),
            "unknown native tool build certificate"
        );
        ensure!(
            certificate.native_pin == UPSTREAM
                && !certificate.native_production_bodies_changed
                && certificate.native_sources_rechecked_after_build
                && certificate.native_archive_rechecked_after_build,
            "native tool source verification failed"
        );
        ensure!(
            certificate.native_sources.len() == 1158
                && hex::encode(Sha256::digest(serde_json::to_vec(
                    &certificate.native_sources
                )?)) == SOURCE_MAP,
            "native module source map differs"
        );
        ensure!(
            certificate.native_archive_inputs.len() == 1566
                && hex::encode(Sha256::digest(serde_json::to_vec(
                    &certificate.native_archive_inputs
                )?)) == ARCHIVE_MAP,
            "native full-input map differs"
        );
        let artifact = certificate
            .artifacts
            .get(tool.target())
            .context("native tool target is absent from build certificate")?;
        ensure!(
            artifact.sha256 == options.sha256,
            "native tool binding differs from build certificate"
        );
        // Hash while copying from an O_NOFOLLOW descriptor; all future execution
        // uses this private immutable image, never the original path again.
        let image = crate::legacy_repair::process::freeze(&options.executable, &options.sha256)?;
        ensure!(
            fs::metadata(image.path().join("backend"))?.len() == artifact.bytes,
            "native tool size differs from build certificate"
        );
        Ok(Self {
            tool,
            image: Arc::new(image),
        })
    }

    /// Move the complete ownership guard into the worker. Cancelling the async
    /// caller cannot release a native/SQLite writer lock before child reaping.
    pub async fn run<G: Send + 'static>(
        &self,
        args: Vec<OsString>,
        policy: Policy,
        owner: G,
        bounds: Bounds,
    ) -> Result<Output> {
        ensure!(
            !bounds.timeout.is_zero()
                && bounds.timeout <= Duration::from_secs(3600)
                && bounds.max_output > 0
                && bounds.max_output <= 16 * 1024 * 1024,
            "invalid native tool bounds"
        );
        ensure!(
            args.len() <= 128 && args.iter().map(|a| a.len()).sum::<usize>() <= 1024 * 1024,
            "native tool arguments exceed bound"
        );
        self.tool.check_policy(&args, policy)?;
        let cancelled = Arc::new(AtomicBool::new(false));
        let cancel = Cancel(cancelled.clone());
        let backend = self.clone();
        let work = tokio::task::spawn_blocking(move || {
            let _owner = owner;
            backend.execute(args, bounds, &cancelled)
        });
        let output = work.await.context("native tool worker failed")?;
        drop(cancel);
        output
    }

    fn execute(
        &self,
        args: Vec<OsString>,
        bounds: Bounds,
        cancelled: &AtomicBool,
    ) -> Result<Output> {
        ensure!(
            !cancelled.load(Ordering::Acquire),
            "native tool cancelled before start"
        );
        let mut command = Command::new(self.image.path().join("backend"));
        command
            .args(args)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        let mut child = OwnedChild {
            child: command.spawn().context("start pinned native tool")?,
            reaped: false,
            group_clear: false,
        };
        let mut stdout = child
            .child
            .stdout
            .take()
            .context("native stdout is absent")?;
        let mut stderr = child
            .child
            .stderr
            .take()
            .context("native stderr is absent")?;
        crate::legacy_repair::process::nonblocking(&stdout)?;
        crate::legacy_repair::process::nonblocking(&stderr)?;
        let deadline = Instant::now() + bounds.timeout;
        let (mut out, mut err) = (vec![], vec![]);
        let (mut out_eof, mut err_eof) = (false, false);
        loop {
            ensure!(!cancelled.load(Ordering::Acquire), "native tool cancelled");
            ensure!(Instant::now() < deadline, "native tool deadline exceeded");
            if !out_eof {
                out_eof = drain(&mut stdout, &mut out, err.len(), bounds.max_output)?;
            }
            if !err_eof {
                err_eof = drain(&mut stderr, &mut err, out.len(), bounds.max_output)?;
            }
            if out_eof && err_eof {
                if let Some(status) = child.child.try_wait()? {
                    child.reaped = true;
                    ensure!(
                        child.group_absent()?,
                        "native tool left background descendants"
                    );
                    child.group_clear = true;
                    return Ok(Output {
                        status,
                        stdout: out,
                        stderr: err,
                    });
                }
            }
            std::thread::sleep(POLL);
        }
    }
}

struct Cancel(Arc<AtomicBool>);
impl Drop for Cancel {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}
struct OwnedChild {
    child: Child,
    reaped: bool,
    group_clear: bool,
}
impl OwnedChild {
    fn group_absent(&self) -> Result<bool> {
        #[cfg(unix)]
        {
            use rustix::process::{test_kill_process_group, Pid};
            match test_kill_process_group(Pid::from_child(&self.child)) {
                Ok(()) => Ok(false),
                Err(rustix::io::Errno::SRCH) => Ok(true),
                Err(error) => Err(error).context("inspect owned native tool group"),
            }
        }
        #[cfg(not(unix))]
        {
            anyhow::bail!("native process ownership requires Unix")
        }
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.reaped && self.group_clear {
            return;
        }
        #[cfg(unix)]
        {
            // We created this process group; no caller-supplied PID is used.
            use rustix::process::{kill_process_group, Pid, Signal};
            let _ = kill_process_group(Pid::from_child(&self.child), Signal::KILL);
        }
        if !self.reaped {
            let _ = self.child.kill();
            self.reaped = self.child.wait().is_ok();
        }
        // Orphaned descendants belong to the OS reaper. They have been killed;
        // retain the caller's store lease while their group disappears. A
        // program which leaves descendants never receives a success result.
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if matches!(self.group_absent(), Ok(true)) {
                break;
            }
            std::thread::sleep(POLL);
        }
    }
}
fn drain(pipe: &mut impl Read, output: &mut Vec<u8>, other: usize, maximum: usize) -> Result<bool> {
    let mut buffer = [0; 8192];
    // One bounded read per stream/iteration prevents a noisy stdout producer
    // from starving stderr, cancellation or the deadline.
    match pipe.read(&mut buffer) {
        Ok(0) => Ok(true),
        Ok(count) => {
            ensure!(
                count <= maximum.saturating_sub(other + output.len()),
                "native tool output exceeds bound"
            );
            output.extend_from_slice(&buffer[..count]);
            Ok(false)
        }
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) =>
        {
            Ok(false)
        }
        Err(error) => Err(error).context("read native tool output"),
    }
}

/// The exact directory-inode flock used by native Store_chaindata. This is
/// intentionally a directory descriptor, not a similarly named lock file.
pub struct NativeDirectoryOwner(File);
impl NativeDirectoryOwner {
    pub fn acquire(path: &Path) -> Result<Self> {
        #[cfg(unix)]
        {
            use rustix::fs::{flock, open, FlockOperation, Mode, OFlags};
            let file: File = open(
                path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?
            .into();
            flock(&file, FlockOperation::NonBlockingLockExclusive)
                .context("native store already has an owner")?;
            Ok(Self(file))
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            anyhow::bail!("native directory ownership requires Unix")
        }
    }
}
impl Drop for NativeDirectoryOwner {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            let _ = rustix::fs::flock(&self.0, rustix::fs::FlockOperation::Unlock);
        }
    }
}

#[cfg(all(test, unix))]
mod tests;
