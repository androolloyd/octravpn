//! Bounded, owned transport to the pinned native-format helper.
use anyhow::{bail, ensure, Context, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Read, Write},
    path::Path,
    process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

const MAX: usize = 1_048_576;
const MAX_IMAGE: u64 = 512 * 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(300);
const CLOSE_TIMEOUT: Duration = Duration::from_secs(2);
const POLL: Duration = Duration::from_millis(5);

pub(super) struct Session {
    child: Option<Child>,
    input: Option<ChildStdin>,
    output: Option<ChildStdout>,
    pending: Vec<u8>,
    timeout: Duration,
    close_timeout: Duration,
    // Keep the verified, private executable alive until the child is reaped.
    image: Option<tempfile::TempDir>,
}

impl Session {
    pub(super) fn open(backend: &Path, sha: &str, directory: &Path, chain: &str) -> Result<Self> {
        let image = freeze(backend, sha)?;
        let child = Command::new(image.path().join("backend"))
            .env_clear()
            .arg(directory)
            .arg(chain)
            .current_dir(directory)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // Native failures use the bounded protocol. Avoid unbounded helper
            // logging or accidental inherited-stderr disclosure.
            .stderr(Stdio::null())
            .spawn()
            .context("start pinned legacy backend")?;
        let mut session = Self {
            child: Some(child),
            input: None,
            output: None,
            pending: vec![],
            timeout: REQUEST_TIMEOUT,
            close_timeout: CLOSE_TIMEOUT,
            image: Some(image),
        };
        let child = session.child.as_mut().context("legacy backend is closed")?;
        session.input = child.stdin.take();
        session.output = child.stdout.take();
        nonblocking(
            session
                .input
                .as_ref()
                .context("backend stdin unavailable")?,
        )?;
        nonblocking(
            session
                .output
                .as_ref()
                .context("backend stdout unavailable")?,
        )?;
        Ok(session)
    }

    pub(super) fn receive(&mut self) -> Result<Value> {
        let result = self.receive_before(Instant::now() + self.timeout);
        self.finish(result)
    }

    pub(super) fn request(&mut self, value: &Value) -> Result<Value> {
        // The same deadline bounds encoding, a pipe whose reader stops, and a
        // reply whose writer stops. Each completed operation starts a new one.
        let deadline = Instant::now() + self.timeout;
        let result = (|| {
            let bytes = encode(value)?;
            let input = self.input.as_mut().context("native backend is closed")?;
            let mut written = 0;
            while written < bytes.len() {
                remaining(deadline)?;
                match input.write(&bytes[written..]) {
                    Ok(0) => bail!("native backend request pipe closed"),
                    Ok(count) => written += count,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => pause(deadline)?,
                    Err(error) => return Err(error).context("write native backend request"),
                }
            }
            self.receive_before(deadline)
        })();
        self.finish(result)
    }

    fn receive_before(&mut self, deadline: Instant) -> Result<Value> {
        loop {
            remaining(deadline)?;
            if let Some(end) = self.pending.iter().position(|byte| *byte == b'\n') {
                let rest = self.pending.split_off(end + 1);
                let line = std::mem::replace(&mut self.pending, rest);
                let value: Value =
                    serde_json::from_slice(&line).context("invalid native backend JSON")?;
                let object = value
                    .as_object()
                    .context("native response is not an object")?;
                ensure!(object.len() == 1, "ambiguous native backend response");
                if object.contains_key("error") {
                    // Refusals may contain native filesystem or state values.
                    // Do not forward arbitrary helper text into CLI logs.
                    bail!("native legacy repair refused the operation");
                }
                return object
                    .get("ok")
                    .cloned()
                    .context("native backend response has no result");
            }
            ensure!(
                self.pending.len() < MAX,
                "native backend response exceeds bound"
            );
            let output = self.output.as_mut().context("native backend is closed")?;
            let mut buffer = [0; 8192];
            let limit = buffer.len().min(MAX - self.pending.len());
            match output.read(&mut buffer[..limit]) {
                Ok(0) => bail!("native backend response ended before a complete line"),
                Ok(count) => self.pending.extend_from_slice(&buffer[..count]),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => pause(deadline)?,
                Err(error) => return Err(error).context("read native backend response"),
            }
        }
    }

    fn finish<T>(&mut self, result: Result<T>) -> Result<T> {
        match result {
            Ok(value) => Ok(value),
            Err(error) => {
                // Native durable phases are not rolled back by transport
                // failure. Close/reap only this session's private helper.
                let _ = self.close();
                Err(error)
            }
        }
    }

    pub(super) fn close(&mut self) -> Result<()> {
        self.input.take();
        self.output.take();
        self.pending.clear();
        let Some(mut child) = self.child.take() else {
            return Ok(());
        };
        match wait(&mut child, Instant::now() + self.close_timeout) {
            Ok(Some(status)) => {
                ensure!(status.success(), "native backend failed while closing");
                Ok(())
            }
            Ok(None) => {
                // EOF gives native close/finalizers a bounded chance to release
                // SC ownership. SIGKILL is then directed only at our own Child;
                // wait reaps it before releasing the executable image.
                terminate(&mut child)?;
                bail!("native backend did not close before deadline")
            }
            Err(error) => {
                let _ = terminate(&mut child);
                Err(error)
            }
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.close();
        self.image.take();
    }
}

fn remaining(deadline: Instant) -> Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
        .context("native backend request deadline exceeded")
}
fn pause(deadline: Instant) -> Result<()> {
    thread::sleep(POLL.min(remaining(deadline)?));
    Ok(())
}
fn wait(child: &mut Child, deadline: Instant) -> Result<Option<ExitStatus>> {
    loop {
        if let Some(status) = child.try_wait().context("inspect native backend exit")? {
            return Ok(Some(status));
        }
        let Some(left) = deadline.checked_duration_since(Instant::now()) else {
            return Ok(None);
        };
        thread::sleep(POLL.min(left));
    }
}
fn terminate(child: &mut Child) -> Result<()> {
    let killed = child.kill();
    let reaped = child.wait();
    killed.context("terminate stuck native backend")?;
    reaped.context("reap terminated native backend")?;
    Ok(())
}

#[cfg(unix)]
fn nonblocking(pipe: &impl std::os::fd::AsFd) -> Result<()> {
    use rustix::fs::{fcntl_getfl, fcntl_setfl, OFlags};
    fcntl_setfl(pipe, fcntl_getfl(pipe)? | OFlags::NONBLOCK)?;
    Ok(())
}
#[cfg(not(unix))]
fn nonblocking<T>(_: &T) -> Result<()> {
    bail!("legacy backend transport requires Unix")
}

struct Line(Vec<u8>);
impl Write for Line {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX - self.0.len() {
            return Err(io::Error::other("native backend request exceeds bound"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn encode(value: &Value) -> Result<Vec<u8>> {
    let mut line = Line(vec![]);
    serde_json::to_writer(&mut line, value).context("encode bounded native request")?;
    line.write_all(b"\n")?;
    Ok(line.0)
}

#[cfg(unix)]
fn source(path: &Path) -> Result<fs::File> {
    use rustix::fs::{open, Mode, OFlags};
    use std::os::unix::fs::PermissionsExt;
    let file: fs::File = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )?
    .into();
    let metadata = file.metadata()?;
    ensure!(metadata.is_file(), "legacy backend is not a regular file");
    ensure!(
        metadata.permissions().mode() & 0o111 != 0,
        "legacy backend is not executable"
    );
    Ok(file)
}
#[cfg(not(unix))]
fn source(_: &Path) -> Result<fs::File> {
    bail!("legacy backend transport requires Unix")
}

fn freeze(path: &Path, expected: &str) -> Result<tempfile::TempDir> {
    let expected = hex::decode(expected)?;
    ensure!(expected.len() == 32, "backend SHA256 must contain 32 bytes");
    let mut input = source(path)?;
    ensure!(
        input.metadata()?.len() <= MAX_IMAGE,
        "legacy backend exceeds size limit"
    );
    let mut builder = tempfile::Builder::new();
    builder.prefix("octra-legacy-backend-");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(fs::Permissions::from_mode(0o700));
    }
    let directory = builder.tempdir()?;
    let destination = directory.path().join("backend");
    let mut output = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&destination)?;
    let mut digest = Sha256::new();
    let mut bytes = vec![0; 65536];
    let mut size = 0_u64;
    loop {
        let count = input.read(&mut bytes)?;
        if count == 0 {
            break;
        }
        size += count as u64;
        ensure!(size <= MAX_IMAGE, "legacy backend grew beyond bound");
        digest.update(&bytes[..count]);
        output.write_all(&bytes[..count])?;
    }
    ensure!(
        digest.finalize().as_slice() == expected,
        "legacy backend SHA256 differs"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o500))?;
    }
    output.sync_all()?;
    fs::File::open(directory.path())?.sync_all()?;
    Ok(directory)
}

#[cfg(all(test, unix))]
mod tests;
