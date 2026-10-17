//! Reusable framed FHE process, sharing the existing worker admission policy.
use super::{file_hash, rss_mb, Failure, Worker};
use std::{
    io::{self, Read, Write},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};
pub(crate) struct Session {
    worker: Arc<Worker>,
    child: Child,
    input: Option<ChildStdin>,
    output: Option<ChildStdout>,
}
impl Session {
    pub(crate) fn open(worker: Arc<Worker>) -> Result<Self, Failure> {
        if file_hash(&worker.executable)? != worker.executable_sha {
            return Err(Failure::Unavailable(
                "worker executable changed; restart required".into(),
            ));
        }
        let child = Command::new(&worker.executable)
            .arg("crypto-worker")
            .arg("--parent-pid")
            .arg(std::process::id().to_string())
            .arg("--session")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| e.to_string())?;
        let mut session = Self {
            worker,
            child,
            input: None,
            output: None,
        };
        session.input = session.child.stdin.take();
        session.output = session.child.stdout.take();
        nonblocking(session.input.as_ref().ok_or("worker stdin missing")?)?;
        nonblocking(session.output.as_ref().ok_or("worker stdout missing")?)?;
        if file_hash(&session.worker.executable)? != session.worker.executable_sha {
            return Err(Failure::Unavailable(
                "worker executable changed during spawn".into(),
            ));
        }
        Ok(session)
    }
    pub(crate) fn alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
    pub(crate) fn exchange(
        &mut self,
        bytes: &[u8],
        maximum: usize,
        deadline: Instant,
        cancelled: impl Fn() -> bool,
    ) -> Result<Vec<u8>, Failure> {
        let header = (bytes.len() as u64).to_be_bytes();
        let mut sent = 0_usize;
        let mut received = 0_usize;
        let mut frame = [0_u8; 8];
        let mut output: Option<Vec<u8>> = None;
        loop {
            if cancelled() {
                return Err(Failure::Cancelled);
            }
            if Instant::now() >= deadline {
                return Err(Failure::TimedOut);
            }
            if rss_mb(self.child.id()).is_some_and(|rss| rss > self.worker.limits.rss_mb) {
                return Err(Failure::MemoryExceeded);
            }
            let mut progress = false;
            if sent < header.len() + bytes.len() {
                let part = if sent < header.len() {
                    &header[sent..]
                } else {
                    &bytes[sent - header.len()..]
                };
                match self
                    .input
                    .as_mut()
                    .ok_or("worker session closed")?
                    .write(&part[..part.len().min(65_536)])
                {
                    Ok(0) => return Err("worker request pipe closed".into()),
                    Ok(n) => {
                        sent += n;
                        progress = true;
                    }
                    Err(e)
                        if e.kind() == io::ErrorKind::WouldBlock
                            || e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e.to_string().into()),
                }
            }
            let target = match output.as_mut() {
                None => &mut frame[received..],
                Some(bytes) => &mut bytes[received..],
            };
            if !target.is_empty() {
                let limit = target.len().min(65_536);
                match self
                    .output
                    .as_mut()
                    .ok_or("worker session closed")?
                    .read(&mut target[..limit])
                {
                    Ok(0) => return Err("worker response pipe closed".into()),
                    Ok(n) => {
                        received += n;
                        progress = true;
                    }
                    Err(e)
                        if e.kind() == io::ErrorKind::WouldBlock
                            || e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e.to_string().into()),
                }
            }
            if output.is_none() && received == 8 {
                let length = usize::try_from(u64::from_be_bytes(frame))
                    .map_err(|_| "worker response length overflow")?;
                if length == 0 || length > maximum {
                    return Err("worker response frame exceeds local limit".into());
                }
                let mut bytes = Vec::new();
                bytes
                    .try_reserve_exact(length)
                    .map_err(|_| Failure::MemoryExceeded)?;
                bytes.resize(length, 0);
                output = Some(bytes);
                received = 0;
            }
            if sent == header.len() + bytes.len()
                && output.as_ref().is_some_and(|bytes| received == bytes.len())
            {
                return output.ok_or_else(|| "worker response missing".into());
            }
            if !progress {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }
    #[cfg(feature = "test-helpers")]
    pub(crate) fn pid(&self) -> u32 {
        self.child.id()
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.input.take();
        self.output.take();
    }
}
#[cfg(unix)]
fn nonblocking(pipe: &impl std::os::fd::AsFd) -> Result<(), Failure> {
    use rustix::fs::{fcntl_getfl, fcntl_setfl, OFlags};
    fcntl_setfl(
        pipe,
        fcntl_getfl(pipe).map_err(|e| e.to_string())? | OFlags::NONBLOCK,
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}
#[cfg(not(unix))]
fn nonblocking<T>(_: &T) -> Result<(), Failure> {
    Err(Failure::Unavailable(
        "FHE process sessions require Unix".into(),
    ))
}
