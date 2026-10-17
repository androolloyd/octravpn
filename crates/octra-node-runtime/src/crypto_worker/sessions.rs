//! Two native FHE session lanes, retired after the native ten-second idle span.
use super::{Error, Pool};
use crate::single_private::worker::Session;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};
#[derive(Default)]
pub(super) struct Sessions {
    update: Option<Saved>,
    view: Option<Saved>,
}
struct Saved {
    process: Session,
    last_used: Instant,
}
pub(super) struct Reaper {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}
impl Reaper {
    pub(super) fn start(sessions: Arc<Mutex<Sessions>>) -> Result<Self, String> {
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let thread = std::thread::Builder::new()
            .name("octra-fhe-idle".into())
            .spawn(move || {
                while !stopped.load(Ordering::Acquire) {
                    let mut sessions = sessions
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let Sessions { update, view } = &mut *sessions;
                    for slot in [update, view] {
                        if slot.as_ref().is_some_and(|saved| {
                            saved.last_used.elapsed() >= Duration::from_secs(10)
                        }) {
                            slot.take();
                        }
                    }
                    drop(sessions);
                    std::thread::sleep(Duration::from_millis(50));
                }
            })
            .map_err(|e| e.to_string())?;
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }
}
impl Drop for Reaper {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
impl Pool {
    pub(super) fn session_exchange(
        &self,
        view: bool,
        bytes: &[u8],
        deadline: Instant,
        cancelled: impl Fn() -> bool,
    ) -> Result<Vec<u8>, Error> {
        self.reaper
            .get_or_init(|| Reaper::start(self.sessions.clone()))
            .as_ref()
            .map_err(|_| Error::Unavailable("crypto idle reaper unavailable".into()))?;
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| Error::Unavailable("crypto sessions poisoned".into()))?;
        let slot = if view {
            &mut sessions.view
        } else {
            &mut sessions.update
        };
        if slot.as_mut().is_some_and(|saved| {
            saved.last_used.elapsed() >= Duration::from_secs(10) || !saved.process.alive()
        }) {
            slot.take();
        }
        if slot.is_none() {
            *slot = Some(Saved {
                process: Session::open(self.worker.clone())
                    .map_err(|e| Error::Unavailable(e.to_string()))?,
                last_used: Instant::now(),
            });
        }
        let result = slot
            .as_mut()
            .expect("session installed")
            .process
            .exchange(bytes, super::MAX_BYTES, deadline, cancelled)
            .map_err(|e| Error::Unavailable(e.to_string()));
        match result {
            Ok(bytes) => {
                slot.as_mut().expect("session installed").last_used = Instant::now();
                Ok(bytes)
            }
            Err(error) => {
                slot.take();
                Err(error)
            }
        }
    }
    pub(super) fn retire_session(&self, view: bool) {
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if view {
            sessions.view.take();
        } else {
            sessions.update.take();
        }
    }
    #[cfg(feature = "test-helpers")]
    pub fn session_pid(&self, view: bool) -> Option<u32> {
        let sessions = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if view {
            sessions.view.as_ref()
        } else {
            sessions.update.as_ref()
        }
        .map(|saved| saved.process.pid())
    }
}
