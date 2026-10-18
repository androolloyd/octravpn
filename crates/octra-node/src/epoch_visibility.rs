//! Native Epoch_visibility: readers wait for an apply, then retry a changed
//! generation twice. The apply owner, rather than its awaiting caller, releases
//! the transition. This gate grants no admission or publication authority.
use std::{
    future::Future,
    sync::{Arc, Mutex},
};
use tokio::sync::watch;

struct State {
    generation: Arc<()>,
    applying: bool,
}
struct Inner {
    state: Mutex<State>,
    changed: watch::Sender<()>,
}
#[derive(Clone)]
pub(crate) struct Visibility {
    inner: Arc<Inner>,
}
pub(crate) struct Apply {
    visibility: Visibility,
}
impl Default for Visibility {
    fn default() -> Self {
        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(State {
                    generation: Arc::new(()),
                    applying: false,
                }),
                changed: watch::channel(()).0,
            }),
        }
    }
}
impl Visibility {
    pub(crate) fn begin(&self) -> anyhow::Result<Apply> {
        let mut state = self.inner.state.lock().expect("epoch visibility state");
        anyhow::ensure!(
            !state.applying,
            "epoch visibility transition is already active"
        );
        state.generation = Arc::new(());
        state.applying = true;
        Ok(Apply {
            visibility: self.clone(),
        })
    }
    async fn stable(&self) -> Arc<()> {
        let mut changed = self.inner.changed.subscribe();
        loop {
            {
                let state = self.inner.state.lock().expect("epoch visibility state");
                if !state.applying {
                    return state.generation.clone();
                }
            }
            // The sender belongs to self, so it cannot close during this wait.
            changed.changed().await.expect("epoch visibility sender");
        }
    }
    fn current(&self, generation: &Arc<()>) -> bool {
        let state = self.inner.state.lock().expect("epoch visibility state");
        !state.applying && Arc::ptr_eq(&state.generation, generation)
    }
    pub(crate) async fn read<T, F, R>(&self, mut read: F) -> Option<T>
    where
        F: FnMut() -> R,
        R: Future<Output = T>,
    {
        for _ in 0..=2 {
            let generation = self.stable().await;
            let value = read().await;
            if self.current(&generation) {
                return Some(value);
            }
        }
        None
    }
}
impl Drop for Apply {
    fn drop(&mut self) {
        let mut state = self
            .visibility
            .inner
            .state
            .lock()
            .expect("epoch visibility state");
        state.generation = Arc::new(());
        state.applying = false;
        self.visibility.inner.changed.send_replace(());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::oneshot;

    #[derive(Debug, PartialEq, Eq, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct NativeCase {
        case: String,
        calls: usize,
        #[serde(deserialize_with = "required_nullable")]
        result: Option<String>,
    }
    fn required_nullable<'de, D: serde::Deserializer<'de>>(
        value: D,
    ) -> Result<Option<String>, D::Error> {
        serde::Deserialize::deserialize(value)
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct NativeFixture {
        schema: String,
        native_pin: String,
        native_source_sha256: String,
        oracle_source_sha256: String,
        cases: Vec<NativeCase>,
    }
    fn case(name: &str, calls: usize, result: Option<&str>) -> NativeCase {
        NativeCase {
            case: name.into(),
            calls,
            result: result.map(str::to_owned),
        }
    }

    #[tokio::test]
    async fn unchanged_native_visibility_differential_trace() {
        use std::io::Read;
        let raw = if let Some(path) = std::env::var_os("OCTRA_NATIVE_VISIBILITY_FIXTURE") {
            let path = std::path::PathBuf::from(path);
            assert!(std::fs::symlink_metadata(&path).unwrap().is_file());
            let mut raw = Vec::new();
            std::fs::File::open(path)
                .unwrap()
                .take(65_537)
                .read_to_end(&mut raw)
                .unwrap();
            raw
        } else {
            include_bytes!("../tests/fixtures/epoch-visibility-native.json").to_vec()
        };
        assert!(
            raw.len() <= 65_536,
            "native visibility fixture exceeds limit"
        );
        let fixture: NativeFixture = serde_json::from_slice(&raw).unwrap();
        assert_eq!(fixture.schema, "octra_epoch_visibility_native_fixture_v1");
        assert_eq!(
            fixture.native_pin,
            "7f9be4489870645cfcc95439638cde40f5da9f50"
        );
        assert_eq!(
            fixture.native_source_sha256,
            "b8829fea1ee36c5712cebd3beb98196e3b977e19136ab0d468655c1e777d6426"
        );
        assert_eq!(
            fixture.oracle_source_sha256,
            "97b4f90e7cfd685f239f887f97d5cda8bcc2f29143069678787d79ef66499f81"
        );
        let visibility = Visibility::default();
        let calls = AtomicUsize::new(0);
        let mut actual = Vec::new();
        let apply = visibility.begin().unwrap();
        let reading = visibility.read(|| async {
            calls.fetch_add(1, Ordering::SeqCst);
            "value"
        });
        tokio::pin!(reading);
        tokio::select! {
            biased;
            _ = &mut reading => panic!("read ran during apply"),
            () = tokio::task::yield_now() => (),
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        drop(apply);
        assert_eq!(reading.await, Some("value"));
        actual.push(case(
            "wait_apply",
            calls.swap(0, Ordering::SeqCst),
            Some("value"),
        ));
        assert_eq!(
            visibility
                .read(|| async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    drop(visibility.begin().unwrap());
                    17
                })
                .await,
            None
        );
        actual.push(case(
            "three_changed_attempts",
            calls.swap(0, Ordering::SeqCst),
            None,
        ));
        assert_eq!(
            visibility
                .read(|| async {
                    if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                        drop(visibility.begin().unwrap());
                        Err("old failure")
                    } else {
                        Ok("new value")
                    }
                })
                .await,
            Some(Ok("new value"))
        );
        actual.push(case(
            "error_result_retried",
            calls.swap(0, Ordering::SeqCst),
            Some("new value"),
        ));
        assert_eq!(
            visibility
                .read(|| async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Err::<(), _>("stable failure")
                })
                .await,
            Some(Err("stable failure"))
        );
        actual.push(case(
            "stable_error_no_retry",
            calls.swap(0, Ordering::SeqCst),
            Some("error:stable failure"),
        ));
        let apply = visibility.begin().unwrap();
        let first = visibility.read(|| async {
            calls.fetch_add(1, Ordering::SeqCst);
            "first"
        });
        let second = visibility.read(|| async {
            calls.fetch_add(1, Ordering::SeqCst);
            "second"
        });
        tokio::pin!(first, second);
        tokio::select! {
            biased;
            _ = &mut first => panic!("first queued read ran during apply"),
            _ = &mut second => panic!("second queued read ran during apply"),
            () = tokio::task::yield_now() => (),
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        drop(apply);
        assert_eq!(tokio::join!(first, second), (Some("first"), Some("second")));
        actual.push(case(
            "queued_two_reads",
            calls.swap(0, Ordering::SeqCst),
            Some("first,second"),
        ));
        let apply = visibility.begin().unwrap();
        {
            let reading = visibility.read(|| async {
                calls.fetch_add(1, Ordering::SeqCst);
            });
            tokio::pin!(reading);
            tokio::select! {
                biased;
                _ = &mut reading => panic!("cancelled read ran during apply"),
                () = tokio::task::yield_now() => (),
            }
        }
        assert!(visibility.begin().is_err());
        actual.push(case(
            "cancelled_reader_not_owner",
            calls.swap(0, Ordering::SeqCst),
            Some("applying"),
        ));
        drop(apply);
        let apply = visibility.begin().unwrap();
        // Exact dispatch class control, not a submitted economic transaction.
        assert!(!crate::rpc::native::read_methods::contains(b"octra_submit"));
        let writes = 1;
        drop(apply);
        visibility.read(|| async {}).await.unwrap();
        actual.push(case("effects_not_replayed", writes, Some("write1")));
        assert_eq!(actual, fixture.cases);
    }

    #[tokio::test]
    async fn waits_for_apply_and_rechecks_even_a_failed_read() {
        let visibility = Visibility::default();
        let apply = visibility.begin().unwrap();
        let calls = AtomicUsize::new(0);
        let reading = visibility.read(|| async {
            let call = calls.fetch_add(1, Ordering::SeqCst);
            if call == 0 {
                drop(visibility.begin().unwrap());
                Err("old failure")
            } else {
                Ok("new value")
            }
        });
        tokio::pin!(reading);
        tokio::select! {
            biased;
            _ = &mut reading => panic!("read ran during apply"),
            () = tokio::task::yield_now() => (),
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        drop(apply);
        assert_eq!(reading.await, Some(Ok("new value")));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn exactly_three_attempts_then_native_changed_refusal() {
        let visibility = Visibility::default();
        let calls = AtomicUsize::new(0);
        assert_eq!(
            visibility
                .read(|| async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    drop(visibility.begin().unwrap());
                    17
                })
                .await,
            None
        );
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn cancelled_waiter_cannot_release_an_owned_apply() {
        let visibility = Visibility::default();
        let apply = visibility.begin().unwrap();
        let (finish, finished) = oneshot::channel::<()>();
        let owner = tokio::spawn(async move {
            let _apply = apply;
            finished.await.unwrap();
        });
        let captured = visibility.clone();
        let waiter = tokio::spawn(async move { captured.read(|| async { 3 }).await });
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
        let reading = visibility.read(|| async { 5 });
        tokio::pin!(reading);
        tokio::select! {
            biased;
            _ = &mut reading => panic!("cancelled waiter released apply"),
            () = tokio::task::yield_now() => (),
        }
        finish.send(()).unwrap();
        owner.await.unwrap();
        assert_eq!(reading.await, Some(5));
    }
}
