//! Tests use an actual packaged helper; absence never silently skips crypto.
use octra_node_runtime::crypto_worker::{Limits, Pool, Scope};
use std::{
    cell::RefCell,
    path::PathBuf,
    sync::{atomic::AtomicBool, Arc},
};
thread_local! {static POOL:RefCell<Option<Arc<Pool>>>=const {RefCell::new(None)};}
pub(crate) fn executable() -> PathBuf {
    let executable=PathBuf::from(std::env::var_os("OCTRA_CRYPTO_WORKER_EXE")
        .or_else(||option_env!("CARGO_BIN_EXE_octra-native-worker").map(Into::into))
        .or_else(||option_env!("CARGO_BIN_EXE_octra-node").map(Into::into))
        .expect("qualification requires packaged octra-native-worker/octra-node or OCTRA_CRYPTO_WORKER_EXE"));
    assert!(
        executable.is_absolute(),
        "crypto qualification helper must be absolute"
    );
    executable
}
pub(crate) fn pool() -> Arc<Pool> {
    POOL.with(|slot| {
        let saved = slot.borrow().clone();
        if let Some(pool) = saved {
            return pool;
        }
        let pool = Pool::open(
            &executable(),
            Limits {
                capacity: 1,
                timeout_seconds: 600.,
                rss_mb: 9216,
            },
        )
        .expect("open trusted packaged crypto helper");
        *slot.borrow_mut() = Some(pool.clone());
        pool
    })
}
#[allow(dead_code)] // Actor-only suites configure the same pool inside their worker.
pub(crate) fn scope(view: bool) -> Scope {
    pool().scope(view, Arc::new(AtomicBool::new(false)))
}
