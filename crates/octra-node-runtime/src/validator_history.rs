//! Membership derived from one retained canonical tree, never peer metadata or
//! a speculative batch. Finality authentication of the store belongs to its
//! publisher; this reader checks head identity and every loaded object hash.
use crate::{
    canonical::{Head, Reader},
    execution::Error,
};
use octra_node_protocol::{
    consensus::{relief::Mark, ValidatorSet},
    validator::{
        config::{anchor::Source, Config},
        update,
    },
};
mod authority;
pub use authority::{Authority, ReceiptPolicy};
#[derive(Clone, Debug, Default)]
pub struct Environment {
    pub current: Option<Vec<u8>>,
    pub next: Option<Vec<u8>>,
    pub activate: Option<Vec<u8>>,
    pub fallback_activate: Option<Vec<u8>>,
}
#[derive(Clone)]
pub struct CanonicalValidators {
    reader: Reader,
    environment: Environment,
}
fn error(e: impl std::fmt::Display) -> Error {
    Error(e.to_string())
}
fn diagnostic(bytes: Vec<u8>) -> Error {
    Error(
        String::from_utf8(bytes)
            .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned()),
    )
}
impl CanonicalValidators {
    pub fn new(reader: Reader, environment: Environment) -> Self {
        Self {
            reader,
            environment,
        }
    }
    async fn read<T>(
        &self,
        head: &Head,
        f: impl FnOnce(Source<'_>) -> Result<T, Vec<u8>>,
    ) -> Result<T, Error> {
        let active = self
            .reader
            .read_at(head, &[b"meta", update::ACTIVE_KEY])
            .await
            .map_err(error)?;
        let pending = self
            .reader
            .read_at(head, &[b"meta", update::PENDING_KEY])
            .await
            .map_err(error)?;
        f(Source {
            chain: self.reader.chain().chain_id.as_bytes(),
            height: i64::try_from(head.cursor.epoch.0).map_err(error)?,
            current: self.environment.current.as_deref(),
            next: self.environment.next.as_deref(),
            activate: self.environment.activate.as_deref(),
            fallback_activate: self.environment.fallback_activate.as_deref(),
            active: active.as_deref(),
            pending: pending.as_deref(),
        })
        .map_err(diagnostic)
    }
    pub async fn config(&self, head: &Head) -> Result<Config, Error> {
        self.read(head, |s| s.config()).await
    }
    pub async fn stake_set(&self, head: &Head, epoch: i64) -> Result<ValidatorSet, Error> {
        self.read(head, |s| s.stake_set(epoch)).await
    }
    pub async fn expected_set(
        &self,
        head: &Head,
        epoch: i64,
        round: Option<i64>,
        relief: &impl Fn(i64) -> Result<Option<Mark>, Vec<u8>>,
    ) -> Result<ValidatorSet, Error> {
        self.read(head, |s| s.expected_set(epoch, round, relief))
            .await
    }
}
