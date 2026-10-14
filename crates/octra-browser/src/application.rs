//! Wallet and execution capabilities are separate from immutable asset reads.
use crate::{Error, Provenance};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[path = "bridge.rs"]
mod bridge;
pub(crate) use bridge::{Bridge, Request, Review, MAX_REQUEST};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    pub circle_id: String,
    pub provenance: Provenance,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadMethod {
    ProgramInfo,
    ProgramView,
    WalletInfo,
    WalletBalance,
    TransactionWait,
}
#[derive(Clone, Debug)]
pub struct ReadRequest {
    pub context: Context,
    pub method: ReadMethod,
    pub params: Value,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Call {
    pub method: String,
    #[serde(default)]
    pub params: Vec<Value>,
    pub amount: String,
    pub ou: String,
}
impl Call {
    pub fn validate(&self) -> Result<(), Error> {
        if self.method.is_empty()
            || self.method.len() > 128
            || !self
                .method
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            || self.params.len() > 256
            || [&self.amount, &self.ou]
                .iter()
                .any(|v| v.is_empty() || v.len() > 128 || !v.bytes().all(|b| b.is_ascii_digit()))
        {
            return Err(Error::Invalid("invalid Circle call".into()));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Intent {
    pub context: Context,
    pub call: Call,
}
/// Submission capability issued only by the trusted review boundary.
/// Hosts must still apply wallet policy, chain identity, fee limits
/// and current nonce. Callers cannot construct an unchecked action.
#[derive(Debug)]
pub struct ReviewedAction {
    intent: Intent,
}
impl ReviewedAction {
    pub fn intent(&self) -> &Intent {
        &self.intent
    }
    pub fn into_intent(self) -> Intent {
        self.intent
    }
}
#[async_trait]
pub trait ApplicationHost: Send + Sync {
    async fn read(&self, request: ReadRequest) -> Result<Value, Error>;
    async fn submit(&self, action: ReviewedAction) -> Result<Value, Error>;
}
#[derive(Default)]
pub struct UnavailableHost;
#[async_trait]
impl ApplicationHost for UnavailableHost {
    async fn read(&self, _: ReadRequest) -> Result<Value, Error> {
        Err(Error::Unavailable(
            "application read capability is not configured".into(),
        ))
    }
    async fn submit(&self, _: ReviewedAction) -> Result<Value, Error> {
        Err(Error::Unavailable(
            "transaction submission capability is not configured".into(),
        ))
    }
}
