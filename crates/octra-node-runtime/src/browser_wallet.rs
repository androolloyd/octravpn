//! Reviewed Circle calls become native signed transactions. Keys stay in a
//! host-owned signer; the node owns authenticated state, pending nonces and
//! atomic admission. Neither capability is provided by the Circle document.
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use num_bigint::BigInt;
use num_traits::{Signed, Zero};
use octra_browser::{
    application::{ApplicationHost, Context, Intent, ReadMethod, ReadRequest, ReviewedAction},
    Error, Provenance,
};
use octra_exex::ChainIdentity;
use octra_node_protocol::transaction::{
    address_from_public_key, check_envelope, is_valid_address, Nonce, OpType, Transaction,
};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::Mutex;

#[async_trait]
pub trait Signer: Send + Sync {
    fn public_key(&self) -> [u8; 32];
    /// Sign precisely the native transaction signing bytes. Implementations may
    /// use a local keystore or require approval on an external signing device.
    async fn sign(&self, bytes: &[u8]) -> Result<[u8; 64], Error>;
}

pub struct Account {
    pub provenance: Provenance,
    /// Spendable balance after the node's pending reservations.
    pub available: BigInt,
    pub next_nonce: Nonce,
    pub timestamp: f64,
}

#[async_trait]
pub trait Node: Send + Sync {
    /// Refuse while syncing or if the reviewed snapshot is no longer current.
    async fn account(&self, context: &Context, address: &[u8]) -> Result<Account, Error>;
    /// Recheck the snapshot, signature, pending nonce, balance, release profile,
    /// native payload/fee rules and capacity atomically when staging. A returned
    /// error or cancellation must not trigger an automatic wallet retry.
    async fn submit(&self, context: &Context, transaction: Transaction) -> Result<(), Error>;
    /// Return status only for this wallet's call to this Circle on the bound
    /// chain. Committed status must come from authenticated canonical history.
    async fn status(&self, context: &Context, address: &[u8], hash: &str) -> Result<Value, Error>;
}

pub struct Policy {
    pub chain: ChainIdentity,
    pub max_amount: BigInt,
    pub max_ou: BigInt,
}

pub struct Wallet {
    node: Arc<dyn Node>,
    signer: Arc<dyn Signer>,
    policy: Policy,
    public_key: Vec<u8>,
    address: Vec<u8>,
    // Serialize this wallet's preparation and submission. The node must also
    // protect against competing wallet instances and non-browser submitters.
    signing: Mutex<()>,
}
fn invalid(reason: impl Into<String>) -> Error {
    Error::Invalid(reason.into())
}
fn unavailable(reason: impl std::fmt::Display) -> Error {
    Error::Unavailable(reason.to_string())
}
impl Wallet {
    pub fn new(
        node: Arc<dyn Node>,
        signer: Arc<dyn Signer>,
        policy: Policy,
    ) -> Result<Self, Error> {
        if policy.chain.chain_id.is_empty()
            || policy.max_amount.is_negative()
            || !policy.max_ou.is_positive()
        {
            return Err(invalid("invalid browser wallet policy"));
        }
        let public_key = STANDARD.encode(signer.public_key()).into_bytes();
        let address = address_from_public_key(&public_key);
        Ok(Self {
            node,
            signer,
            policy,
            public_key,
            address,
            signing: Mutex::new(()),
        })
    }
    fn context(&self, context: &Context) -> Result<(), Error> {
        let Provenance::Canonical(snapshot) = &context.provenance else {
            return Err(invalid("wallet requires an authenticated chain snapshot"));
        };
        if snapshot.chain_id != self.policy.chain.chain_id
            || snapshot.genesis_root != hex::encode(self.policy.chain.genesis_root.0)
            || !is_valid_address(context.circle_id.as_bytes())
        {
            return Err(invalid("wallet chain or Circle binding differs"));
        }
        Ok(())
    }
    async fn account(&self, context: &Context) -> Result<Account, Error> {
        self.context(context)?;
        let account = self.node.account(context, &self.address).await?;
        if account.provenance != context.provenance {
            return Err(Error::SnapshotChanged);
        }
        if account.available.is_negative()
            || account.next_nonce.get() <= 0
            || !account.timestamp.is_finite()
        {
            return Err(unavailable("invalid wallet account context"));
        }
        Ok(account)
    }
    async fn call(&self, intent: Intent) -> Result<Value, Error> {
        self.context(&intent.context)?;
        intent.call.validate()?;
        let amount: BigInt = intent.call.amount.parse().map_err(unavailable)?;
        let ou: BigInt = intent.call.ou.parse().map_err(unavailable)?;
        if amount > self.policy.max_amount || ou > self.policy.max_ou || ou.is_zero() {
            return Err(invalid("Circle call exceeds wallet spending policy"));
        }
        let _guard = self.signing.lock().await;
        let account = self.account(&intent.context).await?;
        if &amount + &ou > account.available {
            return Err(invalid("insufficient available wallet balance"));
        }
        let mut tx = Transaction {
            from: self.address.clone(),
            to: intent.context.circle_id.as_bytes().to_vec(),
            amount,
            nonce: account.next_nonce,
            ou,
            timestamp: account.timestamp,
            signature: vec![],
            public_key: Some(self.public_key.clone()),
            message: Some(serde_json::to_vec(&intent.call.params).map_err(unavailable)?),
            encrypted_data: Some(intent.call.method.into_bytes()),
            op_type: OpType::CircleCall,
        };
        if !crate::admission::call_params_ok(&tx) {
            return Err(invalid("contract call params contain invalid characters"));
        }
        let minimum = octra_node_protocol::transaction_policy::ou_cost(&tx, &BigInt::zero());
        if tx.ou < minimum {
            return Err(invalid(format!("fee too low (min: {minimum})")));
        }
        let signature = self
            .signer
            .sign(&tx.signing_bytes().map_err(unavailable)?)
            .await?;
        tx.signature = STANDARD.encode(signature).into_bytes();
        check_envelope(&tx).map_err(unavailable)?;
        if !tx.verify(&self.public_key) {
            return Err(unavailable("wallet signer returned an invalid signature"));
        }
        let hash = hex::encode(tx.hash().map_err(unavailable)?);
        // The node rechecks the head after a potentially slow hardware signer.
        self.node.submit(&intent.context, tx).await?;
        Ok(json!({"hash":hash}))
    }
}
#[async_trait]
impl ApplicationHost for Wallet {
    async fn read(&self, request: ReadRequest) -> Result<Value, Error> {
        self.context(&request.context)?;
        match request.method {
            ReadMethod::WalletInfo | ReadMethod::WalletBalance => {
                let account = self.account(&request.context).await?;
                Ok(if request.method == ReadMethod::WalletInfo {
                    json!({"address":std::str::from_utf8(&self.address).map_err(unavailable)?})
                } else {
                    json!({"balance":account.available.to_string(),"next_nonce":account.next_nonce.get()})
                })
            }
            ReadMethod::TransactionWait => {
                let hash = request
                    .params
                    .get("hash")
                    .and_then(Value::as_str)
                    .filter(|s| {
                        s.len() == 64
                            && s.bytes()
                                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    })
                    .ok_or_else(|| invalid("invalid transaction hash"))?;
                self.node
                    .status(&request.context, &self.address, hash)
                    .await
            }
            _ => Err(unavailable("wallet cannot execute program reads")),
        }
    }
    async fn submit(&self, action: ReviewedAction) -> Result<Value, Error> {
        self.call(action.into_intent()).await
    }
}

#[cfg(test)]
#[path = "browser_wallet_tests.rs"]
mod tests;
