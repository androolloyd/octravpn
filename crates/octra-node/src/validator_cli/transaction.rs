//! Native `bft_control_tx` wallet, transaction and signed-intent operations.
//! Signing uses the protocol's native JSON preimage and bond domain. Preparing
//! a transaction grants no admission, validator membership or duty authority.
use anyhow::{bail, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use clap::{Args, ValueEnum};
use ed25519_dalek::{Signer, SigningKey};
use num_bigint::BigInt;
use octra_node_protocol::{
    transaction::{self, Nonce, OpType, Transaction},
    transaction_policy,
    validator::{intent::Identity, registry},
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

const WALLET_LIMIT: u64 = 65_536;
const MESSAGE_LIMIT: u64 = 33_554_432;
const RESPONSE_LIMIT: usize = 1_048_576;

#[derive(Args)]
pub struct Options {
    /// Report the native tool capabilities without opening a wallet or network.
    #[arg(long)]
    pub capabilities: bool,
    /// Native JSON wallet containing address, pub and base64 priv (32-byte seed).
    #[arg(
        long,
        required_unless_present = "capabilities",
        allow_hyphen_values = true
    )]
    pub wallet: Option<PathBuf>,
    /// RPC endpoint. Required for nonce discovery and submission, never defaulted.
    #[arg(long, allow_hyphen_values = true)]
    pub rpc: Option<String>,
    /// Native op_type, including all validator controls and other known operations.
    #[arg(long, required_unless_present_any = ["capabilities", "exit_intent"], allow_hyphen_values = true)]
    pub op: Option<String>,
    /// Explicit nonce permits offline preparation without an RPC request.
    #[arg(long, allow_hyphen_values = true)]
    pub nonce: Option<String>,
    #[arg(long, default_value = "0", allow_hyphen_values = true)]
    pub amount: String,
    #[arg(long, allow_hyphen_values = true)]
    pub to: Option<String>,
    /// Explicit OU fee; otherwise use the native operation cost.
    #[arg(long, allow_hyphen_values = true)]
    pub ou: Option<String>,
    #[arg(long, allow_hyphen_values = true)]
    pub message: Option<String>,
    /// Exact message bytes; takes precedence over --message, as in the native tool.
    #[arg(long, allow_hyphen_values = true)]
    pub message_file: Option<PathBuf>,
    /// Required for automatic bond proof and signed local exit intents.
    #[arg(long, allow_hyphen_values = true)]
    pub chain_id: Option<String>,
    /// Emit {tx,tx_hash}; never submit the prepared transaction.
    #[arg(long)]
    pub prepare: bool,
    /// Emit the signed transaction only; never submit it.
    #[arg(long)]
    pub print_only: bool,
    /// Explicit signing time in seconds, useful for reproducible offline preparation.
    #[arg(long, allow_hyphen_values = true)]
    pub timestamp: Option<f64>,
    /// Write a signed local intent beside the wallet, without a network transaction.
    #[arg(long, value_enum)]
    pub exit_intent: Option<ExitIntent>,
    #[arg(long, allow_hyphen_values = true, value_parser = native_int64_arg)]
    pub bonded_epoch: Option<i64>,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum ExitIntent {
    Request,
    Cancel,
}

#[derive(Deserialize)]
struct WalletFile {
    address: String,
    #[serde(rename = "pub")]
    public: String,
    #[serde(rename = "priv", deserialize_with = "private_string")]
    private: Zeroizing<String>,
}
fn private_string<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Zeroizing<String>, D::Error> {
    String::deserialize(deserializer).map(Zeroizing::new)
}
struct Wallet {
    file: WalletFile,
    key: SigningKey,
}
impl Wallet {
    fn read(path: &Path) -> Result<Self> {
        let mut bytes = Zeroizing::new(Vec::new());
        read_into(path, WALLET_LIMIT, &mut bytes)?;
        let file: WalletFile =
            serde_json::from_slice(&bytes).context("invalid native wallet JSON")?;
        let secret = Zeroizing::new(
            transaction::decode_base64(file.private.as_bytes())
                .context("invalid wallet private key encoding")?,
        );
        let seed: &[u8; 32] = secret
            .as_slice()
            .try_into()
            .context("wallet private key must contain a 32-byte seed")?;
        let key = SigningKey::from_bytes(seed);
        let public = transaction::decode_base64(file.public.as_bytes())
            .context("invalid wallet public key encoding")?;
        ensure!(
            public.as_slice() == key.verifying_key().as_bytes(),
            "wallet public and private keys differ"
        );
        ensure!(
            file.address.as_bytes() == transaction::address_from_public_key(file.public.as_bytes()),
            "wallet address does not match its public key"
        );
        Ok(Self { file, key })
    }
    fn intent(&self, options: &Options, action: ExitIntent) -> Result<Vec<u8>> {
        let identity = Identity {
            chain_id: options.chain_id()?.as_bytes().to_vec(),
            address: self.file.address.as_bytes().to_vec(),
            pubkey: self.file.public.as_bytes().to_vec(),
            bonded_epoch: options.bonded_epoch.context("missing --bonded-epoch")?,
        };
        let parent = wallet_directory(options.wallet.as_deref().context("missing --wallet")?);
        let control = octra_node_runtime::validator_control::Control::new(parent);
        let value = match action {
            ExitIntent::Request => json!({
                "intent_id": control.request(identity, self.file.private.as_bytes())?,
                "status": "request"
            }),
            ExitIntent::Cancel => {
                control.cancel(&identity, self.file.private.as_bytes())?;
                json!({"intent_id": null, "status": "cancel"})
            }
        };
        Ok(serde_json::to_vec(&value)?)
    }
}

// Native Filename.dirname returns "." for an unqualified wallet filename.
// Rust Path::parent instead returns Some(""); never pass that to directory fsync.
fn wallet_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

/// Detached native signing reuses the same validated/zeroized JSON wallet.
/// The caller supplies its independently trusted role set and exact domain hash.
pub(crate) fn sign_message(
    path: &Path,
    signers: &octra_node_protocol::consensus::ValidatorSet,
    message: &[u8],
) -> Result<octra_node_protocol::state_sync::checkpoint::Signature> {
    use octra_node_protocol::state_sync::checkpoint;
    let wallet = Wallet::read(path)?;
    ensure!(
        signers.public_key(wallet.file.address.as_bytes()) == Some(wallet.file.public.as_bytes()),
        "wallet is not in the configured signer set"
    );
    let signature = checkpoint::Signature {
        signer: wallet.file.address.as_bytes().to_vec(),
        signature: base64::engine::general_purpose::STANDARD
            .encode(wallet.key.sign(message).to_bytes())
            .into_bytes(),
    };
    checkpoint::verify_signature(signers, message, &signature)?;
    Ok(signature)
}

fn read_file(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    read_into(path, limit, &mut bytes)?;
    Ok(bytes)
}
fn read_into(path: &Path, limit: u64, bytes: &mut Vec<u8>) -> Result<()> {
    let file = std::fs::File::open(path)?;
    ensure!(file.metadata()?.is_file(), "input must be a regular file");
    file.take(limit + 1).read_to_end(bytes)?;
    ensure!(bytes.len() as u64 <= limit, "input exceeds its byte limit");
    Ok(())
}
fn native_int64_arg(value: &str) -> std::result::Result<i64, String> {
    octra_node_protocol::native_integer::parse_int64(value.as_bytes())
        .ok_or_else(|| "invalid native int64".to_owned())
}

fn integer(value: &str, name: &str) -> Result<BigInt> {
    transaction::parse_native_integer(value.as_bytes()).with_context(|| format!("invalid --{name}"))
}
fn explicit_nonce(value: &str) -> Result<Nonce> {
    let value = transaction::parse_native_int(value.as_bytes()).context("invalid --nonce")?;
    ensure!(value.get() >= 0, "nonce must be nonnegative");
    Ok(value)
}

impl Options {
    fn chain_id(&self) -> Result<&str> {
        self.chain_id.as_deref().context("missing --chain-id")
    }
    fn draft(&self, wallet: &Wallet, nonce: Nonce, timestamp: f64) -> Result<Transaction> {
        ensure!(timestamp.is_finite(), "timestamp must be finite");
        let op_type = OpType::parse(self.op.as_deref().context("missing --op")?.as_bytes())?;
        let amount = integer(&self.amount, "amount")?;
        let mut message = match &self.message_file {
            Some(path) => Some(read_file(path, MESSAGE_LIMIT)?),
            None => self.message.as_ref().map(|value| value.as_bytes().to_vec()),
        };
        if matches!(
            op_type,
            OpType::ValidatorSetUpdate | OpType::ValidatorReady | OpType::ValidatorEvidence
        ) {
            ensure!(
                message.as_ref().is_some_and(|raw| raw
                    .iter()
                    .any(|b| !matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 12))),
                "{} requires non-empty --message or --message-file",
                op_type.as_str()
            );
        }
        if op_type == OpType::ValidatorBond && message.is_none() {
            let public = wallet.key.verifying_key();
            let binding = registry::bond_message(
                self.chain_id()?.as_bytes(),
                wallet.file.address.as_bytes(),
                &amount,
                nonce,
                public.as_bytes(),
            );
            // Keep native payload field order; JSON object sorting is not signing authority.
            let mut raw = b"{\"consensus_pubkey\":".to_vec();
            transaction::json_string(&mut raw, wallet.file.public.as_bytes());
            raw.extend_from_slice(b",\"proof\":");
            transaction::json_string(
                &mut raw,
                STANDARD
                    .encode(wallet.key.sign(&binding).to_bytes())
                    .as_bytes(),
            );
            raw.push(b'}');
            message = Some(raw);
        }
        let to = self.to.as_ref().map_or_else(
            || {
                if op_type == OpType::ValidatorBond {
                    registry::escrow_address()
                } else {
                    wallet.file.address.as_bytes().to_vec()
                }
            },
            |address| address.as_bytes().to_vec(),
        );
        let mut tx = Transaction {
            from: wallet.file.address.as_bytes().to_vec(),
            to,
            amount,
            nonce,
            ou: 0.into(),
            timestamp,
            signature: Vec::new(),
            public_key: Some(wallet.file.public.as_bytes().to_vec()),
            message,
            op_type,
            encrypted_data: None,
        };
        tx.ou = match &self.ou {
            Some(value) => integer(value, "ou")?,
            None => transaction_policy::ou_cost(
                &tx,
                &transaction_policy::stealth_min_ou(
                    std::env::var("OCTRA_STEALTH_MIN_OU")
                        .ok()
                        .as_deref()
                        .map(str::as_bytes),
                ),
            ),
        };
        tx.signature = STANDARD
            .encode(wallet.key.sign(&tx.signing_bytes()?).to_bytes())
            .into_bytes();
        Ok(tx)
    }
    async fn execute(self) -> Result<Vec<u8>> {
        if self.capabilities {
            return Ok(serde_json::to_vec(
                &json!({"exit_intent":true,"prepare_transaction":true}),
            )?);
        }
        let wallet = Wallet::read(self.wallet.as_deref().context("missing --wallet")?)?;
        if let Some(action) = self.exit_intent {
            return wallet.intent(&self, action);
        }
        let rpc = Rpc::new(self.rpc.as_deref())?;
        let nonce = match &self.nonce {
            Some(value) => explicit_nonce(value)?,
            None => rpc.next_nonce(&wallet.file.address).await?,
        };
        let timestamp = match self.timestamp {
            Some(value) => value,
            None => SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64(),
        };
        let tx = self.draft(&wallet, nonce, timestamp)?;
        let raw = tx.to_json_bytes()?;
        if self.prepare {
            let mut output = b"{\"tx\":".to_vec();
            output.extend_from_slice(&raw);
            output.extend_from_slice(b",\"tx_hash\":");
            transaction::json_string(&mut output, hex::encode(tx.hash()?).as_bytes());
            output.push(b'}');
            Ok(output)
        } else if self.print_only {
            Ok(raw)
        } else {
            Ok(serde_json::to_vec(&rpc.submit(&raw).await?)?)
        }
    }
    pub async fn run(self) -> Result<()> {
        let output = self.execute().await?;
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(&output)?;
        stdout.write_all(b"\n")?;
        Ok(())
    }
}

struct Rpc {
    url: Option<String>,
    client: reqwest::Client,
}
impl Rpc {
    fn new(url: Option<&str>) -> Result<Self> {
        Ok(Self {
            url: url.map(str::to_owned),
            client: reqwest::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(45))
                .connect_timeout(Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::none())
                .user_agent("octra-validator-control/1")
                .build()?,
        })
    }
    async fn call(&self, method: &str, params: &[u8]) -> Result<Value> {
        let mut body = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":".to_vec();
        transaction::json_string(&mut body, method.as_bytes());
        body.extend_from_slice(b",\"params\":");
        body.extend_from_slice(params);
        body.push(b'}');
        // A mutating submission is sent exactly once; transport/RPC errors do not retry it.
        let mut response = self
            .client
            .post(self.url.as_deref().context("missing --rpc")?)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await?
            .error_for_status()?;
        ensure!(
            response
                .content_length()
                .is_none_or(|n| n <= RESPONSE_LIMIT as u64),
            "RPC response too large"
        );
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                chunk.len() <= RESPONSE_LIMIT.saturating_sub(bytes.len()),
                "RPC response too large"
            );
            bytes.extend_from_slice(&chunk);
        }
        let reply: Value = serde_json::from_slice(&bytes).context("invalid RPC JSON")?;
        ensure!(
            reply["jsonrpc"] == "2.0" && reply["id"] == 1,
            "invalid RPC envelope"
        );
        if let Some(error) = reply.get("error") {
            bail!("RPC error: {}", serde_json::to_string(error)?);
        }
        reply.get("result").cloned().context("missing RPC result")
    }
    async fn next_nonce(&self, address: &str) -> Result<Nonce> {
        let account = self
            .call("octra_account", &serde_json::to_vec(&json!([address, 1]))?)
            .await?;
        let current = Nonce::new(account["nonce"].as_i64().context("missing account nonce")?)?;
        ensure!(current != Nonce::MAX, "account nonce exhausted");
        Ok(current.successor())
    }
    async fn submit(&self, transaction: &[u8]) -> Result<Value> {
        let mut params = b"[".to_vec();
        params.extend_from_slice(transaction);
        params.push(b']');
        self.call("octra_submit", &params).await
    }
}

#[cfg(test)]
mod tests;
