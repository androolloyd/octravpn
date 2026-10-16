//! Local authenticated duty pause controls. These commands never submit a
//! transaction and never change validator membership or move stake.
use anyhow::Result;
use base64::{engine::general_purpose::STANDARD, Engine};
use clap::{Args, Subcommand};
use octra_node_protocol::validator::intent::Identity;
use octra_node_runtime::validator_control::Control;
use std::path::PathBuf;

#[derive(Args)]
pub struct Options {
    /// Private 32-byte node identity, also used by run-network.
    #[arg(long)]
    pub key: PathBuf,
    /// Node data directory whose validator-control journal is managed.
    #[arg(long)]
    pub data: PathBuf,
    #[arg(long)]
    pub chain_id: String,
    /// Exact bonded incarnation from octra_validatorEnrollment.
    #[arg(long)]
    pub bonded_epoch: i64,
    #[command(subcommand)]
    pub action: Action,
}
#[derive(Subcommand)]
pub enum Action {
    /// Persist a signed local exit intent before requesting an on-chain exit.
    Request,
    /// Show whether this bonded incarnation has a local exit intent.
    Status,
    /// Cancel the signed local intent and allow automatic duty again.
    Cancel,
}
impl Options {
    pub fn run(self) -> Result<()> {
        let key = crate::identity::read(&self.key)?;
        let public = STANDARD.encode(key.verifying_key().as_bytes());
        let identity = Identity {
            chain_id: self.chain_id.into_bytes(),
            address: octra_node_protocol::transaction::address_from_public_key(public.as_bytes()),
            pubkey: public.into_bytes(),
            bonded_epoch: self.bonded_epoch,
        };
        let control = Control::new(&self.data);
        // Validate the supplied identity even for a missing status file. Keep
        // the temporary native base64 signing seed zeroized on every outcome.
        let seed = zeroize::Zeroizing::new(key.to_bytes());
        let private = zeroize::Zeroizing::new(STANDARD.encode(seed.as_ref()));
        octra_node_protocol::validator::intent::Intent::create(
            identity.clone(),
            private.as_bytes(),
        )?;
        let value = match self.action {
            Action::Request => {
                serde_json::json!({"intent_id":control.request(identity, private.as_bytes())?,"status":"request"})
            }
            Action::Status => {
                serde_json::json!({"intent_id":control.status(&identity)?,"status":"status"})
            }
            Action::Cancel => {
                control.cancel(&identity, private.as_bytes())?;
                serde_json::json!({"intent_id":null,"status":"cancel"})
            }
        };
        println!("{}", serde_json::to_string(&value)?);
        Ok(())
    }
}
