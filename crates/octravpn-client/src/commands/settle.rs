use std::{path::PathBuf, sync::Arc};

use anyhow::{anyhow, Result};

use crate::{runner::Client, settler};

#[derive(clap::Parser, Debug, Clone)]
pub(crate) enum SettleCmd {
    /// Arm a countersigned relay settlement from the durable client journal.
    Arm {
        session_id: String,
        /// Prime the durable journal from a JSON-serialized countersigned SignedReceipt.
        #[arg(long)]
        from_receipt: Option<PathBuf>,
        /// Net amount to freeze with the countersigned receipt.
        #[arg(long)]
        net: Option<u64>,
        /// Relay claim expiry to pass to arm_relay.
        #[arg(long = "relay-expiry")]
        relay_expiry: Option<u64>,
    },
}

pub(crate) async fn run(client: &Arc<Client>, cmd: SettleCmd) -> Result<()> {
    match cmd {
        SettleCmd::Arm {
            session_id,
            from_receipt,
            net,
            relay_expiry,
        } => {
            let id = settler::session_id_from_cli(&session_id)?;
            match (from_receipt, net, relay_expiry) {
                (None, None, None) => settler::arm_recorded_session(client, id).await,
                (Some(path), Some(net), Some(relay_expiry)) => {
                    settler::arm_session_from_receipt(client, id, &path, net, relay_expiry).await
                }
                _ => Err(anyhow!(
                    "`settle arm --from-receipt` requires --net and --relay-expiry; \
                     --net/--relay-expiry require --from-receipt"
                )),
            }
        }
    }
}
