use std::sync::Arc;

use anyhow::Result;

use crate::{runner::Client, settler};

#[derive(clap::Parser, Debug, Clone)]
pub(crate) enum SettleCmd {
    /// Arm a countersigned relay settlement from the durable client journal.
    Arm { session_id: String },
}

pub(crate) async fn run(client: &Arc<Client>, cmd: SettleCmd) -> Result<()> {
    match cmd {
        SettleCmd::Arm { session_id } => {
            let id = settler::session_id_from_cli(&session_id)?;
            settler::arm_recorded_session(client, id).await
        }
    }
}
