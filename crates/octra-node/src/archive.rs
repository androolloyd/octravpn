//! The launcher's canonical ExEx file sink, also available to embedded nodes.
//! At-least-once delivery reuses immutable files only when their bytes agree.
use octra_exex::{native_history::NativeTransaction, CommittedEpoch, ExEx};
use std::path::PathBuf;

pub struct Archive(PathBuf);
impl Archive {
    /// Keep the original name so existing launcher checkpoints remain valid.
    pub const NAME: &'static str = "devnet-archive";
    pub fn new(directory: PathBuf) -> Self {
        Self(directory)
    }
}
impl ExEx<NativeTransaction> for Archive {
    fn name(&self) -> &'static str {
        Self::NAME
    }
    async fn on_epoch(&mut self, event: &CommittedEpoch<NativeTransaction>) -> Result<(), String> {
        let path = self
            .0
            .join(format!("{:016x}.json", event.cursor.sequence.0));
        let bytes = serde_json::to_vec(event).map_err(|e| e.to_string())?;
        tokio::task::spawn_blocking(move || crate::storage::publish(&path, &bytes))
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())
    }
}
