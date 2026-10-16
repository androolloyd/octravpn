//! One authenticated immutable tree shared by execution and committed readers.
use super::{error, reader, Head, Result};
use crate::state_batch::Snapshot;
use sqlx::SqlitePool;
use std::sync::RwLock;

#[derive(Default)]
pub(super) struct Cache(RwLock<Option<(Head, Snapshot)>>);

impl Cache {
    pub(super) fn remember(&self, head: &Head, snapshot: Snapshot) -> Result<()> {
        let snapshot = snapshot.with_persisted_counter().map_err(error)?;
        if hex::encode(snapshot.root().map_err(error)?) != head.ledger_root {
            return Err(error("canonical snapshot cache commitment differs"));
        }
        let mut saved = self
            .0
            .write()
            .map_err(|_| error("canonical snapshot cache poisoned"))?;
        if let Some((previous, _)) = saved.as_ref() {
            if previous.cursor.sequence > head.cursor.sequence {
                return Ok(());
            }
            if previous.cursor.sequence == head.cursor.sequence && previous != head {
                return Err(error("canonical snapshot cache head differs"));
            }
        }
        let previous = saved.replace((head.clone(), snapshot));
        drop(saved);
        drop(previous);
        Ok(())
    }

    pub(super) async fn load(&self, pool: &SqlitePool, head: &Head) -> Result<Snapshot> {
        let cached = self
            .0
            .read()
            .map_err(|_| error("canonical snapshot cache poisoned"))?
            .as_ref()
            .filter(|(saved, _)| saved == head)
            .map(|(_, snapshot)| snapshot.clone());
        if let Some(snapshot) = cached {
            return Ok(snapshot);
        }
        let snapshot = reader::restore(pool, head).await?;
        self.remember(head, snapshot.clone())?;
        Ok(snapshot)
    }
}
