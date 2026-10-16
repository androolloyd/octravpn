//! Captured rule and public-key capabilities for native private-account reads.
use super::Native;
use crate::Committed;
use octra_node_protocol::{
    rpc::Fault,
    rules::{RootRead, Rule},
    state_sync::migration::Admission,
    transaction::{Nonce, RuleMode},
};
use octra_node_runtime::{execution::Error, private_account_rpc::MigrationRules, pvac};
use std::{collections::BTreeMap, io::Read, sync::Arc};

impl Native {
    pub(crate) fn migration_admission(&self) -> Option<Arc<Admission>> {
        self.config.migration.clone()
    }
    pub(crate) fn public_pvac(
        &self,
        committed: &Committed,
        address: &[u8],
    ) -> Result<Option<Vec<u8>>, Error> {
        if !octra_node_protocol::transaction::is_valid_address(address) {
            return Err(Error("invalid public key address".into()));
        }
        match committed.state().get(&[b"pvac_hashes", address]) {
            Some(b"none") => Ok(None),
            Some(hash) => self
                .key_blob(hash)?
                .map(Some)
                .ok_or_else(|| Error("pvac blob unavailable".into())),
            None => {
                let address = std::str::from_utf8(address)
                    .map_err(|_| Error("invalid public key address".into()))?;
                let path = self.config.pvac_dir.join(format!("{address}.pk"));
                let mut options = std::fs::OpenOptions::new();
                options.read(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.custom_flags(
                        (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
                    );
                }
                let Ok(file) = options.open(path) else {
                    return Ok(None);
                };
                let Ok(metadata) = file.metadata() else {
                    return Ok(None);
                };
                if !metadata.is_file() {
                    return Ok(None);
                }
                if metadata.len() > pvac::MAX_BLOB_BYTES as u64 {
                    return Err(Error("legacy pvac blob exceeds public read limit".into()));
                }
                let mut raw = Vec::new();
                if file.take(metadata.len()).read_to_end(&mut raw).is_err()
                    || raw.len() as u64 != metadata.len()
                {
                    return Ok(None);
                }
                Ok(Some(raw))
            }
        }
    }
    pub(crate) async fn private_account_rules(
        &self,
        committed: &Committed,
    ) -> Result<MigrationRules, Fault> {
        let epoch = Nonce::new(committed.head().cursor.epoch.0 as i64)
            .map_err(|_| Fault::new(-32005, b"pvac migration status unavailable"))?
            .successor()
            .get();
        let graph = &self.config.graph;
        let mut roots = BTreeMap::new();
        let mut modes = Vec::new();
        for rule in [
            Rule::OwnerMigration,
            Rule::CipherMigration,
            Rule::Standard,
            Rule::Math,
        ] {
            if let Some(plan) = graph
                .activation(rule)
                .filter(|plan| epoch >= plan.activation_epoch)
            {
                if let std::collections::btree_map::Entry::Vacant(entry) =
                    roots.entry(plan.anchor_epoch)
                {
                    let root = if u64::try_from(plan.anchor_epoch)
                        .is_ok_and(|epoch| epoch <= committed.head().cursor.epoch.0)
                    {
                        match self.history.root(plan.anchor_epoch).await {
                            Ok(Some(root)) => RootRead::Root(hex::encode(root).into_bytes()),
                            Ok(None) => RootRead::Missing,
                            Err(error) => RootRead::Unreadable(error.to_string().into_bytes()),
                        }
                    } else {
                        RootRead::Missing
                    };
                    entry.insert(root);
                }
            }
            modes.push(
                graph
                    .mode(rule, epoch, &|epoch| {
                        roots.get(&epoch).cloned().unwrap_or(RootRead::Missing)
                    })
                    .map_err(|error| Fault::new(-32005, error.message()))?,
            );
        }
        Ok(MigrationRules {
            epoch,
            owner: modes[0],
            cipher: modes[1],
            proof: modes[2],
            math: modes[3] == RuleMode::Active,
        })
    }
    pub(crate) async fn classify_migration(
        &self,
        committed: Committed,
        address: Vec<u8>,
        cipher: Arc<[u8]>,
    ) -> Result<octra_node_runtime::private_account_rpc::Classified, Fault> {
        use octra_node_runtime::pvac_status_actor::{Error as ActorError, Query};
        if committed.assets.identity().chain_id.as_bytes() != self.config.graph.chain_id() {
            return Err(Fault::new(-32005, b"pvac migration status unavailable"));
        }
        let scope = serde_json::to_vec(committed.assets.identity())
            .map_err(|_| Fault::new(-32005, b"pvac migration status unavailable"))?;
        let key_hash = committed
            .state()
            .get(&[b"pvac_hashes", &address])
            .filter(|raw| *raw != b"none")
            .map(<[u8]>::to_vec);
        let native = self.clone();
        let source_address = address.clone();
        self.migration_status
            .query(
                Query {
                    scope,
                    address,
                    key_hash,
                    cipher,
                },
                Box::new(move || native.public_pvac(&committed, &source_address)),
            )
            .await
            .map_err(|error| match error {
                ActorError::Busy | ActorError::Stopped => {
                    Fault::new(-32005, b"pvac migration status busy")
                }
                ActorError::ReadFailed => Fault::new(-32005, b"pvac migration status unavailable"),
            })
    }
    pub(crate) async fn shutdown_migration_status(&self) {
        self.migration_status.shutdown().await;
    }
}
