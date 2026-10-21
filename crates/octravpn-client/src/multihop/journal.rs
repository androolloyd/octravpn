//! An immutable composite identity, reusing the same private single-writer
//! fsync/rename/checksum storage boundary as individual prepaid journals.
use super::{absolute, Options, Pins};
use crate::payments::storage::Store;
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};

const DOMAIN: &[u8] = b"Octranet nested prepaid route v1\0";
#[derive(Serialize)]
struct Hop<'a> {
    plan: &'a crate::AcceptedPlan,
    journal: std::path::PathBuf,
    interface: &'a str,
    receipt_key: [u8; 32],
    pin: Pins,
    mtu: u16,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    identity: serde_json::Value,
    sha256: String,
}
#[derive(Clone)]
pub(super) struct Lease(Arc<Mutex<Store>>);
#[async_trait::async_trait]
impl super::funded::Journal for Lease {
    async fn check(&self) -> Result<()> {
        Self::check(self).await
    }
    async fn network(&self) -> Result<Option<crate::PrivateRouteNetwork>> {
        Ok(None)
    }
    async fn armed(&self, _: &crate::PrivateRouteNetwork) -> Result<()> {
        Ok(())
    }
    async fn released(&self) -> Result<()> {
        Ok(())
    }
}
impl Lease {
    pub(super) fn open(options: &Options, pins: &[Pins], mtus: &[u16]) -> Result<Self> {
        let hops = options
            .hops
            .iter()
            .zip(pins)
            .zip(mtus)
            .map(|((hop, pin), mtu)| {
                Ok(Hop {
                    plan: &hop.plan,
                    journal: absolute(&hop.journal)?,
                    interface: &hop.interface_name,
                    receipt_key: hop.receipt_key.public.0,
                    pin: *pin,
                    mtu: *mtu,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let identity = serde_json::to_value(&hops)?;
        Self::identity(&options.journal, options.mode, identity, None)
    }
    pub(super) fn identity(
        path: &std::path::Path,
        mode: crate::JournalMode,
        identity: serde_json::Value,
        protection: Option<octravpn_core::sealed::Protection>,
    ) -> Result<Self> {
        let expected = digest(&identity)?;
        let mut store = if let Some(protection) = protection {
            Store::open_private(path, mode, protection)?
        } else {
            Store::open(path, mode)?
        };
        if mode == crate::JournalMode::Create {
            store.commit(&serde_json::to_vec(&Envelope {
                identity,
                sha256: expected,
            })?)?;
        } else {
            let stored: Envelope = serde_json::from_slice(&store.read()?)?;
            ensure!(
                stored.sha256 == digest(&stored.identity)?,
                "composite journal checksum differs"
            );
            ensure!(
                stored.identity == identity && stored.sha256 == expected,
                "accepted route order/plans/keys/pins/MTUs changed; refusing resume"
            );
        }
        Ok(Self(Arc::new(Mutex::new(store))))
    }
    pub(super) async fn check(&self) -> Result<()> {
        let store = self.0.clone();
        tokio::task::spawn_blocking(move || {
            store
                .lock()
                .map_err(|_| anyhow::anyhow!("route journal poisoned"))?
                .check()
        })
        .await?
    }
}
fn digest(identity: &serde_json::Value) -> Result<String> {
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash.update(serde_json::to_vec(identity)?);
    Ok(hex::encode(hash.finalize()))
}
