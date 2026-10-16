//! Captured local identity and native readonly services, without BFT history.
use super::Facade;
use crate::rpc::{Context, SingleOptions};
use anyhow::{ensure, Result};
use ed25519_dalek::{Signer, SigningKey};
use octra_node_runtime::{
    status_read,
    validator_history::{CanonicalValidators, Environment},
};
use std::{path::Path, sync::Arc};
impl Facade {
    pub(crate) fn context(
        self: &Arc<Self>,
        key: &SigningKey,
        data: &Path,
        vpn_program: Option<String>,
    ) -> Result<Arc<Context>> {
        let node = self.node();
        ensure!(
            node.store().identity().public_key == key.verifying_key().as_bytes(),
            "Single service key differs from local journal authority"
        );
        let settings = node.settings();
        let environment = Environment {
            current: settings.validators.clone().or_else(|| {
                Some(
                    [
                        settings.wallet_address.as_slice(),
                        b":",
                        settings.wallet_public.as_slice(),
                    ]
                    .concat(),
                )
            }),
            next: settings.next_validators.clone(),
            activate: settings
                .activation
                .map(|epoch| epoch.to_string().into_bytes()),
            fallback_activate: None,
        };
        let membership = CanonicalValidators::new(node.store().reader(), environment);
        let signer = key.clone();
        let status = Arc::new(
            status_read::Service::new(
                node.store().reader(),
                membership,
                settings.wallet_address.clone(),
                key.verifying_key().to_bytes().to_vec(),
                Arc::new(move |bytes| signer.sign(bytes).to_bytes().to_vec()),
                None,
                Some(
                    octra_node_protocol::view_key::public(key.verifying_key().as_bytes())?.to_vec(),
                ),
            )
            .with_control(data),
        );
        // A private Single service never inherits global exporter or join flags.
        // Local settings cannot confer the missing BFT finality capability.
        let captured = octra_node_protocol::consensus::profile::Settings::from_values(
            std::collections::BTreeMap::new(),
        )?;
        let http = Arc::new(crate::rpc::http::Service::new(
            data.to_path_buf(),
            Some(&captured),
            node.store().chain().chain_id.as_bytes().to_vec(),
            key.verifying_key().to_bytes().to_vec(),
        ));
        let fees = octra_node_protocol::submit_rpc::Fees::capture(|name| {
            if name == "OCTRA_STEALTH_MIN_OU" {
                Some(settings.stealth_minimum.as_bytes().to_vec())
            } else {
                None
            }
        });
        Ok(Context::single(
            self.clone(),
            SingleOptions {
                status,
                http,
                fees,
                vpn_program,
            },
        ))
    }
}
