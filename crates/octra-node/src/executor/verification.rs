// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::Native;
use octra_node_protocol::{
    aml::rpc::{
        self,
        verification::{self, Material, Verified},
    },
    rpc::Fault,
};
use octra_node_runtime::state_batch::Snapshot;
use std::sync::Arc;
#[derive(Clone)]
pub(crate) struct VerificationLease(Arc<tokio::sync::OwnedSemaphorePermit>);
impl Native {
    pub(crate) fn begin_verification(&self) -> std::result::Result<VerificationLease, Fault> {
        self.verification
            .clone()
            .try_acquire_owned()
            .map(|permit| VerificationLease(Arc::new(permit)))
            .map_err(|_| Fault::new(-32005, b"Program verification busy"))
    }
    pub(crate) async fn verify_record(
        &self,
        lease: VerificationLease,
        material: Material,
        source_entry: bool,
        stored_base64: Vec<u8>,
    ) -> std::result::Result<Verified, Fault> {
        match tokio::task::spawn_blocking(move || {
            let _lease = lease.0;
            verification::verify(material, source_entry, &stored_base64)
        })
        .await
        {
            Ok(Ok(verified)) => Ok(verified),
            Ok(Err(rpc::Error::Rpc(fault))) => Err(fault),
            Ok(Err(rpc::Error::Unavailable(_))) => Err(Fault::new(
                -32000,
                b"compile error: compiler resources unavailable",
            )),
            Err(_) => Err(Fault::new(-32000, b"compile error: compiler failed")),
        }
    }
    pub(crate) fn program_abi(
        &self,
        state: &Snapshot,
        address: &[u8],
        epoch: i64,
    ) -> std::result::Result<Vec<u8>, Fault> {
        // The isolated application profile is anchored and checked at launch
        // and each execution; this is the same captured decoder capability.
        let points = self.config.graph.isolated_application_anchor().is_some()
            || octra_node_protocol::aml::rpc::Rules::at(self.config.graph.chain_id(), epoch)
                .point_ops;
        octra_node_runtime::program::rpc::derived_abi(
            state,
            address,
            points,
            self.runtime.program_keys(),
        )
    }
}
