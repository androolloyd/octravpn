// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Provider dependencies backed by authenticated canonical history and bounded
//! native workers. RPC-supplied program and storage bytes are never executed.
use super::{
    async_trait, owner, refused, unavailable, CacheLease, Cancellation, Dependencies, Execute,
    Limits, Observation, Prepare, Program, Result, SelfTest,
};
use crate::{
    canonical::Reader,
    circle::CircleRuntime,
    circle_store,
    compute::{Pool, Priority},
    compute_model,
    state_batch::Snapshot,
};
use octra_circle_wasm_host::rust_api::{compute_storage_drop, ComputeStorageLease};
use octra_node_protocol::{
    native_json::{Document, ReadMode},
    resource_compute::{capability::Accelerator, provider},
};

pub struct Native {
    history: Reader,
    runtime: CircleRuntime,
    limits: Limits,
    reads: Pool,
    work: Pool,
}
impl Native {
    pub fn new(
        history: Reader,
        runtime: CircleRuntime,
        limits: Limits,
        handle: tokio::runtime::Handle,
    ) -> Result<Self> {
        let lanes = usize::try_from(limits.lanes)
            .ok()
            .filter(|lanes| *lanes > 0)
            .ok_or_else(|| refused(b"resource compute provider lanes refused"))?;
        let reads =
            Pool::new(crate::compute::Limits::proof(4), handle.clone()).map_err(unavailable)?;
        let work = Pool::new(crate::compute::Limits::proof(lanes), handle).map_err(unavailable)?;
        Ok(Self {
            history,
            runtime,
            limits,
            reads,
            work,
        })
    }
    async fn snapshot(&self, epoch: i64, state_root: Vec<u8>) -> Result<Snapshot> {
        let history = self.history.clone();
        self.reads
            .run_async(Priority::Required, move || async move {
                if state_root.len() != 64 || !state_root.iter().all(u8::is_ascii_hexdigit) {
                    return Err(refused(b"resource compute snapshot root refused"));
                }
                let epoch = u64::try_from(epoch)
                    .map_err(|_| refused(b"resource compute snapshot root differs"))?;
                let head = history
                    .head_for_epoch_opt(epoch)
                    .await
                    .map_err(unavailable)?
                    .ok_or_else(|| refused(b"resource compute snapshot root differs"))?;
                let root = hex::decode(&state_root)
                    .map_err(|_| refused(b"resource compute snapshot root refused"))?;
                if root != head.cursor.state_root.0 {
                    return Err(refused(b"resource compute snapshot root differs"));
                }
                history.snapshot_at(&head).await.map_err(unavailable)
            })
            .await
            .map_err(unavailable)?
            .ok_or_else(|| refused(b"resource compute provider busy"))?
    }
    async fn run<T: Send + 'static>(
        &self,
        task: impl FnOnce() -> Result<T> + Send + 'static,
    ) -> Result<T> {
        self.work
            .run_threaded(Priority::Required, task)
            .await
            .map_err(unavailable)?
            .ok_or_else(|| refused(b"resource compute provider busy"))?
    }
    fn accelerator(&self) -> Result<()> {
        if self.limits.accelerator == Accelerator::Cpu {
            Ok(())
        } else {
            Err(refused(
                &[
                    b"resource compute accelerator unavailable: ".as_slice(),
                    self.limits.accelerator.name(),
                ]
                .concat(),
            ))
        }
    }
}
#[async_trait]
impl Dependencies for Native {
    async fn program(&self, epoch: i64, state_root: Vec<u8>, circle: Vec<u8>) -> Result<Program> {
        let snapshot = self.snapshot(epoch, state_root).await?;
        self.reads
            .run_threaded(Priority::Required, move || {
                let program = circle_store::public_program(&snapshot, &circle)
                    .map_err(|error| refused(&error.0))?;
                if program.privacy_class != b"public"
                    || program.resource_mode != b"public_resources"
                {
                    return Err(refused(b"resource compute circle is not public"));
                }
                Ok(Program {
                    circle_id: circle,
                    code_b64: program.code_b64.to_vec(),
                    code_hash: program.code_hash.to_vec(),
                    runtime: program.runtime.to_vec(),
                })
            })
            .await
            .map_err(unavailable)?
            .ok_or_else(|| refused(b"resource compute provider busy"))?
    }
    async fn storage(
        &self,
        epoch: i64,
        state_root: Vec<u8>,
        circle: Vec<u8>,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let snapshot = self.snapshot(epoch, state_root).await?;
        self.reads
            .run_threaded(Priority::Required, move || {
                circle_store::storage_at(&snapshot, &circle, 2048, 2 * 1024 * 1024).map_err(
                    |error| match error.0.as_slice() {
                        b"circle storage entries exceed limit" => {
                            refused(b"resource compute storage entries exceed limit")
                        }
                        b"circle storage bytes exceed limit" => {
                            refused(b"resource compute storage exceeds limit")
                        }
                        other => refused(other),
                    },
                )
            })
            .await
            .map_err(unavailable)?
            .ok_or_else(|| refused(b"resource compute provider busy"))?
    }
    async fn load_model(&self, cancel: Cancellation, request: Prepare) -> Result<owner::Model> {
        let snapshot = self
            .snapshot(request.model_epoch, request.model_state_root.clone())
            .await?;
        let limits = compute_model::limits(self.limits.memory_bytes);
        self.run(move || {
            let root = hex::decode(&request.model_state_root).map_err(unavailable)?;
            let source = compute_model::Source {
                epoch: request.model_epoch,
                state: &root,
                tree: &snapshot,
            };
            let loaded = compute_model::load_at(
                source,
                &request.circle_id,
                &request.graph_root,
                &request.model_root,
                &limits,
                &|| cancel.reason(),
            )?;
            let cache = loaded.cache();
            Ok(owner::Model {
                snapshots: vec![(request.model_epoch, request.model_state_root)],
                circle_id: request.circle_id,
                graph_root: request.graph_root,
                model_root: request.model_root,
                program_root: request.program_root,
                executor_root: request.executor_root,
                cache_key: cache.key.clone(),
                cache_root: cache.root.clone(),
                entries: cache.entries.len() as i64,
                bytes: cache.bytes,
            })
        })
        .await
    }
    async fn drop_model(&self, key: Vec<u8>) -> Result<()> {
        self.run(move || {
            let key = std::str::from_utf8(&key).map_err(unavailable)?;
            // The adopted provider's native_drop_model discards the busy bool;
            // external cache holds remain alive until their owners release them.
            let _ = compute_storage_drop(key).map_err(unavailable)?;
            Ok(())
        })
        .await
    }
    fn hold_model(&self, model: &owner::Model) -> Result<CacheLease> {
        let key = std::str::from_utf8(&model.cache_key).map_err(unavailable)?;
        let root = std::str::from_utf8(&model.cache_root).map_err(unavailable)?;
        let entries = usize::try_from(model.entries).map_err(unavailable)?;
        let bytes = usize::try_from(model.bytes).map_err(unavailable)?;
        Ok(Box::new(
            ComputeStorageLease::hold(key, root, entries, bytes).map_err(unavailable)?,
        ))
    }
    async fn self_test(&self) -> Result<SelfTest> {
        self.accelerator()?;
        let runtime = self.runtime.clone();
        self.run(move || {
            let reply = runtime
                .execute(br#"{"action":"compute_self_test"}"#)
                .map_err(unavailable)?;
            let doc = Document::parse_native(reply.as_ref(), ReadMode::Safe)
                .map_err(|error| unavailable(format!("{error:?}")))?;
            provider::SelfTest::from_json(&doc)
        })
        .await
    }
    async fn execute(
        &self,
        model: owner::Model,
        program: Program,
        _storage: Vec<(Vec<u8>, Vec<u8>)>,
        request: Execute,
    ) -> Result<Observation> {
        self.accelerator()?;
        let runtime = self.runtime.clone();
        self.run(move || {
            crate::compute_replay::execute_single(&runtime, &model, &program, &request)
        })
        .await
    }
}
