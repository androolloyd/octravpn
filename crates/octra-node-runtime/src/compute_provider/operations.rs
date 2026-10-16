// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{
    actor, owner, refused, unavailable, watch, Cancellation, Duration, Error, Execute, Executed,
    Prepare, Prepared, Program, Provider, Result,
};
use futures::FutureExt;
use octra_node_protocol::{resource_compute::call::output_hash, transaction::decode_base64};
use sha2::{Digest, Sha256};
use std::{future::Future, panic::AssertUnwindSafe};

struct CancelOnDrop {
    signal: watch::Sender<Option<Vec<u8>>>,
    armed: bool,
}
impl CancelOnDrop {
    fn abort(&self, reason: &[u8]) {
        self.signal.send_if_modified(|current| {
            if current.is_none() {
                *current = Some(reason.to_vec());
                true
            } else {
                false
            }
        });
    }
}
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if self.armed {
            self.abort(b"resource compute request cancelled");
        }
    }
}
pub(super) fn verify_program(expected: &[u8], program: &Program) -> Result<()> {
    let code = decode_base64(&program.code_b64)
        .map_err(|_| refused(b"resource compute program base64 refused"))?;
    if program.code_hash != expected
        || hex::encode(Sha256::digest(code)).as_bytes() != expected
        || program.runtime != b"wasm_v1"
    {
        Err(refused(b"resource compute program root differs"))
    } else {
        Ok(())
    }
}
fn failed() -> Error {
    unavailable("resource compute operation failed: panic")
}
impl Provider {
    pub(super) async fn owned<T, F, W>(&self, work: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(Cancellation) -> W + Send + 'static,
        W: Future<Output = Result<T>> + Send + 'static,
    {
        let (signal, aborted) = watch::channel(None);
        let mut cancel = CancelOnDrop {
            signal,
            armed: true,
        };
        let cancellation = Cancellation {
            aborted,
            status: self.0.status.clone(),
        };
        // Dropping the caller's handle detaches the worker. Its finish/release
        // finalizers and native execution lease remain owned by that worker.
        let mut worker = tokio::spawn(async move {
            AssertUnwindSafe(async move { work(cancellation).await })
                .catch_unwind()
                .await
                .unwrap_or_else(|_| Err(failed()))
        });
        let timeout = tokio::time::sleep(Duration::from_secs(
            self.0.limits.timeout_seconds.max(0) as u64
        ));
        tokio::pin!(timeout);
        let result = tokio::select! {biased;
            result=&mut worker=>result.map_err(unavailable)?,
            ()=&mut timeout=>{cancel.abort(b"resource compute request expired");Err(refused(b"resource compute request expired"))},
        };
        cancel.armed = false;
        result
    }
    async fn read<T, W>(&self, cancel: &Cancellation, work: W) -> Result<T>
    where
        T: Send + 'static,
        W: Future<Output = Result<T>> + Send + 'static,
    {
        if let Some(reason) = cancel.reason() {
            return Err(refused(&reason));
        }
        let mut pending = tokio::spawn(async move {
            AssertUnwindSafe(work)
                .catch_unwind()
                .await
                .unwrap_or_else(|_| Err(failed()))
        });
        tokio::select! {biased;
            result=&mut pending=>result.map_err(unavailable)?,
            reason=cancel.cancelled()=>Err(refused(&reason)),
        }
    }
    async fn allowed(&self, cancel: &Cancellation, token: &owner::Token) -> Result<()> {
        self.command(actor::ControlKind::Check(token.clone()))
            .await?;
        if let Some(reason) = cancel.reason() {
            Err(refused(&reason))
        } else {
            Ok(())
        }
    }
    async fn drop_model(&self, key: Vec<u8>) -> Result<()> {
        let result = AssertUnwindSafe(self.0.deps.drop_model(key))
            .catch_unwind()
            .await
            .unwrap_or_else(|_| Err(unavailable("resource compute cache removal failed: panic")));
        if result.is_err() {
            self.command(actor::ControlKind::Close).await?;
        }
        result
    }
    pub(super) async fn prepare_owned(
        &self,
        cancel: Cancellation,
        request: Prepare,
    ) -> Result<Prepared> {
        match self.reserve(request).await? {
            owner::Preparation::Ready(model) => Ok(model.response()),
            owner::Preparation::Build(plan) => {
                let result = AssertUnwindSafe(self.build_model(&cancel, &plan))
                    .catch_unwind()
                    .await
                    .unwrap_or_else(|_| Err(failed()));
                self.command(actor::ControlKind::Finish(plan.token)).await?;
                result
            }
        }
    }
    async fn build_model(&self, cancel: &Cancellation, plan: &owner::Plan) -> Result<Prepared> {
        let request = &plan.request;
        self.allowed(cancel, &plan.token).await?;
        let test = self.0.deps.self_test().await?;
        if test.executor_root != request.executor_root {
            return Err(refused(b"resource compute executor root differs"));
        }
        let deps = self.0.deps.clone();
        let request = request.clone();
        let program = self
            .read(cancel, async move {
                deps.program(
                    request.model_epoch,
                    request.model_state_root,
                    request.circle_id,
                )
                .await
            })
            .await?;
        verify_program(&plan.request.program_root, &program)?;
        self.allowed(cancel, &plan.token).await?;
        if let Some(model) = &plan.victim {
            self.drop_model(model.cache_key.clone()).await?;
            let dropped = self
                .command(actor::ControlKind::Dropped(plan.token.clone()))
                .await?;
            if !matches!(dropped, actor::Reply::Dropped(true)) {
                return Err(refused(b"resource compute preparation changed"));
            }
        }
        self.allowed(cancel, &plan.token).await?;
        let loaded = self
            .0
            .deps
            .load_model(cancel.clone(), plan.request.clone())
            .await?;
        if !loaded.prepared(&plan.request) {
            return Err(refused(b"resource compute loaded model differs"));
        }
        self.allowed(cancel, &plan.token).await?;
        let response = loaded.response();
        self.command(actor::ControlKind::Remember(plan.token.clone(), loaded))
            .await?;
        Ok(response)
    }
    pub(super) async fn execute_owned(
        &self,
        cancel: Cancellation,
        request: Execute,
    ) -> Result<Executed> {
        let actor::Selected {
            token,
            model,
            lease,
        } = self.select(request.clone()).await?;
        let mut spent = false;
        let result = AssertUnwindSafe(async {
            self.allowed(&cancel, &token).await?;
            self.execute_ready(&cancel, &token, &mut spent, model, request)
                .await
        })
        .catch_unwind()
        .await
        .unwrap_or_else(|_| Err(failed()));
        drop(lease);
        self.command(actor::ControlKind::Release(token, spent))
            .await?;
        result
    }
    async fn execute_ready(
        &self,
        cancel: &Cancellation,
        token: &owner::Token,
        spent: &mut bool,
        model: owner::Model,
        request: Execute,
    ) -> Result<Executed> {
        let output_limit = request
            .max_output_bytes
            .min(self.0.limits.max_response_bytes);
        let deps = self.0.deps.clone();
        let current = request.clone();
        let program = self
            .read(cancel, async move {
                deps.program(current.epoch_id, current.state_root, current.circle_id)
                    .await
            })
            .await?;
        verify_program(&request.program_root, &program)?;
        let deps = self.0.deps.clone();
        let current = request.clone();
        let storage = self
            .read(cancel, async move {
                deps.storage(current.epoch_id, current.state_root, current.circle_id)
                    .await
            })
            .await?;
        self.allowed(cancel, token).await?;
        *spent = true;
        let result = self
            .0
            .deps
            .execute(model, program, storage, request.clone())
            .await?;
        if result.effort_used < 0 || result.effort_used > request.fuel_limit {
            return Err(refused(b"resource compute fuel exceeds requested limit"));
        }
        if result.steps != result.effort_used {
            return Err(refused(b"resource compute fuel report differs"));
        }
        if result.output_json.len() as i64 > output_limit {
            return Err(refused(b"resource compute output exceeds requested limit"));
        }
        if result.trace_root.len() != 64
            || !result
                .trace_root
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        {
            return Err(refused(b"resource compute trace root refused"));
        }
        if result.steps <= 0 || result.operations <= 0 {
            return Err(refused(b"resource compute counters refused"));
        }
        let hash = output_hash(&result.output_json).map_err(|error| {
            if error.is_operational() {
                error
            } else {
                let exception = octra_node_protocol::native_exception::string_argument(
                    b"Invalid_argument",
                    error.as_bytes(),
                );
                refused(
                    &[
                        b"resource compute operation failed: ".as_slice(),
                        &exception,
                    ]
                    .concat(),
                )
            }
        })?;
        Ok(Executed {
            output_json: result.output_json,
            output_hash: hex::encode(hash).into_bytes(),
            trace_root: result.trace_root,
            steps: result.steps,
            operations: result.operations,
            effort_used: result.effort_used,
        })
    }
}
