// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Public Circle application reads backed by the browser's exact committed tree.
//! Wallet capabilities remain explicit. The caller and activation profile never
//! come from app parameters; updates go through transaction admission separately.
use crate::{
    circle::{CircleRuntime, MAX_INPUT_BYTES},
    circle_assets::CanonicalAssets,
    circle_store::{self, Info},
    circle_view,
};
use async_trait::async_trait;
use octra_browser::{
    application::{ApplicationHost, ReadMethod, ReadRequest, ReviewedAction, UnavailableHost},
    AssetResolver, Error, Provenance,
};
use octra_node_protocol::{circle_wasm, native_json::Document};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::Semaphore;

const PUBLIC_CALLER: &str = "oct00000000000000000000000000000000000000000000";
const VIEW_EFFORT: i64 = 20_000_000;

#[derive(Clone)]
pub struct CanonicalApplications {
    assets: CanonicalAssets,
    runtime: CircleRuntime,
    profile: circle_view::Profile,
    wallet: Arc<dyn ApplicationHost>,
    workers: Arc<Semaphore>,
}

fn unavailable(reason: impl std::fmt::Display) -> Error {
    Error::Unavailable(reason.to_string())
}
fn invalid(reason: impl std::fmt::Display) -> Error {
    Error::Invalid(reason.to_string())
}
fn native(error: circle_wasm::Error) -> Error {
    match error {
        circle_wasm::Error::Rejected(e) => invalid(String::from_utf8_lossy(&e)),
        circle_wasm::Error::Unavailable(e) => unavailable(String::from_utf8_lossy(&e)),
    }
}
impl CanonicalApplications {
    /// The trusted host supplies rules for the snapshot's next epoch. The node
    /// resolves these through `circle_view::canonical` before enabling views.
    pub fn new(
        assets: CanonicalAssets,
        runtime: CircleRuntime,
        profile: circle_view::Profile,
    ) -> Self {
        Self {
            assets,
            runtime,
            profile,
            wallet: Arc::new(UnavailableHost),
            workers: Arc::new(Semaphore::new(4)),
        }
    }
    /// Wallet services must independently enforce chain, nonce and spending policy.
    pub fn with_wallet(mut self, wallet: Arc<dyn ApplicationHost>) -> Self {
        self.wallet = wallet;
        self
    }
    pub fn provenance(&self) -> Provenance {
        self.assets.provenance()
    }

    fn info(&self, circle: &[u8]) -> Result<Info, Error> {
        let info = circle_store::info(self.assets.snapshot(), circle)
            .map_err(unavailable)?
            .ok_or(Error::NotFound)?;
        if info.privacy != b"public" {
            return Err(Error::Sealed);
        }
        Ok(info)
    }
    fn check_code_size(&self, info: &Info) -> Result<(), Error> {
        // Local view bound applies to both engines before program allocation.
        if self
            .assets
            .snapshot()
            .get(&[b"circles", &info.circle_id, b"program", b"code_b64"])
            .is_some_and(|encoded| encoded.len() > MAX_INPUT_BYTES)
        {
            return Err(Error::TooLarge);
        }
        Ok(())
    }
    fn program_info(&self, info: &Info) -> Result<Value, Error> {
        self.check_code_size(info)?;
        let descriptor = crate::circle_program::describe(
            &self.runtime,
            self.assets.snapshot(),
            &self.profile,
            info,
        )
        .map_err(native)?;
        serde_json::from_slice(&descriptor.encode()).map_err(unavailable)
    }
    fn view(&self, info: &Info, params: &Value) -> Result<Value, Error> {
        let method = params
            .get("method")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("missing Circle method"))?;
        let args = params
            .get("params")
            .filter(|value| value.is_array())
            .ok_or_else(|| invalid("missing Circle params"))?;
        self.check_code_size(info)?;
        let params =
            Document::parse(&serde_json::to_vec(args).map_err(invalid)?).map_err(invalid)?;
        let query = crate::circle_query::Query::committed(&self.assets, &self.profile)
            .map_err(native)?
            .with_runtime(&self.runtime);
        let receipt = query
            .circle(
                &info.circle_id,
                method.as_bytes(),
                &params,
                PUBLIC_CALLER.as_bytes(),
                VIEW_EFFORT,
            )
            .map_err(native)?;
        if !receipt.success {
            return Err(invalid(String::from_utf8_lossy(
                receipt.error.as_deref().unwrap_or(b"execution reverted"),
            )));
        }
        // The shared query host never publishes storage, assets or events.
        Ok(json!({"result":octb_value(receipt.response.as_ref())?}))
    }
    fn program_read(&self, request: &ReadRequest) -> Result<Value, Error> {
        let kind = match request.method {
            ReadMethod::ProgramInfo => circle_view::ReadKind::Program,
            ReadMethod::ProgramView => circle_view::ReadKind::View,
            _ => return Err(invalid("not a program read")),
        };
        let epoch = circle_view::epoch(self.assets.snapshot().get(&[b"meta", b"last_epoch"]), kind)
            .map_err(unavailable)?;
        if epoch != self.profile.epoch {
            return Err(unavailable(
                "view profile does not match the captured epoch",
            ));
        }
        let info = self.info(request.context.circle_id.as_bytes())?;
        match request.method {
            ReadMethod::ProgramInfo => self.program_info(&info),
            ReadMethod::ProgramView => self.view(&info, &request.params),
            _ => Err(invalid("not a program read")),
        }
    }
}
fn octb_value(value: Option<&crate::octb::Value>) -> Result<Value, Error> {
    value.map_or(Ok(Value::Null), |v| {
        serde_json::from_slice(&v.result_json()).map_err(unavailable)
    })
}
#[async_trait]
impl ApplicationHost for CanonicalApplications {
    async fn read(&self, request: ReadRequest) -> Result<Value, Error> {
        if request.context.provenance != self.provenance() {
            return Err(Error::SnapshotChanged);
        }
        if !matches!(
            request.method,
            ReadMethod::ProgramInfo | ReadMethod::ProgramView
        ) {
            return self.wallet.read(request).await;
        }
        let permit = self
            .workers
            .clone()
            .try_acquire_owned()
            .map_err(|_| unavailable("circle view busy"))?;
        let host = self.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            host.program_read(&request)
        })
        .await
        .map_err(unavailable)?
    }
    async fn submit(&self, action: ReviewedAction) -> Result<Value, Error> {
        if action.intent().context.provenance != self.provenance() {
            return Err(Error::SnapshotChanged);
        }
        self.wallet.submit(action).await
    }
}
