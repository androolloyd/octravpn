// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Program_read_rpc's exclusive compiler worker, separate from epoch execution.
use super::Native;
use octra_node_protocol::{
    aml::compiler::package::CompilerMode,
    aml::rpc as compile,
    native_json::{Document, Value},
    rpc::Fault,
    rules::{RootRead, Rule},
    transaction::RuleMode,
};
use std::sync::Arc;
#[derive(Clone, Copy)]
pub enum Compiler {
    Aml,
    Multi,
    Assembly,
}
impl Native {
    async fn compiler_rules(&self, epoch: i64) -> std::result::Result<compile::Rules, Fault> {
        let graph = &self.config.graph;
        if graph.isolated_application_anchor().is_none() {
            return Ok(compile::Rules::at(graph.chain_id(), epoch));
        }
        // This exceptional local profile is selected only by an independently
        // committed genesis. An RPC flag or peer cannot activate compilation.
        let root = self
            .history
            .root(0)
            .await
            .map_err(|_| Fault::new(110, b"service unavailable"))?;
        let read = |height| {
            if height == 0 {
                root.as_ref().map_or(RootRead::Missing, |bytes| {
                    RootRead::Root(hex::encode(bytes).into_bytes())
                })
            } else {
                RootRead::Missing
            }
        };
        let mode = |rule| {
            graph
                .mode(rule, epoch, &read)
                .map_err(|_| Fault::new(110, b"service unavailable"))
        };
        Ok(compile::Rules {
            compiler: CompilerMode::for_rules(mode(Rule::ProgramSource)?, mode(Rule::FheWork)?),
            point_ops: mode(Rule::Standard)? == RuleMode::Active,
            loops: mode(Rule::ProofExecution)? == RuleMode::Active,
        })
    }
    pub async fn compile(
        &self,
        kind: Compiler,
        epoch: i64,
        document: Arc<Document>,
        params: Value,
    ) -> std::result::Result<Vec<u8>, Fault> {
        if !(0..1_i64 << 62).contains(&epoch) {
            return Err(Fault::new(-32000, b"Program compiler failed"));
        }
        let lease = self
            .compiler
            .clone()
            .try_acquire_owned()
            .map_err(|_| Fault::new(-32005, b"Program compiler busy"))?;
        let rules = self.compiler_rules(epoch).await?;
        let result = tokio::task::spawn_blocking(move || {
            // Dropping the HTTP future cannot release this lease while the
            // blocking worker still owns parsed source and compiler memory.
            let _lease = lease;
            match kind {
                Compiler::Aml => compile::single_params(&document, &params, rules),
                Compiler::Multi => compile::multi_params(&document, &params, rules),
                Compiler::Assembly => compile::assembly_params(&document, &params),
            }
        })
        .await;
        match result {
            Ok(Ok(raw)) => Ok(raw),
            Ok(Err(compile::Error::Rpc(fault))) => Err(fault),
            Ok(Err(compile::Error::Unavailable(_))) => Err(Fault::new(
                -32005,
                b"Program compiler resources unavailable",
            )),
            Err(_) => Err(Fault::new(-32000, b"Program compiler failed")),
        }
    }
}
