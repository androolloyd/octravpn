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

// The grammar's 128-frame syntax limit fits release stacks, while debug parser
// frames require more than Tokio's default 2 MiB. Keep this host resource local;
// changing grammar limits would change compilation semantics.
const COMPILER_STACK_BYTES: usize = 16 * 1024 * 1024;
pub(super) fn on_compiler_stack<T: Send + 'static>(
    work: impl FnOnce() -> compile::Result<T> + Send + 'static,
) -> compile::Result<T> {
    std::thread::Builder::new()
        .name("octra-compiler".into())
        .stack_size(COMPILER_STACK_BYTES)
        .spawn(move || octra_node_protocol::aml::parser::with_recursion_limit(128, work))
        .map_err(|_| compile::Error::Unavailable(b"compiler worker unavailable".to_vec()))?
        .join()
        .map_err(|_| compile::Error::Unavailable(b"compiler worker failed".to_vec()))?
}
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
            on_compiler_stack(move || {
                // Dropping the HTTP future cannot release this lease while the
                // blocking worker still owns parsed source and compiler memory.
                let _lease = lease;
                match kind {
                    Compiler::Aml => compile::single_params(&document, &params, rules),
                    Compiler::Multi => compile::multi_params(&document, &params, rules),
                    Compiler::Assembly => compile::assembly_params(&document, &params),
                }
            })
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

#[cfg(test)]
mod stack_tests {
    use super::*;

    #[test]
    fn compiler_stack_rejects_deep_sources_without_aborting_debug_nodes() {
        std::thread::Builder::new()
            .stack_size(2 * 1024 * 1024)
            .spawn(|| {
                for count in [4, 96, 4096] {
                    let source = format!(
                        "contract X {{ fn f(): int {{ return {}1{} }} }}",
                        "(".repeat(count),
                        ")".repeat(count)
                    );
                    let result = on_compiler_stack(move || {
                        octra_node_protocol::aml::parser::syntax(source.as_bytes())
                            .map(|_| Vec::<u8>::new())
                            .map_err(|e| compile::Error::Rpc(Fault::new(-32000, e.to_string())))
                    });
                    if count == 4096 {
                        let compile::Error::Rpc(fault) = result.unwrap_err() else {
                            panic!("nested source did not reach the lexer guard");
                        };
                        assert!(String::from_utf8_lossy(&fault.message)
                            .contains("syntax nesting exceeds limit"));
                    } else {
                        assert!(result.is_ok(), "{result:?}");
                    }
                }
            })
            .unwrap()
            .join()
            .unwrap();
    }
    #[test]
    fn combined_nesting_is_operational_and_does_not_reset_at_parentheses() {
        let mut term = "1".to_owned();
        for _ in 0..8 {
            term = format!("{}({term})", "true ? 1 : ".repeat(32));
        }
        let source = format!("contract X {{ fn f(): int {{ return {term} }} }}");
        let result = on_compiler_stack(move || {
            compile::single(source.as_bytes(), compile::Rules::at(b"local", 0))
        });
        assert!(
            matches!(result, Err(compile::Error::Unavailable(ref reason))
            if reason == b"local compiler recursion limit exceeded")
        );
        assert!(on_compiler_stack(|| compile::single(
            b"contract X { fn f(): int { return 1 } }",
            compile::Rules::at(b"local", 0)
        ))
        .is_ok());
    }
}
