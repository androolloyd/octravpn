//! Application-only specialization, using the unchanged native Legacy emitter.
//! No compiler flag or source declaration confers typed Program authority.
use super::digest;
use anyhow::{ensure, Context, Result};
use octra_node_protocol::aml::{ast::Visibility, parser};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const CORE: &str = include_str!("../../../../../program/octranet-payments.aml");
const INITIALIZER: &str =
    include_str!("../../../../../program/octranet-payments-circle-init.aml.in");
const CONSTRUCTOR: &str = r#"  constructor(domain: string, max_locked_value: uint, min_operator_stake: uint) {
    require_digest(domain)
    require(min_operator_stake >= 100000000, "operator stake below floor")
    require(max_locked_value > min_operator_stake && max_locked_value <= MAX_UINT, "invalid custody cap")
    self.domain = domain
    self.max_locked_value = max_locked_value
    self.min_operator_stake = min_operator_stake
  }"#;

/// Derive the Circle variant from the single custody implementation. Only its
/// constructor and entry guards differ; every existing public body is retained.
/// The generated Program-syntax raw OCTB executes in the existing Circle host.
pub fn source(domain: &str, custody_cap: u64, minimum_stake: u64) -> Result<String> {
    digest(domain)?;
    ensure!(
        minimum_stake >= 100_000_000 && custody_cap > minimum_stake,
        "invalid Circle custody terms"
    );
    ensure!(
        CORE.matches(CONSTRUCTOR).count() == 1,
        "payment constructor marker changed"
    );
    let ast = parser::parse(CORE.as_bytes())
        .map_err(|error| anyhow::anyhow!("payment source parse: {error:?}"))?;
    let expected: BTreeSet<_> = ast
        .contract
        .functions
        .iter()
        .filter(|function| function.visibility == Visibility::Public)
        .map(|function| function.name.clone())
        .collect();
    ensure!(
        !expected.contains(b"initialize".as_slice())
            && !expected.contains(b"require_initialized".as_slice()),
        "Circle initialization collides with payment source"
    );
    let mut guarded = BTreeSet::new();
    let mut source = String::new();
    for line in CORE.lines() {
        let name = line
            .split_once("fn ")
            .and_then(|(_, tail)| tail.split_once('('))
            .map(|(name, _)| name.as_bytes());
        if let Some(name) = name.filter(|name| expected.contains(*name)) {
            ensure!(guarded.insert(name.to_vec()), "duplicate public entrypoint");
            let (head, body) = line
                .split_once('{')
                .context("payment function header changed")?;
            source.push_str(head);
            source.push_str("{\n    require_initialized()\n");
            source.push_str(body);
        } else {
            source.push_str(line);
        }
        source.push('\n');
    }
    ensure!(
        guarded == expected,
        "not every payment entrypoint was guarded"
    );
    ensure!(
        source.matches("program OctranetPayments {").count() == 1
            && source.matches("  state {\n").count() == 1,
        "payment declaration markers changed"
    );
    let initializer = INITIALIZER
        .replace("$DOMAIN", domain)
        .replace("$CUSTODY_CAP", &custody_cap.to_string())
        .replace("$MIN_STAKE", &minimum_stake.to_string());
    source = source
        .replacen(CONSTRUCTOR, &initializer, 1)
        .replacen(
            "program OctranetPayments {",
            "program OctranetCirclePayments {",
            1,
        )
        .replacen(
            "  state {\n",
            "  state {\n    circle_initialized: uint\n",
            1,
        );
    // The existing header describes the old deployment mechanism, not this app.
    let (_, body) = source
        .split_once("program OctranetCirclePayments {")
        .context("Circle declaration missing")?;
    let source = format!("// Derived Circle custody app: raw OCTB; native consensus unchanged.\n// Deploy, then finalize permissionless initialize() before accepting funds.\nprogram OctranetCirclePayments {{{body}");
    parser::parse(source.as_bytes())
        .map_err(|error| anyhow::anyhow!("Circle source parse: {error:?}"))?;
    Ok(source)
}

/// Compile reviewable specialized source; initialization remains a second
/// finalized transaction because native Circle spawn effects are deferred.
pub fn compile(domain: &str, custody_cap: u64, minimum_stake: u64) -> Result<serde_json::Value> {
    let source = source(domain, custody_cap, minimum_stake)?;
    let mut report = octra_node_runtime::program::build::legacy(source.as_bytes(), true, true)?;
    let factory_source =
        include_bytes!("../../../../../program/octranet-payments-circle-factory.aml");
    let factory = octra_node_runtime::program::build::legacy(factory_source, true, true)?;
    report["factory_bytecode"] = factory["bytecode"].clone();
    report["factory_source_sha256"] = hex::encode(Sha256::digest(factory_source)).into();
    report["application"] = "circle".into();
    report["terms"] = serde_json::json!({"domain":domain,"custody_cap":custody_cap,"minimum_stake":minimum_stake});
    report["initialization"] = "separate-finalized-circle-call".into();
    report["core_source_sha256"] = hex::encode(Sha256::digest(CORE.as_bytes())).into();
    report["initializer_sha256"] = hex::encode(Sha256::digest(INITIALIZER.as_bytes())).into();
    report["source"] = source.into();
    Ok(report)
}
