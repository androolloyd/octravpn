// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{
    Finding, Invariant, Name, Report, Severity, Summary, Visibility, ENGINE, PROOF_GATE,
    PROOF_MODEL, SCHEMA,
};
use crate::transaction::{json_optional, json_string};
struct Rule {
    code: &'static str,
    title: &'static str,
    severity: Severity,
}
const RULES: [Rule; 7] = [
    Rule {
        code: "signed_value_storage",
        title: "value-like storage must not use signed int",
        severity: Severity::Error,
    },
    Rule {
        code: "signed_value_parameter",
        title: "value-moving public parameters must not use signed int",
        severity: Severity::Error,
    },
    Rule {
        code: "signed_value_flow",
        title: "signed values must not flow into value-like storage writes",
        severity: Severity::Error,
    },
    Rule {
        code: "unsigned_arithmetic_range_not_proven",
        title: "unsigned arithmetic writes must prove range safety",
        severity: Severity::Error,
    },
    Rule {
        code: "supply_invariant_unproven",
        title: "balance and total supply writes should preserve conservation",
        severity: Severity::Warning,
    },
    Rule {
        code: "unsigned_parameter_without_positive_guard",
        title: "unsigned value parameters should reject zero unless zero is meaningful",
        severity: Severity::Warning,
    },
    Rule {
        code: "unchecked_transfer_result",
        title: "native transfer result should be checked",
        severity: Severity::Warning,
    },
];
fn list<T>(out: &mut Vec<u8>, values: &[T], mut write: impl FnMut(&mut Vec<u8>, &T)) {
    out.push(b'[');
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        write(out, value);
    }
    out.push(b']');
}
fn strings(out: &mut Vec<u8>, values: &[Name]) {
    list(out, values, |out, value| json_string(out, value));
}
fn boolean(out: &mut Vec<u8>, value: bool) {
    out.extend_from_slice(if value { b"true" } else { b"false" });
}
fn finding(out: &mut Vec<u8>, item: &Finding) {
    out.extend_from_slice(b"{\"severity\":");
    json_string(out, item.severity.text());
    out.extend_from_slice(b",\"code\":");
    json_string(out, item.code.as_bytes());
    out.extend_from_slice(b",\"message\":");
    json_string(out, item.message.as_bytes());
    out.extend_from_slice(b",\"program_name\":");
    json_string(out, &item.program_name);
    out.extend_from_slice(b",\"function_name\":");
    json_optional(out, item.function_name.as_deref());
    out.extend_from_slice(b",\"state_field\":");
    json_optional(out, item.state_field.as_deref());
    out.extend_from_slice(b",\"parameter\":");
    json_optional(out, item.parameter.as_deref());
    out.push(b'}');
}
fn summary(out: &mut Vec<u8>, item: &Summary) {
    out.extend_from_slice(b"{\"name\":");
    json_string(out, &item.name);
    out.extend_from_slice(b",\"visibility\":");
    json_string(
        out,
        match item.visibility {
            Visibility::Public => b"public",
            Visibility::Private => b"private",
            Visibility::Internal => b"internal",
        },
    );
    out.extend_from_slice(b",\"direct_calls\":");
    strings(out, &item.direct_calls);
    out.extend_from_slice(b",\"direct_writes\":");
    strings(out, &item.direct_writes);
    out.extend_from_slice(b",\"transitive_writes\":");
    strings(out, &item.transitive_writes);
    out.extend_from_slice(b",\"value_writes\":");
    strings(out, &item.value_writes);
    out.extend_from_slice(b",\"signed_params\":");
    strings(out, &item.signed_params);
    out.push(b'}');
}
fn invariant(out: &mut Vec<u8>, item: &Invariant) {
    out.extend_from_slice(b"{\"code\":");
    json_string(out, &item.code);
    out.extend_from_slice(b",\"kind\":");
    json_optional(out, item.kind.map(str::as_bytes));
    out.extend_from_slice(b",\"status\":");
    json_string(out, item.status.as_bytes());
    out.extend_from_slice(b",\"expression\":");
    json_optional(out, item.expression.as_deref());
    out.extend_from_slice(b",\"message\":");
    json_string(out, &item.message);
    out.extend_from_slice(b",\"fields\":");
    strings(out, &item.fields);
    out.extend_from_slice(b",\"functions\":");
    strings(out, &item.functions);
    out.push(b'}');
}
impl Report {
    /// Exact field order and byte-string escaping used by the native report.
    pub fn json(&self) -> Vec<u8> {
        let mut out = b"{\"schema\":".to_vec();
        json_string(&mut out, SCHEMA);
        out.extend_from_slice(b",\"engine\":");
        json_string(&mut out, ENGINE);
        out.extend_from_slice(b",\"proof_model\":");
        json_string(&mut out, PROOF_MODEL);
        out.extend_from_slice(b",\"proof_gate\":");
        json_string(&mut out, PROOF_GATE);
        out.extend_from_slice(b",\"program_name\":");
        json_string(&mut out, &self.program_name);
        out.extend_from_slice(b",\"verified\":");
        boolean(&mut out, !self.has_errors());
        out.extend_from_slice(b",\"safety\":");
        json_string(&mut out, self.safety_level());
        out.extend_from_slice(b",\"errors\":");
        out.extend(self.count(Severity::Error).to_string().as_bytes());
        out.extend_from_slice(b",\"warnings\":");
        out.extend(self.count(Severity::Warning).to_string().as_bytes());
        out.extend_from_slice(b",\"trace\":");
        list(&mut out, &RULES, |out, rule| {
            let count = self.code_count(rule.code);
            out.extend_from_slice(b"{\"code\":");
            json_string(out, rule.code.as_bytes());
            out.extend_from_slice(b",\"title\":");
            json_string(out, rule.title.as_bytes());
            out.extend_from_slice(b",\"status\":");
            json_string(
                out,
                if count == 0 {
                    b"pass"
                } else {
                    rule.severity.text()
                },
            );
            out.extend_from_slice(b",\"severity\":");
            json_string(out, rule.severity.text());
            out.extend_from_slice(b",\"findings\":");
            out.extend(count.to_string().as_bytes());
            out.push(b'}');
        });
        out.extend_from_slice(b",\"function_summaries\":");
        list(&mut out, &self.summaries, summary);
        out.extend_from_slice(b",\"invariants\":");
        list(&mut out, &self.invariants, invariant);
        out.extend_from_slice(b",\"findings\":");
        list(&mut out, &self.findings, finding);
        out.push(b'}');
        out
    }
}
