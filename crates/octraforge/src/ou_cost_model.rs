//! Deterministic OU-cost estimator for AML method bodies.
//!
//! We don't have a real on-chain interpreter to measure executed OU
//! against, so the snapshot tool uses a static cost model: count
//! occurrences of known-expensive operations per method and assign a
//! weight to each. Run the model over `program/main.aml`, write the
//! result to `ou-snapshot.txt`, and the CI test in
//! `tests/ou_snapshot.rs` fails if the live model disagrees with the
//! committed snapshot beyond a small tolerance.
//!
//! Regressions of this kind appear when a method body grows — extra
//! loops, signature verifications, Pedersen ops — and forces a reviewer
//! to look at why the cost went up before the PR can merge.

use std::collections::BTreeMap;

/// Per-operation OU weights, calibrated to roughly track Octra's
/// real-world relative costs. Tune as the protocol's gas table firms up.
struct Op {
    pattern: &'static str,
    weight: u64,
}

const OPS: &[Op] = &[
    // Cryptography is by far the most expensive class of host call.
    Op { pattern: "verify_ed25519_acct", weight: 2_500 },
    Op { pattern: "verify_ed25519",      weight: 2_000 },
    Op { pattern: "pedersen_verify_open", weight: 3_500 },
    Op { pattern: "pedersen_verify_eq",   weight: 3_500 },
    Op { pattern: "pedersen_mul_scalar_g", weight: 1_500 },
    Op { pattern: "pedersen_mul_scalar_h", weight: 1_500 },
    Op { pattern: "pedersen_add",         weight:   400 },
    Op { pattern: "pedersen_zero",        weight:   100 },
    Op { pattern: "sha256",               weight:   300 },
    // Octra-protocol-validator query (chain-side lookup).
    Op { pattern: "is_octra_validator",   weight:   500 },
    // State changes / I/O.
    Op { pattern: "emit",                 weight:   200 },
    Op { pattern: "transfer",             weight:   400 },
    Op { pattern: "emit_private_transfer", weight: 1_000 },
    Op { pattern: "mul_div_safe",         weight:   150 },
    // Control flow we expect to recur per iteration.
    Op { pattern: "while ",               weight:   200 },
    Op { pattern: "require(",             weight:    20 },
    // Loop body fixed cost — captures O(hops) work in settle_session.
    Op { pattern: "split_bps",            weight:    30 },
];

/// Strip line and block comments without changing line offsets, so
/// later parsing keeps roughly the same shape. Faithful enough that the
/// op counts won't drift on comment edits.
fn strip_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let bytes = src.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if i + 1 < bytes.len() && &bytes[i..i + 2] == b"//" {
            while i < bytes.len() && bytes[i] != b'\n' {
                out.push(' ');
                i += 1;
            }
        } else if i + 1 < bytes.len() && &bytes[i..i + 2] == b"/*" {
            while i + 1 < bytes.len() && &bytes[i..i + 2] != b"*/" {
                out.push(if bytes[i] == b'\n' { '\n' } else { ' ' });
                i += 1;
            }
            if i + 1 < bytes.len() {
                out.push_str("  ");
                i += 2;
            }
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

/// Extract `fn name(...) {...}` blocks from source. Returns
/// `Vec<(name, body)>`. Ignores `view fn` (read-only, near-free) and
/// `private fn` (helpers; their cost is amortised into the public
/// methods that call them).
pub fn extract_method_bodies(source: &str) -> Vec<(String, String)> {
    let s = strip_comments(source);
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 3 <= bytes.len() {
        let is_word_boundary = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
        if is_word_boundary && bytes[i..].starts_with(b"fn ") {
            // Skip view fn / private fn — they don't count toward gas.
            let prev = previous_word(&s, i);
            if prev == "view" || prev == "private" {
                i += 3;
                continue;
            }
            let mut j = i + 3;
            let name_start = j;
            while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                j += 1;
            }
            let name = s[name_start..j].to_string();
            // Skip parameter list.
            while j < bytes.len() && bytes[j] != b'{' {
                j += 1;
            }
            if j >= bytes.len() {
                break;
            }
            // Find matching brace.
            let body_start = j + 1;
            let mut depth = 1;
            j += 1;
            while j < bytes.len() && depth > 0 {
                match bytes[j] {
                    b'{' => depth += 1,
                    b'}' => depth -= 1,
                    _ => {}
                }
                j += 1;
            }
            if depth == 0 {
                let body = s[body_start..j - 1].to_string();
                if !name.is_empty() {
                    out.push((name, body));
                }
            }
            i = j;
        } else {
            i += 1;
        }
    }
    out
}

fn previous_word(source: &str, end: usize) -> &str {
    let s = source[..end].trim_end();
    let last_space = s.rfind(|c: char| !c.is_ascii_alphanumeric() && c != '_');
    match last_space {
        Some(idx) => &s[idx + 1..],
        None => s,
    }
}

/// Estimate the OU cost of `body` by summing weighted occurrences of
/// known-expensive operations.
pub fn estimate_body_cost(body: &str) -> u64 {
    let mut total: u64 = 0;
    for op in OPS {
        let count = body.matches(op.pattern).count() as u64;
        total = total.saturating_add(count.saturating_mul(op.weight));
    }
    // Constant per-method overhead.
    total.saturating_add(1_000)
}

/// Walk every public method in `source`, return `name → estimated cost`.
pub fn estimate_program_costs(source: &str) -> BTreeMap<String, u64> {
    extract_method_bodies(source)
        .into_iter()
        .map(|(name, body)| (name, estimate_body_cost(&body)))
        .collect()
}

/// Format `costs` as a deterministic snapshot string: lines of
/// `<name> <ou>\n` sorted by name.
pub fn format_snapshot(costs: &BTreeMap<String, u64>) -> String {
    let mut s = String::new();
    s.push_str("# Auto-generated. Update via `cargo test -p octraforge --test ou_snapshot -- --include-ignored`.\n");
    s.push_str("# Deterministic AML OU cost estimates per public method (see ou_cost_model.rs).\n");
    for (name, ou) in costs {
        s.push_str(name);
        s.push(' ');
        s.push_str(&ou.to_string());
        s.push('\n');
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_simple_method_body() {
        let src = r#"
            program X {
                fn foo(): bool { require(true, "ok") return true }
                view fn bar(): bool { return true }
            }
        "#;
        let bodies = extract_method_bodies(src);
        assert_eq!(bodies.len(), 1);
        assert_eq!(bodies[0].0, "foo");
    }

    #[test]
    fn skips_view_and_private() {
        let src = r"
            fn pub_one() { sha256(x) }
            view fn read_only() { return 1 }
            private fn helper() { sha256(x) }
        ";
        let bodies = extract_method_bodies(src);
        assert_eq!(bodies.len(), 1);
        assert_eq!(bodies[0].0, "pub_one");
    }

    #[test]
    fn cost_grows_with_crypto_ops() {
        let cheap = estimate_body_cost("require(true, \"ok\")");
        let expensive = estimate_body_cost(
            "require(verify_ed25519(p, m, s), \"bad\") pedersen_verify_open(c, x, b)",
        );
        assert!(expensive > cheap * 5);
    }

    #[test]
    fn format_is_deterministic() {
        let mut costs = BTreeMap::new();
        costs.insert("b".to_string(), 200);
        costs.insert("a".to_string(), 100);
        let s = format_snapshot(&costs);
        assert!(s.contains("a 100\nb 200\n"));
    }
}
