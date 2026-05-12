//! AML branch coverage report — Foundry `forge coverage` equivalent.
//!
//! Runtime branch hits are recorded by the mock chain via
//! `octravpn_core::coverage`. This module walks `program/main.aml`
//! statically, enumerates the branches we expect tests to exercise, and
//! pairs the two to produce a coverage percentage per method.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write,
    path::Path,
};

pub use octravpn_core::coverage::{enable, finish, record, Recorder};

#[derive(Debug, Clone)]
pub struct CoverageReport {
    pub per_method: BTreeMap<String, MethodCoverage>,
    pub total_hits: usize,
    pub total_branches: usize,
}

#[derive(Debug, Clone)]
pub struct MethodCoverage {
    pub branches_total: usize,
    pub branches_hit: usize,
    pub missing: Vec<String>,
}

impl CoverageReport {
    pub fn percent(&self) -> f64 {
        if self.total_branches == 0 {
            return 100.0;
        }
        #[allow(clippy::cast_precision_loss)]
        let pct = (self.total_hits as f64 / self.total_branches as f64) * 100.0;
        pct
    }

    pub fn pretty(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(
            s,
            "AML branch coverage: {} / {} ({:.1}%)",
            self.total_hits,
            self.total_branches,
            self.percent()
        );
        for (m, mc) in &self.per_method {
            let _ = writeln!(
                s,
                "  {m}: {}/{} ({:.0}%)",
                mc.branches_hit,
                mc.branches_total,
                if mc.branches_total == 0 {
                    100.0
                } else {
                    #[allow(clippy::cast_precision_loss)]
                    let p = (mc.branches_hit as f64 / mc.branches_total as f64) * 100.0;
                    p
                }
            );
            for b in &mc.missing {
                let _ = writeln!(s, "    - uncovered: {b}");
            }
        }
        s
    }
}

/// Build the report by comparing `rec.hit` against branches enumerated
/// statically from `aml_source`.
pub fn report(rec: &Recorder, aml_source: &str) -> CoverageReport {
    let static_branches = enumerate_static_branches(aml_source);
    let mut per_method = BTreeMap::new();
    let mut total_hits = 0;
    let mut total_branches = 0;
    for (method, branches) in static_branches {
        let hit: BTreeSet<String> = rec
            .hit
            .get(&method)
            .cloned()
            .unwrap_or_default();
        let branches_hit = branches.iter().filter(|b| hit.contains(*b)).count();
        let missing: Vec<String> = branches
            .iter()
            .filter(|b| !hit.contains(*b))
            .cloned()
            .collect();
        total_branches += branches.len();
        total_hits += branches_hit;
        per_method.insert(
            method,
            MethodCoverage {
                branches_total: branches.len(),
                branches_hit,
                missing,
            },
        );
    }
    CoverageReport {
        per_method,
        total_hits,
        total_branches,
    }
}

/// Walk the AML source and enumerate the branch labels we expect tests
/// to hit. Labels are stable across edits that don't reorder branches:
/// `require[N]`, `if[N]`, `while[N]` where N is the occurrence index
/// within the method body.
pub fn enumerate_static_branches(source: &str) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (method, body) in crate::ou_cost_model::extract_method_bodies(source) {
        let mut branches = Vec::new();
        let mut require_n = 0;
        let mut if_n = 0;
        let mut while_n = 0;
        for line in body.lines() {
            let t = line.trim();
            if t.starts_with("require(") {
                require_n += 1;
                branches.push(format!("require[{require_n}]"));
            } else if t.starts_with("if ") {
                if_n += 1;
                branches.push(format!("if[{if_n}]"));
            } else if t.starts_with("while ") {
                while_n += 1;
                branches.push(format!("while[{while_n}]"));
            }
        }
        out.insert(method, branches);
    }
    out
}

pub fn write_report(report: &CoverageReport, path: &Path) -> std::io::Result<()> {
    std::fs::write(path, report.pretty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enumerates_branches_for_simple_method() {
        let src = r#"
            fn foo(): bool {
                require(x > 0, "x>0")
                if x > 5 {
                    require(y < 10, "y<10")
                }
                while i < n {
                    i = i + 1
                }
                return true
            }
        "#;
        let m = enumerate_static_branches(src);
        let foo = m.get("foo").unwrap();
        assert!(foo.contains(&"require[1]".to_string()));
        assert!(foo.contains(&"require[2]".to_string()));
        assert!(foo.contains(&"if[1]".to_string()));
        assert!(foo.contains(&"while[1]".to_string()));
    }

    #[test]
    fn report_counts_hits_and_misses() {
        let src = r#"
            fn foo(): bool {
                require(x > 0, "x>0")
                if x > 5 { return false }
                return true
            }
        "#;
        let mut rec = Recorder::default();
        rec.hit
            .entry("foo".into())
            .or_default()
            .insert("require[1]".into());
        let r = report(&rec, src);
        let mc = r.per_method.get("foo").unwrap();
        assert_eq!(mc.branches_hit, 1);
        assert_eq!(mc.branches_total, 2);
        assert!(mc.missing.contains(&"if[1]".to_string()));
    }
}
