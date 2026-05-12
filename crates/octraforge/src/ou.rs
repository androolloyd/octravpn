//! OU (gas) usage tracking + snapshot diffing.
//!
//! Foundry's `forge snapshot` writes `.gas-snapshot` with per-test gas
//! usage and `forge test` will fail if a regression exceeds the
//! tolerance. Equivalent here: `OuRecorder` accumulates per-call OU
//! costs and serializes to a snapshot file the runner can diff.

use std::{collections::BTreeMap, fs, path::Path};

/// Per-test OU cost record.
#[derive(Default, Debug, Clone)]
pub struct OuRecorder {
    /// (test_name → cumulative OU).
    pub costs: BTreeMap<String, u64>,
}

impl OuRecorder {
    pub fn add(&mut self, test: impl Into<String>, ou: u64) {
        *self.costs.entry(test.into()).or_insert(0) += ou;
    }

    /// Serialize to the standard `.ou-snapshot` text format:
    /// `<test_name> <ou>` one per line, sorted.
    pub fn to_snapshot(&self) -> String {
        let mut s = String::new();
        for (name, ou) in &self.costs {
            s.push_str(name);
            s.push(' ');
            s.push_str(&ou.to_string());
            s.push('\n');
        }
        s
    }

    pub fn write(&self, path: &Path) -> std::io::Result<()> {
        fs::write(path, self.to_snapshot())
    }

    /// Load a previous snapshot.
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let raw = fs::read_to_string(path)?;
        let mut costs = BTreeMap::new();
        for line in raw.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Some((name, ou)) = line.rsplit_once(' ') {
                if let Ok(n) = ou.parse::<u64>() {
                    costs.insert(name.to_string(), n);
                }
            }
        }
        Ok(Self { costs })
    }

    /// Diff this against `prev`. Returns lines where the new cost
    /// exceeds the old by more than `tolerance_bps` basis points.
    pub fn diff(&self, prev: &Self, tolerance_bps: u64) -> Vec<String> {
        let mut out = Vec::new();
        for (name, new_ou) in &self.costs {
            if let Some(old_ou) = prev.costs.get(name) {
                if new_ou <= old_ou {
                    continue;
                }
                let delta = new_ou - old_ou;
                let pct_bps = delta.saturating_mul(10_000) / (*old_ou).max(1);
                if pct_bps > tolerance_bps {
                    out.push(format!(
                        "regression {name}: {old_ou} → {new_ou} (+{pct_bps}bps > {tolerance_bps}bps)"
                    ));
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_round_trip() {
        let mut r = OuRecorder::default();
        r.add("test_a", 100);
        r.add("test_b", 250);
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("ou.snap");
        r.write(&p).unwrap();
        let r2 = OuRecorder::load(&p).unwrap();
        assert_eq!(r.costs, r2.costs);
    }

    #[test]
    fn diff_flags_regressions() {
        let mut old = OuRecorder::default();
        old.add("x", 1000);
        let mut new = OuRecorder::default();
        new.add("x", 1100); // 10% increase
        let bad = new.diff(&old, 500); // 5% tolerance
        assert_eq!(bad.len(), 1);
        let bad = new.diff(&old, 1500); // 15% tolerance
        assert!(bad.is_empty());
    }
}
