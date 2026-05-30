//! Shared "named check outcome" vocabulary for the CLI report surfaces
//! (`config validate`, `health`, `audit verify`).
//!
//! Was two near-identical enums — `cli_ops::CheckOutcome` (Ok/Fail/
//! Skipped) and `audit_cli::CheckResult` (Ok/Fail/Skipped/Warn) — that
//! had independently drifted to different `Skipped` labels ("SKIP" vs
//! "SKIPPED"). Unified here with the short `"SKIP"` label (consistent
//! with the other ≤4-char labels and clean in every column width). The
//! `#[serde(tag = "status")]` JSON shape is unchanged from both
//! originals, so the machine-readable `--json` / `--format json` output
//! is byte-identical.

use serde::Serialize;

/// Outcome of one named check in a CLI report.
#[derive(Debug, Serialize, Clone)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(crate) enum Check {
    Ok {
        detail: String,
    },
    Fail {
        detail: String,
    },
    /// An earlier check made this one un-runnable (e.g. the config
    /// failed to parse, so every downstream field is skipped).
    Skipped {
        detail: String,
    },
    /// Soft warning — surfaced to the operator but does NOT flip a
    /// report's `overall_pass` (used by `audit verify`'s cross-check).
    Warn {
        detail: String,
    },
}

impl Check {
    /// True only for [`Check::Fail`]. `Skipped`/`Warn` do not fail a
    /// report.
    pub(crate) fn is_fail(&self) -> bool {
        matches!(self, Self::Fail { .. })
    }

    /// Fixed-width-friendly status label for the human table output.
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::Ok { .. } => "OK",
            Self::Fail { .. } => "FAIL",
            Self::Skipped { .. } => "SKIP",
            Self::Warn { .. } => "WARN",
        }
    }

    /// The free-text detail carried by every variant.
    pub(crate) fn detail(&self) -> &str {
        match self {
            Self::Ok { detail }
            | Self::Fail { detail }
            | Self::Skipped { detail }
            | Self::Warn { detail } => detail,
        }
    }
}
