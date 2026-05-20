//! Forward-compat enforcement for `#[non_exhaustive]` on
//! `octra_circle_sim::ChainError`.

#![allow(clippy::needless_pass_by_value)] // intentional: matching consumes the value

use octra_circle_sim::ChainError;

#[deny(unreachable_patterns)]
#[test]
fn public_error_enums_are_non_exhaustive() {
    fn check(e: ChainError) -> &'static str {
        match e {
            ChainError::SessionNotFound(_) => "nf",
            ChainError::Rpc(_) => "rpc",
            ChainError::Unauthorized(_) => "auth",
            _ => "future",
        }
    }
    assert_eq!(check(ChainError::SessionNotFound(1)), "nf");
}
