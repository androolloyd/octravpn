// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Shared native private-transition failures. User and preverification messages
//! are distinct from the canonical refusal reason; local failures are unavailable.
use crate::private_crypto as crypto;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failure {
    pub tag: &'static str,
    pub reason: Vec<u8>,
    pub user_reason: Vec<u8>,
    pub preverify_reason: Option<Vec<u8>>,
}
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("private transition rejected: {0:?}")]
    Rejected(Failure),
    #[error("private execution unavailable: {0}")]
    Unavailable(String),
}
pub(crate) fn failure(tag: &'static str, reason: impl AsRef<[u8]>, user: Option<Vec<u8>>) -> Error {
    let reason = reason.as_ref().to_vec();
    Error::Rejected(Failure {
        tag,
        user_reason: user.unwrap_or_else(|| reason.clone()),
        reason,
        preverify_reason: None,
    })
}
pub(crate) fn check<T>(
    result: Result<T, impl CryptoFailure>,
    tag: &'static str,
    prefix: &[u8],
    user: Option<&[u8]>,
) -> Result<T, Error> {
    result.map_err(|error| match error.classify() {
        Ok(reason) => failure(
            tag,
            [prefix, &reason].concat(),
            user.map(|p| [p, &reason].concat()),
        ),
        Err(error) => Error::Unavailable(error),
    })
}
pub(crate) trait CryptoFailure {
    fn classify(self) -> Result<Vec<u8>, String>;
}
impl CryptoFailure for crypto::Error {
    fn classify(self) -> Result<Vec<u8>, String> {
        match self {
            Self::Rejected(reason) => Ok(reason),
            Self::Unavailable(error) => Err(error.to_string()),
        }
    }
}
impl CryptoFailure for crypto::isolated::Error {
    fn classify(self) -> Result<Vec<u8>, String> {
        match self {
            Self::Rejected(reason) => Ok(reason),
            Self::Unavailable(reason) => Err(reason),
        }
    }
}
