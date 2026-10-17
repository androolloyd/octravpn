// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Legacy contracts and typed Programs inside the caller's speculative epoch.
//! Artifacts, overlays and canonical persistence keep distinct trust boundaries.
pub mod artifact;
pub mod build;
pub mod execute;
pub mod input;
pub mod journal;
pub mod receipt;
pub mod rpc;
pub mod store;
pub mod upgrade;
pub mod view;
pub use artifact::Artifact;
pub use journal::Journal;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Rejected(Vec<u8>),
    Unavailable(String),
}
impl Error {
    pub fn rejected(reason: impl AsRef<[u8]>) -> Self {
        Self::Rejected(reason.as_ref().to_vec())
    }
    pub fn unavailable(reason: impl std::fmt::Display) -> Self {
        Self::Unavailable(reason.to_string())
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected(reason) => write!(f, "{}", String::from_utf8_lossy(reason)),
            Self::Unavailable(reason) => f.write_str(reason),
        }
    }
}
impl std::error::Error for Error {}
impl From<octra_node_protocol::octb::Error> for Error {
    fn from(error: octra_node_protocol::octb::Error) -> Self {
        if error.is_operational() {
            Self::unavailable(error)
        } else {
            Self::rejected(error.to_string())
        }
    }
}
impl From<octra_node_protocol::aml::compiler::package::Error> for Error {
    fn from(error: octra_node_protocol::aml::compiler::package::Error) -> Self {
        use octra_node_protocol::aml::compiler::package::Error as E;
        match error {
            E::Rejected(reason) => Self::Rejected(reason),
            E::Unavailable(reason) => {
                Self::Unavailable(String::from_utf8_lossy(&reason).into_owned())
            }
        }
    }
}
pub type Result<T> = std::result::Result<T, Error>;
