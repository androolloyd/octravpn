// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Compute coordination policy. These message pools use a host-supplied view;
//! they do not establish finality or authorize funded execution themselves.
mod actor;
pub mod admission;
mod auth;
pub mod cancellation;
mod command;
mod committee;
pub mod funding;
mod jobs;
pub mod reads;
pub mod rpc;
mod service;
pub use jobs::{JobHandle, JobHost, Jobs};
pub use service::{Dependencies, Service};
mod history;
pub use committee::{session_key, CommitteeBook, CommitteeLease};
mod offers;
pub mod provider;
pub use history::HistoryWorker;
mod request;
mod results;
pub use auth::View;
pub use offers::{OfferBook, OfferSnapshot, OfferState};
pub use request::{CallAdmission, CancelStatus, JobStatus, Request, Response};
pub use results::{CertificateProgress, Execution, RequestBook, RequestState};
pub const MAX_OFFERS: usize = 64;
pub const MAX_REQUESTS: usize = 128;
pub const MAX_JOBS: usize = 32;
pub const MAX_CANCELLED_SESSIONS: usize = 256;
pub const MAX_CALLER_SESSIONS: usize = MAX_JOBS;
pub const MAX_COMMITTEE_LEASES: usize = 256;
pub const MAX_PENDING_REVEALS_PER_NODE: usize = 4;
pub const DATA_CHANNEL_LIMIT: usize = 512;
pub const CONTROL_CHANNEL_LIMIT: usize = 64;
pub const MAX_READ_MESSAGES: usize = 32;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Head {
    pub epoch: i64,
    pub state_root: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence {
    pub executor_root: Vec<u8>,
    pub evidence_root: Vec<u8>,
    pub profile: Vec<u8>,
}
