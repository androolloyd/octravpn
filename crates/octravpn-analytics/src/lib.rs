//! `octravpn-analytics` — historical analytics indexer for the OctraVPN
//! audit log.
//!
//! ## What this is
//!
//! A small, in-memory indexer that consumes the HMAC-chained audit log
//! produced by `octravpn-node` and exposes Prometheus + JSON
//! time-series views over the last day / week / month. Designed to be
//! either spawned in-process by the node (the default — see
//! `octravpn-node/src/hub.rs`) or run as a standalone binary
//! (`octravpn-analytics --audit-dir … --listen … --bearer-token …`).
//!
//! ## What this is not
//!
//! - **Not** a database. State is process-local and lost on restart.
//!   Boot-time replay (`Indexer::ingest_audit_dir`) reconstitutes the
//!   recent retention window from disk, but anything beyond
//!   `BucketWidth::OneDay × 365` falls off the back.
//! - **Not** authoritative for forensics. The audit log + receipt
//!   journal are. This crate is purely observational.
//! - **Not** an HFHE / chain client. It reads files and a tokio
//!   channel, nothing more.
//!
//! ## Architecture
//!
//! ```text
//!  audit-YYYY-MM-DD.jsonl ──┐
//!                           ├──► audit_reader::scan_dir ──► AnalyticsEvent stream
//!  AuditLog live tap ───────┘                                          │
//!                                                                       ▼
//!                                                              IndexerState
//!                                                              (tumbling buckets:
//!                                                               1m / 5m / 1h / 1d)
//!                                                                       │
//!                                                  ┌───────────────────┼───────────────────┐
//!                                                  ▼                   ▼                   ▼
//!                                            /metrics       /analytics/series      /analytics/health
//! ```
//!
//! See the per-module doc comments for the design rationale of each
//! piece.

pub mod audit_reader;
pub mod bucket;
pub mod event;
pub mod http;
pub mod indexer;

pub use audit_reader::{chain_step, load_audit_key, scan_dir, verify_file, AuditFileScan};
pub use bucket::{BucketSeries, BucketWidth};
pub use event::AnalyticsEvent;
pub use http::{router, serve, HttpState};
pub use indexer::{metric, ChainVerifyStatus, Indexer, IndexerState};
