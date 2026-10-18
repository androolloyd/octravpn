//! Reusable OctraVPN client services and their command-line adapter.
//!
//! Payment clients accept an externally confirmed plan, retain their original
//! journal, and take caller-owned shutdown futures. They install no global
//! signal handler, route, tracing subscriber or browser integration.
//! The opt-in MultiPaymentClient separately owns a Linux composite route lease;
//! its documented management exceptions and crash recovery apply to that API.
//!
//! ```no_run
//! use octravpn_client::{PaymentClient, PaymentOptions, PaymentSummary};
//! # async fn embed(options: PaymentOptions, shutdown: impl std::future::Future<Output = anyhow::Result<()>>) -> anyhow::Result<PaymentSummary> {
//! let client = PaymentClient::open(options).await?;
//! // Provision explicit host routes using client.interface().
//! client.run(shutdown).await
//! # }
//! ```

mod chain_v3;
pub mod cli;
mod commands;
mod config;
mod discover;
mod discover_v2;
mod migration;
mod multihop;
mod onboarding;
mod paid_routes;
mod payment_runner;
mod payments;
mod portal;
mod runner;
mod settle_state;
mod settler;
mod tailnet;
mod v2_cache;
mod v2_runner;
mod v3_runner;
mod wallet;
mod wireguard;

pub use payment_runner::{
    Client as PaymentClient, Interface, Options as PaymentOptions, Plan as AcceptedPlan,
    StockClient, StockOptions, Summary as PaymentSummary,
};
pub use payments::OpenMode as JournalMode;

pub use multihop::{
    Client as MultiPaymentClient, HopPlan as MultiHopPlan, Options as MultiPaymentOptions,
    RoutePlan as MultiRoutePlan,
};
