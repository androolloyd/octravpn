// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native caller-facing compute RPC. The gateway owns admission, current
//! canonical views and read authentication; this module owns byte-preserving
//! parameter decoding and native response/error shapes.
mod decode;
mod encode;
use super::{JobStatus, Request, Response};
use async_trait::async_trait;
pub use decode::{cancellation_of_params, read_of_params, request_of_params};
pub use encode::{cancel_receipt_json, response_json, status_json};
use octra_node_protocol::{
    native_exception,
    native_json::{Document, Value},
    resource_compute::{message::CancelAck, read::Read, Error as ComputeError},
    rpc::Fault,
};

pub const SUBMIT: &[u8] = b"octra_circleComputeSubmit";
pub const STATUS: &[u8] = b"octra_circleComputeStatus";
pub const CANCEL: &[u8] = b"octra_circleComputeCancel";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cancellation {
    pub caller: Vec<u8>,
    pub caller_public_key: Vec<u8>,
    pub caller_signature: Vec<u8>,
    pub session_id: Vec<u8>,
    pub until: Option<i64>,
}
impl Cancellation {
    /// The service supplies its configured chain; RPC clients cannot replace it.
    pub fn in_chain(
        &self,
        chain: &[u8],
    ) -> octra_node_protocol::resource_compute::message::Cancellation {
        octra_node_protocol::resource_compute::message::Cancellation {
            chain_id: chain.to_vec(),
            caller: self.caller.clone(),
            caller_public_key: self.caller_public_key.clone(),
            caller_signature: self.caller_signature.clone(),
            session_id: self.session_id.clone(),
            until: self.until,
        }
    }
}

/// Native codec/invariant exceptions remain distinct from ordinary RPC faults.
/// The HTTP host must apply its operational failure policy instead of turning
/// these into caller refusals or a successful partial response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Rpc(Fault),
    Exception(Vec<u8>),
    Unavailable(Vec<u8>),
}
impl From<Fault> for Error {
    fn from(fault: Fault) -> Self {
        Self::Rpc(fault)
    }
}
impl From<ComputeError> for Error {
    fn from(error: ComputeError) -> Self {
        match error {
            ComputeError::Rejected(reason) => invalid_argument(&reason),
            ComputeError::Unavailable(reason) => Self::Unavailable(reason),
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bytes = match self {
            Self::Rpc(fault) => &fault.message,
            Self::Exception(reason) | Self::Unavailable(reason) => reason,
        };
        write!(formatter, "{}", String::from_utf8_lossy(bytes))
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;
pub type ServiceResult<T> = std::result::Result<T, Vec<u8>>;

fn invalid_argument(reason: &[u8]) -> Error {
    Error::Exception(native_exception::string_argument(
        b"Invalid_argument",
        reason,
    ))
}
fn refused(code: i64, message: &[u8], reason: &[u8]) -> Error {
    Fault::new(code, message).string_data(reason).into()
}

#[async_trait]
pub trait Gateway: Send + Sync {
    async fn submit(&self, request: Request) -> ServiceResult<(Vec<u8>, Vec<u8>)>;

    /// Verify the signed read against the service's own chain, node and current
    /// epoch before looking up jobs, and verify the job belongs to its caller.
    async fn status(&self, read: Read) -> ServiceResult<Option<JobStatus>>;

    async fn cancel(&self, cancellation: Cancellation) -> ServiceResult<usize>;

    /// Reauthenticate the supplied caller/session cancellation, including when
    /// a caller invokes this method independently of `cancel`.
    async fn cancel_receipts(&self, cancellation: Cancellation) -> ServiceResult<Vec<CancelAck>>;
}

pub async fn submit(
    service: &(impl Gateway + ?Sized),
    document: &Document,
    params: &Value,
) -> Result<Vec<u8>> {
    let request = request_of_params(document, params)?;
    match service.submit(request).await {
        Ok((job_id, node_id)) => Ok(encode::submitted(&job_id, &node_id)),
        Err(reason) => Err(refused(
            -32040,
            b"resource compute request refused",
            &reason,
        )),
    }
}

pub async fn status(
    service: &(impl Gateway + ?Sized),
    document: &Document,
    params: &Value,
) -> Result<Vec<u8>> {
    let read = read_of_params(document, params)?;
    let job_id = read.job_id.clone();
    match service.status(read).await {
        Err(reason) => Err(refused(-32042, b"resource compute read refused", &reason)),
        Ok(None) => Err(Fault::new(112, b"not found")
            .string_data(b"resource compute job")
            .into()),
        Ok(Some(value)) => status_json(&job_id, &value),
    }
}

pub async fn cancel(
    service: &(impl Gateway + ?Sized),
    document: &Document,
    params: &Value,
) -> Result<Vec<u8>> {
    let cancellation = cancellation_of_params(document, params)?;
    let cancelled = service
        .cancel(cancellation.clone())
        .await
        .map_err(|reason| refused(-32041, b"resource compute cancellation refused", &reason))?;
    let receipts = service
        .cancel_receipts(cancellation)
        .await
        .map_err(|reason| {
            refused(
                -32041,
                b"resource compute cancellation recorded; receipts unavailable",
                &reason,
            )
        })?;
    encode::cancelled(cancelled, &receipts)
}
