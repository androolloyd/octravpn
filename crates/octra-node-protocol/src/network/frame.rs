// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native frame lengths and message-specific caps, checked before payload allocation.
use super::Error;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAX_FRAME_SIZE: usize = 10_000_000;
pub const HANDSHAKE_PAYLOAD_MAX: usize = 64 * 1024;
pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(10);
pub const DEFAULT_WRITE_IDLE: Duration = Duration::from_secs(300);

pub const fn known_message(message: u8) -> bool {
    matches!(message,0x01..=0x05|0x10..=0x12|0x20..=0x21|0x30..=0x41)
}
pub const fn max_payload_size(message: u8) -> usize {
    match message {
        0x01 | 0x02 | 0x05 => HANDSHAKE_PAYLOAD_MAX,
        0x03 | 0x04 | 0x10 => 4 * 1024,
        0x11 => 512 * 1024,
        0x20 => 5_000_000 + 4096,
        0x30 | 0x3c => 256 * 1024,
        0x32 => 1024 * 1024,
        0x37 | 0x39 | 0x3b | 0x40 => 8 * 1024 * 1024,
        0x41 => 384 * 1024,
        _ if known_message(message) => 16 * 1024,
        _ => 4 * 1024,
    }
}
pub fn message_name(message: u8) -> String {
    match message {
        0x01 => "HELLO",
        0x02 => "HELLO_ACK",
        0x03 => "PING",
        0x04 => "PONG",
        0x05 => "HELLO_FINISH",
        0x10 => "GET_PEERS",
        0x11 => "PEERS",
        0x12 => "PROFILE",
        0x20 => "TX_GOSSIP",
        0x21 => "PROOFCERT_GOSSIP",
        0x30 => "CONS_PROPOSE",
        0x31 => "CONS_VOTE",
        0x32 => "CONS_FINALIZE",
        0x33 => "CONS_TIMEOUT",
        0x34 => "QUERY_EPOCH_ROOT",
        0x35 => "EPOCH_ROOT_RESPONSE",
        0x36 => "QUERY_BUNDLE",
        0x37 => "BUNDLE_RESPONSE",
        0x38 => "QUERY_CATCHUP_RANGE_V1",
        0x39 => "CATCHUP_RANGE_RESPONSE_V1",
        0x3a => "QUERY_CATCHUP_RANGE_V2",
        0x3b => "CATCHUP_RANGE_RESPONSE_V2",
        0x3c => "RESOURCE_ATTESTATION",
        0x3d => "VOTE_EVIDENCE",
        0x3e => "CONS_ROUND_SYNC",
        0x3f => "CONS_ROUND_FETCH",
        0x40 => "EPOCH_BROADCAST",
        0x41 => "RESOURCE_COMPUTE",
        _ => return format!("UNKNOWN(0x{message:02x})"),
    }
    .to_owned()
}

pub fn check_payload(message: u8, length: usize) -> Result<(), Error> {
    let maximum = max_payload_size(message);
    if length > maximum {
        return Err(format!(
            "frame_payload_too_large type = 0x{message:02x} size = {length} max = {maximum}"
        )
        .into());
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub message: u8,
    pub payload: Vec<u8>,
}
impl Frame {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let length = self
            .payload
            .len()
            .checked_add(1)
            .ok_or_else(|| Error::from("frame allocation unavailable"))?;
        if length > MAX_FRAME_SIZE {
            return Err(format!("frame_too_large size = {length} max = {MAX_FRAME_SIZE}").into());
        }
        check_payload(self.message, self.payload.len())?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(4 + length)
            .map_err(|_| Error::from("frame allocation unavailable"))?;
        output.extend_from_slice(&(length as u32).to_be_bytes());
        output.push(self.message);
        output.extend_from_slice(&self.payload);
        Ok(output)
    }
}

async fn read_exact<R: AsyncRead + Unpin>(reader: &mut R, bytes: &mut [u8]) -> Result<(), Error> {
    let mut offset = 0;
    while offset < bytes.len() {
        let read = reader
            .read(&mut bytes[offset..])
            .await
            .map_err(|e| Error::from(e.to_string()))?;
        if read == 0 {
            return Err("connection_closed".into());
        }
        offset += read;
        tokio::task::yield_now().await;
    }
    Ok(())
}

pub async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    timeout: Duration,
    payload_cap: usize,
) -> Result<Frame, Error> {
    tokio::time::timeout(timeout, async {
        let mut header = [0; 4];
        read_exact(reader, &mut header).await?;
        let length = u32::from_be_bytes(header) as usize;
        if length == 0 {
            return Err(Error::from("empty_frame"));
        }
        if length > MAX_FRAME_SIZE {
            return Err(format!("frame_too_large size = {length}").into());
        }
        let mut message = [0];
        read_exact(reader, &mut message).await?;
        let payload_len = length - 1;
        if payload_len > payload_cap {
            return Err(
                format!("frame_payload_limit size = {payload_len} max = {payload_cap}").into(),
            );
        }
        check_payload(message[0], payload_len)?;
        let mut payload = Vec::new();
        payload
            .try_reserve_exact(payload_len)
            .map_err(|_| Error::from("frame allocation unavailable"))?;
        payload.resize(payload_len, 0);
        read_exact(reader, &mut payload).await?;
        Ok(Frame {
            message: message[0],
            payload,
        })
    })
    .await
    .map_err(|_| Error::from("read timeout"))?
}

pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &Frame,
    idle: Duration,
) -> Result<(), Error> {
    if idle.is_zero() {
        return Err("invalid write idle interval".into());
    }
    let encoded = frame.encode()?;
    let mut offset = 0;
    while offset < encoded.len() {
        let written = tokio::time::timeout(idle, writer.write(&encoded[offset..]))
            .await
            .map_err(|_| Error::from("write timeout"))?
            .map_err(|e| Error::from(e.to_string()))?;
        if written == 0 {
            return Err("write_failed".into());
        }
        offset += written;
        tokio::task::yield_now().await;
    }
    Ok(())
}
