// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Connections become available to callers only after the native challenge exchange.
use super::{
    budget::{Action, Budget, PeerClass, Verdict},
    frame::{self, Frame},
    handshake::{Ack, Finish, Hello},
    Error,
};
use ed25519_dalek::SigningKey;
use rand::{CryptoRng, RngCore};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
mod driver;
pub use driver::{Driver, Peer};

#[derive(Clone, Debug)]
pub struct LocalNode {
    pub chain_id: Vec<u8>,
    pub node_address: Vec<u8>,
    pub config_hash: [u8; 32],
    pub listen_port: u16,
    pub best_epoch: i64,
    pub best_root: [u8; 32],
}
impl LocalNode {
    pub fn fresh_hello<R: CryptoRng + RngCore>(
        &self,
        key: &SigningKey,
        rng: &mut R,
    ) -> Result<Hello, Error> {
        Hello::new(
            key,
            self.chain_id.clone(),
            self.node_address.clone(),
            self.config_hash,
            self.listen_port,
            self.best_epoch,
            self.best_root,
            rng,
        )
    }
}
#[derive(Clone, Copy, Debug)]
pub struct Timeouts {
    pub handshake_read: Duration,
    pub read_idle: Duration,
    pub write_idle: Duration,
}
impl Default for Timeouts {
    fn default() -> Self {
        Self {
            handshake_read: frame::DEFAULT_READ_TIMEOUT,
            read_idle: Duration::from_secs(60),
            write_idle: frame::DEFAULT_WRITE_IDLE,
        }
    }
}

pub struct Connection<S> {
    stream: S,
    peer: Hello,
    budget: Budget,
    created: Instant,
    closed: bool,
    timeouts: Timeouts,
}
impl<S: AsyncRead + AsyncWrite + Unpin> Connection<S> {
    /// Transfer ownership to independent reader/writer loops. A cancelled driver
    /// closes both halves; partially processed frames can never be reused.
    pub fn into_driver(self) -> Result<(Peer, Driver<S>), Error> {
        driver::create(self)
    }
    fn authenticated(stream: S, peer: Hello, timeouts: Timeouts) -> Self {
        Self {
            stream,
            peer,
            budget: Budget::new(0.0, PeerClass::Observer),
            created: Instant::now(),
            closed: false,
            timeouts,
        }
    }
    pub const fn peer(&self) -> &Hello {
        &self.peer
    }
    pub const fn is_closed(&self) -> bool {
        self.closed
    }
    /// The host must derive this role from its authenticated validator registry.
    pub fn set_peer_class(&mut self, class: PeerClass) {
        self.budget.set_peer_class(class);
    }
    pub async fn close(&mut self) {
        self.closed = true;
        let _ = tokio::time::timeout(self.timeouts.write_idle, self.stream.shutdown()).await;
    }
    pub async fn send(&mut self, message: &Frame) -> Result<(), Error> {
        if self.closed {
            return Err("connection_closed".into());
        }
        // Cancellation may leave a partial frame. Reuse is allowed only after
        // the entire operation completes successfully.
        self.closed = true;
        let result = frame::write_frame(&mut self.stream, message, self.timeouts.write_idle).await;
        if result.is_err() {
            self.close().await;
        } else {
            self.closed = false;
        }
        result
    }
    pub async fn receive(&mut self) -> Result<Frame, Error> {
        if self.closed {
            return Err("connection_closed".into());
        }
        self.closed = true;
        loop {
            let message = match frame::read_frame(
                &mut self.stream,
                self.timeouts.read_idle,
                frame::MAX_FRAME_SIZE - 1,
            )
            .await
            {
                Ok(message) => message,
                Err(error) => {
                    self.close().await;
                    return Err(error);
                }
            };
            match self.budget.admit(
                self.created.elapsed().as_secs_f64(),
                message.message,
                message.payload.len() as i64,
            ) {
                Verdict::Accept => {
                    self.closed = false;
                    return Ok(message);
                }
                Verdict::Drop(rejection) if rejection.action == Action::Discard => {}
                Verdict::Drop(rejection) => {
                    self.close().await;
                    return Err(rejection.reason.into());
                }
            }
        }
    }
}

fn handshake_error(error: Error) -> Error {
    if error.as_bytes() == b"read timeout" || error.as_bytes() == b"write timeout" {
        return "handshake timeout".into();
    }
    // Codec failures use the native Failure envelope; OS-specific I/O errors
    // remain diagnostic and are not part of consensus or wire encodings.
    let mut output = b"handshake failed: Failure(\"".to_vec();
    for byte in error.into_bytes() {
        match byte {
            b'\\' => output.extend_from_slice(b"\\\\"),
            b'"' => output.extend_from_slice(b"\\\""),
            b'\n' => output.extend_from_slice(b"\\n"),
            b'\r' => output.extend_from_slice(b"\\r"),
            b'\t' => output.extend_from_slice(b"\\t"),
            32..=126 => output.push(byte),
            _ => output.extend_from_slice(format!("\\{byte:03}").as_bytes()),
        }
    }
    output.extend_from_slice(b"\")");
    Error::new(output)
}
async fn receive_handshake<S: AsyncRead + Unpin>(
    stream: &mut S,
    timeouts: Timeouts,
) -> Result<Frame, Error> {
    frame::read_frame(
        stream,
        timeouts.handshake_read,
        frame::HANDSHAKE_PAYLOAD_MAX,
    )
    .await
    .map_err(handshake_error)
}
async fn send_handshake<S: AsyncWrite + Unpin>(
    stream: &mut S,
    message: u8,
    payload: Vec<u8>,
    timeouts: Timeouts,
) -> Result<(), Error> {
    frame::write_frame(stream, &Frame { message, payload }, timeouts.write_idle)
        .await
        .map_err(handshake_error)
}

/// Generates a fresh local nonce on every connection, including reconnects.
pub async fn dial<S, R>(
    mut stream: S,
    local: &LocalNode,
    key: &SigningKey,
    allowed: &[Vec<u8>],
    rng: &mut R,
    timeouts: Timeouts,
) -> Result<Connection<S>, Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
    R: CryptoRng + RngCore,
{
    let hello = local.fresh_hello(key, rng)?;
    send_handshake(
        &mut stream,
        0x01,
        hello.encode().map_err(handshake_error)?,
        timeouts,
    )
    .await?;
    let response = receive_handshake(&mut stream, timeouts).await?;
    if response.message != 0x02 {
        return Err(format!("expected HELLO_ACK, got 0x{:02x}", response.message).into());
    }
    let ack = Ack::decode(&response.payload).map_err(handshake_error)?;
    ack.validate(&hello, allowed)?;
    let finish = Finish::new(&hello, &ack.hello, key).map_err(handshake_error)?;
    send_handshake(
        &mut stream,
        0x05,
        finish.encode().map_err(handshake_error)?,
        timeouts,
    )
    .await?;
    Ok(Connection::authenticated(stream, ack.hello, timeouts))
}

pub async fn accept<S, R>(
    mut stream: S,
    local: &LocalNode,
    key: &SigningKey,
    allowed: &[Vec<u8>],
    rng: &mut R,
    timeouts: Timeouts,
) -> Result<Connection<S>, Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
    R: CryptoRng + RngCore,
{
    let hello = local.fresh_hello(key, rng)?;
    let request = receive_handshake(&mut stream, timeouts).await?;
    if request.message != 0x01 {
        return Err(format!("expected HELLO, got 0x{:02x}", request.message).into());
    }
    let peer = Hello::decode(&request.payload).map_err(handshake_error)?;
    peer.validate(&hello.chain_id, &hello.config_hash, allowed)?;
    let ack = Ack::new(hello.clone(), peer.nonce.clone(), key).map_err(handshake_error)?;
    send_handshake(
        &mut stream,
        0x02,
        ack.encode().map_err(handshake_error)?,
        timeouts,
    )
    .await?;
    let request = receive_handshake(&mut stream, timeouts).await?;
    if request.message != 0x05 {
        return Err(format!("expected HELLO_FINISH, got 0x{:02x}", request.message).into());
    }
    let finish = Finish::decode(&request.payload).map_err(handshake_error)?;
    finish.validate(&peer, &hello)?;
    Ok(Connection::authenticated(stream, peer, timeouts))
}
