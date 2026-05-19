//! Tailscale `controlbase` framing layer.
//!
//! Implements the 3-byte / 5-byte message header used by Tailscale's
//! `/ts2021` upgrade once the HTTP `Upgrade:` step has hijacked the
//! TCP socket. Source citations:
//!
//! - `tailscale/control/controlbase/messages.go` — header layout
//!   (regular = 3 bytes, initiation = 5 bytes, msg types 1/2/3/4)
//! - `tailscale/control/controlbase/conn.go` — framed read/write loops
//! - juanfont/headscale `hscontrol/noise.go::handle_ts2021_post` —
//!   the reference responder pattern this module mirrors.
//!
//! ## Frame layout
//!
//! | Header  | Bytes | Used by                              |
//! | ------- | ----- | ------------------------------------ |
//! | Regular | 3     | Reply (2), Record (3)                |
//! | Initiation | 5  | Initiation (1) — carries protoVersion |
//!
//! Regular: `[msg_type:u8][len:u16be]` followed by `len` body bytes.
//! Initiation: `[msg_type:u8][protocolVersion:u16be][len:u16be]`
//! followed by `len` body bytes.
//!
//! ## What this module exposes
//!
//! - [`MsgType`] — the four documented message types.
//! - [`Framed`] — `read_frame`/`write_frame`/`write_initiation`/`write_reply`
//!   over any `AsyncRead + AsyncWrite + Unpin`.
//! - [`NoiseStream`] — the post-handshake wrapper that encrypts every
//!   `AsyncWrite::poll_write` into a single Record frame and decrypts
//!   the next Record frame on `AsyncRead::poll_read`. Hand this to
//!   `h2::server::handshake` to speak HTTP/2 over Noise.
//!
//! ## Decision log
//!
//! - **Plaintext records are bounded by snow's `MAXMSGLEN - TAGLEN`
//!   (65519 bytes).** Any single `poll_write` larger than that is
//!   chunked across multiple Record frames; the caller doesn't see
//!   the boundary. h2 typically sends frames much smaller than that.
//! - **`NoiseStream` buffers exactly one decrypted record at a time.**
//!   When the buffer drains we read the next frame. This means
//!   `poll_read` can advance the read state machine without yielding
//!   to the executor more than once per record — the same pattern
//!   tokio's `BufReader` uses.
//! - **No tokio_util::codec::Framed.** We use that name because it
//!   matches Tailscale's `controlbase.Conn` naming, but the API here
//!   is hand-written so we can expose `into_inner` cleanly and so the
//!   reader can switch from header-mode → body-mode without
//!   `Box<dyn Decoder>` overhead.

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

/// Tailscale's `controlbase` message type byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MsgType {
    /// Handshake Initiation (`-> e, es, s, ss`). Carries a 2-byte
    /// `protocolVersion` between the type byte and the length, hence
    /// the 5-byte header instead of 3.
    Initiation = 1,
    /// Handshake Reply (`<- e, ee, se`). 3-byte header.
    Reply = 2,
    /// Encrypted transport record. 3-byte header.
    Record = 3,
}

impl MsgType {
    fn from_u8(b: u8) -> io::Result<Self> {
        match b {
            1 => Ok(Self::Initiation),
            2 => Ok(Self::Reply),
            3 => Ok(Self::Record),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown controlbase msg type: {other}"),
            )),
        }
    }
}

/// Snow's MAXMSGLEN (65535) minus TAGLEN (16). Any payload larger
/// than this in a single Record frame is rejected by snow on encrypt.
pub const MAX_PLAINTEXT_PER_RECORD: usize = 65535 - 16;

/// Header types as decoded by [`Framed::read_frame`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameHeader {
    /// A regular 3-byte-header frame (Reply or Record).
    Regular { msg_type: MsgType, len: u16 },
    /// An initiation 5-byte-header frame.
    Initiation { protocol_version: u16, len: u16 },
}

/// A framing reader/writer over an arbitrary AsyncRead+AsyncWrite
/// transport. Owns the underlying socket; recover via
/// [`Framed::into_inner`] or convert to a [`NoiseStream`] via
/// [`Framed::into_transport`].
pub struct Framed<T> {
    inner: T,
}

impl<T> Framed<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(inner: T) -> Self {
        Self { inner }
    }

    /// Consume the framer and return the unwrapped socket.
    pub fn into_inner(self) -> T {
        self.inner
    }

    /// Read one frame off the wire. Returns the decoded header + the
    /// frame body. Reads exactly the right number of bytes — the
    /// caller should not perform any further reads on `inner` between
    /// `read_frame` calls.
    pub async fn read_frame(&mut self) -> io::Result<(FrameHeader, Vec<u8>)> {
        let mut type_byte = [0u8; 1];
        self.inner.read_exact(&mut type_byte).await?;
        let mt = MsgType::from_u8(type_byte[0])?;

        let header = match mt {
            MsgType::Initiation => {
                let mut rest = [0u8; 4];
                self.inner.read_exact(&mut rest).await?;
                let proto = u16::from_be_bytes([rest[0], rest[1]]);
                let len = u16::from_be_bytes([rest[2], rest[3]]);
                FrameHeader::Initiation {
                    protocol_version: proto,
                    len,
                }
            }
            MsgType::Reply | MsgType::Record => {
                let mut rest = [0u8; 2];
                self.inner.read_exact(&mut rest).await?;
                let len = u16::from_be_bytes([rest[0], rest[1]]);
                FrameHeader::Regular { msg_type: mt, len }
            }
        };

        let len = match header {
            FrameHeader::Regular { len, .. } | FrameHeader::Initiation { len, .. } => len,
        };
        let mut body = vec![0u8; len as usize];
        if len > 0 {
            self.inner.read_exact(&mut body).await?;
        }
        Ok((header, body))
    }

    /// Write a regular 3-byte-header frame (Reply or Record).
    pub async fn write_frame(&mut self, msg_type: MsgType, body: &[u8]) -> io::Result<()> {
        if body.len() > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("frame body too large: {} bytes", body.len()),
            ));
        }
        if matches!(msg_type, MsgType::Initiation) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "use write_initiation for Initiation frames",
            ));
        }
        let mut hdr = [0u8; 3];
        hdr[0] = msg_type as u8;
        hdr[1..3].copy_from_slice(&(body.len() as u16).to_be_bytes());
        self.inner.write_all(&hdr).await?;
        if !body.is_empty() {
            self.inner.write_all(body).await?;
        }
        Ok(())
    }

    /// Write an initiation (5-byte-header) frame. The protocol_version
    /// is the same one mixed into the Noise prologue.
    pub async fn write_initiation(
        &mut self,
        protocol_version: u16,
        body: &[u8],
    ) -> io::Result<()> {
        if body.len() > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("initiation body too large: {} bytes", body.len()),
            ));
        }
        let mut hdr = [0u8; 5];
        hdr[0] = MsgType::Initiation as u8;
        hdr[1..3].copy_from_slice(&protocol_version.to_be_bytes());
        hdr[3..5].copy_from_slice(&(body.len() as u16).to_be_bytes());
        self.inner.write_all(&hdr).await?;
        if !body.is_empty() {
            self.inner.write_all(body).await?;
        }
        Ok(())
    }

    /// Convenience wrapper for the responder's `<- e, ee, se` message.
    pub async fn write_reply(&mut self, body: &[u8]) -> io::Result<()> {
        self.write_frame(MsgType::Reply, body).await
    }

    /// Wrap the underlying socket in a Noise transport stream. Caller
    /// must have already completed the Noise handshake; the returned
    /// type implements `AsyncRead + AsyncWrite` and can be handed to
    /// `h2::server::handshake`.
    pub fn into_transport(self, transport: snow::TransportState) -> NoiseStream<T> {
        NoiseStream::new(self.inner, transport)
    }
}

/// A Noise-encrypted bytestream over a `T: AsyncRead + AsyncWrite`.
///
/// Every `poll_write` encrypts the slice into one (or more) Record
/// frames; every `poll_read` decrypts the next Record frame and serves
/// bytes from a per-record buffer. Plaintext-per-record is capped at
/// [`MAX_PLAINTEXT_PER_RECORD`] (snow `MAXMSGLEN - TAGLEN`).
///
/// State machine:
///
/// - **Read:** `ReadState::Header` → read 3 bytes → `ReadState::Body{len}`
///   → read `len` bytes → decrypt → `ReadState::ServingPlaintext{buf, pos}`
///   → drain → back to `Header`.
/// - **Write:** `WriteState::Idle` → on `poll_write`, encrypt into
///   `enc_buf`, push header + ciphertext → `WriteState::Flushing` →
///   write_all to inner socket → back to `Idle`.
pub struct NoiseStream<T> {
    inner: T,
    transport: snow::TransportState,
    read_state: ReadState,
    write_state: WriteState,
}

enum ReadState {
    /// Reading the 3-byte regular header.
    Header { buf: [u8; 3], filled: usize },
    /// Reading the ciphertext body of length `len`.
    Body { buf: Vec<u8>, filled: usize },
    /// Plaintext available to hand back to the caller.
    ServingPlaintext { buf: Vec<u8>, pos: usize },
    /// Stream is closed (peer hung up cleanly during header read).
    Eof,
}

enum WriteState {
    /// No outbound bytes pending.
    Idle,
    /// Bytes ready to flush to the inner socket. We hold these until
    /// the inner sink has consumed them all.
    Flushing { buf: Vec<u8>, pos: usize },
}

impl<T> NoiseStream<T> {
    fn new(inner: T, transport: snow::TransportState) -> Self {
        Self {
            inner,
            transport,
            read_state: ReadState::Header {
                buf: [0u8; 3],
                filled: 0,
            },
            write_state: WriteState::Idle,
        }
    }

    /// Consume the wrapper and return the inner socket + transport
    /// state. Useful for shutting down cleanly while still owning the
    /// rekeyed cipher.
    pub fn into_parts(self) -> (T, snow::TransportState) {
        (self.inner, self.transport)
    }
}

impl<T> AsyncRead for NoiseStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            // Take ownership of the state by swapping in a sentinel so
            // we can mutate freely; we restore at every continue point.
            let cur = std::mem::replace(
                &mut self.read_state,
                ReadState::Header {
                    buf: [0u8; 3],
                    filled: 0,
                },
            );
            match cur {
                ReadState::Eof => {
                    self.read_state = ReadState::Eof;
                    return Poll::Ready(Ok(()));
                }
                ReadState::ServingPlaintext { buf, pos } => {
                    let remaining = &buf[pos..];
                    let n = remaining.len().min(out.remaining());
                    if n == 0 {
                        // out has zero capacity; restore + yield empty.
                        self.read_state = ReadState::ServingPlaintext { buf, pos };
                        return Poll::Ready(Ok(()));
                    }
                    out.put_slice(&remaining[..n]);
                    let new_pos = pos + n;
                    if new_pos == buf.len() {
                        // Drained: go back to reading the next frame.
                        self.read_state = ReadState::Header {
                            buf: [0u8; 3],
                            filled: 0,
                        };
                    } else {
                        self.read_state = ReadState::ServingPlaintext { buf, pos: new_pos };
                    }
                    return Poll::Ready(Ok(()));
                }
                ReadState::Header { mut buf, mut filled } => {
                    let mut rb = ReadBuf::new(&mut buf[filled..]);
                    match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                        Poll::Pending => {
                            self.read_state = ReadState::Header { buf, filled };
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(e)) => {
                            self.read_state = ReadState::Header { buf, filled };
                            return Poll::Ready(Err(e));
                        }
                        Poll::Ready(Ok(())) => {
                            let n = rb.filled().len();
                            if n == 0 {
                                if filled == 0 {
                                    // Clean EOF on a frame boundary.
                                    self.read_state = ReadState::Eof;
                                    return Poll::Ready(Ok(()));
                                }
                                self.read_state = ReadState::Header { buf, filled };
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "EOF mid-header",
                                )));
                            }
                            filled += n;
                            if filled < 3 {
                                self.read_state = ReadState::Header { buf, filled };
                                continue;
                            }
                            // Full header. Validate msg type + decode length.
                            let mt = match MsgType::from_u8(buf[0]) {
                                Ok(m) => m,
                                Err(e) => return Poll::Ready(Err(e)),
                            };
                            if !matches!(mt, MsgType::Record) {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    format!(
                                        "expected Record frame in transport mode, got {mt:?}"
                                    ),
                                )));
                            }
                            let len =
                                u16::from_be_bytes([buf[1], buf[2]]) as usize;
                            if len == 0 {
                                // Empty record; treat as a no-op and keep reading.
                                self.read_state = ReadState::Header {
                                    buf: [0u8; 3],
                                    filled: 0,
                                };
                                continue;
                            }
                            self.read_state = ReadState::Body {
                                buf: vec![0u8; len],
                                filled: 0,
                            };
                        }
                    }
                }
                ReadState::Body { mut buf, mut filled } => {
                    let mut rb = ReadBuf::new(&mut buf[filled..]);
                    match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                        Poll::Pending => {
                            self.read_state = ReadState::Body { buf, filled };
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(e)) => {
                            self.read_state = ReadState::Body { buf, filled };
                            return Poll::Ready(Err(e));
                        }
                        Poll::Ready(Ok(())) => {
                            let n = rb.filled().len();
                            if n == 0 {
                                self.read_state = ReadState::Body { buf, filled };
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "EOF mid-body",
                                )));
                            }
                            filled += n;
                            if filled < buf.len() {
                                self.read_state = ReadState::Body { buf, filled };
                                continue;
                            }
                            // Full ciphertext. Decrypt.
                            let mut plaintext = vec![0u8; buf.len()];
                            let plen = match self
                                .transport
                                .read_message(&buf, &mut plaintext)
                            {
                                Ok(p) => p,
                                Err(e) => {
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        format!("noise decrypt: {e}"),
                                    )))
                                }
                            };
                            plaintext.truncate(plen);
                            self.read_state = ReadState::ServingPlaintext {
                                buf: plaintext,
                                pos: 0,
                            };
                        }
                    }
                }
            }
        }
    }
}

impl<T> AsyncWrite for NoiseStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        // If we have buffered ciphertext from a previous call, flush
        // it first. Backpressure: we don't accept new plaintext until
        // the previous record is fully on the wire.
        loop {
            let cur = std::mem::replace(&mut self.write_state, WriteState::Idle);
            match cur {
                WriteState::Idle => {
                    if bytes.is_empty() {
                        self.write_state = WriteState::Idle;
                        return Poll::Ready(Ok(0));
                    }
                    let take = bytes.len().min(MAX_PLAINTEXT_PER_RECORD);
                    // Encrypt: ciphertext = plaintext + TAGLEN(16).
                    let mut ciphertext = vec![0u8; take + 16];
                    let clen = match self
                        .transport
                        .write_message(&bytes[..take], &mut ciphertext)
                    {
                        Ok(n) => n,
                        Err(e) => {
                            return Poll::Ready(Err(io::Error::other(
                                format!("noise encrypt: {e}"),
                            )))
                        }
                    };
                    ciphertext.truncate(clen);
                    // Frame.
                    let mut framed = Vec::with_capacity(3 + clen);
                    framed.push(MsgType::Record as u8);
                    framed.extend_from_slice(&(clen as u16).to_be_bytes());
                    framed.extend_from_slice(&ciphertext);
                    self.write_state = WriteState::Flushing { buf: framed, pos: 0 };
                    // Drive at least one write before yielding so we
                    // don't always need a second poll.
                }
                WriteState::Flushing { buf, pos } => {
                    let rem = &buf[pos..];
                    match Pin::new(&mut self.inner).poll_write(cx, rem) {
                        Poll::Pending => {
                            self.write_state = WriteState::Flushing { buf, pos };
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(e)) => {
                            self.write_state = WriteState::Flushing { buf, pos };
                            return Poll::Ready(Err(e));
                        }
                        Poll::Ready(Ok(0)) => {
                            self.write_state = WriteState::Flushing { buf, pos };
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "inner write returned 0",
                            )));
                        }
                        Poll::Ready(Ok(n)) => {
                            let new_pos = pos + n;
                            if new_pos == buf.len() {
                                // Full record on the wire — accept the
                                // plaintext bytes we encrypted.
                                self.write_state = WriteState::Idle;
                                let consumed = bytes.len().min(MAX_PLAINTEXT_PER_RECORD);
                                return Poll::Ready(Ok(consumed));
                            }
                            self.write_state = WriteState::Flushing { buf, pos: new_pos };
                        }
                    }
                }
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Drain any in-flight ciphertext before flushing the inner.
        loop {
            let cur = std::mem::replace(&mut self.write_state, WriteState::Idle);
            match cur {
                WriteState::Idle => {
                    return Pin::new(&mut self.inner).poll_flush(cx);
                }
                WriteState::Flushing { buf, pos } => {
                    let rem = &buf[pos..];
                    match Pin::new(&mut self.inner).poll_write(cx, rem) {
                        Poll::Pending => {
                            self.write_state = WriteState::Flushing { buf, pos };
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(e)) => {
                            self.write_state = WriteState::Flushing { buf, pos };
                            return Poll::Ready(Err(e));
                        }
                        Poll::Ready(Ok(0)) => {
                            self.write_state = WriteState::Flushing { buf, pos };
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "inner write returned 0",
                            )));
                        }
                        Poll::Ready(Ok(n)) => {
                            let new_pos = pos + n;
                            if new_pos == buf.len() {
                                self.write_state = WriteState::Idle;
                            } else {
                                self.write_state =
                                    WriteState::Flushing { buf, pos: new_pos };
                            }
                        }
                    }
                }
            }
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        // Flush our buffer, then shut down the inner.
        match Pin::new(&mut *self).poll_flush(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_shutdown(cx),
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    /// Round-trip a Reply frame through Framed.
    #[tokio::test]
    async fn regular_frame_round_trip() {
        let (a, b) = duplex(4096);
        let mut writer = Framed::new(a);
        let mut reader = Framed::new(b);

        let payload = b"hello reply".to_vec();
        writer.write_reply(&payload).await.unwrap();
        let (hdr, body) = reader.read_frame().await.unwrap();
        match hdr {
            FrameHeader::Regular { msg_type, len } => {
                assert_eq!(msg_type, MsgType::Reply);
                assert_eq!(len as usize, payload.len());
            }
            FrameHeader::Initiation { .. } => {
                panic!("expected regular header, got {hdr:?}")
            }
        }
        assert_eq!(body, payload);
    }

    /// Round-trip an Initiation frame including the protocolVersion
    /// field.
    #[tokio::test]
    async fn initiation_frame_round_trip() {
        let (a, b) = duplex(4096);
        let mut writer = Framed::new(a);
        let mut reader = Framed::new(b);

        let body = b"<initiation-bytes>".to_vec();
        writer.write_initiation(39, &body).await.unwrap();
        let (hdr, recv) = reader.read_frame().await.unwrap();
        match hdr {
            FrameHeader::Initiation { protocol_version, len } => {
                assert_eq!(protocol_version, 39);
                assert_eq!(len as usize, body.len());
            }
            FrameHeader::Regular { .. } => {
                panic!("expected initiation header, got {hdr:?}")
            }
        }
        assert_eq!(recv, body);
    }

    /// Multiple frames back-to-back on one duplex.
    #[tokio::test]
    async fn multi_frame_initiation_then_reply() {
        let (a, b) = duplex(8192);
        let mut writer = Framed::new(a);
        let mut reader = Framed::new(b);

        writer.write_initiation(39, b"init body").await.unwrap();
        writer.write_reply(b"reply body").await.unwrap();
        writer.write_frame(MsgType::Record, b"record one").await.unwrap();

        let (h1, b1) = reader.read_frame().await.unwrap();
        assert!(matches!(h1, FrameHeader::Initiation { protocol_version: 39, .. }));
        assert_eq!(b1, b"init body");

        let (h2, b2) = reader.read_frame().await.unwrap();
        assert!(matches!(
            h2,
            FrameHeader::Regular { msg_type: MsgType::Reply, .. }
        ));
        assert_eq!(b2, b"reply body");

        let (h3, b3) = reader.read_frame().await.unwrap();
        assert!(matches!(
            h3,
            FrameHeader::Regular { msg_type: MsgType::Record, .. }
        ));
        assert_eq!(b3, b"record one");
    }

    /// Bogus msg-type byte → InvalidData.
    #[tokio::test]
    async fn rejects_unknown_msg_type() {
        let (mut a, b) = duplex(64);
        a.write_all(&[7, 0, 0]).await.unwrap();
        let mut reader = Framed::new(b);
        let err = reader.read_frame().await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// Drive a paired snow IK round-trip into `into_transport()` and
    /// prove encrypted bytes round-trip through both directions.
    #[tokio::test]
    async fn noise_stream_round_trip() {
        use crate::tailscale_wire::ServerNoiseKey;
        use std::sync::Arc;
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let server = Arc::new(ServerNoiseKey::load_or_generate(dir.path()).unwrap());
        let server_pub = server.public_bytes();

        // Run the IK handshake in-process to recover paired
        // TransportState halves.
        let mut init = server.build_initiator(&server_pub).unwrap();
        let mut resp = server.build_responder().unwrap();
        let mut buf1 = [0u8; 1024];
        let n1 = init.write_message(b"", &mut buf1).unwrap();
        let mut throw = [0u8; 1024];
        resp.read_message(&buf1[..n1], &mut throw).unwrap();
        let mut buf2 = [0u8; 1024];
        let n2 = resp.write_message(b"", &mut buf2).unwrap();
        init.read_message(&buf2[..n2], &mut throw).unwrap();
        let init_t = init.into_transport_mode().unwrap();
        let resp_t = resp.into_transport_mode().unwrap();

        // Pair the two transport halves over a tokio duplex pipe.
        let (a, b) = duplex(64 * 1024);
        let mut client = Framed::new(a).into_transport(init_t);
        let mut serverside = Framed::new(b).into_transport(resp_t);

        // Client → server.
        client.write_all(b"hello from client").await.unwrap();
        client.flush().await.unwrap();
        let mut got = [0u8; 17];
        serverside.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hello from client");

        // Server → client.
        serverside.write_all(b"hello back!").await.unwrap();
        serverside.flush().await.unwrap();
        let mut got2 = [0u8; 11];
        client.read_exact(&mut got2).await.unwrap();
        assert_eq!(&got2, b"hello back!");

        // Drain a second record.
        client.write_all(b"second record").await.unwrap();
        client.flush().await.unwrap();
        let mut got3 = [0u8; 13];
        serverside.read_exact(&mut got3).await.unwrap();
        assert_eq!(&got3, b"second record");
    }

    /// A larger-than-MAX_PLAINTEXT_PER_RECORD payload triggers more
    /// than one Record frame on the wire but round-trips cleanly.
    #[tokio::test]
    async fn noise_stream_chunks_large_writes() {
        use crate::tailscale_wire::ServerNoiseKey;
        use std::sync::Arc;
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let server = Arc::new(ServerNoiseKey::load_or_generate(dir.path()).unwrap());
        let server_pub = server.public_bytes();

        let mut init = server.build_initiator(&server_pub).unwrap();
        let mut resp = server.build_responder().unwrap();
        let mut buf1 = [0u8; 1024];
        let n1 = init.write_message(b"", &mut buf1).unwrap();
        let mut throw = [0u8; 1024];
        resp.read_message(&buf1[..n1], &mut throw).unwrap();
        let mut buf2 = [0u8; 1024];
        let n2 = resp.write_message(b"", &mut buf2).unwrap();
        init.read_message(&buf2[..n2], &mut throw).unwrap();
        let init_t = init.into_transport_mode().unwrap();
        let resp_t = resp.into_transport_mode().unwrap();

        // Pipe must hold > 2× MAX_PLAINTEXT_PER_RECORD to avoid
        // half-record stalls in the single-threaded test.
        let pipe_bytes = (MAX_PLAINTEXT_PER_RECORD * 3) + 64 * 1024;
        let (a, b) = duplex(pipe_bytes);
        let mut client = Framed::new(a).into_transport(init_t);
        let mut serverside = Framed::new(b).into_transport(resp_t);

        let payload_len = MAX_PLAINTEXT_PER_RECORD + 1024;
        let payload: Vec<u8> = (0..payload_len).map(|i| (i % 251) as u8).collect();

        let payload_clone = payload.clone();
        let writer = tokio::spawn(async move {
            client.write_all(&payload_clone).await.unwrap();
            client.flush().await.unwrap();
        });

        let mut out = vec![0u8; payload_len];
        serverside.read_exact(&mut out).await.unwrap();
        writer.await.unwrap();
        assert_eq!(out, payload);
    }
}
