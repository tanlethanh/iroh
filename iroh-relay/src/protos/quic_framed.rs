//! QUIC stream framing layer for the relay protocol.
//!
//! Provides [`QuicBytesFramed`], a length-prefixed framing layer over QUIC bidirectional
//! streams. This replaces `WsBytesFramed` (WebSocket framing) for QUIC relay transport,
//! eliminating TCP delayed ACK, Nagle, WebSocket overhead, and TLS record layer.
//!
//! Frame format: `[varint length][relay frame bytes...]`

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, Bytes, BytesMut};
use n0_future::{Sink, Stream};

use super::streams::StreamError;
use crate::ExportKeyingMaterial;

/// Maximum frame size (same as WebSocket: 1 MB).
const MAX_QUIC_FRAME_SIZE: usize = 1024 * 1024;

/// Error type for QUIC framing operations.
#[derive(Debug)]
pub enum QuicFramedError {
    /// IO error from QUIC stream read/write.
    Io(std::io::Error),
    /// Frame too large.
    FrameTooLarge(usize),
    /// Stream finished with partial frame data remaining.
    StreamFinished,
}

impl std::fmt::Display for QuicFramedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "QUIC IO error: {e}"),
            Self::FrameTooLarge(size) => {
                write!(f, "frame too large: {size} bytes (max {MAX_QUIC_FRAME_SIZE})")
            }
            Self::StreamFinished => write!(f, "stream finished with partial frame"),
        }
    }
}

impl std::error::Error for QuicFramedError {}

impl From<std::io::Error> for QuicFramedError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

// Convert QuicFramedError into StreamError (tokio_websockets::Error) for compatibility
// with the RelayedStream<S> bounds. We wrap it as an IO error.
impl From<QuicFramedError> for StreamError {
    fn from(e: QuicFramedError) -> Self {
        tokio_websockets::Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
    }
}

/// Length-prefixed framing over a QUIC bidirectional stream.
///
/// Implements `Stream<Item = Result<Bytes, StreamError>>` and `Sink<Bytes, Error = StreamError>`
/// so it can be used as a drop-in replacement for `WsBytesFramed` inside `RelayedStream<S>`.
///
/// The `Connection` handle is stored here to prevent it from being dropped — dropping a
/// `noq::Connection` sends a QUIC close frame and tears down all streams.
#[derive(Debug)]
pub struct QuicBytesFramed {
    /// Keep the connection alive for the lifetime of the framed streams.
    _connection: noq::Connection,
    send: noq::SendStream,
    recv: noq::RecvStream,
    /// Read buffer for accumulating partial frames.
    read_buf: BytesMut,
    /// Current frame's expected length (None = reading header).
    pending_frame_len: Option<usize>,
    /// Write buffer for outgoing frames.
    write_buf: BytesMut,
    /// Whether the stream has been finished (EOF).
    finished: bool,
}

impl QuicBytesFramed {
    /// Create a new `QuicBytesFramed` from a QUIC connection and its bidirectional stream pair.
    ///
    /// The connection is stored internally to prevent it from being dropped (which would close
    /// all streams and terminate the relay session).
    pub fn new(connection: noq::Connection, send: noq::SendStream, recv: noq::RecvStream) -> Self {
        Self {
            _connection: connection,
            send,
            recv,
            read_buf: BytesMut::with_capacity(8192),
            pending_frame_len: None,
            write_buf: BytesMut::with_capacity(8192),
            finished: false,
        }
    }
}

/// Encode a length as a varint (same encoding as QUIC VarInt / relay FrameType).
///
/// Returns the number of bytes written.
fn encode_varint(buf: &mut BytesMut, value: u64) {
    if value < 0x40 {
        buf.extend_from_slice(&[value as u8]);
    } else if value < 0x4000 {
        buf.extend_from_slice(&[(0x40 | (value >> 8)) as u8, value as u8]);
    } else if value < 0x4000_0000 {
        let mut b = [0u8; 4];
        b[0] = 0x80 | (value >> 24) as u8;
        b[1] = (value >> 16) as u8;
        b[2] = (value >> 8) as u8;
        b[3] = value as u8;
        buf.extend_from_slice(&b);
    } else {
        let mut b = [0u8; 8];
        b[0] = 0xc0 | (value >> 56) as u8;
        b[1] = (value >> 48) as u8;
        b[2] = (value >> 40) as u8;
        b[3] = (value >> 32) as u8;
        b[4] = (value >> 24) as u8;
        b[5] = (value >> 16) as u8;
        b[6] = (value >> 8) as u8;
        b[7] = value as u8;
        buf.extend_from_slice(&b);
    }
}

/// Try to decode a varint from the buffer. Returns `Ok(Some((value, consumed)))` if
/// successful, `Ok(None)` if not enough data, `Err` if invalid.
fn decode_varint(buf: &[u8]) -> Result<Option<(u64, usize)>, QuicFramedError> {
    if buf.is_empty() {
        return Ok(None);
    }
    let first = buf[0];
    let (len, mask) = match first >> 6 {
        0 => (1, 0x3f),
        1 => (2, 0x3f),
        2 => (4, 0x3f),
        3 => (8, 0x3f),
        _ => unreachable!(),
    };
    if buf.len() < len {
        return Ok(None);
    }
    let mut value = (first & mask) as u64;
    for &byte in &buf[1..len] {
        value = (value << 8) | byte as u64;
    }
    Ok(Some((value, len)))
}

// QUIC relay transport does not use TLS keying material export for authentication.
// The handshake falls back to challenge-based auth when export_keying_material returns None.
impl ExportKeyingMaterial for QuicBytesFramed {
    fn export_keying_material<T: AsMut<[u8]>>(
        &self,
        _output: T,
        _label: &[u8],
        _context: Option<&[u8]>,
    ) -> Option<T> {
        None
    }
}

impl Stream for QuicBytesFramed {
    type Item = Result<Bytes, StreamError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        if this.finished {
            return Poll::Ready(None);
        }

        loop {
            // Step 1: Try to parse the frame length from the buffer.
            if this.pending_frame_len.is_none() {
                match decode_varint(&this.read_buf) {
                    Ok(Some((len, consumed))) => {
                        let len = len as usize;
                        if len > MAX_QUIC_FRAME_SIZE {
                            return Poll::Ready(Some(Err(
                                QuicFramedError::FrameTooLarge(len).into()
                            )));
                        }
                        this.read_buf.advance(consumed);
                        this.pending_frame_len = Some(len);
                    }
                    Ok(None) => {
                        // Need more data for the varint header.
                    }
                    Err(e) => return Poll::Ready(Some(Err(e.into()))),
                }
            }

            // Step 2: If we know the frame length, check if we have enough data.
            if let Some(frame_len) = this.pending_frame_len {
                if this.read_buf.len() >= frame_len {
                    let frame = this.read_buf.split_to(frame_len).freeze();
                    this.pending_frame_len = None;
                    return Poll::Ready(Some(Ok(frame)));
                }
            }

            // Step 3: Read more data from the QUIC stream.
            let mut tmp = [0u8; 8192];
            match this.recv.poll_read(cx, &mut tmp) {
                Poll::Ready(Ok(n)) => {
                    if n == 0 {
                        this.finished = true;
                        if this.read_buf.is_empty() {
                            return Poll::Ready(None);
                        } else {
                            return Poll::Ready(Some(Err(
                                QuicFramedError::StreamFinished.into()
                            )));
                        }
                    }
                    this.read_buf.extend_from_slice(&tmp[..n]);
                    // Loop back to try parsing again.
                }
                Poll::Ready(Err(e)) => {
                    return Poll::Ready(Some(Err(QuicFramedError::Io(e.into()).into())));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl Sink<Bytes> for QuicBytesFramed {
    type Error = StreamError;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // QUIC streams are always ready to accept writes (buffered internally).
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        let this = self.get_mut();
        let len = item.len();
        if len > MAX_QUIC_FRAME_SIZE {
            return Err(QuicFramedError::FrameTooLarge(len).into());
        }
        // Encode: varint length prefix + payload
        this.write_buf.clear();
        encode_varint(&mut this.write_buf, len as u64);
        this.write_buf.extend_from_slice(&item);
        // Write the entire frame to the QUIC send stream.
        // quinn::SendStream::write_all is sync in the sense that it buffers,
        // but we need to use the async path. Buffer it and flush in poll_flush.
        // Actually, quinn SendStream::write() is async. We need to buffer here
        // and write in poll_flush. But Sink::start_send is sync.
        // So we accumulate in write_buf and flush writes in poll_flush.
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        while !this.write_buf.is_empty() {
            match Pin::new(&mut this.send).poll_write(cx, &this.write_buf) {
                Poll::Ready(Ok(n)) => {
                    this.write_buf.advance(n);
                }
                Poll::Ready(Err(e)) => {
                    let io_err: std::io::Error = e.into();
                    return Poll::Ready(Err(QuicFramedError::Io(io_err).into()));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        // Flush remaining data first.
        while !this.write_buf.is_empty() {
            match Pin::new(&mut this.send).poll_write(cx, &this.write_buf) {
                Poll::Ready(Ok(n)) => {
                    this.write_buf.advance(n);
                }
                Poll::Ready(Err(e)) => {
                    let io_err: std::io::Error = e.into();
                    return Poll::Ready(Err(QuicFramedError::Io(io_err).into()));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        // Finish the send stream.
        _ = this.send.finish();
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_roundtrip() {
        for &value in &[0u64, 1, 63, 64, 16383, 16384, 1073741823, 1073741824] {
            let mut buf = BytesMut::new();
            encode_varint(&mut buf, value);
            let (decoded, consumed) = decode_varint(&buf).unwrap().unwrap();
            assert_eq!(decoded, value);
            assert_eq!(consumed, buf.len());
        }
    }
}
