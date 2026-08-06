// SPDX-License-Identifier: MIT
// Copyright 2026 Seclave AB

//! The Seclave hardware password manager's USB-slave wire protocol.
//!
//! A Seclave 2 in its "Usb slave" menu exposes a CDC-ACM serial port. The
//! host sends commands wrapped in a 2-byte little-endian length frame; the
//! device answers with *unframed* responses, so a client parses the reply
//! incrementally against the field count the in-flight command expects
//! ([`parse_response`] returns `None` until enough bytes have arrived).
//! Integers and length-prefixed fields share one variable-length encoding:
//! a value below 254 is a single byte, anything larger is `0xFF`, a length
//! byte (1 or 2), and that many little-endian value bytes. Text fields are
//! Latin-1. The user approves each secret read on the device's own screen -
//! that confirmation, not host software, is the security boundary.
//!
//! This first release covers the wire format: constants, integer/field
//! encoding, framing, and response parsing. Serial transport and a session
//! layer follow in later releases; the Python `seclave` package already
//! ships them, and both
//! implementations are held byte-identical by the conformance vectors in the
//! [seclave-tools](https://github.com/seclave/seclave-tools) repo (the
//! Python implementation, validated against real hardware, generates them).
//!
//! ```
//! use seclave::{build_frame, parse_response, encode_field, OP_GET_PASSWORD, ST_OK};
//!
//! // Command: get the password for the entry labelled "gmail".
//! let mut payload = vec![OP_GET_PASSWORD];
//! payload.extend_from_slice(&encode_field(b"gmail"));
//! let frame = build_frame(&payload).unwrap();
//! assert_eq!(frame[..2], (frame.len() as u16 - 2).to_le_bytes());
//!
//! // Response: status byte, then one length-prefixed field.
//! let reply = [&[ST_OK] as &[u8], &encode_field(b"hunter2")].concat();
//! let parsed = parse_response(&reply, 1).unwrap().unwrap();
//! let (start, end) = parsed.fields[0];
//! assert_eq!(&reply[start..end], b"hunter2");
//! ```

#![forbid(unsafe_code)]

use std::fmt;

/// USB vendor ID of the Seclave device.
pub const USB_VID: u16 = 0x20A0;
/// USB product ID of the Seclave device.
pub const USB_PID: u16 = 0x41E3;

// Opcodes (first payload byte).
pub const OP_GET_GROUP: u8 = 1;
pub const OP_GET_USERNAME: u8 = 2;
pub const OP_GET_PASSWORD: u8 = 3;
pub const OP_GET_OPTIONAL: u8 = 4;
pub const OP_GET_WWWFILL: u8 = 5;
pub const OP_GET_LABELIDX: u8 = 6;
pub const OP_GET_WWWFILLIDX: u8 = 7;
pub const OP_PUT_WWWFILL: u8 = 8;
pub const OP_PUT_ENTRY: u8 = 9;
pub const OP_DEL_ENTRY: u8 = 10;
pub const OP_DEL_WWWFILL: u8 = 11;
pub const OP_GET_BACKUP: u8 = 12;

// Response status codes.
pub const ST_OK: u8 = 0;
pub const ST_ENTRY_NOT_FOUND: u8 = 1;
/// Never seen on the wire in practice - the port vanishes instead.
pub const ST_PARSE_ERROR: u8 = 2;
/// The user declined the command on the device.
pub const ST_ABORT: u8 = 3;
/// Enumeration terminator, not an error.
pub const ST_OUT_OF_INDEX: u8 = 4;
pub const ST_LABEL_EXISTS: u8 = 5;
pub const ST_NO_SPACE: u8 = 6;
pub const ST_BAD_LABEL: u8 = 7;
pub const ST_BAD_DOMAIN: u8 = 8;
/// GET_WWWFILL: success, and more logins exist for this domain.
pub const ST_MORE_LABELS: u8 = 9;

// Field maxima (bytes on the wire, Latin-1).
pub const MAX_LABEL: usize = 16;
pub const MAX_GROUP: usize = 8;
pub const MAX_USERNAME: usize = 50;
pub const MAX_PASSWORD: usize = 50;
pub const MAX_OPTIONAL: usize = 83;
pub const MAX_ENTRIES: usize = 500;

/// Outer frame payload bound. A 0-length or oversized frame silently drops
/// the device out of slave mode, so [`build_frame`] refuses to build one.
pub const MAX_FRAME_PAYLOAD: usize = 228;

/// Why a decode could not complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// Not enough bytes accumulated yet; read more and retry. Responses are
    /// unframed, so this is the normal mid-response state, not a fault.
    NeedMore,
    /// The escape form carried a length byte other than 1 or 2. The stream
    /// is unframeable from here; treat the connection as lost.
    BadEscapeLength(u8),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::NeedMore => write!(f, "need more bytes"),
            DecodeError::BadEscapeLength(n) => {
                write!(f, "bad integer escape length {n}")
            }
        }
    }
}

impl std::error::Error for DecodeError {}

/// Encode an integer in the protocol's variable-length form.
pub fn encode_int(value: u16) -> Vec<u8> {
    if value < 254 {
        vec![value as u8]
    } else if value <= 0xFF {
        vec![0xFF, 1, value as u8]
    } else {
        let bytes = value.to_le_bytes();
        vec![0xFF, 2, bytes[0], bytes[1]]
    }
}

/// Encode a length-prefixed field.
///
/// Protocol fields are at most [`MAX_OPTIONAL`] bytes; a slice longer than
/// an u16 cannot be a field at all, so that is treated as a caller bug.
pub fn encode_field(data: &[u8]) -> Vec<u8> {
    assert!(
        data.len() <= u16::MAX as usize,
        "field of {} bytes cannot exist in this protocol",
        data.len()
    );
    let mut out = encode_int(data.len() as u16);
    out.extend_from_slice(data);
    out
}

/// Decode an integer at `off`. Returns the value and the offset just past it.
pub fn decode_int(buf: &[u8], off: usize) -> Result<(u16, usize), DecodeError> {
    let first = *buf.get(off).ok_or(DecodeError::NeedMore)?;
    if first != 0xFF {
        return Ok((first as u16, off + 1));
    }
    let nbytes = *buf.get(off + 1).ok_or(DecodeError::NeedMore)?;
    if nbytes != 1 && nbytes != 2 {
        return Err(DecodeError::BadEscapeLength(nbytes));
    }
    let end = off + 2 + nbytes as usize;
    if end > buf.len() {
        return Err(DecodeError::NeedMore);
    }
    let mut value: u16 = 0;
    for (i, byte) in buf[off + 2..end].iter().enumerate() {
        value |= (*byte as u16) << (8 * i);
    }
    Ok((value, end))
}

/// Decode a length-prefixed field at `off` without copying it: returns the
/// `(start, end)` span of the field's bytes and the offset just past it.
pub fn decode_field_span(buf: &[u8], off: usize) -> Result<((usize, usize), usize), DecodeError> {
    let (length, off) = decode_int(buf, off)?;
    let end = off + length as usize;
    if end > buf.len() {
        return Err(DecodeError::NeedMore);
    }
    Ok(((off, end), end))
}

/// Wrap a command payload in the outer 2-byte little-endian length frame.
///
/// Refuses an empty or oversized payload: sending one silently drops the
/// device out of slave mode, so a violation here is a client bug to surface,
/// not a wire condition to tolerate.
pub fn build_frame(payload: &[u8]) -> Result<Vec<u8>, FrameError> {
    if payload.is_empty() || payload.len() > MAX_FRAME_PAYLOAD {
        return Err(FrameError::PayloadOutOfRange(payload.len()));
    }
    let mut out = Vec::with_capacity(2 + payload.len());
    out.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// The payload handed to [`build_frame`] was empty or oversized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    PayloadOutOfRange(usize),
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let FrameError::PayloadOutOfRange(len) = self;
        write!(f, "frame payload out of range: {len} bytes")
    }
}

impl std::error::Error for FrameError {}

/// A parsed device response: the status code and the `(start, end)` spans of
/// its fields within the buffer it was parsed from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub fields: Vec<(usize, usize)>,
}

/// Try to parse a complete response from `buf`.
///
/// Returns `Ok(None)` while more bytes are still needed (responses are
/// unframed, so accumulate and retry), `Ok(Some(response))` once complete.
/// A status other than [`ST_OK`] / [`ST_MORE_LABELS`] carries no fields.
/// [`DecodeError::BadEscapeLength`] means the stream is unframeable.
pub fn parse_response(buf: &[u8], field_count: usize) -> Result<Option<Response>, DecodeError> {
    let (status, mut off) = match decode_int(buf, 0) {
        Ok(decoded) => decoded,
        Err(DecodeError::NeedMore) => return Ok(None),
        Err(err) => return Err(err),
    };
    if status != ST_OK as u16 && status != ST_MORE_LABELS as u16 {
        return Ok(Some(Response {
            status,
            fields: Vec::new(),
        }));
    }
    let mut fields = Vec::with_capacity(field_count);
    for _ in 0..field_count {
        match decode_field_span(buf, off) {
            Ok((span, next)) => {
                fields.push(span);
                off = next;
            }
            Err(DecodeError::NeedMore) => return Ok(None),
            Err(err) => return Err(err),
        }
    }
    Ok(Some(Response { status, fields }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn int_roundtrip_across_escape_boundary() {
        for value in [0u16, 1, 253, 254, 255, 256, 1000, u16::MAX] {
            let encoded = encode_int(value);
            assert_eq!(decode_int(&encoded, 0), Ok((value, encoded.len())));
        }
    }

    #[test]
    fn int_decode_incomplete_asks_for_more() {
        for raw in [&[][..], &[0xFF], &[0xFF, 2, 0x34]] {
            assert_eq!(decode_int(raw, 0), Err(DecodeError::NeedMore));
        }
    }

    #[test]
    fn int_decode_rejects_bad_escape() {
        assert_eq!(
            decode_int(&[0xFF, 3, 0, 0, 0], 0),
            Err(DecodeError::BadEscapeLength(3))
        );
    }

    #[test]
    fn field_span_points_into_buffer() {
        let encoded = encode_field(b"gmail");
        let ((start, end), next) = decode_field_span(&encoded, 0).unwrap();
        assert_eq!(&encoded[start..end], b"gmail");
        assert_eq!(next, encoded.len());
    }

    #[test]
    fn frame_bounds_are_enforced() {
        assert!(build_frame(&[]).is_err());
        assert!(build_frame(&[0u8; MAX_FRAME_PAYLOAD + 1]).is_err());
        let frame = build_frame(&[0u8; MAX_FRAME_PAYLOAD]).unwrap();
        assert_eq!(frame.len(), MAX_FRAME_PAYLOAD + 2);
    }

    #[test]
    fn error_status_carries_no_fields() {
        let parsed = parse_response(&[ST_ABORT], 2).unwrap().unwrap();
        assert_eq!(parsed.status, ST_ABORT as u16);
        assert!(parsed.fields.is_empty());
    }

    #[test]
    fn partial_response_is_not_an_error() {
        let mut reply = vec![ST_OK];
        reply.extend_from_slice(&encode_field(b"alice"));
        for cut in 0..reply.len() {
            assert_eq!(parse_response(&reply[..cut], 1), Ok(None));
        }
        assert!(parse_response(&reply, 1).unwrap().is_some());
    }
}
