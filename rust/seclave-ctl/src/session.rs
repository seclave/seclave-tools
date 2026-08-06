// SPDX-License-Identifier: MIT
// Copyright 2026 Seclave AB

//! Serial transport and device session, ported from the Python `seclave`
//! library (the hardware-validated reference). One method per protocol
//! command; blocking reads poll on a short timeout so a command can wait
//! indefinitely for the on-device confirmation.
//!
//! Memory hygiene mirrors the Python library's documented posture: every
//! buffer that can hold secret bytes (command payloads, the outgoing frame,
//! the receive buffer, extracted fields) is wrapped in [`Zeroizing`], so it
//! is wiped on every exit path - early returns, `?`, panics - not just the
//! happy one. The receive buffer is pre-allocated to its limit so growth
//! can never reallocate and strand a partial copy in freed heap. The copies
//! we cannot control are the kernel's tty buffer and stdout, where a CLI
//! prints secrets by design; the device's on-screen confirmation, not host
//! memory hygiene, is what actually protects secrets.

use std::fmt;
use std::io::{Read, Write};
use std::time::Duration;

use seclave::{
    build_frame, encode_int, parse_response, DecodeError, ST_ABORT, ST_MORE_LABELS, ST_OK,
    ST_OUT_OF_INDEX, USB_PID, USB_VID,
};
use zeroize::Zeroizing;

/// Secret bytes off the wire: wiped when dropped, on every exit path.
pub type Secret = Zeroizing<Vec<u8>>;

/// How long a single blocked read waits before reporting "nothing yet"; the
/// receive loop repeats it, so this only bounds how fast Ctrl-C style exits
/// can take effect.
const RECV_POLL: Duration = Duration::from_millis(250);

/// One response is at most a status byte and a handful of short fields; a
/// buffer this full means the stream is unframeable. Also the receive
/// buffer's fixed pre-allocation.
const RECV_LIMIT: usize = 4096;

#[derive(Debug)]
pub enum CtlError {
    /// The user declined the command on the device (ST_ABORT).
    Declined,
    /// Any other non-OK status from the device.
    Device(u16),
    /// The port went away, or the stream became unframeable.
    Disconnected(String),
    /// Input refused before sending (validation or encoding).
    BadInput(String),
}

impl fmt::Display for CtlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CtlError::Declined => write!(f, "declined on the device"),
            CtlError::Device(status) => write!(f, "{}", status_message(*status)),
            CtlError::Disconnected(why) => {
                write!(f, "the device went away ({why})")
            }
            CtlError::BadInput(why) => write!(f, "{why}"),
        }
    }
}

fn status_message(status: u16) -> String {
    match status as u8 {
        seclave::ST_ENTRY_NOT_FOUND => "the entry was not found on the device".into(),
        seclave::ST_LABEL_EXISTS => "an entry with that label already exists".into(),
        seclave::ST_NO_SPACE => "the device is full (500 entries)".into(),
        seclave::ST_BAD_LABEL => "the label or group has invalid characters or length".into(),
        seclave::ST_BAD_DOMAIN => "the domain has invalid characters or length".into(),
        other => format!("device error {other}"),
    }
}

/// Encode text as Latin-1, the device's charset.
pub fn latin1(text: &str) -> Result<Zeroizing<Vec<u8>>, CtlError> {
    text.chars()
        .map(|c| {
            u8::try_from(c as u32).map_err(|_| {
                CtlError::BadInput(format!(
                    "only Latin-1 characters are allowed \
                     ({c:?} is not)"
                ))
            })
        })
        .collect::<Result<Vec<u8>, CtlError>>()
        .map(Zeroizing::new)
}

/// Decode Latin-1 bytes (the first 256 Unicode code points, so lossless).
pub fn latin1_str(bytes: &[u8]) -> String {
    bytes.iter().map(|b| *b as char).collect()
}

/// Lowercase a domain byte exactly as the device does: ASCII A-Z plus the
/// six two-case Latin-1 letters its charset permits; every other byte,
/// including 0xDF (sharp s), compares exact.
fn fold_byte(byte: u8) -> u8 {
    match byte {
        b'A'..=b'Z' => byte + 0x20,
        0xC4 => 0xE4, // A-umlaut
        0xC5 => 0xE5, // A-ring
        0xC6 => 0xE6, // AE
        0xD6 => 0xF6, // O-umlaut
        0xD8 => 0xF8, // O-slash
        0xDC => 0xFC, // U-umlaut
        other => other,
    }
}

/// The device's wwwfill uniqueness key: domain under the device's own case
/// fold, username byte-exact.
pub fn wwwfill_key(domain: &str, username: &str) -> Result<(Vec<u8>, String), CtlError> {
    let folded = latin1(domain)?.iter().map(|b| fold_byte(*b)).collect();
    Ok((folded, username.to_string()))
}

/// Reduce a URL to the bare host the device stores.
pub fn normalize_domain(text: &str) -> String {
    let text = text.trim();
    let text = match text.split_once("://") {
        Some((_, rest)) => rest,
        None => text,
    };
    let text = text.split('/').next().unwrap_or("");
    text.split(':').next().unwrap_or("").to_string()
}

/// Start a command payload; push_field() appends its length-prefixed fields.
/// Pre-allocated past the frame bound so appending never reallocates while
/// a secret is in the buffer (an oversized payload errors in build_frame).
fn payload_start(opcode: u8) -> Zeroizing<Vec<u8>> {
    let mut payload = Zeroizing::new(Vec::with_capacity(seclave::MAX_FRAME_PAYLOAD + 64));
    payload.push(opcode);
    payload
}

/// Append one length-prefixed field, without an intermediate unzeroed copy
/// (which is why this exists instead of seclave::encode_field here).
fn push_field(payload: &mut Zeroizing<Vec<u8>>, text: &str) -> Result<(), CtlError> {
    let bytes = latin1(text)?;
    payload.extend_from_slice(&encode_int(bytes.len() as u16));
    payload.extend_from_slice(&bytes);
    Ok(())
}

pub struct Session {
    port: Box<dyn serialport::SerialPort>,
}

impl Session {
    pub fn open(path: &str) -> Result<Session, CtlError> {
        // CDC-ACM ignores line coding; serialport's raw defaults are what
        // matters. The baud number is cosmetic.
        let port = serialport::new(path, 115_200)
            .timeout(RECV_POLL)
            .open()
            .map_err(|e| CtlError::Disconnected(format!("cannot open {path}: {e}")))?;
        Ok(Session { port })
    }

    /// Send one command and read its unframed reply until it parses.
    fn exchange(
        &mut self,
        payload: &[u8],
        field_count: usize,
    ) -> Result<(u16, Vec<Secret>), CtlError> {
        // Flush stale input first: the late response to an interrupted
        // command would otherwise be parsed as this command's reply.
        let _ = self.port.clear(serialport::ClearBuffer::Input);
        let frame =
            Zeroizing::new(build_frame(payload).map_err(|e| CtlError::BadInput(e.to_string()))?);
        self.port
            .write_all(&frame)
            .map_err(|e| CtlError::Disconnected(e.to_string()))?;
        let mut buf = Zeroizing::new(Vec::with_capacity(RECV_LIMIT));
        let mut chunk = Zeroizing::new([0u8; 512]);
        loop {
            match self.port.read(&mut chunk[..]) {
                Ok(0) => return Err(CtlError::Disconnected("EOF".into())),
                Ok(n) => {
                    if buf.len() + n > RECV_LIMIT {
                        // Checked before extending so the buffer never grows
                        // past its pre-allocation (no realloc, no stray copy).
                        return Err(CtlError::Disconnected("unframeable stream".into()));
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {
                    continue; // normally the device waiting for the user
                }
                Err(e) => return Err(CtlError::Disconnected(e.to_string())),
            }
            match parse_response(&buf, field_count) {
                Ok(Some(response)) => {
                    let fields = response
                        .fields
                        .iter()
                        .map(|(start, end)| Zeroizing::new(buf[*start..*end].to_vec()))
                        .collect();
                    return Ok((response.status, fields));
                }
                Ok(None) => {}
                Err(DecodeError::BadEscapeLength(_)) => {
                    return Err(CtlError::Disconnected("unframeable stream".into()));
                }
                Err(DecodeError::NeedMore) => unreachable!("parse_response maps this"),
            }
        }
    }

    /// exchange() with the common status handling: ABORT is a decline, and
    /// anything else non-OK (and not in `also_ok`) is a device error.
    fn command(
        &mut self,
        payload: &[u8],
        field_count: usize,
        also_ok: &[u8],
    ) -> Result<(u16, Vec<Secret>), CtlError> {
        let (status, fields) = self.exchange(payload, field_count)?;
        if status == ST_ABORT as u16 {
            return Err(CtlError::Declined);
        }
        if status != ST_OK as u16 && !also_ok.iter().any(|s| *s as u16 == status) {
            return Err(CtlError::Device(status));
        }
        Ok((status, fields))
    }

    pub fn list_labels(&mut self) -> Result<Vec<String>, CtlError> {
        let mut labels = Vec::new();
        for index in 0.. {
            let mut payload = payload_start(seclave::OP_GET_LABELIDX);
            payload.extend_from_slice(&encode_int(index));
            let (status, fields) = self.command(&payload, 1, &[ST_OUT_OF_INDEX])?;
            if status == ST_OUT_OF_INDEX as u16 {
                return Ok(labels);
            }
            labels.push(latin1_str(&fields[0]));
        }
        unreachable!()
    }

    pub fn list_wwwfill(&mut self) -> Result<Vec<(String, String)>, CtlError> {
        let mut rows = Vec::new();
        for index in 0.. {
            let mut payload = payload_start(seclave::OP_GET_WWWFILLIDX);
            payload.extend_from_slice(&encode_int(index));
            let (status, fields) = self.command(&payload, 2, &[ST_OUT_OF_INDEX])?;
            if status == ST_OUT_OF_INDEX as u16 {
                return Ok(rows);
            }
            rows.push((latin1_str(&fields[0]), latin1_str(&fields[1])));
        }
        unreachable!()
    }

    /// One field of an entry, by label. The device model is the same for all
    /// four fields; secrecy is a client-side presentation concern.
    pub fn get_field(&mut self, opcode: u8, label: &str) -> Result<Secret, CtlError> {
        let mut payload = payload_start(opcode);
        push_field(&mut payload, label)?;
        let (_, mut fields) = self.command(&payload, 1, &[])?;
        Ok(fields.remove(0))
    }

    /// The index-th login on a domain: (username, password, more).
    pub fn get_wwwfill(
        &mut self,
        domain: &str,
        index: u16,
    ) -> Result<(Secret, Secret, bool), CtlError> {
        let mut payload = payload_start(seclave::OP_GET_WWWFILL);
        push_field(&mut payload, domain)?;
        payload.extend_from_slice(&encode_int(index));
        let (status, mut fields) = self.command(&payload, 2, &[ST_MORE_LABELS])?;
        let password = fields.remove(1);
        let username = fields.remove(0);
        Ok((username, password, status == ST_MORE_LABELS as u16))
    }

    pub fn put_entry(
        &mut self,
        label: &str,
        group: &str,
        username: &str,
        password: &str,
        optional: &str,
    ) -> Result<(), CtlError> {
        let mut payload = payload_start(seclave::OP_PUT_ENTRY);
        for text in [label, group, username, password, optional] {
            push_field(&mut payload, text)?;
        }
        self.command(&payload, 0, &[]).map(|_| ())
    }

    pub fn put_wwwfill(
        &mut self,
        domain: &str,
        username: &str,
        password: &str,
    ) -> Result<(), CtlError> {
        let mut payload = payload_start(seclave::OP_PUT_WWWFILL);
        for text in [domain, username, password] {
            push_field(&mut payload, text)?;
        }
        self.command(&payload, 0, &[]).map(|_| ())
    }

    pub fn del_entry(&mut self, label: &str) -> Result<(), CtlError> {
        let mut payload = payload_start(seclave::OP_DEL_ENTRY);
        push_field(&mut payload, label)?;
        self.command(&payload, 0, &[]).map(|_| ())
    }

    pub fn del_wwwfill(&mut self, domain: &str, username: &str) -> Result<(), CtlError> {
        let mut payload = payload_start(seclave::OP_DEL_WWWFILL);
        push_field(&mut payload, domain)?;
        push_field(&mut payload, username)?;
        self.command(&payload, 0, &[]).map(|_| ())
    }
}

/// Find the device's port: the udev-provided stable name first, then USB
/// enumeration by VID/PID.
pub fn find_port() -> Option<String> {
    if cfg!(target_os = "linux") && std::path::Path::new("/dev/seclave").exists() {
        return Some("/dev/seclave".into());
    }
    for info in serialport::available_ports().unwrap_or_default() {
        if let serialport::SerialPortType::UsbPort(usb) = info.port_type {
            if usb.vid == USB_VID && usb.pid == USB_PID {
                return Some(info.port_name);
            }
        }
    }
    None
}

/// Client-side validation for restricted fields (label, group), mirroring
/// the device's charset so an invalid put is refused before it is sent.
pub fn validate_restricted(
    value: &str,
    maxlen: usize,
    what: &str,
    allow_empty: bool,
) -> Result<(), CtlError> {
    if value.is_empty() {
        return if allow_empty {
            Ok(())
        } else {
            Err(CtlError::BadInput(format!("{what}: required")))
        };
    }
    let encoded = latin1(value)?;
    if encoded.len() > maxlen {
        return Err(CtlError::BadInput(format!(
            "{what}: too long (max {maxlen})"
        )));
    }
    const EXTRA: &str =
        "._-\u{E6}\u{C6}\u{E5}\u{C5}\u{E4}\u{C4}\u{F6}\u{D6}\u{F8}\u{D8}\u{FC}\u{DC}\u{DF}";
    for c in value.chars() {
        if !c.is_ascii_alphanumeric() && !EXTRA.contains(c) {
            return Err(CtlError::BadInput(format!(
                "{what}: character {c:?} is not allowed here"
            )));
        }
    }
    Ok(())
}

/// Length/charset validation for free-form fields.
pub fn validate_freeform(value: &str, maxlen: usize, what: &str) -> Result<(), CtlError> {
    let encoded = latin1(value)
        .map_err(|_| CtlError::BadInput(format!("{what}: only Latin-1 characters are allowed")))?;
    if encoded.len() > maxlen {
        return Err(CtlError::BadInput(format!(
            "{what}: too long (max {maxlen})"
        )));
    }
    Ok(())
}
