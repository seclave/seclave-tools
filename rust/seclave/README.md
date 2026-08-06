# seclave

The Seclave hardware password manager's USB-slave wire protocol, in Rust.

A Seclave 2 in its "Usb slave" menu exposes a CDC-ACM serial port. The host
sends commands wrapped in a 2-byte little-endian length frame; the device
answers with unframed responses, so a client parses the reply incrementally
(`parse_response` returns `None` until enough bytes have arrived). The user
approves each secret read on the device's own screen - that confirmation,
not host software, is the security boundary.

This first release covers the wire format: protocol constants,
integer/field encoding, command framing, and response parsing. Serial
transport and a session layer follow in later releases; the Python
[`seclave`](https://pypi.org/project/seclave/) package already ships them.
Both implementations live in the
[seclave-tools](https://github.com/seclave/seclave-tools) repo and are held
byte-identical by shared conformance vectors generated from the Python
implementation, which is validated against real hardware.

```rust
use seclave::{build_frame, parse_response, encode_field, OP_GET_PASSWORD, ST_OK};

// Command: get the password for the entry labelled "gmail".
let mut payload = vec![OP_GET_PASSWORD];
payload.extend_from_slice(&encode_field(b"gmail"));
let frame = build_frame(&payload).unwrap();

// Response: status byte, then one length-prefixed Latin-1 field.
let reply = [&[ST_OK] as &[u8], &encode_field(b"hunter2")].concat();
let parsed = parse_response(&reply, 1).unwrap().unwrap();
let (start, end) = parsed.fields[0];
assert_eq!(&reply[start..end], b"hunter2");
```

No dependencies.

## License

MIT.

Seclave is a trademark of Seclave AB. This license grants no trademark rights.
