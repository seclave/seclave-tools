# seclave

The Seclave hardware password manager's USB-slave wire protocol, as a
Python library: framing and parsing, serial transports for
Linux/macOS/Windows, and a session class with one method per device
command.

A Seclave 2 in its "Usb slave" menu exposes a CDC-ACM serial port. The host
sends length-framed commands; the device answers with unframed responses,
and the user approves each secret read on the device's own screen - that
confirmation, not host software, is the security boundary.

Standard library only; no dependencies.

## Usage

```python
import seclave

path = seclave.find_port()                 # by USB VID/PID, or pass a path
transport = seclave.open_serial(path)
transport.open()
session = seclave.DeviceSession(transport)

for label in session.list_labels():        # one confirmation on the device
    print(label)

secret = session.get_password("gmail")     # confirmed on the device
try:
    print(secret.text())
finally:
    secret.clear()                         # zero the mmap pages

transport.close()
```

Secrets are returned as `SecretBuffer` objects backed by anonymous mmap
pages the library zeroes on `.clear()`; response bytes are parsed in place
in an mmap arena that is wiped after every command, so secret bytes never
sit in an intermediate Python `bytes`. Blocking calls raise `Cancelled`
when interrupted with `transport.wake()`, `Disconnected` when the port goes
away, and `DeviceError` for a device-reported failure.

`seclave.testing` is a stub device speaking the protocol over a
pseudo-terminal, for tests and development without hardware
(`python3 -m seclave.testing` prints a port path to point any client at).
`seclave.udev` carries the Linux udev rule for the device (ModemManager
ignore, user access, `/dev/seclave`) and installs it; `seclave-ctl udev
install` is the command-line face of it.

## Relation to the other Seclave tools

- [seclave-companion](https://github.com/seclave/seclave-companion) is the
  desktop GUI. It deliberately does **not** depend on this library - it
  stays a single self-contained file - but its protocol layer and this
  library are the same code, held together by the conformance vectors in
  the [seclave-tools](https://github.com/seclave/seclave-tools) repo.
- `seclave-ctl` is the command-line client built on this library.
- A Rust `seclave` crate implements the same protocol, verified against the
  same vectors.

## License

MIT - see [LICENSE](LICENSE).

Seclave is a trademark of Seclave AB. This license grants no trademark rights.
