# SPDX-License-Identifier: MIT
# Copyright 2026 Seclave AB
"""The Seclave USB-slave protocol, for talking to a Seclave 2 hardware
password manager over its CDC-ACM serial interface.

The device stores named credential entries (label, group, username, password,
optional) plus web logins ("wwwfill": domain, username, password). In its
"Usb slave" menu it exposes a serial port; the host sends length-framed
commands and reads unframed responses, and the user approves each secret
read on the device itself. The protocol is documented in the device manual's
USB-slave integration chapter.

Layers, top to bottom - each section of this module depends only on the ones
above it:

    protocol constants     opcodes, status codes, field maxima
    SecretBuffer           zeroizable mmap home for a secret read off the wire
    wire format            integer/field encoding, framing, response parsing
    transports             PosixSerial (termios), WindowsSerial (ctypes),
                           find_port / open_serial discovery
    validation             client-side field rules and the device's own
                           domain case-fold and wwwfill uniqueness semantics
    DeviceSession          one method per protocol command

Quick start:

    import seclave

    path = seclave.find_port()               # or an explicit port path
    transport = seclave.open_serial(path)
    transport.open()
    session = seclave.DeviceSession(transport)
    for label in session.list_labels():      # confirmed once on the device
        print(label)
    secret = session.get_password("gmail")   # confirmed on the device
    try:
        use(secret.text())
    finally:
        secret.clear()
    transport.close()

Secrets come back as SecretBuffer objects (mmap-backed, zeroed by .clear());
everything else is plain str. Blocking calls raise Cancelled when interrupted
via transport.wake(), Disconnected when the port goes away, and DeviceError
for a device-reported failure. seclave.testing provides a stub device speaking
this protocol over a pseudo-terminal, for tests and development without
hardware.

This module logs through the standard logging module (logger "seclave");
enable DEBUG to trace port discovery and serial I/O.
"""

import io
import os
import sys
import glob
import mmap
import struct
import string
import logging

VERSION = "0.1.0"

_log = logging.getLogger("seclave")

# ---------------------------------------------------------------------------
# Protocol constants for the Seclave USB-slave (CDC-ACM serial) interface.
# ---------------------------------------------------------------------------

USB_VID = 0x20A0
USB_PID = 0x41E3

# Opcodes (first payload byte).
OP_GET_GROUP = 1
OP_GET_USERNAME = 2
OP_GET_PASSWORD = 3
OP_GET_OPTIONAL = 4
OP_GET_WWWFILL = 5
OP_GET_LABELIDX = 6
OP_GET_WWWFILLIDX = 7
OP_PUT_WWWFILL = 8
OP_PUT_ENTRY = 9
OP_DEL_ENTRY = 10
OP_DEL_WWWFILL = 11
OP_GET_BACKUP = 12

# Response status codes.
ST_OK = 0
ST_ENTRY_NOT_FOUND = 1
ST_PARSE_ERROR = 2          # never seen on the wire - the port vanishes instead
ST_ABORT = 3                # user declined on the device
ST_OUT_OF_INDEX = 4         # enumeration terminator, not an error
ST_LABEL_EXISTS = 5
ST_NO_SPACE = 6
ST_BAD_LABEL = 7
ST_BAD_DOMAIN = 8
ST_MORE_LABELS = 9          # GET_WWWFILL: success, and more logins for this domain

STATUS_MESSAGE = {
    ST_ENTRY_NOT_FOUND: "The entry was not found on the device.",
    ST_LABEL_EXISTS: "An entry with that label already exists.",
    ST_NO_SPACE: "The device is full (500 entries).",
    ST_BAD_LABEL: "The label or group has invalid characters or length.",
    ST_BAD_DOMAIN: "The domain has invalid characters or length.",
}

# Field maxima (bytes on the wire, Latin-1).
MAX_LABEL = 16
MAX_GROUP = 8
MAX_USERNAME = 50
MAX_PASSWORD = 50
MAX_OPTIONAL = 83
MAX_ENTRIES = 500

# Outer frame payload bound. A 0-length or >228 frame silently drops the device
# out of slave mode, so we never send one - a violation is a client bug.
MAX_FRAME_PAYLOAD = 228

# Size of the mmap arena each transport reads responses into. Device responses
# are small - the largest single field is a 224-byte backup blob - so 4 KiB is
# generous headroom for a whole response.
RECV_ARENA = 4096

# How long a single Windows ReadFile waits before reporting "nothing yet". The
# recv loop repeats it, so this only sets how fast Stop waiting takes effect.
RECV_POLL_MS = 250

WWWFILL_GROUP = "wwwfill"

# Charset the device accepts for label / group / domain (case-insensitive).
LABEL_CHARSET = set(string.ascii_letters + string.digits + "._-" +
                    "æÆåÅäÄöÖøØüÜß")

# Refuse to send a wwwfill write that would duplicate an existing
# (domain, username) pair - domain compared case-insensitively, username
# case-sensitively, matching the device's own uniqueness rule.
#
# Seclave firmware 2.6 and earlier can miss its own duplicate check, store the
# second copy, and later stop responding when such a pair is edited on the
# device. Every device in the field today runs an affected firmware, so this
# safeguard defaults ON. Relax it (set False) only for a device confirmed to
# run a firmware release later than 2.6, where the device refuses duplicates
# correctly and this client-side check becomes redundant and over-strict. The
# protocol exposes no firmware version today, so there is nothing to detect
# automatically.
ENFORCE_WWWFILL_DEDUP = True

# ---------------------------------------------------------------------------
# SecretBuffer - a mutable, zeroizable home for a secret read off the wire.
# ---------------------------------------------------------------------------

class SecretBuffer:
    """Holds one secret's bytes in an anonymous mmap so we can overwrite them
    with zeros the instant we're done.

    A secret is read off the serial port straight into the transport's mmap arena
    (never into an intermediate `bytes`), then copied here mmap-to-mmap so it can
    outlive the arena, which is wiped after each command. Both live only in mmap
    pages we explicitly zero. The two copies we cannot control are the kernel's
    tty receive buffer, and the transient `str` created at the moment we display
    the value or place it on the clipboard (which the windowing/clipboard system
    may then retain). We do not lock pages into RAM: the real security boundary is
    the user confirming each read on the device, not host memory hygiene.

    `source` is any bytes-like object - typically a memoryview slice of the arena,
    which copies no intermediate bytes.
    """

    def __init__(self, source):
        self._length = len(source)
        # mmap needs at least one byte; an empty secret still gets a real map.
        self._map = mmap.mmap(-1, max(self._length, 1))
        if self._length:
            self._map[:self._length] = source

    def text(self):
        return bytes(self._map[:self._length]).decode("latin-1")

    def clear(self):
        self._map[:] = b"\x00" * len(self._map)

    def __len__(self):
        return self._length


# ---------------------------------------------------------------------------
# Wire format. Integers and length-prefixed fields share one variable-length
# encoding. Commands the host sends are wrapped in a 2-byte little-endian length
# prefix; responses from the device are NOT length-framed, so we parse them
# incrementally against the field count the in-flight command expects.
# ---------------------------------------------------------------------------

class NeedMore(Exception):
    """Not enough bytes accumulated yet to finish parsing a response."""


def encode_int(value):
    if value < 254:
        return bytes([value])
    nbytes = 1 if value <= 0xFF else 2
    return bytes([0xFF, nbytes]) + value.to_bytes(nbytes, "little")


def encode_field(data):
    return encode_int(len(data)) + data


def decode_int(buf, off):
    if off >= len(buf):
        raise NeedMore
    first = buf[off]
    if first != 0xFF:
        return first, off + 1
    if off + 1 >= len(buf):
        raise NeedMore
    nbytes = buf[off + 1]
    if nbytes not in (1, 2):
        raise ValueError(f"bad integer escape length {nbytes}")
    end = off + 2 + nbytes
    if end > len(buf):
        raise NeedMore
    return int.from_bytes(buf[off + 2:end], "little"), end


def decode_field_span(buf, off):
    """Return ((start, end), next_off) for a length-prefixed field, without
    copying - the caller decides whether to make a str or a SecretBuffer."""
    length, off = decode_int(buf, off)
    end = off + length
    if end > len(buf):
        raise NeedMore
    return (off, end), end


def build_frame(payload):
    if not (1 <= len(payload) <= MAX_FRAME_PAYLOAD):
        raise ValueError(f"frame payload out of range: {len(payload)} bytes")
    return struct.pack("<H", len(payload)) + payload


def parse_response(buf, field_count):
    """Try to parse a complete response from `buf`.

    Returns (status, [spans]) once enough bytes are present, or None if more are
    still needed. A status other than OK / MORE_LABELS carries no fields.
    """
    try:
        status, off = decode_int(buf, 0)
        if status not in (ST_OK, ST_MORE_LABELS):
            return status, []
        spans = []
        for _ in range(field_count):
            span, off = decode_field_span(buf, off)
            spans.append(span)
        return status, spans
    except NeedMore:
        return None


def latin1(text):
    return text.encode("latin-1")


# ---------------------------------------------------------------------------
# Serial transport. CDC-ACM is a virtual UART, so configuration reduces to "raw
# mode" - baud is irrelevant. Each transport owns an mmap arena and reads one
# response at a time straight into it (never into an intermediate `bytes`). The
# shared interface is:
#   open(), write(bytes), begin_recv(), recv() -> memoryview, wipe(), wake(),
#   close().
# recv() blocks until at least one byte arrives (the device sends nothing while
# awaiting confirmation) and returns a memoryview of everything received so far;
# the session re-parses that view until the response is complete. wake()
# interrupts a blocked recv() for cancel / shutdown; wipe() zeros the used region
# after each command.
# ---------------------------------------------------------------------------

class Disconnected(Exception):
    """The port went away (user left the menu, unplug, or a framing fault)."""


class Cancelled(Exception):
    """A blocked read was interrupted on purpose (Stop waiting)."""


class _Arena:
    """A fixed anonymous mmap that one device response is read into.

    Bytes land directly in these pages, are parsed in place, and the used region
    is zeroed after every command (or the whole arena on close). This is what
    makes secret bytes wipeable end to end: they never sit in a Python `bytes`
    between the kernel and a SecretBuffer.
    """

    def __init__(self, size):
        self._map = mmap.mmap(-1, size)
        self.fill = 0

    def reset(self):
        self.fill = 0

    def view(self):
        return memoryview(self._map)[:self.fill]

    def tail(self):
        return memoryview(self._map)[self.fill:]

    def advance(self, count):
        self.fill += count

    def is_full(self):
        return self.fill >= len(self._map)

    def wipe(self):
        self._map[:self.fill] = b"\x00" * self.fill
        self.fill = 0

    def wipe_all(self):
        self._map[:] = b"\x00" * len(self._map)
        self.fill = 0

    def snapshot(self):
        return bytes(self._map)   # plain copy of the whole arena, for tests


class PosixSerial:
    def __init__(self, path):
        self.path = path
        self.fd = None
        self._reader = None
        self._wake_r, self._wake_w = os.pipe()
        self.arena = _Arena(RECV_ARENA)

    def open(self):
        import termios
        self.fd = os.open(self.path, os.O_RDWR | os.O_NOCTTY)
        iflag, oflag, cflag, lflag, ispeed, ospeed, cc = termios.tcgetattr(self.fd)
        lflag &= ~(termios.ECHO | termios.ICANON | termios.IEXTEN | termios.ISIG)
        iflag &= ~(termios.BRKINT | termios.ICRNL | termios.INPCK |
                   termios.ISTRIP | termios.IXON)
        oflag &= ~termios.OPOST
        cflag &= ~(termios.CSIZE | termios.PARENB)
        cflag |= termios.CS8
        cc = list(cc)
        cc[termios.VMIN] = 1
        cc[termios.VTIME] = 0
        termios.tcsetattr(self.fd, termios.TCSAFLUSH,
                          [iflag, oflag, cflag, lflag, ispeed, ospeed, cc])
        # readinto() lands bytes directly in the arena; closefd=False keeps the
        # fd ours to close explicitly.
        self._reader = io.FileIO(self.fd, mode="r", closefd=False)
        _log.debug("opened %s", self.path)

    def write(self, data):
        import select
        import termios
        # A command starts here. Drop a "Stop waiting" that arrived after the
        # previous command finished (it would cancel this one spuriously), and
        # flush input, where the late response to a cancelled command would
        # otherwise be parsed as this command's reply (responses are unframed).
        readable, _, _ = select.select([self._wake_r], [], [], 0)
        if readable:
            os.read(self._wake_r, 4096)
        try:
            termios.tcflush(self.fd, termios.TCIFLUSH)
        except termios.error:
            raise Disconnected
        sent = 0
        while sent < len(data):
            try:
                sent += os.write(self.fd, data[sent:])
            except OSError:
                raise Disconnected

    def begin_recv(self):
        self.arena.reset()

    def recv(self):
        import select
        readable, _, _ = select.select([self.fd, self._wake_r], [], [])
        if self._wake_r in readable:
            os.read(self._wake_r, 4096)
            raise Cancelled
        if self.arena.is_full():
            # A well-formed response parses long before this; a full arena means
            # the stream is unframeable, so treat it as a lost connection.
            raise Disconnected
        try:
            count = self._reader.readinto(self.arena.tail())
        except OSError:
            raise Disconnected
        if not count:
            raise Disconnected
        self.arena.advance(count)
        return self.arena.view()

    def wipe(self):
        self.arena.wipe()

    def wake(self):
        os.write(self._wake_w, b"x")

    def close(self):
        self.arena.wipe_all()
        if self._reader is not None:
            self._reader.close()   # closefd=False, so the fd stays open here
            self._reader = None
        if self.fd is not None:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None


class WindowsSerial:
    """Win32 comm port via ctypes. Short read timeouts polled in a loop give the
    infinite blocking read that on-device confirmations require."""

    def __init__(self, path):
        # "\\.\COMx" reaches ports numbered above COM9.
        self.path = path if path.startswith("\\\\.\\") else "\\\\.\\" + path
        self.handle = None
        self.cancelled = False
        self.arena = _Arena(RECV_ARENA)

    def open(self):
        import ctypes
        from ctypes import wintypes
        # use_last_error makes ctypes capture GetLastError at the call site;
        # ctypes.get_last_error() then reads that capture. Asking Windows
        # directly later can return a code some intervening call overwrote.
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        # Explicit signatures are required, not cosmetic: ctypes marshals an
        # untyped Python int as a C int, and the access mask below (0xC0000000)
        # does not fit one. A HANDLE is pointer-sized, so it needs declaring
        # too or the value is truncated on 64-bit.
        k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
                                    wintypes.DWORD, wintypes.LPVOID,
                                    wintypes.DWORD, wintypes.DWORD,
                                    wintypes.HANDLE]
        k32.CreateFileW.restype = wintypes.HANDLE
        k32.ReadFile.argtypes = [wintypes.HANDLE, wintypes.LPVOID,
                                 wintypes.DWORD, wintypes.LPDWORD,
                                 wintypes.LPVOID]
        k32.WriteFile.argtypes = [wintypes.HANDLE, wintypes.LPCVOID,
                                  wintypes.DWORD, wintypes.LPDWORD,
                                  wintypes.LPVOID]
        k32.CloseHandle.argtypes = [wintypes.HANDLE]
        k32.CancelIoEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
        k32.GetCommState.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
        k32.SetCommState.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
        k32.SetCommTimeouts.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
        k32.EscapeCommFunction.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        k32.ClearCommError.argtypes = [wintypes.HANDLE, wintypes.LPDWORD,
                                       wintypes.LPVOID]
        k32.PurgeComm.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        GENERIC = 0xC0000000            # GENERIC_READ | GENERIC_WRITE
        OPEN_EXISTING = 3
        INVALID_HANDLE = ctypes.c_void_p(-1).value
        self.handle = k32.CreateFileW(self.path, GENERIC, 0, None,
                                      OPEN_EXISTING, 0, None)
        if not self.handle or self.handle == INVALID_HANDLE:
            err = ctypes.get_last_error()
            self.handle = None
            _log.debug("CreateFileW %s failed, error %d", self.path, err)
            raise Disconnected
        _log.debug("opened %s", self.path)
        self._k32 = k32
        # A valid-but-cosmetic DCB; the device ignores line coding.
        class DCB(ctypes.Structure):
            _fields_ = [("DCBlength", wintypes.DWORD), ("BaudRate", wintypes.DWORD),
                        ("fFlags", wintypes.DWORD), ("wReserved", wintypes.WORD),
                        ("XonLim", wintypes.WORD), ("XoffLim", wintypes.WORD),
                        ("ByteSize", ctypes.c_byte), ("Parity", ctypes.c_byte),
                        ("StopBits", ctypes.c_byte), ("XonChar", ctypes.c_char),
                        ("XoffChar", ctypes.c_char), ("ErrorChar", ctypes.c_char),
                        ("EofChar", ctypes.c_char), ("EvtChar", ctypes.c_char),
                        ("wReserved1", wintypes.WORD)]
        dcb = DCB()
        dcb.DCBlength = ctypes.sizeof(DCB)
        if not k32.GetCommState(self.handle, ctypes.byref(dcb)):
            _log.debug("GetCommState failed, error %d", ctypes.get_last_error())
        dcb.BaudRate = 115200
        dcb.ByteSize = 8
        dcb.Parity = 0
        dcb.StopBits = 0
        # fBinary | fDtrControl=ENABLE | fRtsControl=ENABLE. A CDC device that
        # waits for the host to raise DTR never sees our first frame otherwise.
        dcb.fFlags = 0x1 | 0x10 | 0x1000
        if not k32.SetCommState(self.handle, ctypes.byref(dcb)):
            _log.debug("SetCommState failed, error %d", ctypes.get_last_error())

        class COMMTIMEOUTS(ctypes.Structure):
            _fields_ = [("ReadIntervalTimeout", wintypes.DWORD),
                        ("ReadTotalTimeoutMultiplier", wintypes.DWORD),
                        ("ReadTotalTimeoutConstant", wintypes.DWORD),
                        ("WriteTotalTimeoutMultiplier", wintypes.DWORD),
                        ("WriteTotalTimeoutConstant", wintypes.DWORD)]
        # MAXDWORD/MAXDWORD/RECV_POLL_MS is the documented way to say "return as
        # soon as any byte is here, else give up after RECV_POLL_MS". An all-zero
        # struct means the opposite on Windows: ReadFile waits for every byte
        # asked for, which never happens when a response is shorter than the
        # buffer. recv() loops over the short waits to get the infinite block.
        timeouts = COMMTIMEOUTS()
        timeouts.ReadIntervalTimeout = 0xFFFFFFFF
        timeouts.ReadTotalTimeoutMultiplier = 0xFFFFFFFF
        timeouts.ReadTotalTimeoutConstant = RECV_POLL_MS
        if not k32.SetCommTimeouts(self.handle, ctypes.byref(timeouts)):
            _log.debug("SetCommTimeouts failed, error %d", ctypes.get_last_error())
        # DTR/RTS again through the escape codes: some drivers honour these when
        # they ignore the DCB flags.
        k32.EscapeCommFunction(self.handle, 5)   # SETDTR
        k32.EscapeCommFunction(self.handle, 3)   # SETRTS

    def write(self, data):
        import ctypes
        from ctypes import wintypes
        # A command starts here. Drop a "Stop waiting" that arrived after the
        # previous command finished (it would cancel this one spuriously), and
        # purge input, where the late response to a cancelled command would
        # otherwise be parsed as this command's reply (responses are unframed).
        self.cancelled = False
        self._k32.PurgeComm(self.handle, 0x0008)   # PURGE_RXCLEAR
        written = wintypes.DWORD(0)
        ok = self._k32.WriteFile(self.handle, data, len(data),
                                 ctypes.byref(written), None)
        # Opcode only: the rest of a put frame is the secret itself.
        _log.debug("write %d bytes (opcode %s), ok=%s wrote=%d error=%d", len(data),
              data[2] if len(data) > 2 else "?", bool(ok), written.value,
              0 if ok else ctypes.get_last_error())
        if not ok:
            # wake()'s CancelIoEx aborts any I/O on the handle, this write
            # included; that is a cancel, not a dead port.
            raise Cancelled if self.cancelled else Disconnected

    def begin_recv(self):
        # The cancel flag is NOT cleared here: write() clears it when the
        # command starts, so a "Stop waiting" landing between write() and this
        # call still cancels the command instead of being lost.
        self.arena.reset()

    def recv(self):
        import ctypes
        from ctypes import wintypes
        if self.arena.is_full():
            raise Disconnected   # see PosixSerial.recv
        remaining = len(self.arena._map) - self.arena.fill
        # ReadFile writes straight into the arena pages at the current offset -
        # no intermediate ctypes/bytes buffer.
        dest = (ctypes.c_char * remaining).from_buffer(self.arena._map,
                                                       self.arena.fill)
        read = wintypes.DWORD(0)
        _log.debug("read: waiting for up to %d bytes", remaining)
        while True:
            ok = self._k32.ReadFile(self.handle, dest, remaining,
                                    ctypes.byref(read), None)
            if not ok:
                err = ctypes.get_last_error()
                _log.debug("read failed, error %d", err)
                raise Cancelled if self.cancelled else Disconnected
            if read.value:
                _log.debug("read got %d bytes", read.value)
                self.arena.advance(read.value)
                return self.arena.view()
            if self.cancelled:
                raise Cancelled
            # Nothing yet - normally the device waiting for the user to
            # confirm. Probe that the port still exists: a surprise removal
            # can make ReadFile report success with zero bytes, which is
            # otherwise indistinguishable from a quiet device.
            errors = wintypes.DWORD(0)
            if not self._k32.ClearCommError(self.handle, ctypes.byref(errors),
                                            None):
                _log.debug("port gone (ClearCommError error %d)",
                      ctypes.get_last_error())
                raise Disconnected

    def wipe(self):
        self.arena.wipe()

    def wake(self):
        # The recv loop notices the flag between polls; CancelIoEx cuts short a
        # read that is already blocked.
        self.cancelled = True
        if self.handle is not None:
            self._k32.CancelIoEx(self.handle, None)

    def close(self):
        self.arena.wipe_all()
        if self.handle is not None:
            self._k32.CloseHandle(self.handle)
            self.handle = None


def open_serial(path):
    if os.name == "nt":
        return WindowsSerial(path)
    return PosixSerial(path)


def _read_text(path):
    try:
        with open(path) as fh:
            return fh.read().strip()
    except OSError:
        return ""


def _linux_matches_seclave(tty_name):
    device = os.path.realpath(f"/sys/class/tty/{tty_name}/device")
    for _ in range(6):  # walk up to the USB device dir holding idVendor/idProduct
        vid = os.path.join(device, "idVendor")
        pid = os.path.join(device, "idProduct")
        if os.path.exists(vid) and os.path.exists(pid):
            return (_read_text(vid).lower() == f"{USB_VID:04x}" and
                    _read_text(pid).lower() == f"{USB_PID:04x}")
        device = os.path.dirname(device)
    return False


def find_port(forced=None):
    """Return the device's serial node, or None if it isn't present."""
    if forced:
        return forced if os.path.exists(forced) or os.name == "nt" else None
    if sys.platform.startswith("linux"):
        if os.path.exists("/dev/seclave"):   # stable name if a udev rule provides one
            return "/dev/seclave"
        for node in sorted(glob.glob("/dev/ttyACM*")):
            if _linux_matches_seclave(os.path.basename(node)):
                return node
        return None
    if sys.platform == "darwin":
        matches = sorted(glob.glob("/dev/cu.usbmodem*"))
        return matches[0] if matches else None
    if os.name == "nt":
        return _find_windows_port()
    return None


def _find_windows_port():
    import winreg
    # Precise: map our VID/PID to its assigned COM port name. A composite
    # enumeration puts the port under an interface key (VID_x&PID_y&MI_zz), so
    # both spellings are searched.
    prefix = f"VID_{USB_VID:04X}&PID_{USB_PID:04X}"
    try:
        usb = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SYSTEM\CurrentControlSet\Enum\USB")
    except OSError as err:
        _log.debug("cannot read the USB enum key: %s", err)
        usb = None
    if usb is not None:
        for device in _subkeys(usb):
            if not device.upper().startswith(prefix):
                continue
            try:
                parent = winreg.OpenKey(usb, device)
            except OSError:
                continue
            for instance in _subkeys(parent):
                try:
                    params = winreg.OpenKey(parent, instance + r"\Device Parameters")
                    port = winreg.QueryValueEx(params, "PortName")[0]
                except OSError:
                    continue
                _log.debug("found %s under USB\\%s\\%s", port, device, instance)
                return port
            _log.debug("USB\\%s has no PortName under any instance", device)
    # Fallback: the COM ports the system knows about, USB ones first. Anything
    # here may be a modem or a motherboard port, so it is a guess by design.
    ports = _serialcomm_ports()
    _log.debug("no VID/PID match; SERIALCOMM lists %s", ports or "nothing")
    for name, port in ports:
        if "USBSER" in name.upper() or "VCP" in name.upper():
            return port
    return ports[0][1] if ports else None


def _subkeys(key):
    import winreg
    names = []
    try:
        for i in range(winreg.QueryInfoKey(key)[0]):
            names.append(winreg.EnumKey(key, i))
    except OSError:
        pass
    return names


def _serialcomm_ports():
    """[(device name, COM port)] from the SERIALCOMM map, e.g. USBSER000 -> COM3."""
    import winreg
    found = []
    try:
        serialcomm = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                    r"HARDWARE\DEVICEMAP\SERIALCOMM")
        for i in range(winreg.QueryInfoKey(serialcomm)[1]):
            name, port, _ = winreg.EnumValue(serialcomm, i)
            found.append((name, port))
    except OSError as err:
        _log.debug("cannot read SERIALCOMM: %s", err)
    return found


# ---------------------------------------------------------------------------
# Client-side validation (before send). Put handlers silently truncate and
# DEL_WWWFILL rejects over-length input, so we never send anything invalid.
# ---------------------------------------------------------------------------

def validate_restricted(value, maxlen, allow_empty, dots_ok=True):
    if not value and not allow_empty:
        return "Required."
    if latin1_safe(value) is None:
        return "Only Latin-1 characters are allowed."
    if len(value.encode("latin-1")) > maxlen:
        return f"Too long (max {maxlen})."
    for ch in value:
        if ch == "." and dots_ok:
            continue
        if ch not in LABEL_CHARSET:
            return f"Character {ch!r} is not allowed here."
    return None


def latin1_safe(value):
    try:
        return value.encode("latin-1")
    except UnicodeEncodeError:
        return None


def validate_freeform(value, maxlen, allow_empty=True):
    if not value and not allow_empty:
        return "Required."
    if latin1_safe(value) is None:
        return "Only Latin-1 characters are allowed."
    if len(value.encode("latin-1")) > maxlen:
        return f"Too long (max {maxlen})."
    return None


def normalize_domain(text):
    """Reduce a URL to the bare host the device stores (strip scheme/port/path)."""
    text = text.strip()
    if "://" in text:
        text = text.split("://", 1)[1]
    text = text.split("/", 1)[0]
    text = text.split(":", 1)[0]
    return text


# The device folds a domain's case byte by byte, lowering ONLY ASCII A-Z and
# the six two-case Latin-1 letters its charset permits - Ä Å Æ Ö Ø Ü; every
# other byte, including ß, compares exact. Python's str comparisons disagree
# with that: casefold() maps ß -> "ss" (so "straße.de" would wrongly equal
# "strasse.de" - both are dialog-legal domains) and lower() folds all Latin-1
# uppercase (É -> é), which matters for domains other tools already stored on
# the device. So fold at the byte level with the device's exact table.
_LATIN1_CASE_PAIRS = {0xC4: 0xE4, 0xC5: 0xE5, 0xC6: 0xE6,   # Ä Å Æ
                      0xD6: 0xF6, 0xD8: 0xF8, 0xDC: 0xFC}   # Ö Ø Ü
_LATIN1_FOLD = bytes(b + 0x20 if 0x41 <= b <= 0x5A
                     else _LATIN1_CASE_PAIRS.get(b, b) for b in range(256))


def latin1_fold(text):
    """Lowercase a domain exactly as the device does (bytes out)."""
    return text.encode("latin-1").translate(_LATIN1_FOLD)


def wwwfill_key(domain, username):
    """The device's wwwfill uniqueness key: the domain compares under the
    device's own case fold (see _LATIN1_FOLD above), the username byte-exact.
    Any client-side duplicate logic must use exactly these semantics to agree
    with the device."""
    return (latin1_fold(domain), username)


def wwwfill_duplicate_error(pairs, domain, username, skip=None):
    """Refuse a wwwfill write that would duplicate an existing entry.

    `pairs` is the device's current set of (domain, username) pairs; `skip`
    is the old identity of the pair being edited, so an unchanged edit does
    not collide with itself - but only one occurrence is skipped, so an edit
    of a pair the device already holds twice (the dangerous state) is still
    refused. Returns a message to show the user, or None when the write is
    safe to send. Gated by ENFORCE_WWWFILL_DEDUP; see the comment there.
    """
    if not ENFORCE_WWWFILL_DEDUP:
        return None
    new_key = wwwfill_key(domain, username)
    skip_key = wwwfill_key(*skip) if skip is not None else None
    skipped = False
    for pair in pairs:
        if wwwfill_key(*pair) != new_key:
            continue
        if skip_key == new_key and not skipped:
            skipped = True   # the row being edited itself
            continue
        return (f"A web password for {pair[0]} / {pair[1]} already exists "
                "(domains match case-insensitively). Duplicates can lock up "
                "Seclave firmware 2.6 and earlier, so it was not sent.")
    return None


def find_wwwfill_duplicates(pairs):
    """Return one representative (domain, username) per pair stored more than
    once under the device's uniqueness key. A duplicate already on the device
    means an affected firmware (2.6 or earlier) admitted it - the state from
    which an edit can lock up the device - so the UI warns about it at load
    time, the one case the pre-send refusal cannot prevent."""
    counts = {}
    for pair in pairs:
        key = wwwfill_key(*pair)
        counts[key] = counts.get(key, 0) + 1
    reported = set()
    duplicates = []
    for pair in pairs:
        key = wwwfill_key(*pair)
        if counts[key] > 1 and key not in reported:
            reported.add(key)
            duplicates.append(pair)
    return duplicates


# ---------------------------------------------------------------------------
# DeviceSession - high-level commands. Each builds a frame, sends it, and reads
# the reply into the transport's mmap arena until it parses. Every command wipes
# the arena when it finishes (the `finally` blocks below), so secret bytes never
# outlive the command in the arena. Confirmable commands block inside recv()
# until the user acts on the device; ABORT means they declined.
# ---------------------------------------------------------------------------

class DeviceError(Exception):
    def __init__(self, status):
        super().__init__(STATUS_MESSAGE.get(status, f"Device error {status}."))
        self.status = status


class DeviceSession:
    def __init__(self, transport):
        self.transport = transport

    def _exchange(self, payload, field_count):
        """Send one command and read its unframed reply into the arena. Returns
        (status, spans, view); the spans index into `view`, a memoryview over the
        arena. The caller must read what it needs and then wipe the arena."""
        self.transport.write(build_frame(payload))
        self.transport.begin_recv()
        while True:
            view = self.transport.recv()
            parsed = parse_response(view, field_count)
            if parsed is not None:
                status, spans = parsed
                return status, spans, view

    # --- enumerations: confirm once on the device, then stream ---

    def list_labels(self):
        labels = []
        index = 0
        while True:
            payload = bytes([OP_GET_LABELIDX]) + encode_int(index)
            try:
                status, spans, view = self._exchange(payload, 1)
                if status == ST_OUT_OF_INDEX:
                    return labels
                if status == ST_ABORT:
                    raise Cancelled
                if status != ST_OK:
                    raise DeviceError(status)
                (start, end), = spans
                labels.append(bytes(view[start:end]).decode("latin-1"))
            finally:
                self.transport.wipe()
            index += 1

    def list_wwwfill(self):
        rows = []
        index = 0
        while True:
            payload = bytes([OP_GET_WWWFILLIDX]) + encode_int(index)
            try:
                status, spans, view = self._exchange(payload, 2)
                if status == ST_OUT_OF_INDEX:
                    return rows
                if status == ST_ABORT:
                    raise Cancelled
                if status != ST_OK:
                    raise DeviceError(status)
                (ds, de), (us, ue) = spans
                rows.append((bytes(view[ds:de]).decode("latin-1"),
                             bytes(view[us:ue]).decode("latin-1")))
            finally:
                self.transport.wipe()
            index += 1

    # --- per-entry reads. Each is a single field keyed by label. ---

    def get_group(self, label):
        # Group and optional are not secrets: they hold a category or free-form
        # notes/domain and are shown in the table, so a plain str is fine.
        return self._get_text(OP_GET_GROUP, label)

    def get_optional(self, label):
        return self._get_text(OP_GET_OPTIONAL, label)

    def _get_text(self, opcode, label):
        payload = bytes([opcode]) + encode_field(latin1(label))
        try:
            status, spans, view = self._exchange(payload, 1)
            if status == ST_ABORT:
                raise Cancelled
            if status != ST_OK:
                raise DeviceError(status)
            (start, end), = spans
            return bytes(view[start:end]).decode("latin-1")
        finally:
            self.transport.wipe()

    def _get_secret(self, opcode, label):
        payload = bytes([opcode]) + encode_field(latin1(label))
        try:
            status, spans, view = self._exchange(payload, 1)
            if status == ST_ABORT:
                raise Cancelled
            if status != ST_OK:
                raise DeviceError(status)
            (start, end), = spans
            # mmap-to-mmap copy: the secret goes straight from the arena into a
            # SecretBuffer, then the arena is wiped in the finally below.
            return SecretBuffer(view[start:end])
        finally:
            self.transport.wipe()

    def get_username(self, label):
        return self._get_secret(OP_GET_USERNAME, label)

    def get_password(self, label):
        return self._get_secret(OP_GET_PASSWORD, label)

    def get_wwwfill(self, domain, index):
        """Return (username, password, more) for the index-th login on a domain.
        `more` is True when higher indices hold further logins."""
        payload = bytes([OP_GET_WWWFILL]) + encode_field(latin1(domain)) + \
            encode_int(index)
        try:
            status, spans, view = self._exchange(payload, 2)
            if status == ST_ABORT:
                raise Cancelled
            if status not in (ST_OK, ST_MORE_LABELS):
                raise DeviceError(status)
            (us, ue), (ps, pe) = spans
            username = SecretBuffer(view[us:ue])
            password = SecretBuffer(view[ps:pe])
            return username, password, status == ST_MORE_LABELS
        finally:
            self.transport.wipe()

    # --- mutations. Puts/dels return only a status. ---

    def _status_only(self, payload):
        try:
            status, _, _ = self._exchange(payload, 0)
            if status == ST_ABORT:
                raise Cancelled
            if status != ST_OK:
                raise DeviceError(status)
        finally:
            self.transport.wipe()

    def put_entry(self, label, group, username, password, optional):
        payload = bytes([OP_PUT_ENTRY]) + encode_field(latin1(label)) + \
            encode_field(latin1(group)) + encode_field(latin1(username)) + \
            encode_field(latin1(password)) + encode_field(latin1(optional))
        self._status_only(payload)

    def put_wwwfill(self, domain, username, password):
        # Defense in depth: never send a domain outside the charset the device
        # accepts (an embedded NUL is the dangerous case). The dialog validates
        # this already; this guards non-GUI callers such as future bulk-import
        # tooling.
        if validate_restricted(domain, MAX_OPTIONAL, False):
            raise DeviceError(ST_BAD_DOMAIN)
        payload = bytes([OP_PUT_WWWFILL]) + encode_field(latin1(domain)) + \
            encode_field(latin1(username)) + encode_field(latin1(password))
        self._status_only(payload)

    def del_entry(self, label):
        self._status_only(bytes([OP_DEL_ENTRY]) + encode_field(latin1(label)))

    def del_wwwfill(self, domain, username):
        payload = bytes([OP_DEL_WWWFILL]) + encode_field(latin1(domain)) + \
            encode_field(latin1(username))
        self._status_only(payload)
