#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright 2026 Seclave AB
"""Regenerate protocol.json from the Python implementation.

The Python library is the reference: its protocol layer is the one validated
against real hardware. Every implementation in this repo must pass these
vectors, which is what keeps the ports from drifting. Run from this directory:

    python3 gen_vectors.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "python", "seclave"))
import seclave as sc


def hx(data):
    return bytes(data).hex()


def integers():
    """Encode/decode roundtrips across the escape-format boundaries."""
    cases = []
    for value in (0, 1, 42, 252, 253, 254, 255, 256, 500, 1000, 0xFFFE, 0xFFFF):
        encoded = sc.encode_int(value)
        decoded, end = sc.decode_int(encoded, 0)
        assert decoded == value and end == len(encoded)
        cases.append({"value": value, "encoded": hx(encoded)})
    # Non-canonical escape encodings the decoder must still accept.
    for raw, value in (("ff0105", 5), ("ff020500", 5), ("ff02ffff", 0xFFFF)):
        decoded, _ = sc.decode_int(bytes.fromhex(raw), 0)
        assert decoded == value
        cases.append({"value": value, "encoded_alternative": raw})
    return cases


def integer_errors():
    """Encodings decode_int must reject (bad escape length byte)."""
    cases = []
    for raw in ("ff00", "ff03aabbcc"):
        try:
            sc.decode_int(bytes.fromhex(raw), 0)
        except ValueError:
            cases.append({"encoded": raw})
        else:
            raise AssertionError(f"expected rejection of {raw}")
    return cases


def integer_incomplete():
    """Prefixes for which the decoder must ask for more bytes, not fail."""
    cases = []
    for raw in ("", "ff", "ff01", "ff02", "ff0234"):
        try:
            sc.decode_int(bytes.fromhex(raw), 0)
        except sc.NeedMore:
            cases.append({"encoded": raw})
        else:
            raise AssertionError(f"expected NeedMore on {raw!r}")
    return cases


def fields():
    cases = []
    for payload in (b"", b"a", b"gmail", bytes(range(256)), b"x" * 254):
        encoded = sc.encode_field(payload)
        (start, end), nxt = sc.decode_field_span(encoded, 0)
        assert encoded[start:end] == payload and nxt == len(encoded)
        cases.append({"payload": hx(payload), "encoded": hx(encoded)})
    return cases


def frames():
    cases = []
    for payload in (b"\x01", b"\x0agmail", b"z" * sc.MAX_FRAME_PAYLOAD):
        cases.append({"payload": hx(payload), "framed": hx(sc.build_frame(payload))})
    return cases


def frame_errors():
    """Payload lengths build_frame must refuse (the device would drop out of
    slave mode)."""
    cases = []
    for length in (0, sc.MAX_FRAME_PAYLOAD + 1):
        try:
            sc.build_frame(b"q" * length)
        except ValueError:
            cases.append({"payload_length": length})
        else:
            raise AssertionError(f"expected refusal of length {length}")
    return cases


def responses():
    """parse_response cases: status handling, field extraction, incremental
    parsing. `fields` holds the decoded field bytes; `incomplete` means the
    parser must report that more bytes are needed."""

    def case(raw, field_count):
        parsed = sc.parse_response(raw, field_count)
        entry = {"bytes": hx(raw), "field_count": field_count}
        if parsed is None:
            entry["incomplete"] = True
        else:
            status, spans = parsed
            entry["status"] = status
            entry["fields"] = [hx(raw[s:e]) for s, e in spans]
        return entry

    cases = []
    ok_two = bytes([sc.ST_OK]) + sc.encode_field(b"alice") + sc.encode_field(b"hunter2")
    more = bytes([sc.ST_MORE_LABELS]) + sc.encode_field(b"u") + sc.encode_field(b"p")
    big = bytes([sc.ST_OK]) + sc.encode_field(b"B" * 254)
    for raw, count in (
        (bytes([sc.ST_OK]) + sc.encode_field(b"gmail"), 1),
        (bytes([sc.ST_OK]) + sc.encode_field(b""), 1),
        (ok_two, 2),
        (more, 2),                                   # MORE_LABELS is a success
        (big, 1),                                    # length uses the escape form
        (bytes([sc.ST_OK]), 0),                      # status-only reply
        (bytes([sc.ST_ABORT]), 1),                   # error: no fields follow
        (bytes([sc.ST_ENTRY_NOT_FOUND]), 2),
        (bytes([sc.ST_OUT_OF_INDEX]), 1),
        (b"", 1),                                    # nothing yet
        (ok_two[:3], 2),                             # mid-field
        (ok_two[:7], 2),                             # first field only
        (big[:100], 1),                              # mid-escaped-length field
    ):
        cases.append(case(raw, count))
    return cases


def main():
    vectors = {
        "_comment": "Conformance vectors for the Seclave USB-slave wire protocol. "
                    "Generated by gen_vectors.py from the Python implementation "
                    "(the reference, validated against hardware). Do not edit "
                    "by hand; regenerate and re-run every consumer's tests.",
        "integers": integers(),
        "integer_errors": integer_errors(),
        "integer_incomplete": integer_incomplete(),
        "fields": fields(),
        "frames": frames(),
        "frame_errors": frame_errors(),
        "responses": responses(),
    }
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "protocol.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(vectors, fh, indent=1)
        fh.write("\n")
    total = sum(len(v) for v in vectors.values() if isinstance(v, list))
    print(f"wrote {out}: {total} cases")


if __name__ == "__main__":
    main()
