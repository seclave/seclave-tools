#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright 2026 Seclave AB
"""Run the shared conformance vectors against the Python implementation.

The vectors are generated FROM this implementation (see vectors/gen_vectors.py),
so for Python this is a self-check; its real job is to fail when someone edits
the wire format without regenerating, which would silently strand the other
implementations on the old bytes. Run: python3 tests/test_vectors.py
"""

import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import seclave as sc

with open(os.path.join(HERE, "..", "..", "..", "vectors", "protocol.json"),
          encoding="utf-8") as fh:
    VECTORS = json.load(fh)


class VectorTests(unittest.TestCase):
    def test_integers(self):
        for case in VECTORS["integers"]:
            if "encoded" in case:
                encoded = bytes.fromhex(case["encoded"])
                self.assertEqual(sc.encode_int(case["value"]).hex(),
                                 case["encoded"])
            else:
                encoded = bytes.fromhex(case["encoded_alternative"])
            value, end = sc.decode_int(encoded, 0)
            self.assertEqual((value, end), (case["value"], len(encoded)))

    def test_integer_errors(self):
        for case in VECTORS["integer_errors"]:
            with self.assertRaises(ValueError):
                sc.decode_int(bytes.fromhex(case["encoded"]), 0)

    def test_integer_incomplete(self):
        for case in VECTORS["integer_incomplete"]:
            with self.assertRaises(sc.NeedMore):
                sc.decode_int(bytes.fromhex(case["encoded"]), 0)

    def test_fields(self):
        for case in VECTORS["fields"]:
            payload = bytes.fromhex(case["payload"])
            encoded = bytes.fromhex(case["encoded"])
            self.assertEqual(sc.encode_field(payload).hex(), case["encoded"])
            (start, end), nxt = sc.decode_field_span(encoded, 0)
            self.assertEqual(encoded[start:end], payload)
            self.assertEqual(nxt, len(encoded))

    def test_frames(self):
        for case in VECTORS["frames"]:
            self.assertEqual(
                sc.build_frame(bytes.fromhex(case["payload"])).hex(),
                case["framed"])

    def test_frame_errors(self):
        for case in VECTORS["frame_errors"]:
            with self.assertRaises(ValueError):
                sc.build_frame(b"q" * case["payload_length"])

    def test_responses(self):
        for case in VECTORS["responses"]:
            raw = bytes.fromhex(case["bytes"])
            parsed = sc.parse_response(raw, case["field_count"])
            if case.get("incomplete"):
                self.assertIsNone(parsed, case)
                continue
            self.assertIsNotNone(parsed, case)
            status, spans = parsed
            self.assertEqual(status, case["status"], case)
            self.assertEqual([raw[s:e].hex() for s, e in spans],
                             case["fields"], case)


if __name__ == "__main__":
    unittest.main(verbosity=1)
