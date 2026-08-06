# Conformance vectors

`protocol.json` holds byte-level test vectors for the Seclave USB-slave wire
protocol: integer and field encodings (including non-canonical forms a
decoder must accept, incomplete prefixes, and rejects), command framing with
its bounds, and response parsing (status handling, field extraction, and
incremental "need more bytes" states). All byte strings are lowercase hex.

The Python implementation in `python/seclave/` is the reference - it is the
code that has been validated against real hardware - and `gen_vectors.py`
generates this file from it. Every implementation in the repo runs the same
vectors in its own test suite; that shared file, not review discipline, is
what keeps the ports byte-identical.

To change the wire format (which the shipped protocol does not do - it is
frozen): change the Python implementation, run `python3 gen_vectors.py`
here, and re-run every consumer's tests.
