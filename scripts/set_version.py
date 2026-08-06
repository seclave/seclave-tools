#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright 2026 Seclave AB
"""Set the release version everywhere it is stamped.

Three files carry a version (the two Python packages and the Rust
workspace); packaging derives everything else from those. This script is
what keeps "bump the version" a one-command change:

    python3 scripts/set_version.py 0.2.0

CI refuses a release tag that does not match all three, so a missed spot
cannot ship.
"""

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# (path, pattern) - the one versioned line in each file.
STAMPS = [
    ("python/seclave/seclave/__init__.py", r'^VERSION = "([^"]+)"$'),
    ("python/seclave-ctl/seclave_ctl.py", r'^VERSION = "([^"]+)"$'),
    ("rust/Cargo.toml", r'^version = "([^"]+)"$'),
]


def main():
    if len(sys.argv) != 2 or not re.fullmatch(r"\d+\.\d+\.\d+", sys.argv[1]):
        raise SystemExit("usage: set_version.py <major.minor.patch>")
    version = sys.argv[1]
    for rel_path, pattern in STAMPS:
        path = os.path.join(ROOT, rel_path)
        text = open(path, encoding="utf-8").read()
        match = re.search(pattern, text, re.M)
        if not match:
            raise SystemExit(f"no version stamp found in {rel_path}")
        new_line = match.group(0).replace(match.group(1), version)
        open(path, "w", encoding="utf-8").write(
            text[:match.start()] + new_line + text[match.end():])
        print(f"{rel_path}: {match.group(1)} -> {version}")
    print("Now update rust/Cargo.lock: (cd rust && cargo update -w)")


if __name__ == "__main__":
    main()
