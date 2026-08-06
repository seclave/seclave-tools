#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright 2026 Seclave AB
"""seclave-ctl end-to-end tests against the library's stub device.

Each test runs main() in-process with --port pointing at a pty served by
seclave.testing.FakeDevice. Run: python3 tests/test_cli.py
"""

import io
import os
import sys
import unittest
import contextlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "..", "seclave"))

import seclave
import seclave_ctl
from seclave.testing import FakeDevice, start_pty


class CliTests(unittest.TestCase):
    def setUp(self):
        self.device = FakeDevice()
        self.path, _thread, self._slave = start_pty(self.device)

    def run_cli(self, *argv, stdin=None):
        out, err = io.StringIO(), io.StringIO()
        if stdin is not None:
            old_stdin, sys.stdin = sys.stdin, io.StringIO(stdin)
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = seclave_ctl.main(["--port", self.path] + list(argv))
        finally:
            if stdin is not None:
                sys.stdin = old_stdin
        return code, out.getvalue(), err.getvalue()

    def test_list(self):
        code, out, _ = self.run_cli("list")
        self.assertEqual(code, 0)
        lines = out.splitlines()
        self.assertIn("gmail", lines)
        self.assertIn("github", lines)
        self.assertEqual(len(lines), 6)   # 3 entries + 3 web logins

    def test_list_www(self):
        code, out, _ = self.run_cli("list-www")
        self.assertEqual(code, 0)
        self.assertIn("github.com\talice", out.splitlines())

    def test_get_each_field(self):
        for field, expected in (("group", "personal"),
                                ("username", "alice@example.com"),
                                ("password", "hunter2"),
                                ("optional", "notes")):
            code, out, _ = self.run_cli("get", "gmail", field)
            self.assertEqual((code, out.strip()), (0, expected), field)

    def test_get_missing_entry(self):
        code, _, err = self.run_cli("get", "nosuch", "password")
        self.assertEqual(code, 1)
        self.assertIn("not found", err)

    def test_get_declined(self):
        self.device.always_abort = True
        code, _, err = self.run_cli("get", "gmail", "password")
        self.assertEqual(code, 1)
        self.assertIn("declined", err)

    def test_put_then_get(self):
        code, _, err = self.run_cli(
            "put", "new-entry", "--group", "work", "--username", "carol",
            "--password", "pw123", "--optional", "a note")
        self.assertEqual((code, err), (0, ""))
        code, out, _ = self.run_cli("get", "new-entry", "password")
        self.assertEqual((code, out.strip()), (0, "pw123"))

    def test_put_password_stdin(self):
        code, _, _ = self.run_cli("put", "stdin-entry", "--password-stdin",
                                  stdin="from-stdin\n")
        self.assertEqual(code, 0)
        self.assertEqual(self.device.entries["stdin-entry"]["password"],
                         "from-stdin")

    def test_put_rejects_bad_label(self):
        code, _, err = self.run_cli("put", "bad label!", "--password", "x")
        self.assertEqual(code, 1)
        self.assertIn("label", err)
        self.assertNotIn("bad label!", self.device.entries)

    def test_put_rejects_overlong_password(self):
        code, _, err = self.run_cli("put", "longpw", "--password",
                                    "x" * (seclave.MAX_PASSWORD + 1))
        self.assertEqual(code, 1)
        self.assertIn("password", err)

    def test_del(self):
        code, _, _ = self.run_cli("del", "gmail")
        self.assertEqual(code, 0)
        self.assertNotIn("gmail", self.device.entries)
        code, _, _ = self.run_cli("del", "gmail")
        self.assertEqual(code, 1)   # already gone

    def test_get_www_first_and_all(self):
        code, out, _ = self.run_cli("get-www", "github.com")
        self.assertEqual((code, out), (0, "alice\twebpass-a\n"))
        code, out, _ = self.run_cli("get-www", "github.com", "--all")
        self.assertEqual(code, 0)
        self.assertEqual(out.splitlines(),
                         ["alice\twebpass-a", "bob\twebpass-b"])

    def test_put_www_normalizes_domain(self):
        code, _, _ = self.run_cli("put-www", "https://new.example.com/login",
                                  "dave", "--password", "pw")
        self.assertEqual(code, 0)
        self.assertIn(dict(domain="new.example.com", username="dave",
                           password="pw"), self.device.web)

    def test_put_www_refuses_duplicate(self):
        code, _, err = self.run_cli("put-www", "github.com", "alice",
                                    "--password", "pw")
        self.assertEqual(code, 1)
        self.assertIn("already exists", err)

    def test_put_www_force_overrides(self):
        code, _, _ = self.run_cli("put-www", "github.com", "alice",
                                  "--password", "newpw", "--force")
        self.assertEqual(code, 0)
        self.assertEqual(self.device.web[0]["password"], "newpw")

    def test_del_www(self):
        code, _, _ = self.run_cli("del-www", "github.com", "bob")
        self.assertEqual(code, 0)
        self.assertEqual(len(self.device.web), 2)

    def test_udev_show(self):
        code, out, _ = self.run_cli("udev", "show")
        self.assertEqual(code, 0)
        self.assertIn('ATTRS{idVendor}=="20a0"', out)
        self.assertIn('ATTRS{idProduct}=="41e3"', out)
        self.assertIn('SYMLINK+="seclave"', out)
        self.assertEqual(out, seclave.udev.RULES)

    def test_udev_install_writes_the_rule(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            rule_path = os.path.join(tmp, "60-seclave.rules")
            code, out, _ = self.run_cli("udev", "install", "--path", rule_path)
            self.assertEqual(code, 0)
            self.assertEqual(open(rule_path).read(), seclave.udev.RULES)
            self.assertIn(rule_path, out)

    def test_udev_install_permission_error_suggests_sudo(self):
        code, _, err = self.run_cli("udev", "install", "--path",
                                    "/proc/denied/60-seclave.rules")
        self.assertEqual(code, 1)
        self.assertIn("sudo", err)

    def test_udev_needs_no_device(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = seclave_ctl.main(["udev", "show"])   # no --port at all
        self.assertEqual(code, 0)
        self.assertIn("20a0", out.getvalue())

    def test_no_device(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = seclave_ctl.main(["--port", "/dev/does-not-exist", "list"])
        self.assertEqual(code, 1)
        self.assertIn("no Seclave found", err.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=1)
