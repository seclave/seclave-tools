# SPDX-License-Identifier: MIT
# Copyright 2026 Seclave AB
"""The Linux udev rule for the Seclave, and its installation.

pip/pipx/uv can install programs but not system configuration, so a
pip-installed client has no way to receive this rule the way the
seclave-companion deb/rpm ships it (those install the identical rule to
/usr/lib/udev/rules.d, the vendor directory). This module closes that gap:
`seclave-ctl udev install` writes the rule to /etc/udev/rules.d, the local
admin directory, which overrides the vendor copy by filename - having both
is harmless because they are the same rule.

The rule does three things: keeps ModemManager from probing the port with AT
commands (which corrupts the first exchange), grants the logged-in desktop
user access without group setup (logind ACL via the uaccess tag, with
classic dialout membership as the fallback), and creates a stable
/dev/seclave symlink so clients need not guess ttyACM numbers.
"""

import os
import shutil
import subprocess

RULES = """\
# Seclave 2 in USB-slave mode (CDC-ACM serial, USB ID 20a0:41e3).
#
# - ID_MM_DEVICE_IGNORE keeps ModemManager off the port; it otherwise probes
#   the new ACM device with AT commands and corrupts the first exchange.
# - TAG+="uaccess" grants the logged-in desktop user access via a logind ACL,
#   so no group membership is needed on a systemd desktop. GROUP/MODE remain
#   as the fallback for everything else (classic "dialout" membership).
# - SYMLINK+="seclave" gives the stable /dev/seclave node the Companion and
#   seclave_ctl prefer over guessing ttyACM numbers.
#
# Numbered 60- so the uaccess tag is set before systemd's seat rules run.

SUBSYSTEM=="usb", ATTRS{idVendor}=="20a0", ATTRS{idProduct}=="41e3", ENV{ID_MM_DEVICE_IGNORE}="1"
SUBSYSTEM=="tty", ATTRS{idVendor}=="20a0", ATTRS{idProduct}=="41e3", ENV{ID_MM_DEVICE_IGNORE}="1", MODE="0660", GROUP="dialout", TAG+="uaccess", SYMLINK+="seclave"
"""

DEFAULT_PATH = "/etc/udev/rules.d/60-seclave.rules"


def install(path=DEFAULT_PATH):
    """Write the rule to `path` and reload udev. Returns the path written.

    Writing the default path needs root (PermissionError otherwise, for the
    caller to explain). The reload is best-effort, matching what the deb/rpm
    postinstall does: in a container or chroot there is no udev daemon to
    talk to, and the rule then simply applies from the next boot.
    """
    with open(path, "w", encoding="ascii") as fh:
        fh.write(RULES)
    if shutil.which("udevadm"):
        with open(os.devnull, "wb") as devnull:
            for command in (["udevadm", "control", "--reload-rules"],
                            ["udevadm", "trigger", "--subsystem-match=usb",
                             "--subsystem-match=tty"]):
                subprocess.call(command, stdout=devnull, stderr=devnull)
    return path
