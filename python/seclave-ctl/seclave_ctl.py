#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright 2026 Seclave AB
"""seclave-ctl - command-line client for the Seclave hardware password manager.

Talks to a Seclave 2 in its "Usb slave" menu over the seclave library. Reads
print the requested value to stdout (that is the point of a CLI: pipe it),
so treat your terminal and shell history accordingly; the device asks for
confirmation on its own screen before releasing a secret.

    seclave-ctl list
    seclave-ctl get gmail password | wl-copy
    seclave-ctl put backup-mail --group personal --username bob --password-stdin
    seclave-ctl del old-entry
    seclave-ctl list-www
    seclave-ctl get-www github.com --all
    seclave-ctl put-www github.com alice --password-stdin
    seclave-ctl del-www github.com alice

The port is found by USB VID/PID (or a udev-provided /dev/seclave); use
--port for an explicit path. --debug traces discovery and serial I/O.
"""

import sys
import getpass
import logging
import argparse

import seclave
import seclave.udev

VERSION = "0.1.1"

GET_FIELDS = ("group", "username", "password", "optional")


def fail(message):
    print(f"seclave-ctl: {message}", file=sys.stderr)
    return 1


def read_password(args, prompt):
    """The password for a put: --password, --password-stdin, or an interactive
    prompt. Passing it on the command line exposes it to the process list, so
    scripts should prefer --password-stdin."""
    if args.password is not None:
        return args.password
    if args.password_stdin:
        line = sys.stdin.readline()
        if not line:
            return None
        return line.rstrip("\n")
    if sys.stdin.isatty():
        return getpass.getpass(prompt)
    return None


def print_secret(buffer):
    try:
        print(buffer.text())
    finally:
        buffer.clear()


def cmd_list(session, args):
    for label in session.list_labels():
        print(label)
    return 0


def cmd_list_www(session, args):
    for domain, username in session.list_wwwfill():
        print(f"{domain}\t{username}")
    return 0


def cmd_get(session, args):
    if args.field in ("group", "optional"):
        value = {"group": session.get_group,
                 "optional": session.get_optional}[args.field](args.label)
        print(value)
    else:
        secret = {"username": session.get_username,
                  "password": session.get_password}[args.field](args.label)
        print_secret(secret)
    return 0


def cmd_put(session, args):
    password = read_password(args, f"Password for {args.label}: ")
    if password is None:
        return fail("no password given (use --password, --password-stdin, "
                    "or run interactively)")
    for value, maxlen, what in ((args.label, seclave.MAX_LABEL, "label"),
                                (args.group, seclave.MAX_GROUP, "group")):
        error = seclave.validate_restricted(value, maxlen, what == "group")
        if error:
            return fail(f"{what}: {error}")
    for value, maxlen, what in ((args.username, seclave.MAX_USERNAME, "username"),
                                (password, seclave.MAX_PASSWORD, "password"),
                                (args.optional, seclave.MAX_OPTIONAL, "optional")):
        error = seclave.validate_freeform(value, maxlen)
        if error:
            return fail(f"{what}: {error}")
    session.put_entry(args.label, args.group, args.username, password,
                      args.optional)
    return 0


def cmd_del(session, args):
    session.del_entry(args.label)
    return 0


def cmd_get_www(session, args):
    index = 0
    while True:
        username, password, more = session.get_wwwfill(args.domain, index)
        try:
            sys.stdout.write(f"{username.text()}\t")
        finally:
            username.clear()
        print_secret(password)
        if not (args.all and more):
            return 0
        index += 1


def cmd_put_www(session, args):
    domain = seclave.normalize_domain(args.domain)
    password = read_password(args, f"Password for {args.username} on {domain}: ")
    if password is None:
        return fail("no password given (use --password, --password-stdin, "
                    "or run interactively)")
    for value, maxlen, what in ((args.username, seclave.MAX_USERNAME, "username"),
                                (password, seclave.MAX_PASSWORD, "password")):
        error = seclave.validate_freeform(value, maxlen, allow_empty=False)
        if error:
            return fail(f"{what}: {error}")
    if not args.force:
        # A (domain, username) duplicate can lock up firmware 2.6 and earlier
        # (see the seclave library docs), so refuse unless told otherwise. The
        # check enumerates the device's web logins first.
        pairs = session.list_wwwfill()
        error = seclave.wwwfill_duplicate_error(pairs, domain, args.username)
        if error:
            return fail(error + " (--force overrides)")
    session.put_wwwfill(domain, args.username, password)
    return 0


def cmd_del_www(session, args):
    session.del_wwwfill(args.domain, args.username)
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="seclave-ctl",
        description="Command-line client for the Seclave hardware password "
                    "manager (device in its Usb slave menu).")
    parser.add_argument("--version", action="version",
                        version=f"seclave-ctl {VERSION} (seclave library {seclave.VERSION})")
    parser.add_argument("--port", help="serial port path (default: find the "
                        "device by USB VID/PID)")
    parser.add_argument("--debug", action="store_true",
                        help="trace port discovery and serial I/O to stderr")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="list entry labels")
    sub.add_parser("list-www", help="list web logins as domain<TAB>username")

    get = sub.add_parser("get", help="print one field of an entry")
    get.add_argument("label")
    get.add_argument("field", choices=GET_FIELDS)

    put = sub.add_parser("put", help="store a new entry")
    put.add_argument("label")
    put.add_argument("--group", default="")
    put.add_argument("--username", default="")
    put.add_argument("--password")
    put.add_argument("--password-stdin", action="store_true",
                     help="read the password as one line from stdin")
    put.add_argument("--optional", default="",
                     help="free-form notes/domain field")

    dele = sub.add_parser("del", help="delete an entry")
    dele.add_argument("label")

    get_www = sub.add_parser("get-www",
                             help="print a domain's login as username<TAB>password")
    get_www.add_argument("domain")
    get_www.add_argument("--all", action="store_true",
                         help="print every login stored for the domain")

    put_www = sub.add_parser("put-www", help="store a web login")
    put_www.add_argument("domain")
    put_www.add_argument("username")
    put_www.add_argument("--password")
    put_www.add_argument("--password-stdin", action="store_true",
                         help="read the password as one line from stdin")
    put_www.add_argument("--force", action="store_true",
                         help="skip the duplicate check (see put-www docs)")

    del_www = sub.add_parser("del-www", help="delete a web login")
    del_www.add_argument("domain")
    del_www.add_argument("username")

    udev = sub.add_parser(
        "udev", help="show or install the Linux udev rule for the device")
    udev.add_argument("action", choices=("show", "install"))
    udev.add_argument("--path", default=seclave.udev.DEFAULT_PATH,
                      help="where install writes the rule "
                      "(default: %(default)s)")
    return parser


COMMANDS = {
    "list": cmd_list, "list-www": cmd_list_www,
    "get": cmd_get, "put": cmd_put, "del": cmd_del,
    "get-www": cmd_get_www, "put-www": cmd_put_www, "del-www": cmd_del_www,
}


def cmd_udev(args):
    """The one command that talks to the host, not the device: give
    pip/pipx/uv installs a way to get the serial-access udev rule the
    seclave-companion deb/rpm would have installed."""
    if args.action == "show":
        sys.stdout.write(seclave.udev.RULES)
        return 0
    if not sys.platform.startswith("linux"):
        return fail("udev rules are a Linux mechanism; on macOS and Windows "
                    "the port works without setup")
    try:
        seclave.udev.install(args.path)
    except OSError as err:
        return fail(f"cannot write {args.path} ({err.strerror}) - run with sudo, "
                    f"or: seclave-ctl udev show | sudo tee {args.path}")
    print(f"wrote {args.path} and reloaded udev; replug the device")
    return 0


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.debug:
        logging.basicConfig(level=logging.DEBUG,
                            format="[%(asctime)s] %(message)s",
                            datefmt="%H:%M:%S")
    if args.command == "udev":
        return cmd_udev(args)
    path = seclave.find_port(args.port)
    if path is None:
        return fail("no Seclave found - is the device in its Usb slave menu? "
                    "(--port overrides discovery)")
    transport = seclave.open_serial(path)
    try:
        transport.open()
    except seclave.Disconnected:
        return fail(f"cannot open {path}")
    try:
        return COMMANDS[args.command](seclave.DeviceSession(transport), args)
    except seclave.Cancelled:
        return fail("declined on the device")
    except seclave.DeviceError as err:
        return fail(str(err))
    except seclave.Disconnected:
        return fail("the device went away (left the Usb slave menu, or "
                    "unplugged)")
    finally:
        transport.close()


if __name__ == "__main__":
    sys.exit(main())
