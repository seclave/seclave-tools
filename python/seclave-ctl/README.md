# seclave-ctl

Command-line client for the Seclave hardware password manager. Put the
device in its "Usb slave" menu, then:

```
seclave-ctl list
seclave-ctl get gmail password | wl-copy
seclave-ctl put backup-mail --group personal --username bob --password-stdin
seclave-ctl del old-entry

seclave-ctl list-www
seclave-ctl get-www github.com --all
seclave-ctl put-www github.com alice --password-stdin
seclave-ctl del-www github.com alice
```

Reads print the value to stdout so it can be piped; the device asks for
confirmation on its own screen before releasing a secret, and that
confirmation - not host software - is the security boundary. Passwords for
`put`/`put-www` come from `--password-stdin` (best for scripts), an
interactive prompt, or `--password` (visible in the process list; avoid).

`put-www` refuses a (domain, username) pair the device already stores,
because duplicates can lock up Seclave firmware 2.6 and earlier;
`--force` overrides.

The port is found by USB VID/PID (or a udev-provided `/dev/seclave`);
`--port` overrides. On Linux you need serial access, and pip cannot install
system configuration, so the tool carries the udev rule itself:

```
sudo seclave-ctl udev install      # or inspect first: seclave-ctl udev show
```

It grants the logged-in user access, keeps ModemManager off the port, and
creates a stable `/dev/seclave` - the same rule the `seclave-companion`
deb/rpm installs (having both is harmless). Alternatives: add your user to
the `dialout` group. Exit code 0 on success, 1 on any failure (including
the user declining on the device), 2 on usage errors.

Built on the [seclave](https://pypi.org/project/seclave/) library; both live
in the [seclave-tools](https://github.com/seclave/seclave-tools) repo.

## License

MIT - see [LICENSE](LICENSE).

Seclave is a trademark of Seclave AB. This license grants no trademark rights.
