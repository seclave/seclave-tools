# seclave-ctl

Command-line client for the Seclave hardware password manager, in Rust.
Put the device in its "Usb slave" menu, then:

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
confirmation - not host software - is the security boundary. Host-side,
every buffer that holds secret bytes is wiped on drop (zeroize) and the
receive buffer never reallocates; the copies the tool cannot control are
the kernel's tty buffer and stdout itself. Passwords for
`put`/`put-www` come from `--password-stdin` (best for scripts; also works
interactively with `read -s`) or `--password` (visible in the process
list; avoid). `put-www` refuses a (domain, username) pair the device
already stores, because duplicates can lock up Seclave firmware 2.6 and
earlier; `--force` overrides.

The port is found by USB VID/PID (or a udev-provided `/dev/seclave`);
`--port` overrides. On Linux the port needs access rights, and the tool
carries the udev rule itself:

```
sudo seclave-ctl udev install    # or inspect first: seclave-ctl udev show
```

A Python [seclave-ctl](https://pypi.org/project/seclave-ctl/) with the
same commands exists; the two are ports of each other, built on their
languages' `seclave` protocol libraries and held to the same bytes by the
shared conformance vectors in the
[seclave-tools](https://github.com/seclave/seclave-tools) repo.

## License

MIT.

Seclave is a trademark of Seclave AB. This license grants no trademark rights.
