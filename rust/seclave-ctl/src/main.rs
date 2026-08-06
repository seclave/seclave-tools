// SPDX-License-Identifier: MIT
// Copyright 2026 Seclave AB

//! seclave-ctl - command-line client for the Seclave hardware password
//! manager, on the `seclave` protocol crate.
//!
//! Same commands as the Python seclave-ctl (the two are ports of each
//! other): list/get/put/del, the web-login (-www) variants, and `udev` for
//! the Linux serial-access rule. Reads print the value to stdout so it can
//! be piped; the device asks for confirmation on its own screen before
//! releasing a secret.

#![forbid(unsafe_code)]

mod session;

use std::io::BufRead;
use std::process::ExitCode;

use session::{CtlError, Session};
use zeroize::{Zeroize, Zeroizing};

const USAGE: &str = "\
usage: seclave-ctl [--port PATH] COMMAND ...

  list                          list entry labels
  list-www                      list web logins as domain<TAB>username
  get LABEL FIELD               print one field (group|username|password|optional)
  put LABEL [--group G] [--username U] [--optional O]
            (--password P | --password-stdin)
  del LABEL
  get-www DOMAIN [--all]        print login(s) as username<TAB>password
  put-www DOMAIN USERNAME (--password P | --password-stdin) [--force]
  del-www DOMAIN USERNAME
  udev show|install [--path P]  the Linux serial-access udev rule
  --version

The port is found by USB VID/PID (or a udev-provided /dev/seclave);
--port overrides. Prefer --password-stdin over --password, which is
visible in the process list.";

/// The same rule the Python library embeds and the seclave-companion
/// deb/rpm ships; CI checks the copies against each other.
const UDEV_RULES: &str = include_str!("60-seclave.rules");
const UDEV_DEFAULT_PATH: &str = "/etc/udev/rules.d/60-seclave.rules";

fn fail(message: &str) -> ExitCode {
    eprintln!("seclave-ctl: {message}");
    ExitCode::FAILURE
}

fn usage(message: &str) -> ExitCode {
    eprintln!("seclave-ctl: {message}\n\n{USAGE}");
    ExitCode::from(2)
}

/// Minimal flag scanner: pulls `--name value` and `--name` options out of a
/// command's arguments, leaving positionals in order.
struct Args {
    positional: Vec<String>,
    options: Vec<(String, Option<String>)>,
}

impl Args {
    fn parse(raw: &[String], value_options: &[&str], flags: &[&str]) -> Result<Args, String> {
        let mut positional = Vec::new();
        let mut options = Vec::new();
        let mut iter = raw.iter();
        while let Some(arg) = iter.next() {
            if let Some(name) = arg.strip_prefix("--") {
                if value_options.contains(&name) {
                    match iter.next() {
                        Some(value) => options.push((name.into(), Some(value.clone()))),
                        None => return Err(format!("--{name} needs a value")),
                    }
                } else if flags.contains(&name) {
                    options.push((name.into(), None));
                } else {
                    return Err(format!("unknown option --{name}"));
                }
            } else {
                positional.push(arg.clone());
            }
        }
        Ok(Args {
            positional,
            options,
        })
    }

    fn option(&self, name: &str) -> Option<&str> {
        self.options
            .iter()
            .find(|(n, _)| n == name)
            .and_then(|(_, v)| v.as_deref())
    }

    fn flag(&self, name: &str) -> bool {
        self.options.iter().any(|(n, _)| n == name)
    }
}

/// The password for a put: --password, or one line from stdin. No
/// interactive prompt in this port yet; --password-stdin covers scripts and
/// `read -s`-style interactive use.
fn read_password(args: &Args) -> Result<Zeroizing<String>, String> {
    if let Some(password) = args.option("password") {
        // The argv copy stays visible to the OS regardless; that is why the
        // usage text steers people to --password-stdin.
        return Ok(Zeroizing::new(password.to_string()));
    }
    if args.flag("password-stdin") {
        let mut line = String::new();
        if std::io::stdin().lock().read_line(&mut line).unwrap_or(0) == 0 {
            return Err("empty stdin".into());
        }
        let password = Zeroizing::new(line.trim_end_matches('\n').to_string());
        line.zeroize();
        return Ok(password);
    }
    Err("no password given (use --password-stdin, or --password)".into())
}

fn print_secret(bytes: session::Secret, terminator: char) {
    // The transient String is wiped too; stdout itself is the copy this
    // tool cannot control (printing the secret is its purpose).
    let text = Zeroizing::new(session::latin1_str(&bytes));
    print!("{}{terminator}", *text);
}

fn cmd_udev(args: &Args) -> ExitCode {
    let action = args.positional[0].as_str();
    if action == "show" {
        print!("{UDEV_RULES}");
        return ExitCode::SUCCESS;
    }
    if action != "install" {
        return usage("udev needs an action: show or install");
    }
    if !cfg!(target_os = "linux") {
        return fail(
            "udev rules are a Linux mechanism; on macOS and Windows \
             the port works without setup",
        );
    }
    let path = args.option("path").unwrap_or(UDEV_DEFAULT_PATH);
    if let Err(err) = std::fs::write(path, UDEV_RULES) {
        return fail(&format!(
            "cannot write {path} ({err}) - run with sudo, or: \
             seclave-ctl udev show | sudo tee {path}"
        ));
    }
    // Best-effort reload, as the deb/rpm postinstall does: without a udev
    // daemon the rule simply applies from the next boot.
    for reload in [
        vec!["control", "--reload-rules"],
        vec!["trigger", "--subsystem-match=usb", "--subsystem-match=tty"],
    ] {
        let _ = std::process::Command::new("udevadm")
            .args(&reload)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
    println!("wrote {path} and reloaded udev; replug the device");
    ExitCode::SUCCESS
}

fn run(command: &str, args: &Args, session: &mut Session) -> Result<(), CtlError> {
    match command {
        "list" => {
            for label in session.list_labels()? {
                println!("{label}");
            }
        }
        "list-www" => {
            for (domain, username) in session.list_wwwfill()? {
                println!("{domain}\t{username}");
            }
        }
        "get" => {
            let opcode = match args.positional[1].as_str() {
                "group" => seclave::OP_GET_GROUP,
                "username" => seclave::OP_GET_USERNAME,
                "password" => seclave::OP_GET_PASSWORD,
                "optional" => seclave::OP_GET_OPTIONAL,
                other => {
                    return Err(CtlError::BadInput(format!(
                        "unknown field {other:?} (group|username|password|optional)"
                    )))
                }
            };
            let value = session.get_field(opcode, &args.positional[0])?;
            print_secret(value, '\n');
        }
        "put" => {
            let label = &args.positional[0];
            let group = args.option("group").unwrap_or("");
            let username = args.option("username").unwrap_or("");
            let optional = args.option("optional").unwrap_or("");
            let password = read_password(args).map_err(CtlError::BadInput)?;
            session::validate_restricted(label, seclave::MAX_LABEL, "label", false)?;
            session::validate_restricted(group, seclave::MAX_GROUP, "group", true)?;
            session::validate_freeform(username, seclave::MAX_USERNAME, "username")?;
            session::validate_freeform(&password, seclave::MAX_PASSWORD, "password")?;
            session::validate_freeform(optional, seclave::MAX_OPTIONAL, "optional")?;
            session.put_entry(label, group, username, &password, optional)?;
        }
        "del" => session.del_entry(&args.positional[0])?,
        "get-www" => {
            let domain = &args.positional[0];
            let mut index = 0;
            loop {
                let (username, password, more) = session.get_wwwfill(domain, index)?;
                print_secret(username, '\t');
                print_secret(password, '\n');
                if !(args.flag("all") && more) {
                    break;
                }
                index += 1;
            }
        }
        "put-www" => {
            let domain = session::normalize_domain(&args.positional[0]);
            let username = &args.positional[1];
            let password = read_password(args).map_err(CtlError::BadInput)?;
            session::validate_freeform(username, seclave::MAX_USERNAME, "username")?;
            session::validate_freeform(&password, seclave::MAX_PASSWORD, "password")?;
            if !args.flag("force") {
                // A (domain, username) duplicate can lock up firmware 2.6 and
                // earlier, so refuse unless told otherwise.
                let key = session::wwwfill_key(&domain, username)?;
                for (have_domain, have_username) in session.list_wwwfill()? {
                    if session::wwwfill_key(&have_domain, &have_username)? == key {
                        return Err(CtlError::BadInput(format!(
                            "a web password for {have_domain} / {have_username} \
                             already exists (domains match case-insensitively); \
                             duplicates can lock up Seclave firmware 2.6 and \
                             earlier (--force overrides)"
                        )));
                    }
                }
            }
            session.put_wwwfill(&domain, username, &password)?;
        }
        "del-www" => {
            session.del_wwwfill(&args.positional[0], &args.positional[1])?;
        }
        _ => unreachable!("dispatch checked the command"),
    }
    Ok(())
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.iter().any(|a| a == "--version") {
        println!("seclave-ctl {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    // The one global option; everything after the command belongs to it.
    let (port_override, rest) = match argv.first().map(String::as_str) {
        Some("--port") => match argv.get(1) {
            Some(path) => (Some(path.clone()), &argv[2..]),
            None => return usage("--port needs a value"),
        },
        _ => (None, &argv[..]),
    };
    let Some(command) = rest.first().map(String::as_str) else {
        return usage("no command given");
    };
    // (positional argument count, value options, flags)
    let spec: (usize, &[&str], &[&str]) = match command {
        "list" | "list-www" => (0, &[], &[]),
        "get" => (2, &[], &[]),
        "put" => (
            1,
            &["group", "username", "password", "optional"],
            &["password-stdin"],
        ),
        "del" => (1, &[], &[]),
        "get-www" => (1, &[], &["all"]),
        "put-www" => (2, &["password"], &["password-stdin", "force"]),
        "del-www" => (2, &[], &[]),
        "udev" => (1, &["path"], &[]),
        other => return usage(&format!("unknown command {other:?}")),
    };
    let args = match Args::parse(&rest[1..], spec.1, spec.2) {
        Ok(args) => args,
        Err(message) => return usage(&message),
    };
    if args.positional.len() != spec.0 {
        return usage(&format!("{command} takes {} argument(s)", spec.0));
    }
    if command == "udev" {
        return cmd_udev(&args); // needs no device
    }
    let Some(path) = port_override.or_else(session::find_port) else {
        return fail(
            "no Seclave found - is the device in its Usb slave menu? \
             (--port overrides discovery)",
        );
    };
    let mut session = match Session::open(&path) {
        Ok(session) => session,
        Err(err) => return fail(&err.to_string()),
    };
    match run(command, &args, &mut session) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => fail(&err.to_string()),
    }
}
