// SPDX-License-Identifier: MIT
// Copyright 2026 Seclave AB

//! End-to-end tests: the built seclave-ctl binary against the Python
//! library's stub device over a real pseudo-terminal - the same wire path as
//! hardware, minus the joystick. Needs python3 and the repo checkout
//! (CI has both); the stub keeps state for the lifetime of one Stub, so a
//! test can put and then get.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};

struct Stub {
    process: Child,
    port: String,
}

impl Stub {
    fn start() -> Stub {
        let python_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../python/seclave");
        let mut process = Command::new("python3")
            .args(["-m", "seclave.testing"])
            .env("PYTHONPATH", python_dir)
            .stdout(Stdio::piped())
            .spawn()
            .expect("python3 with the seclave package on PYTHONPATH");
        let mut port = String::new();
        BufReader::new(process.stdout.as_mut().unwrap())
            .read_line(&mut port)
            .unwrap();
        Stub {
            process,
            port: port.trim().to_string(),
        }
    }

    /// Run the binary against this stub; (exit code, stdout, stderr).
    fn ctl(&self, args: &[&str], stdin: Option<&str>) -> (i32, String, String) {
        let mut command = Command::new(env!("CARGO_BIN_EXE_seclave-ctl"));
        command.args(["--port", &self.port]).args(args);
        command.stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = command.spawn().unwrap();
        if let Some(text) = stdin {
            child
                .stdin
                .take()
                .unwrap()
                .write_all(text.as_bytes())
                .unwrap();
        }
        let out = child.wait_with_output().unwrap();
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }
}

impl Drop for Stub {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

#[test]
fn list_shows_seeded_entries() {
    let stub = Stub::start();
    let (code, out, _) = stub.ctl(&["list"], None);
    assert_eq!(code, 0);
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines.contains(&"gmail"), "{out}");
    assert!(lines.contains(&"github"), "{out}");
    assert_eq!(lines.len(), 6); // 3 entries + 3 web logins
}

#[test]
fn get_each_field() {
    let stub = Stub::start();
    for (field, expected) in [
        ("group", "personal"),
        ("username", "alice@example.com"),
        ("password", "hunter2"),
        ("optional", "notes"),
    ] {
        let (code, out, _) = stub.ctl(&["get", "gmail", field], None);
        assert_eq!((code, out.trim()), (0, expected), "{field}");
    }
}

#[test]
fn get_missing_entry_fails_cleanly() {
    let stub = Stub::start();
    let (code, _, err) = stub.ctl(&["get", "nosuch", "password"], None);
    assert_eq!(code, 1);
    assert!(err.contains("not found"), "{err}");
}

#[test]
fn put_then_get_roundtrip() {
    let stub = Stub::start();
    let (code, _, err) = stub.ctl(
        &[
            "put",
            "new-entry",
            "--group",
            "work",
            "--username",
            "carol",
            "--password-stdin",
        ],
        Some("pw123\n"),
    );
    assert_eq!(code, 0, "{err}");
    let (code, out, _) = stub.ctl(&["get", "new-entry", "password"], None);
    assert_eq!((code, out.trim()), (0, "pw123"));
}

#[test]
fn put_rejects_bad_label_before_sending() {
    let stub = Stub::start();
    let (code, _, err) = stub.ctl(&["put", "bad label!", "--password", "x"], None);
    assert_eq!(code, 1);
    assert!(err.contains("label"), "{err}");
    let (_, out, _) = stub.ctl(&["list"], None);
    assert!(!out.contains("bad label!"));
}

#[test]
fn del_removes_and_second_del_fails() {
    let stub = Stub::start();
    assert_eq!(stub.ctl(&["del", "gmail"], None).0, 0);
    assert_eq!(stub.ctl(&["del", "gmail"], None).0, 1);
}

#[test]
fn get_www_first_and_all() {
    let stub = Stub::start();
    let (code, out, _) = stub.ctl(&["get-www", "github.com"], None);
    assert_eq!((code, out.as_str()), (0, "alice\twebpass-a\n"));
    let (code, out, _) = stub.ctl(&["get-www", "github.com", "--all"], None);
    assert_eq!(code, 0);
    assert_eq!(
        out.lines().collect::<Vec<_>>(),
        vec!["alice\twebpass-a", "bob\twebpass-b"]
    );
}

#[test]
fn put_www_normalizes_refuses_duplicates_and_forces() {
    let stub = Stub::start();
    // URL in, bare host stored.
    let (code, _, err) = stub.ctl(
        &[
            "put-www",
            "https://new.example.com/login",
            "dave",
            "--password",
            "pw",
        ],
        None,
    );
    assert_eq!(code, 0, "{err}");
    let (_, out, _) = stub.ctl(&["list-www"], None);
    assert!(out.contains("new.example.com\tdave"), "{out}");
    // Duplicate (domain case-folded) refused, then forced through.
    let (code, _, err) = stub.ctl(
        &["put-www", "GITHUB.COM", "alice", "--password", "pw2"],
        None,
    );
    assert_eq!(code, 1);
    assert!(err.contains("already exists"), "{err}");
    let (code, _, _) = stub.ctl(
        &[
            "put-www",
            "github.com",
            "alice",
            "--password",
            "pw2",
            "--force",
        ],
        None,
    );
    assert_eq!(code, 0);
    let (_, out, _) = stub.ctl(&["get-www", "github.com"], None);
    assert_eq!(out, "alice\tpw2\n");
}

#[test]
fn del_www() {
    let stub = Stub::start();
    assert_eq!(stub.ctl(&["del-www", "github.com", "bob"], None).0, 0);
    let (_, out, _) = stub.ctl(&["get-www", "github.com", "--all"], None);
    assert_eq!(out.lines().count(), 1);
}

#[test]
fn udev_show_needs_no_device() {
    let stub = Stub::start(); // unused port; udev must not touch it
    let mut command = Command::new(env!("CARGO_BIN_EXE_seclave-ctl"));
    let out = command.args(["udev", "show"]).output().unwrap();
    drop(stub);
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("idVendor}==\"20a0\""), "{text}");
    assert!(text.contains("SYMLINK+=\"seclave\""), "{text}");
}

#[test]
fn udev_install_writes_the_rule() {
    let dir = std::env::temp_dir().join(format!("seclave-ctl-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("60-seclave.rules");
    let out = Command::new(env!("CARGO_BIN_EXE_seclave-ctl"))
        .args(["udev", "install", "--path", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let written = std::fs::read_to_string(&path).unwrap();
    assert!(written.contains("ID_MM_DEVICE_IGNORE"));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn version_and_usage() {
    let out = Command::new(env!("CARGO_BIN_EXE_seclave-ctl"))
        .arg("--version")
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("seclave-ctl "));
    let out = Command::new(env!("CARGO_BIN_EXE_seclave-ctl"))
        .arg("frobnicate")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}
