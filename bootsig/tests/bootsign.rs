// SPDX-License-Identifier: Apache-2.0
//! `bootsign` driven as a person would drive it: the binary, real files, and
//! its exit status. The first place `check` is seen *accepting* a boot set,
//! because this is the first place one is signed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

const BOOTSIGN: &str = env!("CARGO_BIN_EXE_bootsign");

/// A fresh scratch directory per test, under the system's temporary
/// directory and so outside any git work tree.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("bootsign-test-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    /// An ESP with a kernel, an initrd and, if given, a `boot.conf`.
    fn esp(&self, boot_conf: Option<&[u8]>) -> PathBuf {
        let esp = self.0.join("esp");
        fs::create_dir_all(esp.join("bhaskix")).unwrap();
        fs::write(esp.join("bhaskix/kernel"), b"\x7fELF a kernel").unwrap();
        fs::write(esp.join("bhaskix/initrd.tar"), b"an initrd").unwrap();
        if let Some(conf) = boot_conf {
            fs::write(esp.join("bhaskix/boot.conf"), conf).unwrap();
        }
        esp
    }

    /// A key made by `bootsign keygen`; returns (secret, public).
    fn key(&self) -> (PathBuf, PathBuf) {
        let keys = self.0.join("keys");
        let out = run(&["keygen"], &[("BHASKIX_KEYS", keys.as_os_str())]);
        assert!(out.status.success(), "{}", text(&out));
        let mut secret = None;
        let mut public = None;
        for entry in fs::read_dir(&keys).unwrap() {
            let path = entry.unwrap().path();
            match path.extension().and_then(|e| e.to_str()) {
                Some("secret") => secret = Some(path),
                Some("public") => public = Some(path),
                _ => {}
            }
        }
        (secret.unwrap(), public.unwrap())
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run(args: &[&str], env: &[(&str, &std::ffi::OsStr)]) -> Output {
    let mut command = Command::new(BOOTSIGN);
    command.args(args);
    for (key, value) in env {
        command.env(key, value);
    }
    command.output().unwrap()
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn path(p: &Path) -> &str {
    p.to_str().unwrap()
}

#[test]
fn keygen_writes_outside_the_tree_with_private_permissions() {
    let scratch = Scratch::new();
    let (secret, public) = scratch.key();
    assert_eq!(fs::metadata(&secret).unwrap().len(), 64);
    assert_eq!(fs::metadata(&public).unwrap().len(), 32);
    assert_eq!(
        fs::metadata(&secret).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let dir = secret.parent().unwrap();
    assert_eq!(
        fs::metadata(dir).unwrap().permissions().mode() & 0o777,
        0o700
    );
}

#[test]
fn keygen_refuses_a_directory_inside_a_git_work_tree() {
    let scratch = Scratch::new();
    fs::create_dir_all(scratch.0.join("repo/.git")).unwrap();
    let keys = scratch.0.join("repo/somewhere/keys");
    let out = run(&["keygen"], &[("BHASKIX_KEYS", keys.as_os_str())]);
    assert!(!out.status.success());
    assert!(
        text(&out).contains("inside the git work tree"),
        "{}",
        text(&out)
    );
    assert!(!keys.exists(), "nothing may be written when it refuses");
}

#[test]
fn a_signed_boot_set_is_verified_and_a_changed_one_is_not() {
    let scratch = Scratch::new();
    let (secret, public) = scratch.key();
    let esp = scratch.esp(Some(b"cmdline=\n"));
    let out = run(&["sign", "--key", path(&secret), path(&esp)], &[]);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(
        fs::metadata(esp.join("bhaskix/boot.sig")).unwrap().len(),
        7984
    );

    let out = run(&["show", path(&esp), "--public", path(&public)], &[]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("verified: key"), "{}", text(&out));

    // Without a key, show reports and does not judge.
    let out = run(&["show", path(&esp)], &[]);
    assert!(out.status.success());
    assert!(
        text(&out).contains("signature not checked"),
        "{}",
        text(&out)
    );

    // One byte of the kernel changed: named, and not verified.
    fs::write(esp.join("bhaskix/kernel"), b"\x7fELF a kernel!").unwrap();
    let out = run(&["show", path(&esp), "--public", path(&public)], &[]);
    assert!(!out.status.success());
    let said = text(&out);
    assert!(said.contains("DIFFERS"), "{said}");
    assert!(
        said.contains("the kernel is not the one boot.sig names"),
        "{said}"
    );
}

#[test]
fn an_absent_boot_conf_is_signed_as_empty() {
    let scratch = Scratch::new();
    let (secret, public) = scratch.key();
    let esp = scratch.esp(None);
    assert!(
        run(&["sign", "--key", path(&secret), path(&esp)], &[])
            .status
            .success()
    );
    assert!(
        run(&["show", path(&esp), "--public", path(&public)], &[])
            .status
            .success()
    );
    // And a boot.conf that appears afterwards is a different boot set.
    fs::write(esp.join("bhaskix/boot.conf"), b"").unwrap();
    assert!(
        run(&["show", path(&esp), "--public", path(&public)], &[])
            .status
            .success()
    );
    fs::write(esp.join("bhaskix/boot.conf"), b"cmdline=x\n").unwrap();
    assert!(
        !run(&["show", path(&esp), "--public", path(&public)], &[])
            .status
            .success()
    );
}

#[test]
fn signing_is_hedged_so_two_signatures_differ_and_both_verify() {
    let scratch = Scratch::new();
    let (secret, public) = scratch.key();
    let esp = scratch.esp(None);
    assert!(
        run(&["sign", "--key", path(&secret), path(&esp)], &[])
            .status
            .success()
    );
    let first = fs::read(esp.join("bhaskix/boot.sig")).unwrap();
    assert!(
        run(&["sign", "--key", path(&secret), path(&esp)], &[])
            .status
            .success()
    );
    let second = fs::read(esp.join("bhaskix/boot.sig")).unwrap();
    assert_eq!(first[..128], second[..128], "the statement is the same");
    assert_ne!(first[128..], second[128..], "the signatures are not");
    assert!(
        run(&["show", path(&esp), "--public", path(&public)], &[])
            .status
            .success()
    );
}

#[test]
fn a_damaged_secret_key_is_refused_and_nothing_is_written() {
    let scratch = Scratch::new();
    let (secret, _) = scratch.key();
    let mut bytes = fs::read(&secret).unwrap();
    bytes[63] ^= 1; // PK.root's last byte: signatures it makes cannot verify
    fs::write(&secret, &bytes).unwrap();
    let esp = scratch.esp(None);
    let out = run(&["sign", "--key", path(&secret), path(&esp)], &[]);
    assert!(!out.status.success());
    assert!(text(&out).contains("does not verify"), "{}", text(&out));
    assert!(
        !esp.join("bhaskix/boot.sig").exists(),
        "a boot.sig that fails was written"
    );
}

#[test]
fn a_key_file_of_the_wrong_size_is_refused() {
    let scratch = Scratch::new();
    let bad = scratch.0.join("short.secret");
    fs::write(&bad, [0u8; 63]).unwrap();
    let esp = scratch.esp(None);
    let out = run(&["sign", "--key", path(&bad), path(&esp)], &[]);
    assert!(!out.status.success());
    assert!(text(&out).contains("63 bytes"), "{}", text(&out));
}

#[test]
fn the_test_key_is_named_as_one_wherever_it_signs() {
    let scratch = Scratch::new();
    let keys = Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/keys");
    let esp = scratch.esp(None);
    let secret = keys.join("bootsig-TEST-KEY.secret");
    let out = run(&["sign", "--key", path(&secret), path(&esp)], &[]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("TEST KEY"), "{}", text(&out));
    let public = keys.join("bootsig-TEST-KEY.public");
    let out = run(&["show", path(&esp), "--public", path(&public)], &[]);
    assert!(text(&out).contains("TEST KEY"), "{}", text(&out));
}
