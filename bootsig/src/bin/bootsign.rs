// SPDX-License-Identifier: Apache-2.0
//! `bootsign`: makes and reads `bhaskix\boot.sig` (RFC 0091 step 2).
//!
//! Named after `sbsign`, the tool that signs the loader itself for the
//! firmware (link 1). This one signs the boot set the loader checks
//! (link 2):
//!
//! ```text
//! bootsign keygen [--test]                      a key pair, outside the tree
//! bootsign sign --key <file.secret> <esp-dir>   writes <esp-dir>/bhaskix/boot.sig
//! bootsign show <esp-dir> [--public <file>]...  what the loader would decide
//! ```
//!
//! **Keys live outside the tree** (RFC 0091 question 7, decided 2026-10-29):
//! in `$BHASKIX_KEYS`, by default `~/.bhaskix-keys/`, a `0700` directory with
//! the secret `0600`. `keygen` refuses a destination inside a git work tree,
//! because a key there is one `git add` away from being published, and it
//! never overwrites a key. `--test` writes the project's **published** test key
//! instead, to `tests/keys/` — it protects nothing, on purpose, and the report
//! names it in red wherever it signed.
//!
//! **Signing is hedged**, as the project lead chose: fresh randomness from the
//! operating system for every signature, so the same files signed twice give
//! two `boot.sig` files that both verify. Every `boot.sig` is checked with the
//! loader's own `check` before it is written; one that would not verify is
//! never written.

use bhaskix_bootsig::slh_dsa::{self, N, PUBLIC_KEY_BYTES, SECRET_KEY_BYTES};
use bhaskix_bootsig::statement::{self, BOOT_SIG_BYTES, BootSig, Digests, KeyId, TEST_KEY_ID};
use bhaskix_sha256::digest;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const GREEN: &str = "\x1b[1;32m";
const RED: &str = "\x1b[1;31m";
const DIM: &str = "\x1b[2m";
const RESET: &str = "\x1b[0m";

const USAGE: &str = "usage:
  bootsign keygen [--test]
  bootsign sign --key <file.secret> <esp-dir>
  bootsign show <esp-dir> [--public <file.public>]...";

/// The test key's file names, under `tests/keys/`.
const TEST_KEY: &str = "bootsig-TEST-KEY";

/// A refusal: what to say, and the exit status that says it.
struct Refused(String);

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("keygen") => keygen(&args[1..]),
        Some("sign") => sign(&args[1..]),
        Some("show") => show(&args[1..]),
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(Refused(why)) => {
            eprintln!("bootsign: {RED}refused{RESET}: {why}");
            ExitCode::FAILURE
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// `n` bytes from the operating system's random source.
fn random<const LEN: usize>() -> Result<[u8; LEN], Refused> {
    let mut bytes = [0; LEN];
    fs::File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut bytes))
        .map_err(|e| Refused(format!("could not read /dev/urandom: {e}")))?;
    Ok(bytes)
}

fn read(path: &Path) -> Result<Vec<u8>, Refused> {
    fs::read(path).map_err(|e| Refused(format!("could not read {}: {e}", path.display())))
}

/// The git work tree `path` would be inside, if any: its nearest existing
/// ancestor, and every directory above that, checked for `.git`.
fn work_tree_holding(path: &Path) -> Option<PathBuf> {
    let mut at = path.to_path_buf();
    while !at.exists() {
        at = at.parent()?.to_path_buf();
    }
    let at = at.canonicalize().ok()?;
    at.ancestors()
        .find(|dir| dir.join(".git").exists())
        .map(Path::to_path_buf)
}

fn keygen(args: &[String]) -> Result<(), Refused> {
    let test = match args {
        [] => false,
        [flag] if flag == "--test" => true,
        _ => return Err(Refused(format!("keygen takes only --test\n{USAGE}"))),
    };
    let (sk, pk) = slh_dsa::keygen_internal(&random::<N>()?, &random::<N>()?, &random::<N>()?);
    let id = statement::key_id(&pk);
    let (dir, name) = if test {
        if !Path::new("bootsig/Cargo.toml").exists() {
            return Err(Refused(
                "--test writes tests/keys/: run it from the repository root".into(),
            ));
        }
        (PathBuf::from("tests/keys"), TEST_KEY.to_string())
    } else {
        let dir = match std::env::var_os("BHASKIX_KEYS") {
            Some(dir) => PathBuf::from(dir),
            None => match std::env::var_os("HOME") {
                Some(home) => Path::new(&home).join(".bhaskix-keys"),
                None => return Err(Refused("neither BHASKIX_KEYS nor HOME is set".into())),
            },
        };
        if let Some(tree) = work_tree_holding(&dir) {
            return Err(Refused(format!(
                "{} is inside the git work tree at {}: a key there is one `git add` from being \
                 published. Set BHASKIX_KEYS to a directory outside it.",
                dir.display(),
                tree.display()
            )));
        }
        (dir, format!("boot-{}", hex(&id)))
    };
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
        .map_err(|e| Refused(format!("could not create {}: {e}", dir.display())))?;
    let secret = dir.join(format!("{name}.secret"));
    let public = dir.join(format!("{name}.public"));
    for (path, bytes, mode) in [(&secret, &sk[..], 0o600), (&public, &pk[..], 0o644)] {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(path)
            .map_err(|e| Refused(format!("will not write {}: {e}", path.display())))?;
        file.write_all(bytes)
            .map_err(|e| Refused(format!("could not write {}: {e}", path.display())))?;
    }
    let label = if test {
        format!(" {RED}TEST KEY{RESET}, published on purpose")
    } else {
        String::new()
    };
    println!("{GREEN}ok{RESET}    key {}{label}", hex(&id));
    println!("      secret  {}", secret.display());
    println!("      public  {}", public.display());
    Ok(())
}

fn secret_key(path: &Path) -> Result<[u8; SECRET_KEY_BYTES], Refused> {
    let bytes = read(path)?;
    bytes.as_slice().try_into().map_err(|_| {
        Refused(format!(
            "{} is {} bytes, and a secret key is {SECRET_KEY_BYTES}",
            path.display(),
            bytes.len()
        ))
    })
}

fn public_key(path: &Path) -> Result<[u8; PUBLIC_KEY_BYTES], Refused> {
    let bytes = read(path)?;
    bytes.as_slice().try_into().map_err(|_| {
        Refused(format!(
            "{} is {} bytes, and a public key is {PUBLIC_KEY_BYTES}",
            path.display(),
            bytes.len()
        ))
    })
}

/// The digests of the three files the loader reads from `esp`.
fn held(esp: &Path) -> Result<Digests, Refused> {
    let dir = esp.join("bhaskix");
    let conf = dir.join("boot.conf");
    // An absent `boot.conf` hashes as empty, which is what the loader treats it as.
    let boot_conf = if conf.exists() {
        read(&conf)?
    } else {
        Vec::new()
    };
    Ok(Digests {
        kernel: digest(&read(&dir.join("kernel"))?),
        initrd: digest(&read(&dir.join("initrd.tar"))?),
        boot_conf: digest(&boot_conf),
    })
}

fn key_label(id: &KeyId) -> String {
    if *id == TEST_KEY_ID {
        format!("{} {RED}TEST KEY{RESET}", hex(id))
    } else {
        hex(id)
    }
}

fn sign(args: &[String]) -> Result<(), Refused> {
    let [flag, key, esp] = args else {
        return Err(Refused(format!(
            "sign takes --key <file.secret> <esp-dir>\n{USAGE}"
        )));
    };
    if flag != "--key" {
        return Err(Refused(format!(
            "sign takes --key <file.secret> <esp-dir>\n{USAGE}"
        )));
    }
    let sk = secret_key(Path::new(key))?;
    let mut pk = [0; PUBLIC_KEY_BYTES];
    pk.copy_from_slice(&sk[2 * N..]);
    let id = statement::key_id(&pk);
    let esp = Path::new(esp);
    let digests = held(esp)?;
    let stmt = statement::statement(&id, &digests);
    let signature = slh_dsa::sign(&stmt, &[], &sk, Some(&random::<N>()?))
        .map_err(|e| Refused(format!("signing failed: {e:?}")))?;
    let mut file = Vec::with_capacity(BOOT_SIG_BYTES);
    file.extend_from_slice(&stmt);
    file.extend_from_slice(&signature);
    // The loader's own check, before anything is written.
    if let Err(refusal) = statement::check(&file, &[pk], &digests) {
        return Err(Refused(format!(
            "the boot.sig this made does not verify ({}): the secret key is damaged",
            refusal.describe()
        )));
    }
    let out = esp.join("bhaskix").join("boot.sig");
    fs::write(&out, &file)
        .map_err(|e| Refused(format!("could not write {}: {e}", out.display())))?;
    println!(
        "{GREEN}ok{RESET}    signed {} with key {}",
        out.display(),
        key_label(&id)
    );
    println!("      {DIM}verified before writing, with the loader's own check{RESET}");
    Ok(())
}

fn show(args: &[String]) -> Result<(), Refused> {
    let Some((esp, rest)) = args.split_first() else {
        return Err(Refused(format!(
            "show takes <esp-dir> [--public <file.public>]...\n{USAGE}"
        )));
    };
    let mut keys = Vec::new();
    let mut rest = rest;
    while let [flag, path, tail @ ..] = rest {
        if flag != "--public" {
            return Err(Refused(format!(
                "show takes --public <file.public>, not {flag}"
            )));
        }
        keys.push(public_key(Path::new(path))?);
        rest = tail;
    }
    if !rest.is_empty() {
        return Err(Refused(format!("--public needs a file\n{USAGE}")));
    }
    let esp = Path::new(esp);
    let bytes = read(&esp.join("bhaskix").join("boot.sig"))?;
    let sig = BootSig::parse(&bytes).map_err(|refusal| Refused(refusal.describe().into()))?;
    let named = sig.digests();
    let held = held(esp)?;
    println!("      boot.sig   key {}", key_label(&sig.key_id()));
    for (file, statement, read) in [
        ("kernel", named.kernel, held.kernel),
        ("initrd.tar", named.initrd, held.initrd),
        ("boot.conf", named.boot_conf, held.boot_conf),
    ] {
        let verdict = if statement == read {
            format!("{GREEN}matches{RESET}")
        } else {
            format!("{RED}DIFFERS{RESET} (read {})", hex(&read))
        };
        println!("      {file:<10} {} {verdict}", hex(&statement));
    }
    if keys.is_empty() {
        println!("      {DIM}signature not checked: no --public key given{RESET}");
        return Ok(());
    }
    match statement::check(&bytes, &keys, &held) {
        Ok(id) => {
            println!("{GREEN}ok{RESET}    verified: key {}", key_label(&id));
            Ok(())
        }
        Err(refusal) => {
            println!("{RED}FAILED{RESET} not verified: {}", refusal.describe());
            Err(Refused("the loader would not verify this boot set".into()))
        }
    }
}
