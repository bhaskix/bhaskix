// SPDX-License-Identifier: Apache-2.0
//! `audit-verify` -- checks a kept disk's audit logs, RFC 0101 step 3.
//!
//! ```text
//! audit-verify <disk-image>
//! ```
//!
//! Mounts the image with the filesystem's own reader, finds every log under
//! `/audit`, recomputes each chain, and prints one line per log: whole, with
//! its record count and head, or **broken at** the first entry that does not
//! follow from the ones before it. The exit status is 0 only if there is at
//! least one log and every log is whole.
//!
//! Something other than the writer checking the writer's work is the point:
//! `bin/auditd` reports a head, and this recomputes one from the bytes on
//! the disk.

use std::process::ExitCode;

use bhaskix_auditlog::{Break, verify};
use bhaskix_fs::{Filesystem, Image, Kind};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn why(broken: Break) -> String {
    match broken {
        Break::Torn { bytes } => format!("{bytes} byte(s) past the last whole entry"),
        Break::Previous { index } => format!(
            "entry {index}: the link it carries is not where the entries before it lead -- \
             something before it, or it, was removed, inserted or moved"
        ),
        Break::Link { index } => {
            format!("entry {index}: its record and its link disagree -- it was changed")
        }
        Break::Sequence { index, found } => {
            format!("entry {index}: it carries sequence {found}")
        }
        Break::NoAttach => "entry 0 is not the record that names the boot".to_string(),
    }
}

fn run(path: &str) -> Result<bool, String> {
    let bytes = std::fs::read(path).map_err(|error| format!("{path}: {error}"))?;
    let mut image = Image::new(&bytes);
    let mut filesystem = Filesystem::mount(&mut image)
        .map_err(|error| format!("{path}: not mountable: {error:?}"))?;
    let root = filesystem
        .root()
        .map_err(|error| format!("{path}: no root: {error:?}"))?;
    let (_, directory) = filesystem
        .lookup(&root, b"audit")
        .map_err(|_| format!("{path}: no /audit directory"))?;
    let mut names = Vec::new();
    filesystem.list(&directory, |entry| {
        names.push(entry.name[..usize::from(entry.length)].to_vec());
    });
    let mut whole = true;
    let mut logs = 0;
    for name in names {
        let shown = String::from_utf8_lossy(&name).into_owned();
        let Ok((_, inode)) = filesystem.lookup(&directory, &name) else {
            continue;
        };
        if inode.kind != Kind::File {
            continue;
        }
        logs += 1;
        let mut contents = vec![0u8; usize::try_from(inode.size).unwrap_or(0)];
        let read = filesystem.read(&inode, 0, &mut contents);
        contents.truncate(read);
        match verify(&contents) {
            Ok(verified) => println!(
                "audit/{shown}: {} records, chain whole, head {}, boot {:016x}{:016x}, \
                 {} before the reader, {} unrecorded",
                verified.records,
                hex(&verified.head),
                verified.boot[0],
                verified.boot[1],
                verified.before,
                verified.gaps,
            ),
            Err(broken) => {
                whole = false;
                println!("audit/{shown}: BROKEN at {}", why(broken));
            }
        }
    }
    if logs == 0 {
        return Err(format!("{path}: /audit holds no log"));
    }
    Ok(whole)
}

fn main() -> ExitCode {
    let mut arguments = std::env::args().skip(1);
    let (Some(path), None) = (arguments.next(), arguments.next()) else {
        eprintln!("usage: audit-verify <disk-image>");
        return ExitCode::from(2);
    };
    match run(&path) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(error) => {
            eprintln!("audit-verify: {error}");
            ExitCode::from(2)
        }
    }
}
