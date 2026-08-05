// SPDX-License-Identifier: Apache-2.0
//! Reads the placement table, so that `services.toml` decides what gets built.
//!
//! RFC 0013's claim is that moving a service between the nucleus and its own
//! domain is one line in one file. This is the line's other end: for every
//! service in the table, a `cfg` saying where it goes, which the kernel uses to
//! choose between starting a thread and loading a program.
//!
//! It emits a `cfg` and not a string. A string could be printed while the
//! kernel did something else entirely; a `cfg` compiles one of the two paths
//! and not the other, so the table cannot disagree with the build. What the
//! *machine* did is reported separately, from what actually happened, and the
//! boot gate compares that with the table — because a build that reads the
//! table and a report generated from the same table would agree with each other
//! whatever the machine did.

// The workspace denies `panic!` because a panic in the nucleus is a denial of
// service (docs/coding-style.md §4). This is not the nucleus: it is a program
// that runs on a developer's machine and whose only job is to read one file.
// Failing loudly here stops a bad table at the build, which is the whole point
// of reading it at build time -- returning a default would place a service
// somewhere nobody asked for and say nothing.
#![allow(clippy::panic, clippy::expect_used)]

use std::path::Path;

fn main() {
    let table = Path::new("..").join("services.toml");
    println!("cargo::rerun-if-changed={}", table.display());
    println!("cargo::rustc-check-cfg=cfg(vfs_in_domain)");

    // The override RFC 0013 resolved question 3 with. It exists so that CI can
    // build *both* placements of a service from one tree: without it, testing
    // the other placement would mean editing the table, and a test that edits
    // the file it is testing is not testing it.
    println!("cargo::rerun-if-env-changed=BHASKIX_PLACEMENT_VFS");
    if let Ok(placement) = std::env::var("BHASKIX_PLACEMENT_VFS") {
        match placement.as_str() {
            "domain" => println!("cargo::rustc-cfg=vfs_in_domain"),
            "nucleus" => {}
            other => panic!("BHASKIX_PLACEMENT_VFS={other:?} is not a placement"),
        }
        return;
    }

    let text = std::fs::read_to_string(&table)
        .unwrap_or_else(|error| panic!("{}: {error}", table.display()));

    let mut name = String::new();
    for line in text.lines() {
        let line = line.trim();
        if let Some(value) = line.strip_prefix("name") {
            name = unquote(value);
        } else if let Some(value) = line.strip_prefix("placement") {
            let placement = unquote(value);
            match placement.as_str() {
                "nucleus" | "domain" => {}
                other => panic!("services.toml: {name} has placement {other:?}"),
            }
            if name == "vfs" && placement == "domain" {
                println!("cargo::rustc-cfg=vfs_in_domain");
            }
        }
    }
}

/// `= "value"` -> `value`.
fn unquote(value: &str) -> String {
    value
        .trim_start()
        .trim_start_matches('=')
        .trim()
        .trim_matches('"')
        .to_string()
}
