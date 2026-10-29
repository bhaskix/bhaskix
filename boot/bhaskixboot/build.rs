// SPDX-License-Identifier: Apache-2.0
//! The boot-set public keys this loader trusts, compiled in -- RFC 0091 link 2.
//!
//! `BHASKIX_BOOT_KEYS=<file.public>[:<file.public>...]` names them: each a
//! 32-byte SLH-DSA-SHA2-128s public key as `bootsign keygen` writes it. Unset,
//! the loader trusts the project's **published test key**,
//! `tests/keys/bootsig-TEST-KEY.public`, which the lanes and CI sign with and
//! the boot report names in red. A loader that trusts it accepts anything
//! anyone signs, so the release recipe refuses to build one (RFC 0091 step 5).
//!
//! The keys are in the loader's image, so link 1 -- the firmware's check of
//! that image -- covers them.

// The workspace denies `panic!` and `expect` because a panic on the machine is
// a denial of service. This runs on a developer's machine, once, to read key
// files: failing loudly stops a missing or wrong-sized key at the build,
// instead of shipping a loader that trusts nothing or the wrong thing.
#![allow(clippy::panic, clippy::expect_used)]

use std::path::PathBuf;

fn main() {
    println!("cargo::rerun-if-env-changed=BHASKIX_BOOT_KEYS");
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets it"));
    let paths: Vec<PathBuf> = match std::env::var("BHASKIX_BOOT_KEYS") {
        Ok(list) if !list.is_empty() => list.split(':').map(PathBuf::from).collect(),
        _ => vec![manifest.join("../../tests/keys/bootsig-TEST-KEY.public")],
    };
    let mut out = String::from("/// The boot-set public keys compiled in, by `build.rs`.\n");
    out.push_str("pub const KEYS: &[[u8; 32]] = &[\n");
    for path in &paths {
        println!("cargo::rerun-if-changed={}", path.display());
        let bytes = std::fs::read(path)
            .unwrap_or_else(|error| panic!("boot key {}: {error}", path.display()));
        if bytes.len() != 32 {
            panic!(
                "boot key {} is {} bytes; a public key is 32",
                path.display(),
                bytes.len()
            );
        }
        out.push_str(&format!("    {bytes:?},\n"));
    }
    out.push_str("];\n");
    let dest = PathBuf::from(std::env::var("OUT_DIR").expect("cargo sets it")).join("keys.rs");
    std::fs::write(dest, out).expect("OUT_DIR is writable");
}
