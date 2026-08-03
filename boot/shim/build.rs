// SPDX-License-Identifier: Apache-2.0
//! Points the linker at the kernel link script.
//!
//! Done here rather than in `.cargo/config.toml` so that the path is absolute.
//! A relative `-T` in rustflags resolves against the current directory, which
//! silently produces a differently-linked kernel when someone runs `cargo
//! build` from a subdirectory.

// Build scripts are host tooling, not kernel code. They run on a developer's
// machine at build time, where a panic is a build failure with a clear message
// rather than a denial of service. The workspace-wide ban on `expect` exists
// for code that runs in the nucleus (docs/coding-style.md §4).
#![allow(clippy::expect_used)]

fn main() {
    let manifest_dir =
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is always set by cargo");

    // `-bins` so the script applies to the kernel binary only, and never to a
    // host build script or a test harness.
    println!("cargo:rustc-link-arg-bins=-T{manifest_dir}/linker.ld");
    println!("cargo:rustc-link-arg-bins=-pie");
    println!("cargo:rustc-link-arg-bins=--no-dynamic-linker");

    println!("cargo:rerun-if-changed=linker.ld");
    println!("cargo:rerun-if-changed=build.rs");
}
