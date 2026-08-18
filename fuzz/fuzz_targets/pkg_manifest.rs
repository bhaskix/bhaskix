// SPDX-License-Identifier: Apache-2.0
//! Coverage-guided fuzzing of the package manifest grammar.
//!
//! RFC 0030: the manifest is the reviewable half of a package — the file a
//! human reads to know what authority a program asks for. It is also the
//! first thing an installer parses out of an archive an operator was handed,
//! which makes it hostile input by definition, and `docs/coding-style.md` §8
//! applies before it merges.
//!
//! # What counts as a failure
//!
//! A panic, an abort, or a hang. **Not** a refusal: random bytes are not a
//! manifest and refusing them with a line number is the correct answer. What
//! must never happen is an index past a fixed array's count, arithmetic that
//! wraps in the decimal or hex readers, or an accepted manifest whose
//! accessors then disagree with what was accepted.
//!
//! On success, everything a consumer reads is read: the name, the version,
//! every program's path and capability list, every file line's fields — so a
//! parse that "succeeds" into a state whose accessors panic shows up here
//! and not in an installer.
//!
//! Run with:
//!
//! ```text
//! cargo +nightly fuzz run pkg_manifest -- -max_total_time=3600
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

use bhaskix_pkg::manifest;

fuzz_target!(|data: &[u8]| {
    if let Ok(parsed) = manifest::parse(data) {
        let _ = parsed.name;
        let _ = parsed.version;
        for program in parsed.programs() {
            let _ = program.path;
            let _ = program.entry_declared;
            for cap in program.caps() {
                let _ = cap;
            }
            // The cross-check `parse` promises: an accepted program always
            // has its file line.
            assert!(parsed.file(program.path).is_some());
        }
        for file in parsed.files() {
            let _ = file.sha256;
            let _ = file.length;
        }
    }
});
