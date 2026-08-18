// SPDX-License-Identifier: Apache-2.0
//! `mkimage`: the boot image as a function of the package set.
//!
//! [RFC 0030](../../../docs/rfc/0030-packages.md) step 2. The initrd stops
//! being a hand-maintained `cp` list in the Makefile and becomes the output
//! of this tool: static files, plus every package's payloads at their
//! manifest-stated paths, plus the finished manifests themselves — sorted,
//! zero-mtime, byte-identical for the same inputs.
//!
//! # Source manifests, and why hashes are computed here
//!
//! A manifest's `file` lines carry SHA-256 digests, and a binary's digest
//! changes on every rebuild — so a checked-in manifest cannot carry one
//! without being stale by construction. The tree therefore holds
//! `manifest.in` **sources**: the manifest as it will ship, except that
//! where the final file has `file <path> sha256=… length=…` lines, the
//! source has
//!
//! ```text
//! payload <path> from <artifact, relative to the repo root>
//! ```
//!
//! and this tool reads the artifact, computes the digest and length, and
//! writes the finished line. `payload` is deliberately **not** part of
//! `bhaskix-pkg`'s grammar: it is a build-time directive, and the shipped
//! parser stays closed over what the machine will ever see.
//!
//! # The tool distrusts itself
//!
//! Every finished manifest is round-tripped through `bhaskix_pkg::manifest`
//! — the real parser, not this tool's opinion — before anything is staged,
//! and the assembled archive is read back through `bhaskix_ustar` to check
//! that every expected member is present exactly once. A generator that
//! validates its output with the consumer's own parser cannot drift from it.
//!
//! # Why `tar` writes the archive
//!
//! The Makefile's `tar --format=ustar --sort=name --owner=0 --group=0
//! --numeric-owner --mtime=@0` line is the determinism this repository has
//! trusted for every image it ever built; this tool keeps the write side
//! there and owns everything around it. Writing ustar here would mean a
//! second definition of a well-formed header, which is the thing RFC 0030
//! extracted `bhaskix-ustar` to avoid.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// One parsed `manifest.in`: the finished manifest's lines, with the
/// `payload` directives resolved out.
struct Source {
    /// The package name, from its `package` line.
    name: String,
    /// The finished manifest text, `file` lines included.
    finished: String,
    /// Payload path → artifact path, in manifest order.
    payloads: Vec<(String, PathBuf)>,
}

/// Reads a source manifest and finishes it: `payload` lines become `file`
/// lines with computed digests, everything else passes through untouched.
fn finish(source_path: &Path, root: &Path) -> Result<Source, String> {
    let text = std::fs::read_to_string(source_path)
        .map_err(|error| format!("{}: {error}", source_path.display()))?;

    let mut finished = String::new();
    let mut payloads = Vec::new();
    let mut name = None;

    for (index, line) in text.lines().enumerate() {
        let number = index + 1;
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("payload ") {
            let Some((payload, artifact)) = rest.split_once(" from ") else {
                return Err(format!(
                    "{}:{number}: payload line without ' from '",
                    source_path.display()
                ));
            };
            let (payload, artifact) = (payload.trim(), artifact.trim());
            let bytes = std::fs::read(root.join(artifact)).map_err(|error| {
                format!("{}:{number}: {artifact}: {error}", source_path.display())
            })?;
            let digest = bhaskix_pkg::sha256::digest(&bytes);
            let mut hex = String::new();
            for byte in digest {
                let _ = write!(hex, "{byte:02x}");
            }
            let _ = writeln!(
                finished,
                "file {payload} sha256={hex} length={}",
                bytes.len()
            );
            payloads.push((payload.to_string(), root.join(artifact)));
        } else {
            if let Some(rest) = trimmed.strip_prefix("package ") {
                name = Some(rest.trim().to_string());
            }
            finished.push_str(line);
            finished.push('\n');
        }
    }

    // The consumer's parser is the authority on whether this is a manifest.
    if let Err(refusal) = bhaskix_pkg::manifest::parse(finished.as_bytes()) {
        return Err(format!(
            "{}: finished manifest refused by the real parser: {refusal:?}",
            source_path.display()
        ));
    }
    let name = name.ok_or_else(|| format!("{}: no package line", source_path.display()))?;
    Ok(Source {
        name,
        finished,
        payloads,
    })
}

/// Copies `from` to `to`, creating parents.
fn place(from: &Path, to: &Path) -> Result<(), String> {
    if let Some(parent) = to.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("{}: {error}", parent.display()))?;
    }
    std::fs::copy(from, to).map_err(|error| format!("{}: {error}", to.display()))?;
    Ok(())
}

/// Emits one package as an installable `.bpk`: the finished manifest first,
/// then every payload at its path — the member order the format requires,
/// which is why this writes through `tar -T` (an explicit member list, no
/// name sort) instead of the image rule's sorted flags. Same ustar subset,
/// same determinism flags, different ordering authority.
fn emit_bpk(output: &Path, staging: &Path, root: &Path, source_path: &Path) -> Result<(), String> {
    let source = finish(source_path, root)?;
    if staging.exists() {
        std::fs::remove_dir_all(staging)
            .map_err(|error| format!("{}: {error}", staging.display()))?;
    }
    std::fs::create_dir_all(staging).map_err(|error| format!("{}: {error}", staging.display()))?;
    std::fs::write(staging.join("manifest"), source.finished.as_bytes())
        .map_err(|error| format!("manifest: {error}"))?;
    let mut members = String::from(
        "manifest
",
    );
    for (payload, artifact) in &source.payloads {
        place(artifact, &staging.join(payload))?;
        let _ = writeln!(members, "{payload}");
    }
    let list = staging.join(".members");
    std::fs::write(&list, members.as_bytes()).map_err(|error| format!("member list: {error}"))?;
    let status = std::process::Command::new("tar")
        .args([
            "--format=ustar",
            "--owner=0",
            "--group=0",
            "--numeric-owner",
            "--mtime=@0",
            "-cf",
        ])
        .arg(output)
        .arg("-C")
        .arg(staging)
        .arg("-T")
        .arg(&list)
        .status()
        .map_err(|error| format!("tar: {error}"))?;
    if !status.success() {
        return Err(format!("tar exited {status}"));
    }
    // The consumer's verdict, not this tool's: the emitted package must
    // verify with the same crate the installer uses, or nothing ships.
    let bytes = std::fs::read(output).map_err(|error| format!("{}: {error}", output.display()))?;
    bhaskix_pkg::package::verify(&bytes).map_err(|refusal| {
        format!(
            "{}: the emitted package failed verification: {refusal:?}",
            output.display()
        )
    })?;
    println!(
        "built {} ({} bytes, {} payloads, verified)",
        output.display(),
        bytes.len(),
        source.payloads.len(),
    );
    Ok(())
}

/// The tool. `mkimage <output.tar> <staging-dir> --root <repo> --static <dir>
/// --package <manifest.in>...`, or `mkimage --bpk <out.bpk> <staging> --root
/// <repo> --package <one manifest.in>`.
fn run() -> Result<(), String> {
    let mut arguments = std::env::args().skip(1);
    let first = arguments.next().ok_or("usage: mkimage <output.tar> <staging> --root <dir> [--static <dir>] --package <manifest.in>... | mkimage --bpk <out> <staging> --root <dir> --package <manifest.in>")?;
    if first == "--bpk" {
        let output = PathBuf::from(arguments.next().ok_or("--bpk needs an output path")?);
        let staging = PathBuf::from(arguments.next().ok_or("missing staging directory")?);
        let mut root = PathBuf::from(".");
        let mut source = None;
        while let Some(argument) = arguments.next() {
            match argument.as_str() {
                "--root" => root = PathBuf::from(arguments.next().ok_or("--root needs a value")?),
                "--package" => {
                    source = Some(PathBuf::from(
                        arguments.next().ok_or("--package needs a value")?,
                    ))
                }
                other => return Err(format!("unknown argument {other}")),
            }
        }
        let source = source.ok_or("--bpk needs exactly one --package")?;
        return emit_bpk(&output, &staging, &root, &source);
    }
    let output = PathBuf::from(first);
    let staging = PathBuf::from(arguments.next().ok_or("missing staging directory")?);

    let mut root = PathBuf::from(".");
    let mut static_dirs = Vec::new();
    let mut sources = Vec::new();
    // Single build artifacts the image carries at a stated member name --
    // `fs.img` today. Not packages (they are not programs and ask for no
    // authority) and not static tree files (they are built, not checked in).
    let mut loose: Vec<(String, PathBuf)> = Vec::new();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--root" => root = PathBuf::from(arguments.next().ok_or("--root needs a value")?),
            "--static" => static_dirs.push(PathBuf::from(
                arguments.next().ok_or("--static needs a value")?,
            )),
            "--package" => sources.push(PathBuf::from(
                arguments.next().ok_or("--package needs a value")?,
            )),
            "--file" => {
                let value = arguments.next().ok_or("--file needs member=path")?;
                let (member, path) = value
                    .split_once('=')
                    .ok_or_else(|| format!("--file {value}: expected member=path"))?;
                loose.push((member.to_string(), PathBuf::from(path)));
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }

    // A clean stage every run: leftovers are how a removed file survives.
    if staging.exists() {
        std::fs::remove_dir_all(&staging)
            .map_err(|error| format!("{}: {error}", staging.display()))?;
    }
    std::fs::create_dir_all(&staging).map_err(|error| format!("{}: {error}", staging.display()))?;

    // Static files first, so a package that collides with one is caught
    // below rather than silently winning.
    let mut expected: BTreeMap<String, &'static str> = BTreeMap::new();
    for directory in &static_dirs {
        copy_tree(directory, &staging, directory, &mut expected)?;
    }

    for (member, path) in &loose {
        if expected.insert(member.clone(), "build artifact").is_some() {
            return Err(format!("{member}: two owners"));
        }
        place(path, &staging.join(member))?;
    }

    for source_path in &sources {
        let source = finish(source_path, &root)?;
        for (payload, artifact) in &source.payloads {
            let target = staging.join(payload);
            if expected
                .insert(payload.clone(), "package payload")
                .is_some()
            {
                return Err(format!(
                    "{payload}: two owners — a static file and a package, or two packages"
                ));
            }
            place(artifact, &target)?;
        }
        // The finished manifest ships beside the payloads: the authority
        // that was reviewed is the authority the machine can read back.
        let manifest_member = format!("packages/{}.manifest", source.name);
        if expected
            .insert(manifest_member.clone(), "manifest")
            .is_some()
        {
            return Err(format!("{manifest_member}: duplicate package name"));
        }
        let target = staging.join(&manifest_member);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("{}: {error}", parent.display()))?;
        }
        std::fs::write(&target, source.finished.as_bytes())
            .map_err(|error| format!("{}: {error}", target.display()))?;
    }

    // The write side stays with the flags the Makefile proved.
    let status = std::process::Command::new("tar")
        .args([
            "--format=ustar",
            "--sort=name",
            "--owner=0",
            "--group=0",
            "--numeric-owner",
            "--mtime=@0",
            "-cf",
        ])
        .arg(&output)
        .arg("-C")
        .arg(&staging)
        .arg(".")
        .status()
        .map_err(|error| format!("tar: {error}"))?;
    if !status.success() {
        return Err(format!("tar exited {status}"));
    }

    // Read the archive back through the machine's own parser: every
    // expected member present exactly once, nothing unexpected.
    let bytes = std::fs::read(&output).map_err(|error| format!("{}: {error}", output.display()))?;
    let mut seen = BTreeMap::new();
    for entry in bhaskix_ustar::Archive::new(&bytes) {
        if entry.kind() != bhaskix_ustar::EntryKind::File {
            continue;
        }
        let name = String::from_utf8_lossy(entry.name());
        let name = name.strip_prefix("./").unwrap_or(&name).to_string();
        *seen.entry(name).or_insert(0u32) += 1;
    }
    for (member, origin) in &expected {
        match seen.get(member) {
            Some(1) => {}
            Some(count) => return Err(format!("{member}: {count} copies in the image")),
            None => return Err(format!("{member} ({origin}): missing from the image")),
        }
    }
    for member in seen.keys() {
        if !expected.contains_key(member) {
            return Err(format!("{member}: in the image, expected by nobody"));
        }
    }

    println!(
        "built {} ({} bytes, {} members, {} packages)",
        output.display(),
        bytes.len(),
        seen.len(),
        sources.len(),
    );
    Ok(())
}

/// Copies a directory tree into the stage, recording every file placed.
fn copy_tree(
    from: &Path,
    staging: &Path,
    base: &Path,
    expected: &mut BTreeMap<String, &'static str>,
) -> Result<(), String> {
    for entry in std::fs::read_dir(from).map_err(|error| format!("{}: {error}", from.display()))? {
        let entry = entry.map_err(|error| format!("{}: {error}", from.display()))?;
        let path = entry.path();
        if path.is_dir() {
            copy_tree(&path, staging, base, expected)?;
        } else {
            let relative = path
                .strip_prefix(base)
                .map_err(|_| format!("{}: outside its own base", path.display()))?;
            let member = relative.to_string_lossy().to_string();
            if expected.insert(member.clone(), "static file").is_some() {
                return Err(format!("{member}: two owners"));
            }
            place(&path, &staging.join(relative))?;
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("mkimage: {message}");
            ExitCode::FAILURE
        }
    }
}
