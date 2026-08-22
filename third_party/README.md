# `third_party/`

Source that came from somewhere else.

Everything under this directory is **adapted from a third-party project**, kept
here deliberately rather than depended on. Each subdirectory carries a
`PROVENANCE.md` naming the upstream, the version taken, the copyright holder,
the license it was taken under, and what was changed — and its own license text.

`NOTICE` lists every one of them. If a directory here is not in `NOTICE`, that
is a bug in this repository, not a detail.

## Why vendored rather than depended on

Both are supply chain; they fail differently. A dependency is live — it
updates, its own dependencies update, and the reviewable unit is a version
requirement rather than a body of code. Vendored source is frozen: reviewed once
in full, at a known version, changing only when somebody changes it here.

That is a worse deal for maintenance and a better one for a kernel, which is
why `tools/check-deps.py` refuses new external dependencies by default and why
the kernel still has none.

## The rule

**Vendored code is code this project ships.** A license grant covers the right
to use it. It does not make it correct, it does not transfer responsibility for
it, and it does not exempt it from anything: it is reviewed as our own work,
budgeted as our own, held to the same coding standards, and tested here rather
than trusted because it was tested elsewhere.
