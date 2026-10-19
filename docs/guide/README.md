<!-- SPDX-License-Identifier: Apache-2.0 -->

# Guides

How to use Bhaskix as it is today: boot it, use it, and see what it does.
These are not the design documents. [architecture.md](../architecture.md) says
why the system is shaped the way it is; the guides say what to type.

| Guide | What it covers |
|---|---|
| [Get started](get-started.md) | Download and check the release, boot it in QEMU three ways, try your first commands, and leave |
| [The shell and packages](shell-and-packages.md) | Every shell command, what holding a capability means, installing a package, and the kernel's own shell |
| [Linux programs](linux-programs.md) | What "hosted" means, an unmodified Go web server answering your browser, BusyBox for source builds, and what is refused and why |

## How these are written

- **Every command shown was run**, and the output shown is a transcript of that
  run. Long output is trimmed with `…`; nothing is edited.
- **Each guide says when it was last verified, and against what**: a commit, or
  a release's tag. Bhaskix changes quickly, and a guide is only as true as the
  build it was checked against.
- **A guide can only name commands the shell has.** `make gates` reads each
  shell's own command table and refuses a guide that names a command it lacks
  (`tools/check-guides.py`).
- **Limits are stated where you would meet them**, not left for you to find.

They describe the first developer preview, `v0.1.0-preview`, due
29 November 2026, and until then the `main` branch. What the preview does and
does not do is in its [release note](../release-notes.md).

A guide that is wrong is a bug. [Report it](https://github.com/bhaskix/bhaskix/issues).
