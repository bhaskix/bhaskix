<!-- SPDX-License-Identifier: Apache-2.0 -->

# Bhaskix docs

How to run Bhaskix, use it, and understand what it is doing — the knowledgebase.
These are not the design documents: [architecture.md](../architecture.md) says
why the system is shaped the way it is; these pages say what to type, and what
you will see when you do.

Bhaskix is a **developer preview**. Start with *What Bhaskix is* if you want to
know whether it is for you, or *Get started* to boot it in ten minutes.

## Start here

| Guide | What it covers |
|---|---|
| [What Bhaskix is](overview.md) | What it is and is not, what works today and what does not, and how it differs from Linux |
| [Get started](get-started.md) | Download and check the release, boot it in QEMU three ways, try your first commands, and leave |

## Install and run

| Guide | What it covers |
|---|---|
| [Build from source](build-from-source.md) | Set up a machine to build Bhaskix, build the ISO, boot it, and run the project's own tests |
| [Run it on a real machine](real-hardware.md) | There is no installer: boot from a USB stick or a server's virtual CD, what hardware is known to work, and how to give the machine back |

## Use

| Guide | What it covers |
|---|---|
| [The shell and packages](shell-and-packages.md) | Every shell command, what holding a capability means, installing a package, and the kernel's own shell |
| [Linux programs](linux-programs.md) | What "hosted" means, an unmodified Go web server answering your browser, BusyBox for source builds, and what is refused and why |

## Secure

| Guide | What it covers |
|---|---|
| [The security model](security-model.md) | No root and no ambient authority: what a program can do is what it holds, how domains are kept apart, and what is not protected yet |
| [Sign your own boot](secure-boot.md) | A boot only you can change: your own key for the loader's check, your own certificate for Secure Boot, and what the project's keys will add |

## Understand

| Guide | What it covers |
|---|---|
| [How Bhaskix works](how-it-works.md) | The nucleus, capabilities, domains, services and the Linux adapter, networking, and how to read the boot report |

## Develop

| Guide | What it covers |
|---|---|
| [Write a program](write-a-program.md) | Change the demonstration program, rebuild, install it as a package and run it — and see what its manifest lets it do |

## Help

| Guide | What it covers |
|---|---|
| [Troubleshooting](troubleshooting.md) | No output, missing firmware files, slow boots, red lines in the boot report, and how to report a problem |
| [Questions and answers](faq.md) | Is it Linux, can I install it, is it ready for production, what runs, the licence, and how to contribute |

## How these are written

- **Every command shown was run**, and the output shown is a transcript of that
  run. Long output is trimmed with `…`; nothing is edited.
- **Each page says when it was last verified, and against what**: a commit, or
  a release's tag. Bhaskix changes quickly, and a page is only as true as the
  build it was checked against.
- **A page can only name commands the shell has.** `make gates` reads each
  shell's own command table and refuses a page that names a command it lacks,
  and refuses a page this index does not list (`tools/check-guides.py`).
- **Limits are stated where you would meet them**, not left for you to find.

They describe the first developer preview, `v0.1.0-preview`, due
29 November 2026, and until then the `main` branch. What the preview does and
does not do is in its [release note](../release-notes.md).

A page that is wrong is a bug. [Report it](https://github.com/bhaskix/bhaskix/issues).
