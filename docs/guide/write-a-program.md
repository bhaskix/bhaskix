<!-- SPDX-License-Identifier: Apache-2.0 -->

# Write a program

**Verified** 2026-10-30 against `aa2dcc5`, in a fresh clone, by running every command shown.

This page changes Bhaskix's demonstration program, builds it into a package,
installs it at the shell and runs it — and then asks for more authority than it
should have, to see the refusal. It needs a checkout that builds:
[Build from source](build-from-source.md) first.

## The program

`user/hello/src/main.rs` is the whole of it — seventy-nine lines, most of them
comments. Its heart:

```rust
/// The console this program greets through — its only capability.
const CONSOLE: u64 = 0;

/// What it says. Proof of the whole chain: packaged, verified, installed,
/// granted, started.
const GREETING: &[u8] = b"namaste from an installed package\n";
```

and a loop that hands the greeting to the console, a few bytes per call:

```rust
let _ = call(syscall::CALL, CONSOLE, console::WRITE, chunk.pack(0));
```

That is a native Bhaskix program in full: it has **no file descriptors, no
standard output and no `printf`**. It holds one capability, in slot 0 — the
console — and it writes by *calling* the console service through that
capability. If it did not hold it, there would be nothing to call.

What it holds is decided by its **manifest**, `packages/demo/hello.manifest.in`:

```
package hello
version 0.1.0

program bin/hello
entry hertz
cap console

payload bin/hello from user/hello/target/x86_64-unknown-none/release/hello
```

`cap console` is the whole of its authority.

## Change it

Edit the greeting:

```sh
sed -i 's/namaste from an installed package/hello from my first Bhaskix program/' user/hello/src/main.rs
```

and rebuild. `make` rebuilds the program, packages it as `hello.bpk`, and puts
the package in the image:

```sh
make iso
```

```
…
   Compiling bhaskix-user-hello v0.1.0 (…/user/hello)
built user/hello/target/x86_64-unknown-none/release/hello
…
built build/hello.bpk (20480 bytes, 1 payloads, verified)
…
built build/bhaskix.iso
```

## Install it and run it

Boot the machine and, at its prompt, install the package and run it:

```sh
make demo
```

```
…
bhaskix$ pkg install hello.bpk
  verified   hello 0.1.0 -- 1 files, 20480 bytes, digests good
  installed  /pkg/hello -- 15408 payload bytes through the journal in 5 writes, 272236158 cycles
bhaskix$ pkg run hello
  running    hello (15408 bytes, grants from its manifest)
hello from my first Bhaskix program
  it ended cleanly
```

`pkg install` checked the package's files against their digests before writing
anything, and wrote through the filesystem's journal. `pkg run` started the
program in a domain of its own, holding exactly what its manifest asks for, and
waited for it to end.

## Ask for too much

Add a line to the manifest asking for direct memory access through a device —
authority the shell has no right to hand out:

```sh
sed -i 's/^cap console$/cap console\ncap dma-window/' packages/demo/hello.manifest.in
make iso
make demo
```

```
…
bhaskix$ pkg install hello.bpk
  verified   hello 0.1.0 -- 1 files, 20480 bytes, digests good
  installed  /pkg/hello -- 15408 payload bytes through the journal in 5 writes, 402420884 cycles
bhaskix$ pkg run hello
  pkg: the manifest asks for authority this shell does not hold -- refused whole, nothing granted
```

**Refused whole, before anything runs**: a program does not get some of what it
asked for. The shell can only pass on authority it holds, and it does not hold
that.

Put both files back when you are done:

```sh
git checkout user/hello/src/main.rs packages/demo/hello.manifest.in
```

## Going further

- **Other capabilities.** The manifests in `packages/` show what each of the
  system's own programs asks for; `bhaskix-abi` is the interface they call.
- **The network.** `user/tcpc/` is a native program that opens TCP connections
  through `bhaskix-sock`, the sockets library.
- **A Linux program instead.** A static x86-64 Linux binary runs unmodified
  through the adapter: [Linux programs](linux-programs.md).
- **Proposing a change** to Bhaskix itself starts with an RFC: `docs/rfc/` and
  `CONTRIBUTING.md` say how.
