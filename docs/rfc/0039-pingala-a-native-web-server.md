# RFC 0039: Pingala — a native web server, and what "secure, performant, scalable" costs

| | |
|---|---|
| **Status** | ⬜ **Draft 2026-08-22.** Nothing here is built. **Question 1 is answered** — the project lead settled the command name on 2026-08-22: it is **`httpd`**, with **Pingala** as the product name, so §1's split is a decision rather than a recommendation and the naming question does not reopen when the manifest ships. The RFC owns steps 1–3 (a parser, a server, a manifest) and *names* steps 4–8 with triggers rather than claiming them, because five of the eight are other RFCs' work and writing them into this one would be a plan pretending to be a decision. Its most useful output may not be the server: §5 audits the phrase in the title against the tree and finds **three of its four words unfunded** |
| **Author(s)** | Tarun Kumar Kushwaha |
| **Subsystem** | userspace (`bin/httpd`), a new `no_std` crate (`bhaskix-http`), `packages/`. **No kernel change is proposed, and none is expected** — if a step needs one, that is the finding, not the step |
| **Milestone** | Phase 2 for steps 1–3. Steps 4–8 span Phase 3 and are gated on decisions this project has not made |
| **Depends on** | [RFC 0027](0027-a-sockets-api-worth-the-name.md) (`bhaskix-sock` — `expect`, `accept`, `recv`, `send`, `shutdown` already exist), [RFC 0020](0020-tcp.md) (the transport, and its ceiling), [RFC 0022](0022-capability-in-a-call.md) / [RFC 0023](0023-a-wake-for-a-connection.md) (rings the program owns, and the wake), [RFC 0016](0016-capability-in-a-reply.md) (a directory *is* a badged endpoint capability, and there is no way up out of one), [RFC 0030](0030-packages.md) (a manifest is the reviewable list of authority), [RFC 0034](0034-the-adoption-case.md) (**D2**, the demonstration this builds toward), [RFC 0031](0031-linux-compatibility-as-an-adapter.md) (why this is native and therefore not blocked on L1–L4), [coding-style.md](../coding-style.md) §8 (a fuzz target *before* merge), [security.md](../security.md) §1 |

---

## Summary

**A web server written natively for Bhaskix, whose value at step 1 is not that it serves pages but
that it is the first thing this system has ever built that a stranger on a network is trying to
break.**

Every parser in this tree is fuzzed. None has been *attacked*. `bin/httpd` is the first program
whose input arrives from an adversary in real time rather than from a corpus, and the first
workload that can produce [RFC 0034](0034-the-adoption-case.md)'s **D2** — a real application
exploited, the blast radius stopping at its domain, its neighbour still serving — which that RFC
calls the most valuable item in the adoption case and records as *nowhere in this tree*.

It is also the only flagship workload that is **not** blocked on Linux compatibility. RFC 0034 §4
found that every audience story except A5 rests on L1–L4, and all four of those rows read
`not started`. A native server needs no `bin/linuxd`, no libc, no dynamic linker, and no BusyBox.

**The product is named Pingala. The command is `httpd`.** §1 says why those are two different
decisions.

**And the honest half.** The title's phrase is *secure, performant, scalable*. §5 checks each word
against the tree. **Secure** is half-true and structurally so — the containment is real and gated;
there is no cryptography in this repository at all. **Performant** is not a tracked property of this
project (RFC 0034 **P4**). **Scalable** is contradicted by a constant: `bin/tcpd` holds
**two** connections. This RFC proposes building the server anyway, at two connections, in plaintext,
because a real workload is what turns those three findings from arguments into measurements.

## Motivation

### The problem this solves

Three problems, and they are not the same one.

**1. The adoption case has no demonstration.** [RFC 0031](0031-linux-compatibility-as-an-adapter.md)
§6 Test 1 is a synthetic probe: a program asks for authority it should not have and is refused five
times. That proves the boundary is *shaped* correctly. It does not show a blast radius, because
nothing is exploded. RFC 0034 **D2** identified this gap and recommended adopting the exploit
demonstration as L3's criterion — where it sits behind L1 and L2, neither of which has started. A
native server moves that demonstration in front of the compatibility work instead of behind it.

**2. Nothing here has ever met a hostile peer.** The fuzzing discipline in this project is genuine
and unusually well measured — 24-hour campaigns, seeded corpora, probe points proven reachable by
deliberate panics rather than inferred from coverage numbers. It is still a corpus. A fuzzer does
not hold a connection open, does not send a body that disagrees with its own length header, and does
not come back a thousand times a second. The one claim in `security.md` §1 that no gate can make is
*this survives someone who is trying*.

**3. The security architecture has no application to be an architecture of.** "A compromised
application does not compromise the system" (RFC 0034 **P2**) is the load-bearing sentence of the
entire pitch, and today the only applications are ones this project wrote, in Rust, holding
capabilities they were designed to hold. A web server is the canonical thing that gets owned.

### Who has this problem

The project lead, who is being asked what Bhaskix is *for* and can currently answer only with
architecture. And the two independent reviewers **R6** has been waiting for since Phase 0, who will
ask what runs on it.

### What happens if we do nothing

The containment claim stays a property of a design rather than an observed outcome, and the first
person to test it is an outsider rather than us.

---

## 1. The name — and the name that is not the name

**The product is `Pingala`. The command a user types is `httpd`.**

These are two decisions and they were nearly made as one, which is why they are separated here.

### Why Pingala

Piṅgala (पिङ्गल) is the author of the *Chandaḥśāstra*, the earliest known Sanskrit treatise on
prosody. Dating is a scholarly range rather than a fact — he is placed between the 4th and 2nd
centuries BCE, identified in different traditions as a younger contemporary of Pāṇini or of
Patañjali — and this document states the range rather than picking the flattering end of it.

What the *Chandaḥśāstra* contains is **the first known description of a binary numeral system**. To
enumerate metres, Piṅgala represents each syllable as one of exactly two weights — *laghu* (light)
and *guru* (heavy) — and gives algorithms that convert between a metre's pattern and its ordinal
number. Two symbols, positional, with a procedure over them, roughly two thousand years before the
machines that would need it.

For a computing project that already carries a mathematician's name, that is the right pedigree, and
it is the same kind of claim `README.md` already makes about Bhāskara I's circle for zero: specific,
checkable, and not inflated. The stronger attributions sometimes attached to Piṅgala — the Fibonacci
sequence, the binomial triangle — belong partly to his commentators and are **deliberately not
claimed here**, on the same rule that governs every other statement in this repository.

It satisfies the constraints asked of it: three syllables, *PING-ga-la*, no consonant cluster a
non-Indian reader will stumble on, no collision with existing software, and no religious weight of
the kind that makes `Brahma-` or `Madhava` awkward in a global project. It has one mnemonic
accident worth naming and not worth arguing from: for a program that answers over a network, the
name begins with `ping`.

### Why the command is still `httpd`

**The standing user-friendliness directive, extended 2026-08-21** — recorded in
[TRACKER.md](../../TRACKER.md) §7 under that date, where four existing shell command names were
checked against it — is explicit: *a person who knows Linux should guess the name and be right.*
A person who knows Linux and wants a web server types `httpd`. They do not type `pingala`.

The two requirements are only in conflict if a program is allowed one name. It is not. The precedent
is the most-deployed web server in history: the project is *Apache HTTP Server*, the binary is
`httpd`, and nobody has ever been confused by it. So:

| | Name | Where it appears |
|---|---|---|
| **Product** | **Pingala** | Release notes, documentation, the crate (`bhaskix-http`'s server), how the thing is spoken about |
| **Command** | `httpd` | `pkg install httpd`, `pkg run httpd`, `packages/httpd.manifest.in`, `bin/httpd` |

This also settles the general case, because the question will recur for the TLS terminator and for
whatever comes after: **product names are Indian — an ancient mathematician or scientist, or a
Sanskrit word; the command stays near-Linux.** The directive's own escape clause applies unchanged —
if a familiar name would imply a guarantee this system does not offer, it is not used.

**Settled 2026-08-22 by the project lead**, per `GOVERNANCE.md` §2: the command is `httpd`. That
is a decision and not a preference, so the rest of this RFC spells the command `httpd` everywhere
and the manifest in §4 is written against it. Runners-up stay recorded in *Alternatives considered*
rather than discarded — not because the decision is soft, but because this project's rule is that a
rejected alternative recorded is worth more than the chosen one explained.

---

## 2. What this is not

Stated before the design, because a web server is a phrase that expands while nobody is looking.

- **Not a Linux web server.** `bin/httpd` is native. It links no libc, holds capabilities, and is
  unrelated to L1–L4. nginx-under-`linuxd` remains the L3 goal and is a different project.
- **Not a framework, a module system, or a scripting host.** A module ABI is ambient authority with
  a plugin interface — [RFC 0030](0030-packages.md) refused install-time scripts for the same
  reason and the refusal transfers.
- **Not dynamic content, at any step in this RFC.** No CGI, no FastCGI, no application protocol.
- **Not HTTP/2 or HTTP/3.** HTTP/2 needs HPACK and stream multiplexing on a transport that cannot
  hold two connections; HTTP/3 needs QUIC, which needs the cryptography §5 says does not exist.
- **Not a claim of production readiness.** `SECURITY.md`'s standing sentence applies to this program
  more than to anything else in the tree: nothing here should run anywhere that matters.

---

## 3. The shape — domains, and what each one does not hold

The differentiator is not the code. It is the answer to *what does the request parser hold when it
is compromised*, and that answer improves across the steps rather than arriving whole. Writing it as
a progression is the point; claiming the endpoint at step 1 would be the exact failure
`security.md` §1's status column was added to stop.

### Step 1 — one domain

```
  wire → bin/netd → bin/ipd → bin/tcpd → bin/httpd → bin/fsd
                                             │
                                   holds: one endpoint to tcpd,
                                          one read-only directory capability,
                                          its rings, one notification.
                                   holds NOT: a console, a writable path,
                                          domain-control, a device, any other
                                          domain's memory, a way up out of the
                                          document root (RFC 0016).
```

**The claim this earns:** a compromise of the request parser reaches a read-only subtree of the
filesystem and nothing else. It cannot write, cannot print, cannot spawn, cannot see another
domain, and cannot climb out of the directory it was given, because there is no `..` to climb —
`kernel/src/namespace.rs` is deleted and a directory is a badged capability rather than a path.

**The claim it does not earn:** that the parser holds *nothing*. It holds the document root. On any
mainstream system that sentence would be the good news; here it is the residual.

### Step 7 — the split (named, not owned by this RFC)

```
  bin/tcpd → bin/httpd  ──(request line + headers)──→  bin/httpfs
             (parser)                                  (holds the directory)
              holds: rings + one endpoint.
              holds NOT: the document root.
```

The parser domain is handed bytes and hands back a parsed request. It holds no directory, no file,
no name. **Then the strong claim is true and testable**: the code that touches attacker bytes holds
nothing at all. This is the arrangement no mainstream stack can copy without rewriting its kernel,
and it is worth being explicit that it is *step 7*, not today.

### Concurrency, failure, `unsafe`

`bin/httpd` is a serve loop in one thread of one domain, exactly like `bin/tcpd`. It takes no lock,
runs in no interrupt context, and has no rank to declare. Its `unsafe` budget is the ring mapping
and nothing else; `bhaskix-http` — the parser — has an `unsafe` budget of **zero**, which is the
same posture `bhaskix-net`, `bhaskix-telemetry` and `abi` already hold and the reason those crates
are host-testable at all.

Failure behaviour, each an assertion rather than a hope: a malformed request line is answered `400`
and the connection closed, never parsed further; a body longer than its declared length is a `400`
and not a resize; a request for a name that escapes the root is a `403` **from the absence of a
capability rather than from a check that said no**; out of connections is what `bin/tcpd` already
does — `CONGESTED`, refusing at the table's size, which is this project's stated posture; a peer
that opens a connection and sends nothing holds one of two slots until the transport step gives
that a deadline, and **that is a denial of service against this design at step 1**, recorded here
rather than discovered later.

---

## 4. The manifest is the product

The single most persuasive artifact this design produces is not a benchmark. It is that the entire
authority of a network-facing server fits on one screen and a reviewer can read it:

```text
# Pingala: the web server. Its whole authority is the six lines below --
# an endpoint to the TCP service, the document root read-only, the rings its
# streams live in, and a wake. No console. No writable path. No domain-control.
package httpd
version 0.1.0

program bin/httpd
entry hertz
cap endpoint tcp
cap directory
cap memory pages=1
cap memory pages=4
cap memory pages=4
cap notification

payload bin/httpd from user/httpd/target/x86_64-unknown-none/release/httpd
```

Every line above is in the grammar `pkg/src/manifest.rs` already parses — verified against
lines 411–429, not assumed.

### Two findings this manifest produced, recorded because they are the useful part

**Finding 1 — `cap directory` cannot say *which* directory.** The grammar has
`Cap::Directory { writable }` and no path. For the shell that is tolerable; for a web server the
document root **is** the security boundary, and a manifest that says "a directory, read-only"
without saying which one is not the reviewable artifact RFC 0030 claims to produce. This is the
third instance of the same gap: `packages/linuxd.manifest.in` cannot say *write-only* about a
console or *sixteen* about notifications, and [RFC 0033](0033-what-a-hosted-process-is.md) already
noted that a grant which "would have to say *a subtree of the filesystem*" is where the grammar
stops being honest. **The trigger it was waiting for is this RFC**, and per RFC 0033's own rule,
fixing the grammar is part of step 3 rather than a follow-up.

**Finding 2 — [RFC 0034](0034-the-adoption-case.md) §4 row A1 lists the grant vocabulary, and the
list is incomplete.** It reads: *"today's nouns are `console`, `endpoint <service>`,
`memory pages=N`, `notification`, `timer`, `device-registers`."* The parser accepts **eleven**
nouns, not six — the six above plus `dma-window`, `interrupt`, `domain-control`, `directory` (in
two forms, read-only and `writable`), and `serve <service>` — across thirteen match arms at
`pkg/src/manifest.rs:411`–`429`. The row then concludes *"there is no `network`, `gpu`,
`camera` or `database` — the pitch's example list is aspirational in every noun it uses"*, and that
conclusion survives; the enumeration under it does not. **Not corrected here**, because it belongs
to RFC 0034 and this RFC is not the place to edit another's ledger — named so it is fixed rather
than found again by whoever quotes the six next.

---

## 5. The audit — what "secure, performant, scalable" costs

The house ledger form. Status vocabulary is this tree's: ✅ true today · 🔨 partly true, with the
limit stated · ⬜ not started · ❌ refused or contradicted.

| # | The claim a web server makes | Status | The line that decides it | What would make it true |
|---|---|---|---|---|
| **W1** | **Secure** — traffic is encrypted | ❌ | **There is no cryptography in this repository.** Checked as a grep for `aes`, `chacha20`, `poly1305`, `x25519`, `ed25519`, `curve25519`, `p256`, `hmac`, `hkdf`, `sha384`, `sha512` across every `.rs` in the tree: **zero hits.** The only primitives are `pkg/src/sha256.rs` (package digests) and `rand/` (RDRAND, RFC 0021). A web server without TLS 1.3 is not a production web server | Step 5 — and it is a **decision before it is work**, because it collides with **P5**, the strongest verified claim this project has: 20 packages in `Cargo.lock`, all `bhaskix-*`. See *Unresolved questions* 2 |
| **W2** | **Secure** — a compromise does not spread | 🔨 | Structural and real. `security.md` §1 **T1**, **T2**, **T10** are built and gated; a directory is a badged capability with no way up out of it (RFC 0016); the manifest in §4 is the whole grant list. **The limit**: at step 1 the parser holds the document root (§3), and native programs have **no ASLR** — `security.md` §1 T1's named weakness, and the hosted-process randomisation gated 2026-08-21 is `bin/linuxd`'s mapping policy, which a native server does not go through | Step 7 (the split) for the strong form; and native ASLR, which is **its own decision** — the ELF loader refuses `ET_DYN` for ring 3 on purpose, so this reopens a settled choice and needs an RFC |
| **W3** | **Secure** — certificates are validated | ⬜ | **There is no wall clock.** RFC 0019 gives monotonic deadlines; there is no RTC, no epoch, no `time()`. Certificate validity is an interval on a calendar and nothing in this system can name a date | A time-of-day source, which is a new device and a new capability, and is not in any RFC |
| **W4** | **Scalable** — many concurrent connections | ❌ | `user/tcpd/src/main.rs:475` — `const MAX_CONNECTIONS: usize = 2`, one outbound and one accepted; a third caller is told `CONGESTED`. And `main.rs:503` — a listener "with spent rings can birth nothing more until the table's next step adds re-arming", so a listener accepts **once**. The industry's floor is C10K; this is C1 | Step 4: the connection table sized from `ResourceEnvelope` rather than a constant, and listener re-arming |
| **W5** | **Scalable** — the transport keeps up | ⬜ | `net/src/tcp/state.rs:45`, in the module's own words: *"No congestion control, no window scaling, no SACK, no timestamps, no path"* MTU discovery. The window is the 16-KiB ring (`STREAM_RING_BYTES`). Across a WAN, a 16-KiB window with no scaling caps a single stream regardless of the link | Step 4. Note the ordering trap: congestion control is meaningless before there is more than one connection to be unfair between |
| **W6** | **Scalable** — waiting on many connections at once | ⬜ | RFC 0023 gives a gifted wake **per connection**. Correct for two, wrong for ten thousand: a program cannot today block on "any of these N" | Step 4 — a wait-on-many primitive that is capability-shaped rather than a descriptor set, which is the interesting design problem in this whole RFC |
| **W7** | **Performant** | ⬜ | **Not a tracked property of this project**, as RFC 0034 **P4** found. `TRACKER.md` §6 lists exactly **one** performance gate: rt latency p99.9 < 50 µs. `architecture.md` line 564's *"Native software never pays"* has no gate. `vision.md` line 86 says *"**Not** a benchmark-first project"* — an **adopted** document. Measured today: 1–2.6 MiB/s per direction, and TRACKER records that widening the window 4× left the rate unchanged, which convicts the per-chunk serve-loop unit rather than the window | Either a benchmark RFC with a written regression bound, or the word comes out of the pitch. RFC 0034 recommended withdrawal; a web server is the workload that would make funding it worthwhile instead. **Governance, not engineering** |
| **W8** | **Production** — the operator's day-one list | ⬜ | No secure boot and no signed image — `security.md` **T6**: *whoever can write the ESP owns ring 0*. Audit is **T8 partial**: the `Audit` class is reserved and refused, so what exists is a debugging record and not an audit record. **There is no UID in this system at all** (RFC 0034 P2), so no users, no RBAC. No live update, no resolver, no containers | Phase 3, in the order `roadmap.md` already ranks it. None of it is web-server work and all of it is between here and the word *production* |
| **W9** | **Production** — it has run on a machine | ⬜ | **M1-17.** The image booted on a Lenovo SR550 on 2026-08-22 and nothing was captured — output reached the framebuffer, not serial-over-LAN, so no boot report was read. Every measurement in this RFC will be QEMU until that changes | A boot somebody *read* |

**Nine rows: zero ✅, two 🔨, six ⬜, one ❌ — with W1 and W4 the two that are flatly contradicted
rather than merely absent.**

The honest reading, in the same spirit as RFC 0034 §5: **the containment half of this is real,
structural, and better than anything a mainstream stack can offer, and it is the only half that is
real.** A pitch built on this table today is a pitch about blast radius, delivered to security
architects, with performance and scale named as destinations and marked unmet. That is a narrower
claim than the one in this RFC's title, and it is the one the tree can pay for.

---

## 6. The demonstration this builds toward

Adopting RFC 0034's **D2** with a concrete script, since a demonstration nobody wrote down is a
demonstration nobody runs:

1. Bhaskix boots. `bin/httpd` serves the document root. A second service — the shell, `bin/traced`,
   anything with a visible output — is running in its own domain.
2. A deliberately vulnerable build of `bin/httpd` is exploited over the network. Not a probe asking
   politely and being refused (that is RFC 0031 Test 1, which already passes): **arbitrary code
   running inside the server's domain.**
3. It then tries, and the boot gate asserts each refusal: read another domain's memory; open a file
   outside the document root; write anything; print to the console; spawn a domain; invoke a native
   syscall kind by number; reach a device.
4. **The neighbour is still serving, and the kernel is untouched**, asserted rather than observed.
5. The grant set afterwards is byte-identical to the manifest in §4 — the assertion RFC 0034 **P2**
   names as missing from Test 1 today.

Step 3 is what makes this different from a sandbox demonstration: on a system with ambient
authority, the interesting question is what the exploit *reaches*; here the interesting question is
that it has nothing to name.

---

## Alternatives considered

| Alternative | Why rejected | Would reconsider if |
|---|---|---|
| **Port nginx under `linuxd` instead of writing one** | It is the L3 goal and it is four milestones away — L1 has not run BusyBox. It also proves the *adapter*, not the architecture: nginx under an adapter is one domain holding whatever the adapter holds, which is exactly the concentration `security.md` T11 already prices. A native server is the thing whose authority a reviewer can read | Nothing — both should exist. They are different demonstrations and this RFC does not compete with L3 |
| **Wait for the transport before writing any server** | Backwards. The transport work in step 4 is a set of guesses about what a server needs — connection lifetimes, wake patterns, buffer sizes — and a two-connection server is what turns those guesses into measurements. This project's own precedent: `bin/blkd` was written by hand and *then* the driver framework, because the framework's motivation was the invoice (RFC 0014) | The step-1 server turns out to need a kernel change, which would mean the shape is wrong |
| **Name the command `pingala`** | Contradicts the standing directive of 2026-08-21 — a Linux user guesses `httpd` and would be wrong. §1's split gives the identity to the product name at no cost to the person typing. **Rejected explicitly by the project lead on 2026-08-22**, rather than left to lapse | Nothing short of the directive itself changing. It would now be a rename of a shipped command, which is the cost §1 was arranged to avoid |
| **Name it `Aryabhata`** | The best-known Indian mathematician and the strongest recognition, but four syllables, and India's first satellite already carries it — a name whose first association is a spacecraft is a name that has been spent | A shorter program wants it more than this one does |
| **Name it `Setu` (bridge) or `Seva` (service)** | Both are two syllables and easier than Pingala; `Seva` literally means *service*, which is close to perfect. Rejected on collision — `Setu` is heavily used in Indian public technology (API Setu, Aarogya Setu) and inherits an association this project does not want, and `Seva` is generic enough to be somebody else's product already. Neither carries a checkable story, which is what `README.md`'s naming paragraph does | A component wants a plain descriptive Sanskrit name rather than a person's — the TLS domain may; see below |
| **Name it `Kanada`** (the atomist) | *KA-na-da* collides audibly with Canada for every English speaker on first hearing | Never for a globally-distributed project |
| **HTTP/2 or HTTP/3 first** | HTTP/2 needs stream multiplexing over a transport holding two connections; HTTP/3 needs QUIC, which needs the cryptography W1 says does not exist. Both are downstream of steps 4 and 5 | Steps 4 and 5 land |
| **A configuration file** | The manifest already declares the authority, and a config language is a second grammar and a second hostile-input parser for a server whose entire configuration at step 1 is *one directory and one port*. `pkg` refused TOML for this reason | The server grows a surface a line grammar cannot express — and the standing directive says that surface arrives as a **TUI** via its own RFC |
| **Put the parser in the kernel for speed** | Not seriously, and recorded so it stays refused: it would put the largest untrusted-input surface in the system inside the 66% of `unsafe` that lives in ring 0 (**T9**), and contradict the one sentence this whole project is built on | Nothing |

## What is refused, and when that changes

| Refused | Why | Trigger to build |
|---|---|---|
| TLS at steps 1–3 | Cryptography does not exist here (W1), and a server that terminates TLS badly is worse than one that does not offer it | Step 5, which is a **primitives decision** before it is code |
| Dynamic content, CGI, modules | A module ABI is ambient authority with a plugin interface; RFC 0030 refused install-time scripts on the same ground | Nothing. A need shaped like CGI is a need for a second domain and an endpoint capability between them |
| Virtual hosts, rewrite rules, proxying | Configuration surface with no user, on a server with two connections | A second document root is genuinely wanted, and the manifest grammar can name both (Finding 1) |
| Authentication, users, sessions | **There is no UID in this system at all.** Inventing one inside a web server would put identity in the worst possible place | The RBAC row of Phase 3, which owns identity |
| Access logging to disk | The server holds no writable path on purpose (§4). Logging through the telemetry plane is the right shape, and the `Audit` class it wants is **reserved and refused** until the audit RFC (`security.md` §8) | The Phase 3 audit framework — and a web-server access log is a good first consumer for its backpressure ring |
| Any published performance number | W7. A rate quoted from a project with one performance gate and an adopted document saying it is not benchmark-first is a number without a bound | A benchmark RFC with a written regression bound |

## Impact on existing design documents

- **[roadmap.md](../roadmap.md)** — Phase 2's list gains no bullet (steps 1–3 are one program and a
  crate). **Phase 3 gains the transport row**, which does not exist today: `roadmap.md` names
  "reassembly and congestion control" as *beyond any RFC's scope yet*, and step 4 is where they get
  one. The **L3** row should gain RFC 0034's **D2** criterion — recommended by that RFC, still
  undecided, and this RFC is the reason it stops being cheap to defer.
- **[RFC 0034](0034-the-adoption-case.md) §4 row A1** — its grant-vocabulary enumeration is
  incomplete (§4, Finding 2). Named, not edited here.
- **[RFC 0033](0033-what-a-hosted-process-is.md)** — its note that the manifest grammar cannot say
  *a subtree of the filesystem* named a trigger. **This RFC is that trigger.** No change to 0033;
  the work lands in step 3.
- **[security.md](../security.md) §1** — no threat row changes status. **T1's named weakness (no
  ASLR for native programs) becomes materially more expensive**, because it is stated about programs
  this project wrote and now applies to one an attacker is aiming at. That sentence belongs in T1
  and is part of step 2, not a follow-up.
- **[vision.md](../vision.md) line 86** — *"Not a benchmark-first project"* is why W7 has nothing
  behind it. Not a defect and **not amended here**; it is an adopted document, and the conflict is
  the pitch's rather than the document's. It is the second governance item after RFC 0034's **G1**,
  and deciding it in the wrong order produces a README that argues with itself.
- **[TRACKER.md](../../TRACKER.md)** — one decision-log row pointing here, per convention.

## Security implications

Reference [security.md](../security.md) §1.

- **New authority?** No new *kind*. `bin/httpd` holds an endpoint capability, a read-only directory
  capability, memory and a notification — every one of which some existing program already holds.
  The kernel gains no method and no object, and if a step needs one that is a finding to report
  rather than a change to make.
- **Reachable without a capability?** Nothing new.
- **A parser for untrusted input?** **Yes — and it is the largest deliberately-exposed one this
  project will have had.** `coding-style.md` §8 binds: a libFuzzer target in `fuzz/` lands
  *before* `bhaskix-http` merges, not after. It is seeded per the rule that harness learned the hard
  way — the valid structure built inside the target and mutated within it, not hoped for from an
  empty corpus, which is the fix `fuzz_targets/fs_image.rs` demonstrated and the three re-seeded
  targets confirmed on 2026-08-21. Probe points proven reachable by deliberate panic before any
  execution count is believed.
- **Scope movement?** One row moves and it should be stated plainly: **network-facing denial of
  service becomes in-scope by implication.** `security.md` §1 lists resource exhaustion (T10) as
  built via `ResourceEnvelope`, and traffic analysis as out of scope — but a slow-loris peer holding
  one of two connection slots is neither, and it is a real defect of §3 at step 1. Either T10's row
  grows a network clause in step 4, or the threat model says DoS against a network service is out of
  scope. **Deciding that is part of step 4 and is not decided here.**
- **New concentration of authority?** No. Unlike `bin/linuxd` — which `security.md` T11 prices as
  the largest concentration in the system — this program's grant list shrinks over the steps rather
  than growing: step 7 takes the document root *away* from the parser.

## Performance implications

**The RFC's own finding is that this project cannot answer this section honestly today** (W7), and
that is recorded rather than papered over with a number.

What steps 1–3 will produce is a *measurement*, not a claim: bytes served per second for a static
file over the loopback and over the emulator's link, at one connection and at two, with the
boundary crossings priced the way every other boundary in this project is priced — the way the
personality relocation was floored at 4,916 cycles and telemetry emit at ~1101 before either was
believed. The expectation, stated in advance so it can be wrong: **the number will be bad, it will
be bounded by the per-chunk serve-loop unit rather than by anything HTTP-shaped, and it will point
at step 4.** TRACKER already convicted that unit twice — once when widening the window 4× left the
rate unchanged, once when IPv6 through the loopback with no emulator in it landed within 5% of v4.

If the measurement instead points at the parser, that is the interesting outcome and the one worth
publishing.

## Testing plan

**Host** — where nearly all of it belongs, per `coding-style.md` §8:

- `bhaskix-http` is pure arithmetic over byte slices with **zero `unsafe`** and no I/O: the request
  line, header folding, the header count and length limits, chunked encoding, percent-decoding, and
  the path resolver. Every refusal gets a test that has been watched go red.
- The path resolver gets adversarial cases as *tests*, not as fuzzing luck: `..`, `%2e%2e`,
  double-encoded traversal, absolute paths, embedded NUL, a name that is `.` all the way down,
  overlong UTF-8. The rule from `pkg/src/manifest.rs:238` — no empty segment, no `.`, no `..` — is
  the precedent and should be reused rather than reinvented.
- **A deliberately reintroduced bug must fail the harness before the harness is believed**, per the
  ELF-parser lesson in `coding-style.md` §8 that cost half a million mutations to learn.

**Fuzz** — `fuzz/fuzz_targets/http_request.rs`, before merge, seeded arms: a well-formed request
with fuzzer-chosen values; a header block with fuzzer bytes spliced in; a chunked body whose
lengths disagree with its content; a path assembled from a table of traversal primitives. Measured
from an **empty** corpus, with the probe points proven reachable.

**QEMU** — two boot gates at step 2, both armed:
1. **Positive**: the host fetches a known file, and the bytes match a hash computed at build time.
2. **Negative**: the host requests a path that escapes the document root and is refused — and the
   gate is watched failing by pointing the document root one level up, which must turn it green
   and must therefore be caught.

Plus the manifest gate RFC 0030 already runs: the grant set at run time equals the installed
manifest, and an over-asking manifest is refused whole before a domain exists.

**Real hardware** — nothing new, and the standing ceiling applies to every number this RFC
produces: **M1-17**.

**What cannot be tested until step 8** — the D2 demonstration in §6. It is written down now
precisely because it cannot be faked early.

## Unresolved questions

1. ~~**Is the command `httpd` or `pingala`?**~~ **Answered 2026-08-22 by the project lead: the
   command is `httpd`**, with **Pingala** as the product name — §1's split, adopted as written. The
   number is kept rather than reclaimed so that later references to "question 2" and "question 5"
   still point where they did.
2. **Where does cryptography come from?** The largest question in this document and it is not a web
   server question. Writing TLS 1.3's primitives by hand means hand-rolling constant-time code,
   which is where hand-rolling most reliably goes wrong; taking a vendored crate spends **P5**,
   which RFC 0034 calls "a supply-chain position almost nothing else in this class holds" and which
   `tools/check-deps.py` enforces with an `ALLOWED_EXTERNAL` set holding exactly one name. **Neither
   option is obviously right and this RFC does not choose.** It gets its own RFC, before step 5.
3. **Is network-facing DoS in the threat model?** §"Security implications". Step 4 decides it.
4. **Does W7 get funded or withdrawn?** RFC 0034 recommended withdrawal. A real workload is the
   argument for funding it instead. It is the second governance item after **G1** and should not be
   decided before it.
5. **What is the wait-on-many primitive?** The genuine design problem here (W6). A readiness set is
   a descriptor table wearing a hat, and this system deleted descriptor tables on purpose. The
   answer is probably one notification signalled by many connections plus a scan, and "probably" is
   why it is a question and not a design.

## Implementation plan

Steps 1–3 are owned by this RFC. **Steps 4–8 are named with their triggers and owned by nobody** —
listing them here is a decomposition, not a schedule, and each needs its own RFC.

1. **`bhaskix-http`** — the protocol as pure host-tested arithmetic. Zero `unsafe`, no I/O, no
   allocation on the request path. Its fuzz target lands in the same change, per `coding-style.md`
   §8. This is the same shape `bhaskix-telemetry` step 1 took and for the same reason: the thing is
   provable before anything can boot it.
2. **`bin/httpd`** — the serve loop over `bhaskix-sock` (`expect`, `accept`, `recv`, `send`,
   `shutdown` — all of which exist today, `sock/src/tcp.rs`). Static files through one directory
   capability. Plaintext. Two connections, because that is what the transport holds. Two boot gates,
   both armed. The measurement, published as a distribution and expected to be bad.
3. **The manifest, and the grammar gap it finds** — `packages/httpd.manifest.in`, plus
   `cap directory path=<name>` so the document root is *named* rather than implied (§4, Finding 1).
   Per RFC 0033's rule, the grammar fix is part of this step and not a follow-up.

--- *below this line, nothing is owned* ---

4. **The transport** — its own RFC. Connection table from `ResourceEnvelope`, listener re-arming,
   congestion control, window scaling, a deadline on an idle peer, and the wait-on-many primitive
   (question 5). **Trigger: step 2's measurement**, which is what says which of these actually
   binds. This is where the word *scalable* is earned or dropped.
5. **Cryptography** — its own RFC, and a decision before it is work (question 2). **Trigger:
   nothing. It should be opened now, in parallel, because it is the longest-lead item here.**
6. **TLS in its own domain**, holding the private key and nothing else — a key the request parser is
   structurally incapable of naming, and revocation that reaches it. This is a differentiator no
   mainstream stack offers, and it is worth stating that it becomes available *for free* from an
   architecture that already exists, which is the strongest argument in this document.
   **Trigger: step 5.**
7. **The split** (§3) — the parser holds nothing. **Trigger: step 6**, since the TLS domain is the
   first split and proves the shape.
8. **D2** (§6) — the demonstration. **Trigger: step 7.**
