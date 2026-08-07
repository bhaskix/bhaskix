// SPDX-License-Identifier: Apache-2.0
//! A ring 3 program.
//!
//! This is the first thing Bhaskix builds that is not the kernel. It exists to
//! be *loaded*: the kernel finds it in the initial ramdisk, parses it as an
//! ELF64 executable, maps its three segments at the addresses the file names,
//! and jumps to the entry point the file declares. Everything the kernel then
//! observes about it is evidence that all of that worked.
//!
//! Until M6-03 the same program was a byte array in the kernel image, copied
//! into a page. That proved ring 3 worked and nothing about loading — the
//! bytes were already in memory, at a fixed offset, with permissions the
//! kernel chose. Here the file chooses, and a loader that ignored the file
//! would fail visibly rather than silently agree.
//!
//! # Why it is assembly
//!
//! It runs in ring 3 with no runtime, no stack frame conventions worth
//! honouring, and no library. Writing it in Rust would mean reading the
//! compiler's output to know what it does, which is the wrong way round for a
//! program whose whole purpose is to be an exactly known sequence of system
//! calls.
//!
//! # The system-call convention
//!
//! `rax` kind, `rdi` capability, `rsi` method, `rdx`/`r10`/`r8`/`r9`
//! arguments — see `docs/rfc/0008-syscall-and-ipc-shape.md`. `syscall`
//! destroys `rcx` and `r11`, so nothing that must survive a call lives there.

#![no_std]
#![no_main]

/// There is nothing to unwind and nothing to print to.
///
/// Reached only if Rust code panics, and there is no Rust code: the program is
/// the `global_asm!` block below. Halting by faulting is the honest outcome —
/// `ud2` in ring 3 is an exception the kernel reports.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // SAFETY: an undefined instruction, deliberately. Ring 3 has no other way
    // to stop that does not depend on the kernel accepting a system call.
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}

core::arch::global_asm!(
    r#"
.section .text._start,"ax",@progbits
.globl _start
_start:
    // --- Fault on purpose, if asked ----------------------------------------
    //
    // `rdi` is the first of the two values the kernel passes at entry, and it
    // is read here because everything below clobbers it:
    //
    //   0  run the probe, as everything before RFC 0017 did
    //   1  write through a null pointer and do not come back
    //   2  spin in ring 3 for ever, making no system call
    //   3  yield for ever, so the only way out is a system call returning
    //   4  receive for ever on capability 0, and never reply
    //
    // Both extra modes live in `bin/probe` rather than in programs of their
    // own because the loader path, the domain, the privilege stack and the
    // entry are already built and tested here. A second ELF would duplicate
    // all of that to execute ten bytes.
    cmp rdi, 1
    jne 3f
    xor rax, rax
    mov qword ptr [rax], 1      // #PF: not present, write, user mode
    ud2                         // unreachable; a backstop, not a plan
3:
    cmp rdi, 2
    jne 5f
    // A thread that cannot end itself. No `syscall`, so it never reaches the
    // kernel of its own accord and never passes a safe point it chose --
    // which is what makes it a test of whether something *else* can stop it.
    // The only way out of this loop is a timer interrupt that does not return.
4:
    jmp 4b
5:
    cmp rdi, 3
    jne 7f
    // The mirror of mode 2, and the other safe point. This thread is *only*
    // ever in the kernel through a system call, so it can never be stopped by
    // an interrupt returning to user mode -- if it stops, it stopped on the
    // way back from `yield`. Between them the two modes cover both doors, and
    // removing either check leaves exactly one of them running.
    //
    // `r15` because `syscall` destroys `rcx` and `r11`, and `rdi` is an
    // argument to the call below.
    mov r15, rdi
6:
    mov rax, 4                  // Kind::Yield
    xor rdi, rdi
    syscall
    jmp 6b
7:
    cmp rdi, 4
    jne 1f
    // A server that takes a call and never answers it. Once it has received,
    // the kernel records that this thread owes its caller a reply -- and then
    // this thread goes straight back to waiting, so the obligation is
    // outstanding for as long as the thread lives. Killing it is what a caller
    // blocked on that reply cannot survive without being told.
    //
    // It blocks in the kernel rather than in ring 3, which is the case RFC
    // 0017 step 2 could not stop: a thread asleep on an endpoint has no next
    // safe point of its own.
8:
    mov rax, 3                  // Kind::Recv
    xor rdi, rdi                // capability index 0
    syscall
    jmp 8b
1:

    // --- Evidence that the loader read the file rather than copying it ------
    //
    // Three facts, each obtainable only if a different segment was mapped as
    // the program headers asked:
    //
    //   1. `MAGIC` reads back its value      -> the read-only segment's
    //                                            contents came from the file
    //   2. `SCRATCH` starts at zero          -> the writable segment's
    //                                            `p_memsz` tail was zero-filled
    //   3. `SCRATCH` accepts a store         -> it is mapped writable, and the
    //                                            read-only segment above is not
    //
    // Addressed absolutely, not through `rip`. If the loader placed this image
    // anywhere but the address the file named, these instructions fault
    // instead of quietly working -- which is the point. A rip-relative version
    // would keep working at any base and prove nothing about placement.
    mov r14, qword ptr [MAGIC]
    mov rax, qword ptr [SCRATCH]
    test rax, rax
    jz 2f
    xor r14, r14                // not zero-filled: report nothing
2:
    mov qword ptr [SCRATCH], r14
    mov r15, qword ptr [SCRATCH]

    mov rax, 1                  // Kind::Call
    xor rdi, rdi                // capability index 0
    mov rsi, 11                 // method: "here is what my segments say"
    mov rdx, r15
    syscall

    // --- The ring 3 checks that predate the loader -------------------------
    mov rbx, 8                  // iterations
10:
    // Spin in ring 3 for long enough that a timer interrupt certainly lands
    // here rather than only inside a system call. Without this the probe
    // never exercises the interrupt-from-user path, and a missing `swapgs`
    // in the interrupt entry passes unnoticed -- which it did.
    //
    // `r12` because `syscall` destroys `rcx` and `r11` and every other free
    // register is an argument.
    mov r12, 0x300000
11:
    dec r12
    jnz 11b

    mov rax, 4                  // Kind::Yield
    xor rdi, rdi
    syscall
    dec rbx
    jnz 10b

    // A syscall number that does not exist, to prove the kernel rejects it as
    // a value rather than using it as an index. The status comes back in rax
    // and is ignored here; the kernel counts it.
    mov rax, 999
    syscall

    // Two IPC calls to a service, through capability index 0.
    //
    // The first asks for six doubled. The second sends the *answer back*, so
    // the service can check what ring 3 actually received — a reply the kernel
    // delivered but user mode never saw would otherwise be indistinguishable
    // from one that arrived.
    //
    // `r13` because `syscall` destroys `rcx` and `r11`, and everything else
    // here is an argument. Blocking in the first call and resuming into the
    // second is also the first time a system call from ring 3 sleeps and comes
    // back, which is what per-thread kernel stacks were built for.
    mov rax, 1                  // Kind::Call
    xor rdi, rdi                // capability index 0
    mov rsi, 7                  // method
    mov rdx, 6                  // argument
    syscall
    mov r13, rdx                // the reply value

    mov rax, 1                  // Kind::Call
    xor rdi, rdi
    mov rsi, 8                  // method: "here is what I was told"
    mov rdx, r13
    syscall

    // Delegation, from user mode. Derive a second capability to the same
    // endpoint into slot 1 of this domain's own CSpace -- weaker rights, and
    // the *same badge*. Nothing in the kernel arranged this: ring 3 asked.
    mov rax, 0                  // Kind::Invoke
    xor rdi, rdi                // on capability 0
    xor rsi, rsi                // method::DERIVE
    mov rdx, 0x21               // rights: READ and DERIVE, less than the parent
    mov r10, 0x12340000         // the same badge the parent carries
    mov r8, 1                   // into slot 1
    syscall

    // Call through the derived capability. The service sees the *same* badge,
    // because a badge says who the granter said this is and a holder cannot
    // say otherwise. What the derived capability differs in is its rights and
    // its position under the parent, which the revocation below shows.
    mov rax, 1                  // Kind::Call
    mov rdi, 1                  // capability 1
    mov rsi, 9
    mov rdx, 5
    syscall

    // And the thing a holder must *not* be able to do: derive the same
    // capability under a badge of its own choosing. Refused, so slot 2 stays
    // empty and the call through it below reaches nobody.
    //
    // Asked from raw ring 3 with no library in the way, because this is a rule
    // enforced at the system call boundary and that is where it should be
    // watched holding.
    mov rax, 0                  // Kind::Invoke
    xor rdi, rdi                // on capability 0
    xor rsi, rsi                // method::DERIVE
    mov rdx, 0x3f               // rights: everything the parent had
    mov r10, 0x56780000         // a badge this program invented
    mov r8, 2                   // into slot 2
    syscall

    mov rax, 1                  // Kind::Call
    mov rdi, 2                  // capability 2, which must not exist
    mov rsi, 12
    mov rdx, 5
    syscall

    // --- RFC 0017 step 4: a program creates a domain -----------------------
    //
    // Capability 3 is a `DomainControl` this domain was given. Nothing else in
    // this program can do this, and nothing in the kernel arranged it: ring 3
    // asks, and the kernel decides.
    //
    // Three asks, and the two refusals matter as much as the success. The
    // envelope allows exactly one child, so the second must be refused for a
    // reason that is about the *budget* and not about the capability -- which
    // is what stops one capability exhausting a table of 32 for the whole
    // machine.
    mov rax, 0                  // Kind::Invoke
    mov rdi, 3                  // capability 3: DomainControl
    mov rsi, 49                 // method::SPAWN
    mov rdx, 6                  // put the new Domain capability in slot 6
    mov r10, 0x646c696863       // "child", packed little-endian
    xor r8, r8
    syscall
    mov r12, rax                // must be OK

    // The same again, into a different slot. The capability is still good; the
    // budget is not.
    mov rax, 0
    mov rdi, 3
    mov rsi, 49
    mov rdx, 7
    mov r10, 0x646c696863
    xor r8, r8
    syscall
    mov r13, rax                // must be QUOTA_EXCEEDED

    // And on something that is not a `DomainControl` at all. Capability 0 is
    // the endpoint this program has been calling all along, so this asks
    // whether the *kind* is checked rather than merely the rights.
    mov rax, 0
    xor rdi, rdi
    mov rsi, 49
    mov rdx, 8
    xor r10, r10
    xor r8, r8
    syscall
    mov r14, rax                // must be WRONG_OBJECT

    // Report all three at once. One message rather than three, so the service
    // cannot see a partial answer and call it a pass.
    //
    // Before the revocation below, and that is not an ordering preference: the
    // report travels on capability 0, and the revocation takes capability 0
    // away. Placed after it, this call reaches nobody and every check it feeds
    // fails for a reason that has nothing to do with what it is testing --
    // which is exactly what the first version of this did.
    mov rax, 1                  // Kind::Call
    xor rdi, rdi
    mov rsi, 13                 // method: "here is what the kernel said"
    mov rdx, r12
    mov r10, r13
    mov r8, r14
    syscall


    // Revoke the parent. Transitively, that must take the derived copy too.
    mov rax, 0                  // Kind::Invoke
    xor rdi, rdi
    mov rsi, 1                  // method::REVOKE
    syscall

    // The same call again. It must fail: the capability slot is still there,
    // and the authority behind it is not.
    mov rax, 1                  // Kind::Call
    mov rdi, 1
    mov rsi, 10
    mov rdx, 5
    syscall

    mov rax, 5                  // Kind::Exit
    syscall

    // Exit does not return. If it ever does, stop here rather than running
    // into whatever follows in the page.
    ud2

// The read-only segment. Its value is ASCII "SEGMENTS", so a memory dump of a
// failing run says which page is which without a symbol table.
.section .rodata,"a",@progbits
.balign 8
MAGIC:
    .quad 0x5345474d454e5453

// The writable segment. Occupies no bytes in the file and a page in memory,
// which is the loader's zero-fill path -- and the only thing that exercises
// it.
.section .bss,"aw",@nobits
.balign 8
SCRATCH:
    .zero 8
"#
);
