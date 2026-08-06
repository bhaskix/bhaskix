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
