// SPDX-License-Identifier: Apache-2.0
// A return to ring 3 that zeroes twelve of the thirteen registers it must.
//
// `tools/check-ring3-entry.py --root tests/fixtures/ring3-entry` has to refuse
// this, naming `r15`; the Makefile runs it and requires the refusal. Not a
// crate and never compiled -- the containment gate skips `tests/fixtures/` for
// exactly this kind of file.
pub unsafe fn enter(rip: u64, rsp: u64) -> ! {
    unsafe {
        core::arch::asm!(
            "push {ss}",
            "push {rsp}",
            "push {rflags}",
            "push {cs}",
            "push {rip}",
            "xor eax, eax",
            "xor ebx, ebx",
            "xor ecx, ecx",
            "xor edx, edx",
            "xor ebp, ebp",
            "xor r8d, r8d",
            "xor r9d, r9d",
            "xor r10d, r10d",
            "xor r11d, r11d",
            "xor r12d, r12d",
            "xor r13d, r13d",
            "xor r14d, r14d",
            "iretq",
            options(noreturn)
        );
    }
}
