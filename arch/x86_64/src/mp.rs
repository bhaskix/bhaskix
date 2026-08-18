// SPDX-License-Identifier: Apache-2.0
//! The real-mode trampoline: a secondary CPU from reset to the kernel.
//!
//! A processor released by STARTUP begins in real mode, at a page-aligned
//! address below one megabyte, with nothing — no GDT, no paging, no stack.
//! This module is the code that takes it the rest of the way: 16-bit entry,
//! protected mode, PAE, long mode with `EFER.NXE` set so the kernel's NX
//! bits are architecture rather than reserved-bit faults, then a stack and
//! a jump to the 64-bit entry the kernel patched in.
//!
//! # The image is copied, never executed in place
//!
//! The bytes live in the kernel's own text section, at a high-half address
//! no real-mode CPU can reach. The kernel copies them to a low page and
//! patches the slots this module names. The code is position-independent by
//! construction: the 16-bit entry recovers its own physical base from `CS`
//! (STARTUP sets `CS` to the page, `IP` to zero) and carries it in `ebx`
//! for the protected-mode load; the 64-bit stage uses RIP-relative
//! addressing, whose displacements the copy preserves — the only absolute
//! values in the page are the ones the kernel wrote there on purpose.
//!
//! # The far jumps are hand-encoded
//!
//! A mode change ends with a far jump whose target is an absolute address
//! known only at copy time. Each is emitted as explicit bytes with a named
//! label on its immediate, so the patch offset is a symbol the kernel reads
//! rather than a magic number counted off a disassembly.

use core::arch::global_asm;

global_asm!(
    r#"
.section .text
.balign 16
.globl bhaskix_mp_start
.globl bhaskix_mp_end
.globl bhaskix_mp_prot32
.globl bhaskix_mp_long64
.globl bhaskix_mp_pm_target
.globl bhaskix_mp_lm_target
.globl bhaskix_mp_gdt
.globl bhaskix_mp_gdtdesc
.globl bhaskix_mp_cr3
.globl bhaskix_mp_stack
.globl bhaskix_mp_entry
.code16
bhaskix_mp_start:
    cli
    cld
    // The page's physical base, recovered from the segment STARTUP set:
    // CS is the SIPI vector shifted left by eight, so CS shifted left by
    // four is the address this page was copied to. Carried in ebx from
    // here to the last jump.
    xor ebx, ebx
    mov bx, cs
    shl ebx, 4
    // Data references below are ds-relative; point ds at this page.
    mov ax, cs
    mov ds, ax
    // lgdt [disp16], hand-encoded: the assembler refuses a symbol
    // difference inside a memory operand, but takes one as a data fixup.
    .byte 0x0f, 0x01, 0x16
    .word bhaskix_mp_gdtdesc - bhaskix_mp_start
    mov eax, cr0
    or eax, 1
    mov cr0, eax
    // ljmp 0x08:imm32, hand-encoded so the immediate has a name. The jump
    // is what loads a protected-mode CS; it must be the next instruction
    // after PE is set.
    .byte 0x66, 0xea
bhaskix_mp_pm_target:
    .long 0
    .word 0x08
.code32
bhaskix_mp_prot32:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    // PAE, required before the root is loaded.
    mov eax, cr4
    or eax, 1 << 5
    mov cr4, eax
    // The root the kernel chose. Read as 32 bits because this instruction
    // runs in protected mode; the kernel refuses bring-up if its root does
    // not fit, rather than letting this read truncate one that does not.
    // mov eax, [ebx + disp32], hand-encoded for the same reason as the
    // lgdt above.
    .byte 0x8b, 0x83
    .long bhaskix_mp_cr3 - bhaskix_mp_start
    mov cr3, eax
    // Long mode and no-execute in one EFER write: LME so turning paging on
    // enters long mode, NXE so the NX bits in the kernel's tables are
    // architecture rather than reserved-bit faults on this CPU too.
    mov ecx, 0xC0000080
    rdmsr
    or eax, (1 << 8) | (1 << 11)
    wrmsr
    mov eax, cr0
    or eax, 0x80000001
    mov cr0, eax
    // ljmp 0x18:imm32, hand-encoded as above. Loads the 64-bit CS.
    .byte 0xea
bhaskix_mp_lm_target:
    .long 0
    .word 0x18
.code64
bhaskix_mp_long64:
    mov ax, 0x10
    mov ss, ax
    mov ds, ax
    mov es, ax
    // The stack is not read, it is CLAIMED. A processor that runs late —
    // and under emulation "late" is routine — must never use an offer
    // meant for a sibling *and also let the sibling use it*: the mailbox
    // is emptied by the winner in the same instruction that wins it, so
    // every stack leaves this slot exactly once. RIP-relative, because
    // the displacement is a distance the copy preserves.
2:
    pause
    mov rax, [rip + bhaskix_mp_stack]
    test rax, rax
    jz 2b
    xor ecx, ecx
    lock cmpxchg [rip + bhaskix_mp_stack], rcx
    jnz 2b
    mov rsp, rax
    xor ebp, ebp
    xor edi, edi
    mov rax, [rip + bhaskix_mp_entry]
    jmp rax

// The bring-up GDT: null, 32-bit code, data, 64-bit code. Selectors 0x08,
// 0x10 and 0x18 above index this table and nothing else ever does — the
// CPU replaces it with its own the moment it reaches the kernel.
.balign 8
bhaskix_mp_gdt:
    .quad 0
    .quad 0x00CF9A000000FFFF
    .quad 0x00CF92000000FFFF
    .quad 0x00AF9A000000FFFF
bhaskix_mp_gdtdesc:
    .word (bhaskix_mp_gdtdesc - bhaskix_mp_gdt) - 1
    .long 0

// The slots the kernel patches, 8-aligned within the page because the
// 64-bit reads above deserve aligned loads.
.balign 8
bhaskix_mp_cr3:
    .quad 0
bhaskix_mp_stack:
    .quad 0
bhaskix_mp_entry:
    .quad 0
bhaskix_mp_end:
"#
);

unsafe extern "C" {
    static bhaskix_mp_start: u8;
    static bhaskix_mp_end: u8;
    static bhaskix_mp_prot32: u8;
    static bhaskix_mp_long64: u8;
    static bhaskix_mp_pm_target: u8;
    static bhaskix_mp_lm_target: u8;
    static bhaskix_mp_gdt: u8;
    static bhaskix_mp_gdtdesc: u8;
    static bhaskix_mp_cr3: u8;
    static bhaskix_mp_stack: u8;
    static bhaskix_mp_entry: u8;
}

/// Where everything sits inside the trampoline image, as byte offsets from
/// its start — which is also its offset from the base of the page the
/// kernel copies it to.
#[derive(Clone, Copy, Debug)]
pub struct Layout {
    /// Total image size. Must fit one page, and [`layout`] asserts it.
    pub len: usize,
    /// The protected-mode far jump's 32-bit immediate: patch with the
    /// page base plus [`Layout::prot32`].
    pub pm_target: usize,
    /// The long-mode far jump's 32-bit immediate: patch with the page
    /// base plus [`Layout::long64`].
    pub lm_target: usize,
    /// The 32-bit entry the first far jump must land on.
    pub prot32: usize,
    /// The 64-bit entry the second far jump must land on.
    pub long64: usize,
    /// The GDT itself, for computing the descriptor's base.
    pub gdt: usize,
    /// The GDT descriptor; its 32-bit base field is at `+ 2`.
    pub gdtdesc: usize,
    /// The root the CPU loads, read as 32 bits — the kernel refuses a
    /// root at or above 4 GiB rather than letting it truncate.
    pub cr3: usize,
    /// The stack mailbox: the kernel offers a stack top here with one
    /// atomic store, and a released processor claims it with `lock
    /// cmpxchg`, emptying the slot in the same instruction — so a stack
    /// leaves this mailbox exactly once no matter how late a processor
    /// runs. Zero means "nothing on offer".
    pub stack: usize,
    /// The 64-bit address of the `extern "C" fn(u32) -> !` to jump to.
    /// The argument register arrives zeroed: a claimed stack is anonymous,
    /// so the entry derives the processor's identity itself.
    pub entry: usize,
}

/// The trampoline's bytes, to be copied below one megabyte and patched.
#[must_use]
pub fn image() -> &'static [u8] {
    let bounds = layout();
    // SAFETY: `bhaskix_mp_start` and the length from `layout` bound exactly
    // the bytes the `global_asm!` above placed in the kernel's text section,
    // immutable for the life of the image.
    unsafe { core::slice::from_raw_parts(&raw const bhaskix_mp_start, bounds.len) }
}

/// Offset of `symbol` from the image start.
fn offset(symbol: *const u8) -> usize {
    // Address arithmetic only; nothing is dereferenced here.
    let start = (&raw const bhaskix_mp_start) as usize;
    symbol as usize - start
}

/// Measures the image, from the symbols the assembly exported.
///
/// # Panics
///
/// If the image outgrows one page — a build error surfacing at first use,
/// not a runtime condition.
#[must_use]
pub fn layout() -> Layout {
    // Addresses of `global_asm!` symbols only; nothing is dereferenced,
    // and the addresses are link-time constants.
    let bounds = {
        Layout {
            len: offset(&raw const bhaskix_mp_end),
            pm_target: offset(&raw const bhaskix_mp_pm_target),
            lm_target: offset(&raw const bhaskix_mp_lm_target),
            prot32: offset(&raw const bhaskix_mp_prot32),
            long64: offset(&raw const bhaskix_mp_long64),
            gdt: offset(&raw const bhaskix_mp_gdt),
            gdtdesc: offset(&raw const bhaskix_mp_gdtdesc),
            cr3: offset(&raw const bhaskix_mp_cr3),
            stack: offset(&raw const bhaskix_mp_stack),
            entry: offset(&raw const bhaskix_mp_entry),
        }
    };
    assert!(bounds.len <= 4096, "the trampoline outgrew its page");
    bounds
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_image_fits_a_page_and_starts_with_cli() {
        let image = image();
        assert!(image.len() <= 4096);
        assert_eq!(image[0], 0xfa, "the first byte must be cli");
    }

    #[test]
    fn the_far_jumps_are_the_encodings_the_patcher_assumes() {
        let image = image();
        let bounds = layout();
        // ljmp 0x08:imm32 in 16-bit code: operand-size prefix, then 0xEA.
        assert_eq!(image[bounds.pm_target - 2], 0x66);
        assert_eq!(image[bounds.pm_target - 1], 0xea);
        assert_eq!(
            &image[bounds.pm_target + 4..bounds.pm_target + 6],
            &[0x08, 0x00]
        );
        // ljmp 0x18:imm32 in 32-bit code: 0xEA alone.
        assert_eq!(image[bounds.lm_target - 1], 0xea);
        assert_eq!(
            &image[bounds.lm_target + 4..bounds.lm_target + 6],
            &[0x18, 0x00]
        );
    }

    #[test]
    fn the_gdt_descriptor_covers_the_gdt() {
        let image = image();
        let bounds = layout();
        let limit = u16::from_le_bytes([image[bounds.gdtdesc], image[bounds.gdtdesc + 1]]);
        assert_eq!(usize::from(limit), bounds.gdtdesc - bounds.gdt - 1);
        assert_eq!(limit, 31, "four descriptors, eight bytes each");
    }

    #[test]
    fn the_patch_slots_are_eight_aligned_and_inside_the_image() {
        let bounds = layout();
        for slot in [bounds.cr3, bounds.stack, bounds.entry] {
            assert_eq!(slot % 8, 0);
            assert!(slot + 8 <= bounds.len);
        }
        assert!(bounds.pm_target + 6 <= bounds.len);
        assert!(bounds.lm_target + 6 <= bounds.len);
    }
}
