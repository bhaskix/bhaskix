/* SPDX-License-Identifier: Apache-2.0
 *
 * Link script for the Bhaskix kernel image.
 *
 * The kernel is linked at the top of the higher half, matching the address
 * space layout in docs/architecture.md §1. The bootloader maps it there and
 * the -2 GiB position lets the compiler use the `kernel` code model, where
 * all symbol references fit in a signed 32-bit displacement.
 */

OUTPUT_FORMAT(elf64-x86-64)
ENTRY(bhaskix_start)

/* One PT_LOAD per protection class, so the bootloader can apply W^X. A single
 * merged segment would have to be mapped read-write-execute, which would
 * violate the invariant in docs/memory.md §3 before the kernel even starts. */
PHDRS
{
    text    PT_LOAD FLAGS((1 << 2) | (1 << 0));    /* R + X */
    rodata  PT_LOAD FLAGS((1 << 2));               /* R     */
    data    PT_LOAD FLAGS((1 << 2) | (1 << 1));    /* R + W */
}

SECTIONS
{
    . = 0xffffffff80000000;

    .text : {
        *(.text .text.*)
    } :text

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    .rodata : {
        *(.rodata .rodata.*)
    } :rodata

    /* The exception table: pairs of (faulting address, recovery address) that
     * make a fault at a known instruction recoverable instead of fatal.
     * Bracketed by symbols so arch::uaccess can walk it, and KEEP so it
     * survives even though nothing references the entries by name. */
    .exception_table : {
        PROVIDE_HIDDEN(__exception_table_start = .);
        KEEP(*(.exception_table))
        PROVIDE_HIDDEN(__exception_table_end = .);
    } :rodata

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    /* The Limine requests live in the WRITABLE segment, not rodata.
     *
     * The bootloader writes response pointers into them. It does so before it
     * applies any protection to our segments, so rodata would happen to work
     * today -- but it would be relying on the bootloader's internal ordering,
     * and it would break the moment anything maps rodata read-only earlier.
     * Writable is what the data actually is. */
    .requests_start_marker : { KEEP(*(.requests_start_marker)) } :data
    .requests              : { KEEP(*(.requests))              } :data
    .requests_end_marker   : { KEEP(*(.requests_end_marker))   } :data

    .data : {
        *(.data .data.*)
    } :data

    .bss : {
        *(.bss .bss.*)
        *(COMMON)
    } :data

    /* Unwinding tables are dead weight: the kernel is built with
     * panic = "abort" and there is no unwinder to consume them. */
    /DISCARD/ : {
        *(.eh_frame*)
        *(.note .note.*)
        *(.comment)
    }
}
