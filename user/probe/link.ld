/* SPDX-License-Identifier: Apache-2.0
 *
 * Layout for the ring 3 probe.
 *
 * Three loadable segments with three different permissions, each on its own
 * page. That is not decoration: it is what makes the kernel's ELF loader do
 * something a `memcpy` could not. A single read-execute blob would load
 * identically whether the loader read the file's program headers or ignored
 * them.
 *
 * The base address is fixed rather than position-independent. The loader
 * refuses `ET_DYN` — it does no relocation — so the program must say where it
 * goes and be put exactly there.
 */

ENTRY(_start)

PHDRS
{
    text   PT_LOAD FLAGS(5);   /* r-x */
    rodata PT_LOAD FLAGS(4);   /* r-- */
    data   PT_LOAD FLAGS(6);   /* rw- */
}

SECTIONS
{
    /* Matches USER_CODE in the kernel. The kernel asserts that system calls
     * arrive from inside this page, which is only evidence of ring 3 if the
     * program really is here -- so the address is the file's claim and the
     * loader's obligation, not a constant both sides happen to share. */
    . = 0x10000000;

    .text : {
        *(.text._start)
        *(.text .text.*)
    } :text

    . = ALIGN(4096);
    .rodata : {
        *(.rodata .rodata.*)
    } :rodata

    . = ALIGN(4096);
    .data : {
        *(.data .data.*)
    } :data

    /* Zero-filled: contributes to p_memsz and not to p_filesz, which is the
     * loader's zero-fill path and the only thing that exercises it. */
    .bss : {
        *(.bss .bss.*)
        *(COMMON)
    } :data

    /DISCARD/ : {
        *(.eh_frame*)
        *(.comment)
        *(.note*)
        *(.debug*)
    }
}
