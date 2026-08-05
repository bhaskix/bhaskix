/* SPDX-License-Identifier: Apache-2.0
 *
 * Layout for the block driver, running in its own domain.
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
    /* Where this program says it goes. The kernel's loader honours it because
     * the file asks; nothing in the kernel chooses an address for a program.
     * Deliberately the same base as the probe's: they never share an address
     * space, and using different ones would suggest the kernel keeps a map of
     * who lives where, which it does not. */
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

    /* Zero-filled: contributes to p_memsz and not to p_filesz. A blkd has
     * real state -- buffers, a line editor -- so unlike the probe this
     * segment is load-bearing rather than a test of the loader. */
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
