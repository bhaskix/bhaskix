/* SPDX-License-Identifier: Apache-2.0
 *
 * Layout for `bin/hosted`, the program a hosted `execve` loads off the
 * filesystem — RFC 0059.
 *
 * Three loadable segments with three different permissions, each on its own
 * page, for the reason `user/probe/link.ld` gives: a single read-execute blob
 * would load identically whether the loader read the program headers or
 * ignored them, and this program exists to prove that a loader in **ring 3**
 * reads them. `bin/linuxd` maps each segment at the protection its own
 * `p_flags` asked for, so a run with the wrong protections faults here rather
 * than passing quietly.
 *
 * Fixed base, not position-independent: nothing in this project relocates, so
 * the program says where it goes and the loader puts it exactly there.
 *
 * **The base is this program's own**, clear of every address `bin/linuxd`
 * maps into a hosted domain — the built-in exec image at 0x20000000, its
 * stack at 0x20010000, the fork trampoline at 0x30000000 — and far below the
 * stack this loader maps at 0x600000000000. A segment that overlapped that
 * stack would be refused by the loader with ENOEXEC, which is a check this
 * base is chosen not to need.
 *
 * It is also unique among every program in this tree, which is a rule with a
 * cost behind it: eight programs once shared 0x10000000 in eight address
 * spaces, so one virtual address meant eight different instructions and a
 * breakpoint fired in whichever program reached it first. The first draft of
 * this file used 0x40000000, which is the memory probe's page.
 */

ENTRY(_start)

PHDRS
{
    /* `FILEHDR PHDRS` puts the ELF header and the program header table
     * inside this segment, so its file offset is zero and `AT_PHDR` has a
     * real address to name. Without them `ld` starts the segment at `.text`
     * and the headers are mapped by nothing. */
    text   PT_LOAD FILEHDR PHDRS FLAGS(5);   /* r-x */
    rodata PT_LOAD FLAGS(4);   /* r-- */
    data   PT_LOAD FLAGS(6);   /* rw- */
}

SECTIONS
{
    /* **The ELF header and the program headers are inside the first loadable
     * segment**, which is what `SIZEOF_HEADERS` here arranges and what every
     * real program does. It is not decoration: `AT_PHDR` in the auxiliary
     * vector is the address of the program headers *in the process's own
     * space*, and a runtime that walks them — Go's `runtime.sysargs`, glibc's
     * static-PIE startup — reads that pointer and follows it. With the headers
     * outside every segment there is no such address, the loader can only
     * report zero, and this program would be proving the loader works while
     * the one field a real runtime depends on was empty. */
    . = 0x70000000 + SIZEOF_HEADERS;

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
