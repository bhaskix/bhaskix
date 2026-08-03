// SPDX-License-Identifier: Apache-2.0
//! Global Descriptor Table and Task State Segment.
//!
//! In 64-bit mode segmentation is almost entirely vestigial: the base and
//! limit fields are ignored for the segments the kernel uses. Three things
//! still matter, and they are the reason this file exists:
//!
//! 1. **Privilege level.** `CS.DPL` is what makes ring 0 ring 0. User mode in
//!    M5 needs its own code and data descriptors.
//! 2. **`RSP0` in the TSS.** The stack the CPU switches to on a privilege
//!    transition. Nothing works in user mode without it.
//! 3. **The IST.** Up to seven stacks the CPU switches to unconditionally for
//!    chosen vectors, *regardless of the current stack's state*. This is the
//!    only mechanism that lets the kernel report a fault that happened because
//!    the stack itself was broken.
//!
//! # Why the double fault gets its own stack
//!
//! A kernel stack overflow runs off the end of the stack into its guard page.
//! That raises a page fault. The CPU tries to push a fault frame — onto the
//! same overflowed stack — which faults again, and a fault during fault
//! delivery is a double fault. If the double-fault handler also has no usable
//! stack, the CPU triple-faults and the machine silently resets.
//!
//! Putting the double-fault handler on `IST1` gives it a known-good stack, so
//! stack overflow becomes a clean diagnostic instead of a reboot loop. This is
//! the single highest-value thing in M2, because "the machine reboots and I
//! don't know why" is the worst debugging position in kernel work.

use core::mem::size_of;

use crate::cell::BootCell;

/// Kernel code segment selector.
pub const KERNEL_CODE: u16 = 0x08;
/// Kernel data segment selector.
pub const KERNEL_DATA: u16 = 0x10;
/// User data segment selector.
pub const USER_DATA: u16 = 0x18;
/// User code segment selector (64-bit).
pub const USER_CODE: u16 = 0x20;
/// TSS descriptor selector.
pub const TSS_SELECTOR: u16 = 0x28;

/// IST slot used by the double-fault handler.
pub const IST_DOUBLE_FAULT: u8 = 1;
/// IST slot used by the NMI handler.
pub const IST_NMI: u8 = 2;

/// Size of each interrupt stack.
///
/// 16 KiB is generous for a handler whose job is to format a diagnostic and
/// halt. It is not a working stack; if a handler ever needs more than this,
/// the handler is doing too much.
const IST_STACK_SIZE: usize = 16 * 1024;

/// A naturally aligned interrupt stack.
///
/// 16-byte alignment is required by the SysV ABI, which the Rust handler code
/// assumes. Getting this wrong produces misaligned SSE accesses inside the
/// fault handler — a fault while reporting a fault.
#[repr(C, align(16))]
struct Stack([u8; IST_STACK_SIZE]);

/// Interrupt stacks, per CPU: `[cpu][0]` is the double-fault stack and
/// `[cpu][1]` the NMI stack.
///
/// Per CPU, not shared, and that is the whole point of this being an array.
/// A shared IST means two processors taking a double fault at the same moment
/// land on the *same* stack and overwrite each other's fault frame — turning
/// two diagnosable faults into one corrupted report, at exactly the moment the
/// machine is least able to explain itself.
///
/// Lives in `.bss`, so it costs address space rather than image size.
static IST_STACKS: BootCell<[[Stack; 2]; crate::percpu::MAX_CPUS]> = BootCell::new(
    [const { [Stack([0; IST_STACK_SIZE]), Stack([0; IST_STACK_SIZE])] }; crate::percpu::MAX_CPUS],
);

/// The 64-bit Task State Segment.
///
/// Layout is fixed by the architecture; the `packed` representation and the
/// reserved fields are not stylistic choices.
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct TaskStateSegment {
    reserved_0: u32,
    /// Stack pointers for privilege levels 0-2.
    privilege_stack_table: [u64; 3],
    reserved_1: u64,
    /// The seven interrupt stacks. Index 0 here is `IST1` in the manual.
    interrupt_stack_table: [u64; 7],
    reserved_2: u64,
    reserved_3: u16,
    /// Offset of the I/O permission bitmap.
    ///
    /// Set past the end of the segment, which means "no bitmap": every I/O
    /// port access from user mode faults. Bhaskix grants port access through
    /// capabilities (M5), never through this bitmap.
    iomap_base: u16,
}

impl TaskStateSegment {
    const fn new() -> Self {
        Self {
            reserved_0: 0,
            privilege_stack_table: [0; 3],
            reserved_1: 0,
            interrupt_stack_table: [0; 7],
            reserved_2: 0,
            reserved_3: 0,
            iomap_base: size_of::<Self>() as u16,
        }
    }
}

/// One TSS per CPU. The task register is per-CPU state, and `ltr` marks the
/// descriptor *busy* — a second CPU running `ltr` against a descriptor the
/// first has already claimed raises `#GP`, so sharing one is not merely
/// unwise, it does not work.
static TSSES: BootCell<[TaskStateSegment; crate::percpu::MAX_CPUS]> =
    BootCell::new([TaskStateSegment::new(); crate::percpu::MAX_CPUS]);

/// The GDT: five 8-byte descriptors plus a 16-byte TSS descriptor.
#[repr(C, align(16))]
struct Gdt {
    entries: [u64; 7],
}

/// One GDT per CPU, because each embeds a descriptor for that CPU's own TSS.
///
/// The five segment descriptors are identical across CPUs; only the TSS
/// descriptor differs. Duplicating the whole table is simpler than sharing the
/// segments and splitting the TSS entry, and costs a few hundred bytes per CPU.
static GDTS: BootCell<[Gdt; crate::percpu::MAX_CPUS]> =
    BootCell::new([const { Gdt { entries: [0; 7] } }; crate::percpu::MAX_CPUS]);

/// Operand for `lgdt`.
#[repr(C, packed)]
struct DescriptorTablePointer {
    limit: u16,
    base: u64,
}

// Descriptor access-byte and flag bits. Named rather than inlined as magic
// hex, because a wrong bit here produces a triple fault with no diagnostic.
const ACCESS_PRESENT: u64 = 1 << 47;
const ACCESS_USER_SEGMENT: u64 = 1 << 44; // code or data, not a system segment
const ACCESS_EXECUTABLE: u64 = 1 << 43;
const ACCESS_READ_WRITE: u64 = 1 << 41;
const ACCESS_ACCESSED: u64 = 1 << 40;
const FLAG_LONG_MODE: u64 = 1 << 53;
const FLAG_GRANULARITY: u64 = 1 << 55;
const FLAG_DEFAULT_SIZE: u64 = 1 << 54; // must be 0 for 64-bit code

// The 20-bit limit is SPLIT across the descriptor: the low 16 bits sit at
// bits 0-15, and the high 4 bits at bits 48-51. Bits 16-39 in between are the
// *base address*, not more limit.
//
// Writing the whole 0xfffff into the low bits -- the obvious-looking mistake --
// puts 0xf into base[3:0]. In 64-bit mode the base is supposed to be ignored,
// so this looks harmless and boots fine right up until a far return, where the
// target lands at base+offset, mid-instruction, and the CPU executes garbage.
const LIMIT_LOW: u64 = 0xffff;
const LIMIT_HIGH: u64 = 0xf << 48;

const fn dpl(level: u64) -> u64 {
    level << 45
}

const fn code_segment(privilege: u64) -> u64 {
    ACCESS_PRESENT
        | ACCESS_USER_SEGMENT
        | ACCESS_EXECUTABLE
        | ACCESS_READ_WRITE
        | ACCESS_ACCESSED
        | FLAG_LONG_MODE
        | FLAG_GRANULARITY
        | dpl(privilege)
        | LIMIT_LOW
        | LIMIT_HIGH
}

const fn data_segment(privilege: u64) -> u64 {
    ACCESS_PRESENT
        | ACCESS_USER_SEGMENT
        | ACCESS_READ_WRITE
        | ACCESS_ACCESSED
        | FLAG_GRANULARITY
        | FLAG_DEFAULT_SIZE
        | dpl(privilege)
        | LIMIT_LOW
        | LIMIT_HIGH
}

/// Builds and loads this CPU's GDT and TSS.
///
/// Every CPU calls this with its own dense identifier. The bootstrap CPU uses
/// 0; secondaries use the index [`crate::percpu::install`] gave them, which is
/// why per-CPU data must be established before this runs.
///
/// # Safety
///
/// Must be called exactly once per CPU, with interrupts disabled, and
/// `cpu_id` must be unique and below [`crate::percpu::MAX_CPUS`]. It replaces
/// whatever descriptor tables were previously loaded on this CPU, so an
/// interrupt taken partway through would use a half-built GDT.
pub unsafe fn init_cpu(cpu_id: usize) {
    if cpu_id >= crate::percpu::MAX_CPUS {
        return;
    }

    // SAFETY: `cpu_id` is unique per the caller's contract, so this CPU is the
    // only writer of these elements; the arrays are `static` and never move.
    unsafe {
        let stacks = &mut IST_STACKS.get_mut()[cpu_id];
        let double_fault_top = (&raw mut stacks[0]).cast::<u8>().add(IST_STACK_SIZE) as u64;
        let nmi_top = (&raw mut stacks[1]).cast::<u8>().add(IST_STACK_SIZE) as u64;

        let tss = &mut TSSES.get_mut()[cpu_id];
        *tss = TaskStateSegment::new();
        tss.interrupt_stack_table[(IST_DOUBLE_FAULT - 1) as usize] = double_fault_top;
        tss.interrupt_stack_table[(IST_NMI - 1) as usize] = nmi_top;

        // RSP0 stays zero until M5. There is no user mode yet, so nothing
        // consults it, and a zero is more honest than a plausible wrong value.

        let tss_base = (&raw const *tss) as u64;
        let tss_limit = (size_of::<TaskStateSegment>() - 1) as u64;

        // A 64-bit TSS descriptor is 16 bytes: the usual 8-byte descriptor
        // with the top half of the base address in the following slot.
        let tss_low = ACCESS_PRESENT
            | (tss_limit & 0xffff)
            | ((tss_base & 0xff_ffff) << 16)
            | (((tss_base >> 24) & 0xff) << 56)
            | (0b1001 << 40); // type: 64-bit TSS, available
        let tss_high = tss_base >> 32;

        let gdt = &mut GDTS.get_mut()[cpu_id];
        gdt.entries = [
            0,               // 0x00 null
            code_segment(0), // 0x08 kernel code
            data_segment(0), // 0x10 kernel data
            data_segment(3), // 0x18 user data
            code_segment(3), // 0x20 user code
            tss_low,         // 0x28 TSS, low half
            tss_high,        //      TSS, high half
        ];

        // The user data descriptor sits *before* user code on purpose:
        // SYSRET derives SS from STAR[63:48]+8 and CS from STAR[63:48]+16, so
        // this ordering is what will let M5 use it without rebuilding the GDT.

        let pointer = DescriptorTablePointer {
            limit: (size_of::<Gdt>() - 1) as u16,
            base: (&raw const *gdt) as u64,
        };

        load_gdt(&pointer);
        load_task_register(TSS_SELECTOR);
    }
}

/// Builds and loads the bootstrap CPU's GDT and TSS.
///
/// # Safety
///
/// As [`init_cpu`], with `cpu_id` 0.
pub unsafe fn init() {
    // SAFETY: delegated; the bootstrap CPU is always dense id 0.
    unsafe { init_cpu(0) }
}

/// Loads the GDT and reloads every segment register.
///
/// `CS` cannot be assigned directly, so it is reloaded with a far return: push
/// the target selector and address, then `retfq` pops both into `CS:RIP`.
///
/// # Safety
///
/// `pointer` must describe a valid GDT whose selectors match the constants in
/// this module.
unsafe fn load_gdt(pointer: &DescriptorTablePointer) {
    // SAFETY: `lgdt` loads the register from the caller-supplied descriptor,
    // whose validity is the caller's obligation. The far return targets `2:`
    // in this same function with the kernel code selector, and the data
    // registers are then loaded with the kernel data selector. Both selectors
    // are indices into the table just loaded.
    unsafe {
        core::arch::asm!(
            "lgdt [{pointer}]",

            // Far return to reload CS.
            "push {code_sel}",
            "lea {tmp}, [rip + 2f]",
            "push {tmp}",
            "retfq",
            "2:",

            // Data segments. SS must be reloaded too: an interrupt taken with
            // a stale SS would fault on the stack switch.
            "mov ss, {data_sel:x}",
            "mov ds, {data_sel:x}",
            "mov es, {data_sel:x}",

            // FS and GS get the null selector. Their *bases* are what matter
            // on x86-64 and are programmed through MSRs when per-CPU data
            // arrives in M4; a stale selector here would be misleading.
            "xor {zero:e}, {zero:e}",
            "mov fs, {zero:x}",
            "mov gs, {zero:x}",

            pointer = in(reg) pointer,
            code_sel = const KERNEL_CODE as u64,
            data_sel = in(reg) KERNEL_DATA as u64,

            // `out`, not `lateout`. `lateout` lets the register allocator
            // reuse a register holding an input, and it did exactly that:
            // `tmp` landed on the same register as an input, so the `lea`
            // clobbered it and the segment loads used a garbage selector.
            // `out` forbids that overlap.
            zero = out(reg) _,
            tmp = out(reg) _,

            // No `preserves_flags`: the `xor` above writes them.
        );
    }
}

/// Loads the task register with the TSS selector.
///
/// # Safety
///
/// `selector` must index a present, available 64-bit TSS descriptor in the
/// currently loaded GDT.
unsafe fn load_task_register(selector: u16) {
    // SAFETY: `ltr` marks the descriptor busy and loads the task register. The
    // caller guarantees the selector is a valid available TSS descriptor;
    // loading a busy or non-TSS descriptor raises #GP.
    unsafe {
        core::arch::asm!("ltr {0:x}", in(reg) selector, options(nomem, nostack, preserves_flags));
    }
}
