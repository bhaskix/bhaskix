// SPDX-License-Identifier: Apache-2.0
//! Interrupt Descriptor Table.
//!
//! 256 gates, all filled. Filling every vector — not just the 32 architectural
//! exceptions — matters: an unexpected interrupt on an unpopulated vector
//! raises a general protection fault whose error code points at the IDT entry,
//! and that #GP is far harder to read than "unexpected interrupt on vector
//! 0x27, probably a spurious PIC IRQ".
//!
//! Every gate points at the corresponding stub in
//! [`trap::isr_stub_table`](crate::trap), addressed arithmetically rather than
//! through 256 named symbols.

use core::mem::size_of;

use crate::cell::BootCell;
use crate::gdt::{self, KERNEL_CODE};
use crate::trap::{STUB_SIZE, isr_stub_table};

/// A 64-bit interrupt gate descriptor.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct IdtEntry {
    offset_low: u16,
    selector: u16,
    /// Bits 0-2 select an IST slot; zero means "keep the current stack".
    ist: u8,
    /// Present bit, DPL, and gate type.
    type_attributes: u8,
    offset_middle: u16,
    offset_high: u32,
    reserved: u32,
}

/// Present, DPL 0, 64-bit interrupt gate.
///
/// An *interrupt* gate rather than a trap gate: it clears IF on entry, so a
/// handler cannot be interrupted before it has established its own state. Trap
/// gates leave interrupts enabled and are the wrong default for a kernel that
/// does not yet have re-entrant handlers.
const GATE_INTERRUPT: u8 = 0b1000_1110;

impl IdtEntry {
    const fn missing() -> Self {
        Self {
            offset_low: 0,
            selector: 0,
            ist: 0,
            type_attributes: 0,
            offset_middle: 0,
            offset_high: 0,
            reserved: 0,
        }
    }

    fn set(&mut self, handler: u64, ist_index: u8) {
        self.offset_low = handler as u16;
        self.offset_middle = (handler >> 16) as u16;
        self.offset_high = (handler >> 32) as u32;
        self.selector = KERNEL_CODE;
        self.ist = ist_index & 0b111;
        self.type_attributes = GATE_INTERRUPT;
        self.reserved = 0;
    }
}

static IDT: BootCell<[IdtEntry; 256]> = BootCell::new([IdtEntry::missing(); 256]);

/// Operand for `lidt`.
#[repr(C, packed)]
struct DescriptorTablePointer {
    limit: u16,
    base: u64,
}

/// Builds and loads the IDT.
///
/// # Safety
///
/// Must be called exactly once, on the bootstrap CPU, after
/// [`gdt::init`](crate::gdt::init) — the gates reference the kernel code
/// selector, which only means anything once our GDT is loaded.
pub unsafe fn init() {
    // SAFETY: single-threaded boot, called once; see the function contract.
    unsafe {
        let idt = IDT.get_mut();
        let table_base = (&raw const isr_stub_table).cast::<u8>();

        for (vector, entry) in idt.iter_mut().enumerate() {
            let stub = table_base.add(vector * STUB_SIZE) as u64;

            // Only two vectors get a dedicated stack, and both for the same
            // reason: they can fire when the current stack is unusable.
            //
            // Deliberately NOT on an IST: the page fault. It will become a
            // routine, frequent event once demand paging lands in M3, and IST
            // stacks do not nest -- a second page fault while handling the
            // first would overwrite the first one's frame. Kernel stack
            // overflow is still caught, as a double fault.
            let ist = match vector as u8 {
                8 => gdt::IST_DOUBLE_FAULT,
                2 => gdt::IST_NMI,
                _ => 0,
            };

            entry.set(stub, ist);
        }

        let pointer = DescriptorTablePointer {
            limit: (size_of::<[IdtEntry; 256]>() - 1) as u16,
            base: IDT.as_ptr() as u64,
        };

        load_idt(&pointer);
    }
}

/// Loads the IDT register.
///
/// # Safety
///
/// `pointer` must describe a fully populated IDT whose gates reference a valid
/// code selector in the current GDT.
unsafe fn load_idt(pointer: &DescriptorTablePointer) {
    // SAFETY: `lidt` reads the descriptor the caller supplied; its validity is
    // the caller's obligation. The instruction itself cannot fail.
    unsafe {
        core::arch::asm!("lidt [{}]", in(reg) pointer, options(readonly, nostack, preserves_flags));
    }
}

/// Human-readable name for an architectural exception vector.
///
/// Returns `None` for vectors that are not architecturally defined, which the
/// caller reports as an unexpected interrupt.
#[must_use]
pub const fn exception_name(vector: u64) -> Option<&'static str> {
    Some(match vector {
        0 => "divide error (#DE)",
        1 => "debug (#DB)",
        2 => "non-maskable interrupt (NMI)",
        3 => "breakpoint (#BP)",
        4 => "overflow (#OF)",
        5 => "bound range exceeded (#BR)",
        6 => "invalid opcode (#UD)",
        7 => "device not available (#NM)",
        8 => "double fault (#DF)",
        9 => "coprocessor segment overrun",
        10 => "invalid TSS (#TS)",
        11 => "segment not present (#NP)",
        12 => "stack-segment fault (#SS)",
        13 => "general protection fault (#GP)",
        14 => "page fault (#PF)",
        16 => "x87 floating-point error (#MF)",
        17 => "alignment check (#AC)",
        18 => "machine check (#MC)",
        19 => "SIMD floating-point error (#XM)",
        20 => "virtualisation exception (#VE)",
        21 => "control protection (#CP)",
        28 => "hypervisor injection (#HV)",
        29 => "VMM communication (#VC)",
        30 => "security exception (#SX)",
        _ => return None,
    })
}

/// Whether this vector pushes an architecture-defined error code.
///
/// Used only for reporting: the stubs already normalise the frame. Printing an
/// error code of zero for a vector that never had one is misleading, and a
/// misleading register dump costs more time than a missing one.
#[must_use]
pub const fn has_error_code(vector: u64) -> bool {
    matches!(vector, 8 | 10..=14 | 17 | 21 | 29 | 30)
}
