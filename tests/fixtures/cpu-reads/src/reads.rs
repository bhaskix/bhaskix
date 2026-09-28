// SPDX-License-Identifier: Apache-2.0
//! A fixture for `tools/check-cpu-reads.py`, which must refuse this file.
//!
//! One read says why a migration cannot split it; the other is the shape
//! found eight times on 2026-09-28 -- read the CPU, then act on that CPU's
//! state, with nothing to stop the thread moving in between.

fn masked_read() -> usize {
    disable_interrupts();
    // CPU: masked -- interrupts were masked just above.
    let cpu = percpu::cpu_id() as usize;
    enable_interrupts();
    cpu
}

fn bare_read() -> Option<u32> {
    let cpu = percpu::cpu_id() as usize;
    let queue = QUEUES[cpu].lock();
    queue.threads[queue.current].as_ref().map(|thread| thread.id)
}
