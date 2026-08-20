// SPDX-License-Identifier: Apache-2.0
//! Wrong in one way, on purpose — see `Cargo.toml`. One architecture-specific
//! instruction, and no `asm_budget` declared for it.
//!
//! This comment is the fixture's second half. It mentions `asm!`,
//! `global_asm!` and `core::arch::x86_64::__cpuid` in prose, and **none of
//! those may count**: a budget inflated by documentation is a budget with room
//! underneath it for a real instruction nobody declared. So a run that reports
//! four sites here has a counter reading comments, and a run that reports one
//! has a counter reading code.

#![no_std]

core::arch::global_asm!(
    r#"
.section .text.fixture,"ax",@progbits
.globl bhaskix_fixture_stop
bhaskix_fixture_stop:
    hlt
"#
);
