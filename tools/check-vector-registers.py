#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The nucleus names no vector register outside its save and restore.

RFC 0094 step 0. **The property the switch path's design rests on**: a user
thread's floating-point and vector state stays in the registers, untouched,
while the kernel runs, until a switch saves it. That is true only because the
kernel's own code never uses those registers -- its target enables `x87` and
`fxsr` and nothing else -- and nothing would notice if a dependency, a
compiler upgrade or a hand-written `asm!` started to: a kernel `memcpy` through
`xmm0` would hand one program another's bytes.

So the release kernel is disassembled and every instruction is read:

* an operand naming a vector, MMX, AVX-512 mask or x87 register fails it;
* an x87 instruction fails it, and so does one that writes `MXCSR` or the
  upper halves (`ldmxcsr`, `vzeroupper`, ...), registers or not;
* the instructions that save, restore and configure the state -- `fxsave`,
  `xsaveopt`, `xrstor`, `xsetbv` and their kin -- are the exception, counted
  and printed, because they are the switch path doing its job.

    check-vector-registers.py target/x86_64-unknown-none/release/bhaskix
    check-vector-registers.py --self-test
"""

import re
import subprocess
import sys

# The switch path's own instructions: save, restore, and what configures them.
ALLOWED = {
    "fxsave", "fxsave64", "fxrstor", "fxrstor64",
    "xsave", "xsave64", "xsaveopt", "xsaveopt64", "xsavec", "xsavec64",
    "xrstor", "xrstor64", "xsetbv", "xgetbv",
}
# Instructions that touch the state with no register operand to give them away.
DENIED = {
    "ldmxcsr", "stmxcsr", "vldmxcsr", "vstmxcsr", "emms", "femms",
    "vzeroupper", "vzeroall",
}
# Registers whose naming means the instruction uses the state.
REGISTER = re.compile(r"%(?:[xyz]mm\d+|mm[0-7]\b|k[0-7]\b|st\b|st\(\d\))")
# One `objdump -d` instruction line: address, then (after --no-show-raw-insn)
# the mnemonic and its operands.
LINE = re.compile(r"^\s*([0-9a-f]+):\s+([a-z][a-z0-9.]*)\s*(.*)$")
FUNCTION = re.compile(r"^[0-9a-f]+ <(.+)>:$")


def check(lines):
    """Answers (offences, allowed-count by mnemonic)."""
    offences = []
    allowed = {}
    where = "?"
    for line in lines:
        header = FUNCTION.match(line.strip())
        if header:
            where = header.group(1)
            continue
        found = LINE.match(line)
        if not found:
            continue
        address, mnemonic, operands = found.groups()
        # A prefix objdump prints as its own word (`rex.W`, `lock`) is not the
        # instruction; the next word is.
        while mnemonic in ("lock", "rep", "repz", "repnz", "data16", "addr32", "notrack", "bnd", "cs", "ds") \
                or mnemonic.startswith("rex"):
            parts = operands.split(None, 1)
            if not parts:
                break
            mnemonic, operands = parts[0], (parts[1] if len(parts) > 1 else "")
        if mnemonic in ALLOWED:
            allowed[mnemonic] = allowed.get(mnemonic, 0) + 1
            continue
        x87 = mnemonic.startswith("f") and mnemonic not in ALLOWED
        if x87 or mnemonic in DENIED or REGISTER.search(operands):
            offences.append(f"{address} in {where}: {mnemonic} {operands}".rstrip())
    return offences, allowed


def disassemble(path):
    out = subprocess.run(
        ["objdump", "-d", "--no-show-raw-insn", path],
        check=True, capture_output=True, text=True,
    )
    return out.stdout.splitlines()


def self_test():
    clean = [
        "ffffffff80001000 <switch>:",
        "ffffffff80001000:\tfxsave64 (%rdi)",
        "ffffffff80001004:\txsaveopt64 (%rdi)",
        "ffffffff80001008:\txrstor64 (%rsi)",
        "ffffffff8000100c:\tmov    %rax,%rbx",
        "ffffffff80001010:\txgetbv",
    ]
    offences, allowed = check(clean)
    assert offences == [], offences
    assert allowed == {"fxsave64": 1, "xsaveopt64": 1, "xrstor64": 1, "xgetbv": 1}, allowed
    for dirty, why in [
        ("ffffffff80002000:\tmovaps %xmm0,(%rdi)", "an xmm register"),
        ("ffffffff80002000:\tvmovdqu %ymm1,(%rdi)", "a ymm register"),
        ("ffffffff80002000:\tkmovw  %k1,%eax", "an AVX-512 mask"),
        ("ffffffff80002000:\tfldz", "an x87 instruction"),
        ("ffffffff80002000:\tldmxcsr (%rsp)", "MXCSR written"),
        ("ffffffff80002000:\tvzeroupper", "the upper halves cleared"),
        ("ffffffff80002000:\tpaddq  %mm0,%mm1", "an MMX register"),
    ]:
        offences, _ = check(["ffffffff80002000 <memcpy>:", dirty])
        assert len(offences) == 1, f"{why} was not refused"
        assert "memcpy" in offences[0], offences
    print("  ok    the vector-register gate refuses an xmm, a ymm, a mask, an x87 instruction, "
          "MXCSR, vzeroupper and an MMX register, and lets the save and restore through")


def main():
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return 0
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    offences, allowed = check(disassemble(sys.argv[1]))
    if offences:
        print(f"FAIL  the kernel uses the vector or x87 registers in {len(offences)} instruction(s); "
              "a user thread's state would not survive the kernel running:")
        for offence in offences[:20]:
            print(f"        {offence}")
        return 1
    saved = ", ".join(f"{count} {name}" for name, count in sorted(allowed.items()))
    print(f"ok    the kernel names no vector or x87 register outside its save and restore ({saved})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
