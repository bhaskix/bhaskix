#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Extract the SLH-DSA-SHA2-128s sigVer vectors `bhaskix-bootsig` is tested against.

    python3 -I tools/acvp-extract.py internalProjection.json \\
        > third_party/acvp-slh-dsa/sha2-128s-sigver.tsv

# What it reads

NIST ACVP-Server's `gen-val/json-files/SLH-DSA-sigVer-FIPS205/internalProjection.json`
-- every parameter set's signature-verification vectors, prompts and verdicts
together, about 30 MB. The file is **checked against the sha256 below before
anything is read from it**, so the committed vectors can only be regenerated
from the exact upstream file they came from (`112690e8484d`, 2025-06-12; see
`third_party/acvp-slh-dsa/PROVENANCE.md`).

# What it keeps

The two SHA2-128s groups whose interface `bhaskix-bootsig` offers: the external
pure interface (FIPS 205 Algorithm 24) and the internal one (Algorithm 20). The
pre-hash group is left out, because RFC 0091 signs pure. Of each test it keeps
what verification needs and what the verdict is -- `tcId`, the group, the
verdict, the reason, the public key, the context, the message and the signature
-- one test per line, tab-separated, the byte fields in hex as upstream wrote
them. The secret key and the signing randomness ACVP also carries are dropped:
nothing here signs.
"""

from __future__ import annotations

import hashlib
import json
import sys

SOURCE_SHA256 = "a013fc2104f4ed4799d96d51141f65b965969b2cf10646626a021b6d456ce792"
PARAMETER_SET = "SLH-DSA-SHA2-128s"
# (signatureInterface, preHash) of the groups kept.
KEPT = {("external", "pure"), ("internal", "none")}


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
        return 2
    raw = open(sys.argv[1], "rb").read()
    found = hashlib.sha256(raw).hexdigest()
    if found != SOURCE_SHA256:
        print(f"acvp-extract: {sys.argv[1]} is not the pinned upstream file "
              f"(sha256 {found}, want {SOURCE_SHA256})", file=sys.stderr)
        return 1
    vectors = json.loads(raw)
    out = sys.stdout
    out.write("# SLH-DSA-SHA2-128s sigVer, from NIST ACVP-Server; see PROVENANCE.md.\n")
    out.write("# tcId\tgroup\ttestPassed\treason\tpk\tcontext\tmessage\tsignature\n")
    kept = 0
    for group in vectors["testGroups"]:
        if group.get("parameterSet") != PARAMETER_SET:
            continue
        if (group.get("signatureInterface"), group.get("preHash")) not in KEPT:
            continue
        for test in group["tests"]:
            fields = [
                str(test["tcId"]),
                str(group["tgId"]),
                "true" if test["testPassed"] else "false",
                test["reason"],
                test["pk"],
                test.get("context", ""),
                test["message"],
                test["signature"],
            ]
            if any("\t" in field or "\n" in field for field in fields):
                print(f"acvp-extract: tcId {test['tcId']} has a tab or newline in a field",
                      file=sys.stderr)
                return 1
            out.write("\t".join(fields) + "\n")
            kept += 1
    print(f"acvp-extract: {kept} tests kept", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
