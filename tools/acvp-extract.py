#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Extract the SLH-DSA-SHA2-128s vectors `bhaskix-bootsig` is tested against.

    python3 -I tools/acvp-extract.py sigver SLH-DSA-sigVer-FIPS205/internalProjection.json \\
        > third_party/acvp-slh-dsa/sha2-128s-sigver.tsv
    python3 -I tools/acvp-extract.py keygen SLH-DSA-keyGen-FIPS205/internalProjection.json \\
        > third_party/acvp-slh-dsa/sha2-128s-keygen.tsv
    python3 -I tools/acvp-extract.py siggen SLH-DSA-sigGen-FIPS205/internalProjection.json \\
        > third_party/acvp-slh-dsa/sha2-128s-siggen.tsv

# What it reads

NIST ACVP-Server's `gen-val/json-files/<kind>/internalProjection.json` for the
three SLH-DSA kinds -- every parameter set's vectors, prompts and answers
together. Each file is **checked against the sha256 below before anything is
read from it**, so the committed vectors can only be regenerated from the exact
upstream files they came from (`112690e8484d`, 2025-06-12; see
`third_party/acvp-slh-dsa/PROVENANCE.md`).

# What it keeps

The two SHA2-128s groups whose interface `bhaskix-bootsig` offers: the external
pure interface (FIPS 205 Algorithm 24) and the internal one (Algorithm 20). The
pre-hash group is left out, because RFC 0091 signs pure. Of each test it keeps
what verification needs and what the verdict is -- `tcId`, the group, the
verdict, the reason, the public key, the context, the message and the signature
-- one test per line, tab-separated, the byte fields in hex as upstream wrote
them. For sigVer the secret key and the signing randomness ACVP also carries are
dropped, because verification needs neither.

**keygen** (step 2, for the signer) keeps every SHA2-128s key generation: the
three seeds in, the secret and public key out. **siggen** keeps the SHA2-128s
signing groups for the same two interfaces, deterministic and hedged: the
secret key, the context, the message, the hedged variant's
`additionalRandomness`, and the signature NIST's signer produced.
"""

from __future__ import annotations

import hashlib
import json
import sys

SOURCE_SHA256 = {
    "sigver": "a013fc2104f4ed4799d96d51141f65b965969b2cf10646626a021b6d456ce792",
    "keygen": "d7c53a1b6450087047b57aae83a5a51a0ac89ecdb23ebe071e83fbb69ae9d920",
    "siggen": "62b42e7c27fda5de8a94aba2943ae413b59b6ea08141f3bc035b1eceae235dba",
}
PARAMETER_SET = "SLH-DSA-SHA2-128s"
# (signatureInterface, preHash) of the groups kept.
KEPT = {("external", "pure"), ("internal", "none")}


def row(fields: list[str], tc_id: object) -> str | None:
    if any("\t" in field or "\n" in field for field in fields):
        print(f"acvp-extract: tcId {tc_id} has a tab or newline in a field", file=sys.stderr)
        return None
    return "\t".join(fields) + "\n"


def sigver(group: dict, test: dict) -> list[str]:
    return [str(test["tcId"]), str(group["tgId"]),
            "true" if test["testPassed"] else "false", test["reason"],
            test["pk"], test.get("context", ""), test["message"], test["signature"]]


def keygen(group: dict, test: dict) -> list[str]:
    return [str(test["tcId"]), test["skSeed"], test["skPrf"], test["pkSeed"],
            test["sk"], test["pk"]]


def siggen(group: dict, test: dict) -> list[str]:
    deterministic = group["deterministic"]
    return [str(test["tcId"]), str(group["tgId"]),
            "true" if deterministic else "false", test["sk"], test.get("context", ""),
            test["message"], "" if deterministic else test["additionalRandomness"],
            test["signature"]]


KINDS = {
    "sigver": (sigver, "tcId\tgroup\ttestPassed\treason\tpk\tcontext\tmessage\tsignature", True),
    "keygen": (keygen, "tcId\tskSeed\tskPrf\tpkSeed\tsk\tpk", False),
    "siggen": (siggen, "tcId\tgroup\tdeterministic\tsk\tcontext\tmessage\taddrnd\tsignature", True),
}
NAMES = {"sigver": "sigVer", "keygen": "keyGen", "siggen": "sigGen"}


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[1] not in KINDS:
        print("usage: acvp-extract.py sigver|keygen|siggen internalProjection.json", file=sys.stderr)
        return 2
    kind, path = sys.argv[1], sys.argv[2]
    raw = open(path, "rb").read()
    found = hashlib.sha256(raw).hexdigest()
    if found != SOURCE_SHA256[kind]:
        print(f"acvp-extract: {path} is not the pinned upstream {kind} file "
              f"(sha256 {found}, want {SOURCE_SHA256[kind]})", file=sys.stderr)
        return 1
    take, header, by_interface = KINDS[kind]
    vectors = json.loads(raw)
    out = sys.stdout
    out.write(f"# {PARAMETER_SET} {NAMES[kind]}, from NIST ACVP-Server; see PROVENANCE.md.\n")
    out.write(f"# {header}\n")
    kept = 0
    for group in vectors["testGroups"]:
        if group.get("parameterSet") != PARAMETER_SET:
            continue
        if by_interface and (group.get("signatureInterface"), group.get("preHash")) not in KEPT:
            continue
        for test in group["tests"]:
            line = row(take(group, test), test["tcId"])
            if line is None:
                return 1
            out.write(line)
            kept += 1
    print(f"acvp-extract: {kept} tests kept", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
