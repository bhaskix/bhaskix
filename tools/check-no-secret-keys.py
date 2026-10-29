#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""No release-signing secret is tracked in this repository.

GOVERNANCE.md section 5 has said "Nobody ships a release-signing key in a
repository" since the project began, and until 2026-10-29 nothing checked it:
a promise in prose. RFC 0091 step 6 prepares the keys that promise is about --
an offline CA and signing leaf for the firmware, and an SLH-DSA key for
`boot.sig` -- so the promise becomes a gate before the first of them exists.

A tracked file is refused when it is any of:

1. **A PEM private key** -- the armour OpenSSL writes around an RSA, EC or
   PKCS#8 key, encrypted or not.
2. **A `*.secret` file** -- the name `bootsign keygen` gives a secret key --
   other than the published test key, which is published on purpose and named
   as such (`tests/keys/`, RFC 0091 question 7).
3. **A 64-byte file ending in a release public key.** An SLH-DSA-SHA2-128s
   secret key is `SK.seed || SK.prf || PK.seed || PK.root` (FIPS 205 section
   9.1), so its last 32 bytes *are* its public key. A secret renamed to
   anything at all is still caught beside the public half committed under
   `boot/keys/`.

What it does not see: a secret inside an archive, or one re-encoded. It is the
check for the mistakes a person makes by hand -- a `git add -A` in the wrong
directory -- not for someone hiding a key on purpose.

`--self-test` builds throwaway repositories, one per kind, and requires each to
be refused and the published test key accepted -- so nothing key-shaped is ever
committed to show that the gate can fail.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

GREEN = "\033[1;32m"
RED = "\033[1;31m"
RESET = "\033[0m"

# Split so this file does not itself hold a whole armour line.
ARMOUR = re.compile(rb"-----BEGIN " + rb"(?:(?:RSA|EC|DSA|ENCRYPTED|OPENSSH) )?PRIVATE KEY-----")
PUBLISHED_TEST_SECRET = "tests/keys/bootsig-TEST-KEY.secret"
RELEASE_PUBLIC_DIR = "boot/keys/"
SECRET_BYTES = 64
PUBLIC_BYTES = 32


def tracked(root: Path) -> list[str]:
    out = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"], capture_output=True, check=True
    ).stdout
    return [name.decode() for name in out.split(b"\0") if name]


def refusals(root: Path) -> list[str]:
    names = tracked(root)
    publics = set()
    for name in names:
        if name.startswith(RELEASE_PUBLIC_DIR) and name.endswith(".public"):
            data = (root / name).read_bytes()
            if len(data) == PUBLIC_BYTES:
                publics.add(data)
    found = []
    for name in names:
        path = root / name
        try:
            data = path.read_bytes()
        except OSError:
            continue
        if ARMOUR.search(data):
            found.append(f"{name}: a PEM private key")
        if name.endswith(".secret") and name != PUBLISHED_TEST_SECRET:
            found.append(f"{name}: a .secret file other than the published test key")
        if len(data) == SECRET_BYTES and data[PUBLIC_BYTES:] in publics:
            found.append(f"{name}: 64 bytes ending in a release public key under {RELEASE_PUBLIC_DIR}")
    return found


def self_test() -> int:
    """Each kind refused in a repository of its own; the published test key accepted."""
    public = bytes(range(PUBLIC_BYTES))
    cases = {
        "an armoured private key": {"notes/key.pem": b"-----BEGIN " + b"PRIVATE KEY-----\nAAAA\n"},
        "an encrypted armoured key": {"k.txt": b"x\n-----BEGIN " + b"ENCRYPTED PRIVATE KEY-----\n"},
        "a .secret file": {"keys/owner.secret": b"\0" * SECRET_BYTES},
        "a renamed release secret": {
            "boot/keys/bootsig-release-x.public": public,
            "docs/innocent.bin": bytes(PUBLIC_BYTES) + public,
        },
    }
    failed = 0
    for label, files in cases.items():
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            for name, data in files.items():
                (root / name).parent.mkdir(parents=True, exist_ok=True)
                (root / name).write_bytes(data)
            subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
            if refusals(root):
                print(f"  {GREEN}ok{RESET}    the secret-key gate refuses {label}")
            else:
                print(f"  {RED}FAIL{RESET}  the secret-key gate accepted {label}")
                failed += 1
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        (root / "tests/keys").mkdir(parents=True)
        (root / PUBLISHED_TEST_SECRET).write_bytes(bytes(SECRET_BYTES))
        subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
        if refusals(root):
            print(f"  {RED}FAIL{RESET}  the secret-key gate refused the published test key")
            failed += 1
        else:
            print(f"  {GREEN}ok{RESET}    the secret-key gate accepts the published test key")
    return 1 if failed else 0


def main() -> int:
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    if sys.argv[1:]:
        print("usage: check-no-secret-keys.py [--self-test]", file=sys.stderr)
        return 2
    root = Path(
        subprocess.run(
            ["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=True
        ).stdout.strip()
    )
    found = refusals(root)
    if found:
        for line in found:
            print(f"  {RED}FAIL{RESET}  {line}")
        print(f"  {RED}FAIL{RESET}  a signing secret is tracked -- GOVERNANCE.md section 5")
        return 1
    print(f"  {GREEN}ok{RESET}    no signing secret is tracked (GOVERNANCE.md section 5)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
