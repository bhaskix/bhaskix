#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Builds and edits a slot disk -- RFC 0100 step 1.

A slot disk is a GPT disk with three partitions the native loader finds by
type: the slot record (one block saying which slot is active and which is on
trial), and slots A and B, each a complete signed boot set behind a one-block
header. The layout is `slotdisk`'s (the crate the loader decides with); this
writes the same bytes from the other side, and the crate's host tests and the
firmware's own partition driver are what check that the two agree.

    slot-disk.py make DISK --a SETDIR --b SETDIR [--size-mib N]
    slot-disk.py record DISK --active a|b [--trial a|b --tries N]
    slot-disk.py show DISK
    slot-disk.py damage DISK a|b       # flips one bit of that slot's kernel
    slot-disk.py damage DISK record    # flips one bit of the record's write count

A SETDIR holds `kernel`, `initrd.tar`, `boot.conf` and `boot.sig`, as the ESP's
`bhaskix/` directory does. Until RFC 0100 step 3 builds the update service,
`record` is how a slot is put on trial or marked good.
"""

import argparse
import os
import struct
import sys
import uuid
import zlib

BLOCK = 512
RECORD_TYPE = uuid.UUID("969cace0-879f-45d7-8393-08b4ce7cbf36")
SLOT_A_TYPE = uuid.UUID("ce2f6916-f0fe-4dc5-9683-ce839d800a72")
SLOT_B_TYPE = uuid.UUID("669e6491-b824-4983-af23-a7c5d7f69482")
FILES = ("kernel", "initrd.tar", "boot.conf", "boot.sig")
ENTRIES = 128
ENTRY_SIZE = 128
# Where each partition starts, in MiB: 1 MiB alignment, as partitioning tools
# do, and the record its own partition so a slot can never be written over it.
RECORD_AT_MIB, RECORD_MIB = 1, 1
SLOT_AT_MIB = 2


def blocks(mib):
    return mib * 1024 * 1024 // BLOCK


def layout(size_mib):
    slot_mib = (size_mib - SLOT_AT_MIB - 1) // 2
    record = (blocks(RECORD_AT_MIB), blocks(RECORD_AT_MIB + RECORD_MIB) - 1)
    a = (blocks(SLOT_AT_MIB), blocks(SLOT_AT_MIB + slot_mib) - 1)
    b = (a[1] + 1, a[1] + blocks(slot_mib))
    return {"record": record, "a": a, "b": b}


def gpt(total_blocks, parts):
    entries = bytearray(ENTRIES * ENTRY_SIZE)
    for index, (kind, name, (first, last)) in enumerate(parts):
        struct.pack_into("<16s16sQQQ", entries, index * ENTRY_SIZE, kind.bytes_le,
                         uuid.uuid4().bytes_le, first, last, 0)
        encoded = name.encode("utf-16-le")[:72]
        entries[index * ENTRY_SIZE + 56:index * ENTRY_SIZE + 56 + len(encoded)] = encoded
    entry_blocks = len(entries) // BLOCK
    disk_guid = uuid.uuid4().bytes_le

    def header(mine, alternate, entries_at):
        fields = struct.pack("<8sIIIIQQQQ16sQIII", b"EFI PART", 0x00010000, 92, 0, 0,
                             mine, alternate, 2 + entry_blocks,
                             total_blocks - 2 - entry_blocks, disk_guid, entries_at,
                             ENTRIES, ENTRY_SIZE, zlib.crc32(entries))
        crc = zlib.crc32(fields)
        return fields[:16] + struct.pack("<I", crc) + fields[20:]

    primary = header(1, total_blocks - 1, 2)
    backup = header(total_blocks - 1, 1, total_blocks - 1 - entry_blocks)
    # The protective MBR: one partition of type 0xEE over the whole disk.
    mbr = bytearray(BLOCK)
    struct.pack_into("<BBBBBBBBII", mbr, 446, 0, 0, 2, 0, 0xEE, 0xFF, 0xFF, 0xFF, 1,
                     min(total_blocks - 1, 0xFFFFFFFF))
    mbr[510:512] = b"\x55\xaa"
    return mbr, primary, bytes(entries), backup


def set_header(lengths):
    offset = BLOCK
    files = []
    for length in lengths:
        files.append((offset, length))
        offset += (length + BLOCK - 1) // BLOCK * BLOCK
    body = b"BHXSET01" + b"".join(struct.pack("<QQ", o, n) for o, n in files)
    return body + bytes(BLOCK - len(body)), files


def record_block(active, trial=None, tries=0, writes=0):
    body = bytearray(28)
    body[0:8] = b"BHXSLOT1"
    body[8] = ord(active.upper())
    if trial:
        body[9] = ord(trial.upper())
        body[10] = tries
    struct.pack_into("<Q", body, 16, writes)
    struct.pack_into("<I", body, 24, zlib.crc32(bytes(body[0:24])))
    return bytes(body) + bytes(BLOCK - 28)


def read_layout(disk):
    with open(disk, "rb") as f:
        f.seek(BLOCK)
        header = f.read(92)
        if header[:8] != b"EFI PART":
            sys.exit(f"{disk}: not a GPT disk")
        entries_at, count, size = struct.unpack_from("<QII", header, 72)
        f.seek(entries_at * BLOCK)
        raw = f.read(count * size)
    found = {}
    for index in range(count):
        kind = uuid.UUID(bytes_le=raw[index * size:index * size + 16])
        first, last = struct.unpack_from("<QQ", raw, index * size + 32)
        for name, wanted in (("record", RECORD_TYPE), ("a", SLOT_A_TYPE), ("b", SLOT_B_TYPE)):
            if kind == wanted:
                found[name] = (first, last)
    if len(found) != 3:
        sys.exit(f"{disk}: not a slot disk")
    return found


def make(args):
    size = args.size_mib
    parts = layout(size)
    total = blocks(size)
    mbr, primary, entries, backup = gpt(total, [
        (RECORD_TYPE, "bhaskix-record", parts["record"]),
        (SLOT_A_TYPE, "bhaskix-slot-a", parts["a"]),
        (SLOT_B_TYPE, "bhaskix-slot-b", parts["b"]),
    ])
    with open(args.disk, "wb") as f:
        f.truncate(total * BLOCK)
        f.seek(0); f.write(mbr)
        f.seek(BLOCK); f.write(primary)
        f.seek(2 * BLOCK); f.write(entries)
        f.seek((total - 1 - len(entries) // BLOCK) * BLOCK); f.write(entries)
        f.seek((total - 1) * BLOCK); f.write(backup)
        for slot, directory in (("a", args.a), ("b", args.b)):
            first, last = parts[slot]
            payloads = [open(os.path.join(directory, name), "rb").read() for name in FILES]
            head, files = set_header([len(p) for p in payloads])
            if files[-1][0] + files[-1][1] > (last - first + 1) * BLOCK:
                sys.exit(f"slot {slot}: the set does not fit in {size} MiB")
            f.seek(first * BLOCK); f.write(head)
            for (offset, _), payload in zip(files, payloads):
                f.seek(first * BLOCK + offset); f.write(payload)
        f.seek(parts["record"][0] * BLOCK)
        f.write(record_block("a"))
    print(f"{args.disk}: {size} MiB, record at {parts['record'][0]}, "
          f"slot A {parts['a'][0]}-{parts['a'][1]}, slot B {parts['b'][0]}-{parts['b'][1]}; A active")


def show(args):
    parts = read_layout(args.disk)
    with open(args.disk, "rb") as f:
        f.seek(parts["record"][0] * BLOCK)
        block = f.read(28)
    if block[:8] != b"BHXSLOT1" or zlib.crc32(block[:24]) != struct.unpack_from("<I", block, 24)[0]:
        print("record: damaged")
        return
    trial = f"{chr(block[9])} on trial, {block[10]} boot(s) left" if block[9] else "nothing on trial"
    print(f"record: {chr(block[8])} active, {trial}, {struct.unpack_from('<Q', block, 16)[0]} write(s)")


def record(args):
    parts = read_layout(args.disk)
    if (args.trial is None) != (args.tries is None):
        sys.exit("--trial and --tries go together")
    with open(args.disk, "r+b") as f:
        f.seek(parts["record"][0] * BLOCK + 16)
        writes = struct.unpack("<Q", f.read(8))[0]
        f.seek(parts["record"][0] * BLOCK)
        f.write(record_block(args.active, args.trial, args.tries or 0, writes + 1))
    show(args)


def damage(args):
    parts = read_layout(args.disk)
    with open(args.disk, "r+b") as f:
        if args.what == "record":
            # The write count: a byte only the CRC covers, so a parser that
            # ignored the CRC would believe the record whole.
            at = parts["record"][0] * BLOCK + 16
        else:
            first = parts[args.what][0]
            f.seek(first * BLOCK + 8)
            kernel_offset = struct.unpack("<Q", f.read(8))[0]
            at = first * BLOCK + kernel_offset + 4096
        f.seek(at)
        byte = f.read(1)[0]
        f.seek(at)
        f.write(bytes([byte ^ 0x01]))
    print(f"{args.disk}: one bit changed at byte {at}")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    m = sub.add_parser("make"); m.add_argument("disk"); m.add_argument("--a", required=True)
    m.add_argument("--b", required=True); m.add_argument("--size-mib", type=int, default=96)
    r = sub.add_parser("record"); r.add_argument("disk")
    r.add_argument("--active", choices=("a", "b"), required=True)
    r.add_argument("--trial", choices=("a", "b")); r.add_argument("--tries", type=int)
    s = sub.add_parser("show"); s.add_argument("disk")
    d = sub.add_parser("damage"); d.add_argument("disk"); d.add_argument("what", choices=("a", "b", "record"))
    args = parser.parse_args()
    {"make": make, "record": record, "show": show, "damage": damage}[args.command](args)


if __name__ == "__main__":
    main()
