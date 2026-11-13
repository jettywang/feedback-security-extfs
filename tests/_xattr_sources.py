"""Generate ``tests/data/xattr_sources.bin.gz``.

The image is a minimal EXT4 filesystem with xattr values stored in all three
ways: inline in the inode body, in an external attribute block and in a
dedicated EA inode. It also contains deliberately damaged attributes and
containers so tests can prove damage is reported per attribute without hiding
other readable attributes.

Regenerate with::

    python -m tests._xattr_sources tests/data/xattr_sources.bin.gz
"""

from __future__ import annotations

import gzip
import struct
import sys

from dissect.extfs.c_ext import c_ext

BLOCK_SIZE = 1024
BLOCKS = 2048
INODES = 256
INODE_SIZE = 256

XATTR_MAGIC = 0xEA020000
XATTR_ENTRY = struct.Struct("<BBHIII")
FILETYPE = 0x0002
EXTENTS_FEATURE = 0x0040
EA_INODE_FEATURE = 0x0400
EA_INODE_FL = 0x00200000

ROOT_DIR_BLOCK = 80
XATTR_BLOCK_MAIN = 100
XATTR_BLOCK_ONLY = 101
XATTR_BLOCK_DAMAGED = 102
XATTR_BLOCK_SHORT = 103
EA_INODE_BLOCK = 110
EA_SHORT_BLOCK = 111


def _entry_area(entries):
    return 4 + sum((16 + len(e["name"]) + 3) & ~3 for e in entries)


def _entry(name, index, *, value=None, inum=0, size=None, offs=None):
    return {
        "name": name,
        "index": index,
        "value": value,
        "inum": inum,
        "size": len(value) if size is None and value is not None else (size or 0),
        "offs": offs,
    }


def _serialise(entries, entry_start, value_start, value_base):
    """Pack entries and values into a bytearray covering [entry_start, value_end)."""
    area = bytearray()
    positions = []
    for entry in entries:
        name = entry["name"]
        positions.append(len(area))
        raw = XATTR_ENTRY.pack(len(name), entry["index"], entry["offs"] or 0, entry["inum"], entry["size"], 0) + name
        raw += b"\x00" * ((4 - len(raw) % 4) % 4)
        area.extend(raw)
    area.extend(b"\x00" * 4)
    assert len(area) == _entry_area(entries), (len(area), _entry_area(entries))

    area_end = entry_start + len(area)
    cursor = value_start
    planned = []
    for rel, entry in sorted(zip(positions, entries), key=lambda pair: -len(pair[1]["value"] or b"")):
        value = entry["value"]
        if value is None:
            continue
        cursor -= len(value)
        if cursor < area_end:
            raise ValueError(f"values overlap entries for {entry['name']!r}")
        planned.append((rel, cursor, value))

    out = bytearray(value_start - entry_start)
    out[0 : len(area)] = area
    for rel, at, value in planned:
        struct.pack_into("<H", out, rel + 2, at - value_base)
        out[at - entry_start : at - entry_start + len(value)] = value
    return bytes(out)


def body(entries):
    value_start = 4 + _entry_area(entries) + sum(len(e["value"] or b"") for e in entries)
    if value_start > 96:
        raise ValueError(f"inode body entries+values need {value_start} bytes, limit is 96")
    return struct.pack("<I", XATTR_MAGIC) + _serialise(entries, 4, 96, 4)


def block(entries, magic=XATTR_MAGIC, size=BLOCK_SIZE):
    data = bytearray(size)
    struct.pack_into("<I", data, 0, magic)
    struct.pack_into("<I", data, 4, 1)
    struct.pack_into("<I", data, 8, 1)
    payload = _serialise(entries, 32, size, 0)
    data[32 : 32 + len(payload)] = payload
    return bytes(data)


def inode(**kwargs):
    i = c_ext.ext4_inode()
    i.i_mode = kwargs.get("mode", 0o100600)
    i.i_links_count = kwargs.get("links", 1)
    i.i_size_lo = kwargs.get("size", 0)
    i.i_size_high = 0
    i.i_flags = kwargs.get("flags", 0)
    i.i_file_acl_lo = kwargs.get("acl", 0)
    i.i_extra_isize = kwargs.get("extra_isize", 32)
    i.i_block = struct.pack("<I", kwargs.get("block", 0)) + b"\x00" * 56
    i.i_extra = kwargs.get("extra", b"")
    return i.dumps().ljust(INODE_SIZE, b"\x00")


def dirent(inum, name, filetype, rec_len):
    return (struct.pack("<IHBB", inum, rec_len, len(name), filetype) + name.encode()).ljust(rec_len, b"\x00")


def build() -> bytes:
    image = bytearray(BLOCK_SIZE * BLOCKS)

    sb = c_ext.ext4_super_block()
    sb.s_inodes_count = INODES
    sb.s_blocks_count_lo = BLOCKS
    sb.s_first_data_block = 1
    sb.s_log_block_size = 0
    sb.s_log_cluster_size = 0
    sb.s_blocks_per_group = 8192
    sb.s_clusters_per_group = 8192
    sb.s_inodes_per_group = INODES
    sb.s_magic = 0xEF53
    sb.s_state = 1
    sb.s_rev_level = 1
    sb.s_first_ino = 11
    sb.s_inode_size = INODE_SIZE
    sb.s_feature_incompat = FILETYPE | EXTENTS_FEATURE | EA_INODE_FEATURE
    sb.s_uuid = bytes.fromhex("ab98e08ee2da4bc9bfc61ac5eafb1001")
    sb.s_volume_name = b"xattr-sources"
    sb.s_last_mounted = b"/evidence"
    image[1024:2048] = sb.dumps()[:1024]

    gd = c_ext.ext2_group_desc()
    gd.bg_block_bitmap_lo = 5
    gd.bg_inode_bitmap_lo = 6
    gd.bg_inode_table_lo = 4
    image[2048:2080] = gd.dumps()[:32]

    inodes = {}
    inodes[2] = inode(mode=0o40755, links=7, size=BLOCK_SIZE, block=ROOT_DIR_BLOCK)

    ibody = [
        _entry(b"inline", 1, value=b"ibody-value"),
        _entry(b"shared", 1, value=b"from-inode"),
    ]
    block_entries = [
        _entry(b"shared", 1, value=b"from-block"),
        _entry(b"blockonly", 1, value=b"external-block-value"),
        _entry(b"inline", 6, value=b"security-inline"),
        _entry(b"mystery", 12, value=b"raw-ns-value"),
        _entry(b"bad_offset", 1, size=16, offs=2040),
        _entry(b"after", 1, value=b"read-after-damage"),
        _entry(b"large", 1, inum=15, size=200),
        _entry(b"eashort", 1, inum=16, size=20),
    ]
    inodes[12] = inode(acl=XATTR_BLOCK_MAIN, extra=body(ibody))
    inodes[13] = inode(acl=XATTR_BLOCK_ONLY)
    inodes[14] = inode(acl=XATTR_BLOCK_DAMAGED, extra=body([_entry(b"ibody_ok", 1, value=b"ibody-value")]))
    inodes[15] = inode(size=200, flags=EA_INODE_FL, block=EA_INODE_BLOCK)
    inodes[16] = inode(size=10, flags=EA_INODE_FL, block=EA_SHORT_BLOCK)
    inodes[17] = inode(acl=XATTR_BLOCK_ONLY, extra=struct.pack("<I", 0xDEADBEEF) + b"\x00" * 92)

    inodes[18] = inode(acl=XATTR_BLOCK_SHORT)

    for inum, data in inodes.items():
        at = 4 * BLOCK_SIZE + (inum - 1) * INODE_SIZE
        image[at : at + INODE_SIZE] = data

    names = [
        (".", 2, 2),
        ("..", 2, 2),
        ("evidence", 12, 1),
        ("block_only", 13, 1),
        ("short_value", 18, 1),
        ("damaged_block", 14, 1),
        ("damaged_ibody", 17, 1),
        ("lost+found", 11, 2),
    ]
    pos = 0
    base = ROOT_DIR_BLOCK * BLOCK_SIZE
    for idx, (name, inum, ftype) in enumerate(names):
        rec = (12 + len(name) + 3) & ~3
        if idx == len(names) - 1:
            rec = BLOCK_SIZE - pos
        image[base + pos : base + pos + rec] = dirent(inum, name, ftype, rec)
        pos += rec

    image[XATTR_BLOCK_MAIN * BLOCK_SIZE : (XATTR_BLOCK_MAIN + 1) * BLOCK_SIZE] = block(block_entries)
    image[XATTR_BLOCK_ONLY * BLOCK_SIZE : (XATTR_BLOCK_ONLY + 1) * BLOCK_SIZE] = block(
        [
            _entry(b"acl", 2, value=b"\x02\x00\x00\x00"),
        ]
    )
    image[XATTR_BLOCK_DAMAGED * BLOCK_SIZE : (XATTR_BLOCK_DAMAGED + 1) * BLOCK_SIZE] = block(
        [_entry(b"broken", 1, value=b"should-not-be-reported")], magic=0xDEADBEEF
    )

    short_entries = [
        _entry(b"short", 1, value=b"0123456789", size=40),
        _entry(b"mystery_truncated", 12, value=b"raw", size=64),
    ]
    image[XATTR_BLOCK_SHORT * BLOCK_SIZE : (XATTR_BLOCK_SHORT + 1) * BLOCK_SIZE] = block(short_entries, size=BLOCK_SIZE)
    # Shrink the declared container by moving the value to the very end so 40 declared
    # bytes run past the 1024-byte block boundary without overlapping another value.
    short = image[XATTR_BLOCK_SHORT * BLOCK_SIZE : (XATTR_BLOCK_SHORT + 1) * BLOCK_SIZE]
    start = short.find(b"0123456789")
    short = bytearray(short)
    short[start : start + 10] = b"\x00" * 10
    short[BLOCK_SIZE - 10 : BLOCK_SIZE] = b"0123456789"
    struct.pack_into("<H", short, 32 + 2, BLOCK_SIZE - 10)
    image[XATTR_BLOCK_SHORT * BLOCK_SIZE : (XATTR_BLOCK_SHORT + 1) * BLOCK_SIZE] = bytes(short)

    payload = b"EA" * 100
    image[EA_INODE_BLOCK * BLOCK_SIZE : EA_INODE_BLOCK * BLOCK_SIZE + len(payload)] = payload
    image[EA_SHORT_BLOCK * BLOCK_SIZE : EA_SHORT_BLOCK * BLOCK_SIZE + 10] = b"0123456789"

    return bytes(image)


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} OUTPUT")
    with gzip.open(sys.argv[1], "wb") as fh:
        fh.write(build())


if __name__ == "__main__":
    main()
