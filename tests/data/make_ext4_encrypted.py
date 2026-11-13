"""Build the mixed plaintext/encrypted ext4 sample used by the tests.

The image is synthetic and deliberately small. It contains:

* a normal directory with two files;
* an encrypted directory whose policy attribute holds a v1 fscrypt context;
* two encrypted names that share the same raw (and therefore display) name;
* an encrypted directory with an unknown context version;
* an encrypted directory marked with the encryption inode flag but without a policy attribute;
* an encrypted file whose context is truncated.

Regenerate with::

    python tests/data/make_ext4_encrypted.py tests/data/ext4_encrypted.bin.gz
"""

from __future__ import annotations

import gzip
import struct
import sys
from pathlib import Path

from dissect.extfs.c_ext import c_ext

BLOCK = 1024
BLOCKS = 128
INODE_SIZE = 256
TABLE_BLOCK = 8

ROOT = 2
TEXT = 9
PLAIN = 10
ENC = 11
PA = 12
PB = 13
EA = 14
EB = 15
ODD_ENTRY = 16
ODD = 17
NC_ENTRY = 18
NC = 19

ROOT_BLOCK = 20
PLAIN_BLOCK = 21
ENC_BLOCK = 22
ODD_BLOCK = 23
NC_BLOCK = 24
FILE_A = 25
FILE_B = 26

XATTR_BLOCK_V1 = 30
XATTR_BLOCK_V2 = 31
XATTR_BLOCK_UNKNOWN = 32
XATTR_BLOCK_TRUNCATED = 33

XATTR_MAGIC = 0xEA020000
EXTENTS_FL = 0x80000
ENCRYPT_FL = 0x800

CTX_V1 = bytes([1, 1, 2, 0]) + bytes.fromhex("0011223344556677") + bytes(range(16))
CTX_V2 = bytes([2, 1, 2, 0]) + bytes.fromhex("8899aabbccddeeff0011223344556677") + bytes(range(16))
CTX_UNKNOWN = bytes([9, 1, 2, 0, 1, 2, 3, 4])
CTX_TRUNCATED = bytes([2, 1, 2])

UUID = bytes.fromhex("00112233445566778899aabbccddeeff")


def dirent(inum: int, name: bytes, file_type: int = 1) -> bytes:
    rec_len = (8 + len(name) + 3) & ~3
    entry = struct.pack("<IHBB", inum, rec_len, len(name), file_type) + name
    return entry.ljust(rec_len, b"\x00")


def directory(entries: list[bytes]) -> bytes:
    out = b""
    for index, entry in enumerate(entries):
        if index == len(entries) - 1:
            entry = entry[:4] + struct.pack("<H", BLOCK - len(out)) + entry[6:]
        out += entry
    return out.ljust(BLOCK, b"\x00")


def inode(mode: int, size: int, block: int = 0, flags: int = 0, acl: int = 0) -> bytes:
    header = struct.pack("<HHHHI", 0xF30A, 1 if block else 0, 4, 0, 0)
    extent = struct.pack("<IHHI", 0, 1, 0, block)
    data = bytes(
        c_ext.ext4_inode(
            i_mode=mode,
            i_size_lo=size,
            i_links_count=1,
            i_flags=EXTENTS_FL | flags,
            i_block=header + extent + b"\x00" * 36,
            i_file_acl_lo=acl,
            i_extra_isize=32,
        )
    )
    return data.ljust(INODE_SIZE, b"\x00")[:INODE_SIZE]


def xattr_block(value: bytes) -> bytes:
    entry = struct.pack("<BBHIII", 1, 9, 96, 0, len(value), 0) + b"c" + b"\x00" * 3
    block = bytearray(BLOCK)
    struct.pack_into("<IIIIIIII", block, 0, XATTR_MAGIC, 1, 1, 0, 0, 0, 0, 0)
    block[32 : 32 + len(entry)] = entry
    block[96 : 96 + len(value)] = value
    return bytes(block)


def build() -> bytes:
    img = bytearray(BLOCK * BLOCKS)

    sb = c_ext.ext4_super_block(
        s_inodes_count=64,
        s_blocks_count_lo=BLOCKS,
        s_first_data_block=1,
        s_log_block_size=0,
        s_log_cluster_size=0,
        s_blocks_per_group=8192,
        s_clusters_per_group=8192,
        s_inodes_per_group=64,
        s_magic=0xEF53,
        s_inode_size=INODE_SIZE,
        s_feature_incompat=0x42,
        s_feature_ro_compat=0x7B,
        s_uuid=UUID,
        s_volume_name=b"enc-sample\x00",
        s_desc_size=32,
    )
    img[1024:2048] = bytes(sb)

    gd = c_ext.ext4_group_desc(bg_block_bitmap_lo=2, bg_inode_bitmap_lo=3, bg_inode_table_lo=TABLE_BLOCK)
    img[2048 : 2048 + 32] = bytes(gd)[:32]

    img[ROOT_BLOCK * BLOCK : (ROOT_BLOCK + 1) * BLOCK] = directory(
        [
            dirent(ROOT, b".", 2),
            dirent(ROOT, b"..", 2),
            dirent(TEXT, b"report.txt"),
            dirent(PLAIN, b"plain", 2),
            dirent(ENC, b"locked", 2),
            dirent(ODD, b"odd", 2),
            dirent(NC, b"nocontext", 2),
        ]
    )
    img[PLAIN_BLOCK * BLOCK : (PLAIN_BLOCK + 1) * BLOCK] = directory(
        [
            dirent(PLAIN, b".", 2),
            dirent(ROOT, b"..", 2),
            dirent(PA, b"alpha"),
            dirent(PB, b"beta"),
        ]
    )

    shared_name = bytes([0x2E, 0x80, 0xFF, 0x41, 0x00, 0x9C])
    other_name = bytes([0xB7, 0x5A, 0x14, 0xFE, 0xE2])
    img[ENC_BLOCK * BLOCK : (ENC_BLOCK + 1) * BLOCK] = directory(
        [
            dirent(ENC, b".", 2),
            dirent(ROOT, b"..", 2),
            dirent(EA, shared_name),
            dirent(EB, shared_name),
            dirent(EA, other_name),
        ]
    )
    img[ODD_BLOCK * BLOCK : (ODD_BLOCK + 1) * BLOCK] = directory(
        [dirent(ODD, b".", 2), dirent(ROOT, b"..", 2), dirent(ODD_ENTRY, bytes([0xE0, 0x81, 0x40, 0x7F]))]
    )
    img[NC_BLOCK * BLOCK : (NC_BLOCK + 1) * BLOCK] = directory(
        [dirent(NC, b".", 2), dirent(ROOT, b"..", 2), dirent(NC_ENTRY, bytes([0xC3, 0x28, 0xA0, 0xA1]))]
    )

    img[FILE_A * BLOCK : (FILE_A + 1) * BLOCK] = b"alpha\n"
    img[FILE_B * BLOCK : (FILE_B + 1) * BLOCK] = b"beta\n"
    img[XATTR_BLOCK_V1 * BLOCK : (XATTR_BLOCK_V1 + 1) * BLOCK] = xattr_block(CTX_V1)
    img[XATTR_BLOCK_V2 * BLOCK : (XATTR_BLOCK_V2 + 1) * BLOCK] = xattr_block(CTX_V2)
    img[XATTR_BLOCK_UNKNOWN * BLOCK : (XATTR_BLOCK_UNKNOWN + 1) * BLOCK] = xattr_block(CTX_UNKNOWN)
    img[XATTR_BLOCK_TRUNCATED * BLOCK : (XATTR_BLOCK_TRUNCATED + 1) * BLOCK] = xattr_block(CTX_TRUNCATED)

    table = TABLE_BLOCK * BLOCK

    def put(inum: int, data: bytes) -> None:
        img[table + (inum - 1) * INODE_SIZE : table + inum * INODE_SIZE] = data

    put(ROOT, inode(0o40755, BLOCK, ROOT_BLOCK))
    put(TEXT, inode(0o100644, 6, FILE_A))
    put(PLAIN, inode(0o40755, BLOCK, PLAIN_BLOCK))
    put(ENC, inode(0o40755, BLOCK, ENC_BLOCK, ENCRYPT_FL, XATTR_BLOCK_V1))
    put(PA, inode(0o100644, 6, FILE_A))
    put(PB, inode(0o100644, 5, FILE_B))
    put(EA, inode(0o100644, 0, 0, ENCRYPT_FL, XATTR_BLOCK_V2))
    put(EB, inode(0o100644, 0, 0, ENCRYPT_FL, XATTR_BLOCK_TRUNCATED))
    put(ODD, inode(0o40755, BLOCK, ODD_BLOCK, ENCRYPT_FL, XATTR_BLOCK_UNKNOWN))
    put(NC, inode(0o40755, BLOCK, NC_BLOCK, ENCRYPT_FL, 0))

    return bytes(img)


def main() -> None:
    with Path(sys.argv[1]).open("wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as fh:
        fh.write(build())


if __name__ == "__main__":
    main()
