"""Runnable demo: recover deleted file names from ext directory rec_len slack.

Builds a synthetic ext filesystem in memory (no disk image needed) whose root
directory contains deleted-entry residue, then prints a forensic-style report.
Every recovered name is tied to the exact byte range it was recovered from, and
candidates with insufficient evidence are called out explicitly.

Run from the repository root:

    .venv/bin/python examples/dir_residue_report.py
"""

from __future__ import annotations

import struct
from io import BytesIO

from dissect.extfs import ExtFS
from dissect.extfs.recovery import ResidueKind, scan_dir_residue

BLOCK_SIZE = 1024
SB_OFFSET = 1024
GD_OFFSET = 2048
INODE_TABLE_BLOCK = 5
INODE_SIZE = 128
DIR_BLOCK_1 = 10
DIR_BLOCK_2 = 11


def _dir_entry(inode: int, rec_len: int, name: bytes, file_type: int) -> bytes:
    entry = struct.pack("<IHBB", inode, rec_len, len(name), file_type) + name
    return entry + b"\x00" * (rec_len - len(entry))


def build_synthetic_image() -> bytes:
    """Minimal ext2-style image with deleted directory entry residue."""
    image = bytearray(32 * BLOCK_SIZE)

    # Superblock: 32 blocks/inodes, 1k blocks, FILETYPE feature, 128 byte inodes
    struct.pack_into("<I", image, SB_OFFSET + 0, 32)  # s_inodes_count
    struct.pack_into("<I", image, SB_OFFSET + 4, 32)  # s_blocks_count_lo
    struct.pack_into("<I", image, SB_OFFSET + 20, 1)  # s_first_data_block
    struct.pack_into("<I", image, SB_OFFSET + 32, 32)  # s_blocks_per_group
    struct.pack_into("<I", image, SB_OFFSET + 36, 32)  # s_clusters_per_group
    struct.pack_into("<I", image, SB_OFFSET + 40, 32)  # s_inodes_per_group
    struct.pack_into("<H", image, SB_OFFSET + 56, 0xEF53)  # s_magic
    struct.pack_into("<H", image, SB_OFFSET + 88, INODE_SIZE)  # s_inode_size
    struct.pack_into("<I", image, SB_OFFSET + 96, 0x2)  # s_feature_incompat = FILETYPE

    # Group descriptor: block bitmap = 3, inode bitmap = 4, inode table = 5
    struct.pack_into("<III", image, GD_OFFSET, 3, 4, INODE_TABLE_BLOCK)

    def write_inode(inum: int, mode: int, size: int, blocks: list[int]) -> None:
        offset = INODE_TABLE_BLOCK * BLOCK_SIZE + (inum - 1) * INODE_SIZE
        struct.pack_into("<H", image, offset + 0, mode)  # i_mode
        struct.pack_into("<I", image, offset + 4, size)  # i_size_lo
        struct.pack_into("<H", image, offset + 26, 2)  # i_links_count
        for index, block in enumerate(blocks):
            struct.pack_into("<I", image, offset + 40 + 4 * index, block)  # i_block

    write_inode(2, 0o40755, 2 * BLOCK_SIZE, [DIR_BLOCK_1, DIR_BLOCK_2])  # root dir
    write_inode(12, 0o100644, 5, [12])  # active.txt
    write_inode(14, 0o100644, 5, [13])  # second.txt

    # Directory block 1: active entries, with deleted-entry residue in the slack
    dir1 = bytearray(BLOCK_SIZE)
    dir1[0:12] = _dir_entry(2, 12, b".", 2)
    dir1[12:24] = _dir_entry(2, 12, b"..", 2)
    dir1[24:1024] = _dir_entry(12, BLOCK_SIZE - 24, b"active.txt", 1)
    dir1[44:60] = _dir_entry(13, 16, b"old.conf", 1)  # complete old record
    dir1[60:80] = _dir_entry(12, 20, b"active.ba", 1)  # old record, inode reused
    dir1[100:117] = b"partial_notes.txt"  # name fragment, header gone
    dir1[1008:1024] = b"truncated_name_x"  # fragment running into the block end
    image[DIR_BLOCK_1 * BLOCK_SIZE : (DIR_BLOCK_1 + 1) * BLOCK_SIZE] = dir1

    # Directory block 2: active entry with a complete old record in its slack
    dir2 = bytearray(BLOCK_SIZE)
    dir2[0:1024] = _dir_entry(14, BLOCK_SIZE, b"second.txt", 1)
    dir2[44:64] = _dir_entry(15, 20, b"deleted.txt", 1)
    image[DIR_BLOCK_2 * BLOCK_SIZE : (DIR_BLOCK_2 + 1) * BLOCK_SIZE] = dir2

    return bytes(image)


def main() -> None:
    image = build_synthetic_image()
    extfs = ExtFS(BytesIO(image))
    root = extfs.root

    print("=" * 78)
    print("Directory residue report (synthetic ext image, root directory inode 2)")
    print("=" * 78)

    print("\nActive entries (regular enumeration, unchanged):")
    for name in sorted(root.listdir()):
        print(f"  {name}")

    residues = scan_dir_residue(root)

    print("\nResidue candidates (recovered from rec_len slack):")
    for residue in residues:
        disk_range = residue.disk_byte_range
        disk_text = f"disk bytes {disk_range[0]}..{disk_range[1]}" if disk_range else "no disk mapping"
        inode_text = f"inode {residue.inode}" if residue.inode is not None else "inode unknown"
        print(f"\n  [{residue.kind.value}] {residue.name_text!r} ({inode_text})")
        print(f"    directory bytes {residue.byte_range[0]}..{residue.byte_range[1]}, {disk_text}")
        print(f"    raw bytes: {residue.name!r}")
        print(f"    assessment: {residue.note}")

    insufficient = [r for r in residues if r.kind is not ResidueKind.COMPLETE_RECORD]
    print("\nInsufficient-evidence summary:")
    if not insufficient:
        print("  none")
    for residue in insufficient:
        reason = (
            "inode number reused by an active entry"
            if residue.kind is ResidueKind.REUSED_INODE
            else "name fragment only, no valid record header"
        )
        print(f"  {residue.name_text!r}: {reason}")
    print("\nNote: fragments ending at a block boundary are reported as-is and are")
    print("never stitched with bytes from the next directory block.")


if __name__ == "__main__":
    main()
