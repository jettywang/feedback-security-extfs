from __future__ import annotations

import stat
import struct
from io import BytesIO

import pytest

from dissect.extfs import ExtFS
from dissect.extfs.exceptions import NotADirectoryError
from dissect.extfs.recovery import ResidueKind, scan_dir_residue

BLOCK_SIZE = 1024
SB_OFFSET = 1024
GD_OFFSET = 2048
INODE_TABLE_BLOCK = 5
INODE_SIZE = 128
DIR_BLOCK_1 = 10
DIR_BLOCK_2 = 11

S_IFDIR = 0o040000
S_IFREG = 0o100000


def _dir_entry(inode: int, rec_len: int, name: bytes, file_type: int) -> bytes:
    entry = struct.pack("<IHBB", inode, rec_len, len(name), file_type) + name
    return entry + b"\x00" * (rec_len - len(entry))


def build_synthetic_image() -> bytes:
    """Build a minimal ext2-style filesystem with deleted directory entry residue.

    Layout of the root directory (inode 2, data blocks 10 and 11):

    Block 10: active entries ``.``, ``..`` and ``active.txt`` (inode 12). The
    rec_len slack of ``active.txt`` holds:
      - offset 44:   complete old record ``old.conf`` (inode 13)
      - offset 60:   old record ``active.ba`` reusing inode 12
      - offset 100:  name fragment ``partial_notes.txt`` without a header
      - offset 1008: name fragment ``truncated_name_x`` running into the block end
    Block 11: active entry ``second.txt`` (inode 14) with a complete old record
    ``deleted.txt`` (inode 15) at directory offset 1068 in its slack.
    """
    image = bytearray(32 * BLOCK_SIZE)

    # Superblock
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

    write_inode(2, S_IFDIR | 0o755, 2 * BLOCK_SIZE, [DIR_BLOCK_1, DIR_BLOCK_2])
    write_inode(12, S_IFREG | 0o644, 5, [12])
    write_inode(14, S_IFREG | 0o644, 5, [13])

    # First directory block
    dir1 = bytearray(BLOCK_SIZE)
    dir1[0:12] = _dir_entry(2, 12, b".", 2)
    dir1[12:24] = _dir_entry(2, 12, b"..", 2)
    dir1[24:1024] = _dir_entry(12, BLOCK_SIZE - 24, b"active.txt", 1)
    dir1[44:60] = _dir_entry(13, 16, b"old.conf", 1)
    dir1[60:80] = _dir_entry(12, 20, b"active.ba", 1)
    dir1[100:117] = b"partial_notes.txt"
    dir1[1008:1024] = b"truncated_name_x"
    image[DIR_BLOCK_1 * BLOCK_SIZE : (DIR_BLOCK_1 + 1) * BLOCK_SIZE] = dir1

    # Second directory block
    dir2 = bytearray(BLOCK_SIZE)
    dir2[0:1024] = _dir_entry(14, BLOCK_SIZE, b"second.txt", 1)
    dir2[44:64] = _dir_entry(15, 20, b"deleted.txt", 1)
    image[DIR_BLOCK_2 * BLOCK_SIZE : (DIR_BLOCK_2 + 1) * BLOCK_SIZE] = dir2

    return bytes(image)


@pytest.fixture
def extfs() -> ExtFS:
    return ExtFS(BytesIO(build_synthetic_image()))


def test_active_listing_unchanged(extfs: ExtFS) -> None:
    assert sorted(extfs.root.listdir()) == [".", "..", "active.txt", "second.txt"]
    assert extfs.get("active.txt").inum == 12
    assert extfs.get("second.txt").inum == 14


def test_residue_classification(extfs: ExtFS) -> None:
    residues = scan_dir_residue(extfs.root)
    by_name = {residue.name: residue for residue in residues}

    complete = by_name[b"old.conf"]
    assert complete.kind is ResidueKind.COMPLETE_RECORD
    assert complete.inode == 13
    assert complete.file_type == 1

    reused = by_name[b"active.ba"]
    assert reused.kind is ResidueKind.REUSED_INODE
    assert reused.inode == 12
    assert "active.txt" in reused.note

    deleted = by_name[b"deleted.txt"]
    assert deleted.kind is ResidueKind.COMPLETE_RECORD
    assert deleted.inode == 15

    fragments = [residue for residue in residues if residue.kind is ResidueKind.NAME_FRAGMENT]
    assert {residue.name for residue in fragments} == {b"partial_notes.txt", b"truncated_name_x"}
    assert all(residue.inode is None for residue in fragments)


def test_recovered_names_map_to_disk_bytes() -> None:
    image = build_synthetic_image()
    extfs = ExtFS(BytesIO(image))

    expected = {
        b"old.conf": (DIR_BLOCK_1 * BLOCK_SIZE + 44, 16),
        b"active.ba": (DIR_BLOCK_1 * BLOCK_SIZE + 60, 20),
        b"partial_notes.txt": (DIR_BLOCK_1 * BLOCK_SIZE + 100, 17),
        b"truncated_name_x": (DIR_BLOCK_1 * BLOCK_SIZE + 1008, 16),
        b"deleted.txt": (DIR_BLOCK_2 * BLOCK_SIZE + 44, 20),
    }
    residues = {residue.name: residue for residue in scan_dir_residue(extfs.root)}
    assert set(residues) == set(expected)

    for name, (disk_offset, size) in expected.items():
        residue = residues[name]
        assert residue.disk_byte_range == (disk_offset, disk_offset + size)
        # The recovered name must be traceable to the raw bytes at that range
        assert name in image[disk_offset : disk_offset + size]


def test_cross_block_fragment_not_stitched(extfs: ExtFS) -> None:
    residues = scan_dir_residue(extfs.root)

    tail = next(residue for residue in residues if residue.name == b"truncated_name_x")
    assert tail.kind is ResidueKind.NAME_FRAGMENT
    assert "must not be concatenated" in tail.note

    # No candidate may combine the block 1 tail with bytes from block 2
    assert all(not residue.name.startswith(b"truncated_name_xsecond") for residue in residues)
    assert all(b"second" not in residue.name for residue in residues)


def test_scan_rejects_non_directory(extfs: ExtFS) -> None:
    node = extfs.get("active.txt")
    assert node.filetype == stat.S_IFREG
    with pytest.raises(NotADirectoryError):
        scan_dir_residue(node)
