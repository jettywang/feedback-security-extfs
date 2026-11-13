"""Dependency-free ext2/ext4 image synthesizer.

The fuzzer needs small, *valid* seed images that the real ``dissect.extfs``
parser accepts, but the test environment cannot rely on ``mkfs.ext4`` being
installed.  This module builds byte-exact ext2/ext4 images in pure Python using
the same :mod:`dissect.cstruct` definitions the parser itself consumes, which
keeps every offset in sync with the structures under test.

Two seed flavours are produced:

* :data:`EXT4` -- an ext4 filesystem whose inodes use extent trees (including a
  depth-1 extent index node), exercising :func:`dissect.extfs.extfs._parse_extents`.
* :data:`EXT2` -- a classic ext2 filesystem with direct/indirect block maps,
  exercising :func:`dissect.extfs.extfs._parse_indirect`.
"""
from __future__ import annotations

import io
import stat
from dataclasses import dataclass

from dissect.extfs.c_ext import c_ext

EXT2 = "ext2"
EXT4 = "ext4"

# Fixed block addresses inside the tiny synthesized images.
BOOT_BLOCK = 0
SUPERBLOCK_BLOCK = 1
GROUP_DESC_BLOCK = 2
INODE_TABLE_BLOCK = 3
ROOT_DIR_BLOCK = 4
FILE_DATA_BLOCK = 5
EXTENT_LEAF_BLOCK = 6
INDIRECT_BLOCK = 7
TOTAL_BLOCKS = 8

BLOCK_SIZE = 1024
INODE_SIZE = 256
INODES_PER_GROUP = 16
BLOCKS_PER_GROUP = TOTAL_BLOCKS
FIRST_INO = 11

# Inode numbers (1-based; inode 0 never exists on disk).
ROOT_INUM = c_ext.EXT2_ROOT_INO
FILE_INUM = 12


@dataclass
class SeedImage:
    """A synthesized filesystem image and the metadata needed to mutate it."""

    flavour: str
    data: bytearray
    block_size: int
    inode_size: int
    inode_table_block: int
    root_inum: int
    file_inum: int
    root_dir_block: int
    file_data_block: int
    extent_leaf_block: int

    def copy(self) -> SeedImage:
        return SeedImage(
            flavour=self.flavour,
            data=bytearray(self.data),
            block_size=self.block_size,
            inode_size=self.inode_size,
            inode_table_block=self.inode_table_block,
            root_inum=self.root_inum,
            file_inum=self.file_inum,
            root_dir_block=self.root_dir_block,
            file_data_block=self.file_data_block,
            extent_leaf_block=self.extent_leaf_block,
        )


def sb_field(name: str) -> int:
    """Return the on-disk offset of a ``ext4_super_block`` field."""
    return c_ext.ext4_super_block.fields[name].offset


def gd_field(name: str) -> int:
    """Return the on-disk offset of an ``ext2_group_desc`` field."""
    return c_ext.ext2_group_desc.fields[name].offset


def inode_field(name: str) -> int:
    """Return the on-disk offset of an ``ext4_inode`` field."""
    return c_ext.ext4_inode.fields[name].offset


def extent_header_field(name: str) -> int:
    return c_ext.ext4_extent_header.fields[name].offset


def extent_field(name: str) -> int:
    return c_ext.ext4_extent.fields[name].offset


def extent_idx_field(name: str) -> int:
    return c_ext.ext4_extent_idx.fields[name].offset


def direntry_field(name: str) -> int:
    return c_ext.ext2_dir_entry_2.fields[name].offset


def superblock_offset() -> int:
    return c_ext.EXT2_SBOFF


def group_desc_offset(block_size: int) -> int:
    # Group descriptors start in the block immediately following the superblock.
    return block_size * GROUP_DESC_BLOCK


def inode_offset(image: SeedImage, inum: int) -> int:
    """Return the absolute byte offset of inode ``inum``."""
    index = inum - 1
    return image.inode_table_block * image.block_size + index * image.inode_size


def _u16(buf: bytearray, offset: int, value: int) -> None:
    buf[offset : offset + 2] = int(value & 0xFFFF).to_bytes(2, "little")


def _u32(buf: bytearray, offset: int, value: int) -> None:
    buf[offset : offset + 4] = int(value & 0xFFFFFFFF).to_bytes(4, "little")


def _write_struct(buf: bytearray, offset: int, structure: object) -> None:
    buf[offset : offset + len(structure)] = structure.dumps()


def _build_superblock(flavour: str) -> bytes:
    sb = c_ext.ext4_super_block()
    sb.s_inodes_count = INODES_PER_GROUP
    sb.s_blocks_count_lo = TOTAL_BLOCKS
    sb.s_r_blocks_count_lo = 0
    sb.s_free_blocks_count_lo = 1
    sb.s_free_inodes_count = INODES_PER_GROUP - FIRST_INO
    sb.s_first_data_block = 1
    sb.s_log_block_size = 0  # 1024 << 0 == 1024
    sb.s_log_cluster_size = 0
    sb.s_blocks_per_group = BLOCKS_PER_GROUP
    sb.s_clusters_per_group = BLOCKS_PER_GROUP
    sb.s_inodes_per_group = INODES_PER_GROUP
    sb.s_magic = c_ext.EXT2_FS_MAGIC
    sb.s_state = 1
    sb.s_creator_os = 0
    sb.s_rev_level = 1
    sb.s_first_ino = FIRST_INO
    sb.s_inode_size = INODE_SIZE
    sb.s_block_group_nr = 0
    sb.s_feature_compat = 0
    sb.s_feature_ro_compat = 0
    sb.s_feature_incompat = c_ext.EXT2_FEATURE_INCOMPAT_FILETYPE
    if flavour == EXT4:
        sb.s_feature_incompat |= (
            c_ext.EXT4_FEATURE_INCOMPAT_EXTENTS | c_ext.EXT4_FEATURE_INCOMPAT_64BIT
        )
        sb.s_desc_size = 64
    else:
        sb.s_desc_size = 0
    sb.s_uuid = b"\x12\x34\x56\x78" + b"\x00" * 12
    sb.s_volume_name = b"fuzzseed\x00"
    sb.s_last_mounted = b"/mnt\x00"
    return sb.dumps()


def _build_group_desc(flavour: str) -> bytes:
    if flavour == EXT4:
        gd = c_ext.ext4_group_desc()
    else:
        gd = c_ext.ext2_group_desc()
    gd.bg_block_bitmap_lo = ROOT_DIR_BLOCK  # any in-range block; contents unused
    gd.bg_inode_bitmap_lo = ROOT_DIR_BLOCK
    gd.bg_inode_table_lo = INODE_TABLE_BLOCK
    gd.bg_free_blocks_count_lo = 1
    gd.bg_free_inodes_count_lo = INODES_PER_GROUP - FIRST_INO
    gd.bg_used_dirs_count_lo = 1
    return gd.dumps()


def _dir_entry(inum: int, rec_len: int, name: str, file_type: int) -> bytes:
    entry = c_ext.ext2_dir_entry_2()
    entry.inode = inum
    entry.rec_len = rec_len
    name_bytes = name.encode()
    entry.name_len = len(name_bytes)
    entry.file_type = file_type
    return entry.dumps() + name_bytes


def _build_root_dir_block() -> bytes:
    block = bytearray(BLOCK_SIZE)
    first = _dir_entry(ROOT_INUM, 12, ".", 2)
    second = _dir_entry(ROOT_INUM, 12, "..", 2)
    lost = _dir_entry(FILE_INUM, BLOCK_SIZE - 24, "f", 1)
    block[: len(first)] = first
    block[12 : 12 + len(second)] = second
    block[24 : 24 + len(lost)] = lost
    return bytes(block)


def _build_inode(mode: int, size: int, flags: int, i_block: bytes) -> c_ext.ext4_inode:
    inode = c_ext.ext4_inode()
    inode.i_mode = mode
    inode.i_uid = 0
    inode.i_gid = 0
    inode.i_size_lo = size & 0xFFFFFFFF
    inode.i_size_high = size >> 32
    inode.i_atime = 0
    inode.i_ctime = 0
    inode.i_mtime = 0
    inode.i_dtime = 0
    inode.i_links_count = 1
    inode.i_blocks_lo = 2
    inode.i_flags = flags
    inode.i_block = i_block.ljust(60, b"\x00")[:60]
    inode.i_generation = 0
    inode.i_extra_isize = 128
    return inode


def _ext4_root_inode() -> c_ext.ext4_inode:
    header = c_ext.ext4_extent_header()
    header.eh_magic = 0xF30A
    header.eh_entries = 1
    header.eh_max = 4
    header.eh_depth = 0
    extent = c_ext.ext4_extent()
    extent.ee_block = 0
    extent.ee_len = 1
    extent.ee_start_hi = 0
    extent.ee_start_lo = ROOT_DIR_BLOCK
    return _build_inode(
        stat.S_IFDIR | 0o755,
        BLOCK_SIZE,
        c_ext.EXT4_EXTENTS_FL,
        header.dumps() + extent.dumps(),
    )


def _ext4_file_inode() -> c_ext.ext4_inode:
    # Depth-1 index node pointing at a leaf block, so the parser must follow a
    # child pointer before it reaches the actual extent.
    header = c_ext.ext4_extent_header()
    header.eh_magic = 0xF30A
    header.eh_entries = 1
    header.eh_max = 4
    header.eh_depth = 1
    idx = c_ext.ext4_extent_idx()
    idx.ei_block = 0
    idx.ei_leaf_hi = 0
    idx.ei_leaf_lo = EXTENT_LEAF_BLOCK
    return _build_inode(
        stat.S_IFREG | 0o644,
        BLOCK_SIZE,
        c_ext.EXT4_EXTENTS_FL,
        header.dumps() + idx.dumps(),
    )


def _extent_leaf_block() -> bytes:
    block = bytearray(BLOCK_SIZE)
    header = c_ext.ext4_extent_header()
    header.eh_magic = 0xF30A
    header.eh_entries = 1
    header.eh_max = 4
    header.eh_depth = 0
    extent = c_ext.ext4_extent()
    extent.ee_block = 0
    extent.ee_len = 1
    extent.ee_start_hi = 0
    extent.ee_start_lo = FILE_DATA_BLOCK
    blob = header.dumps() + extent.dumps()
    block[: len(blob)] = blob
    return bytes(block)


def _ext2_root_inode() -> c_ext.ext4_inode:
    i_block = bytearray(60)
    _u32(i_block, 0, ROOT_DIR_BLOCK)
    return _build_inode(stat.S_IFDIR | 0o755, BLOCK_SIZE, 0, bytes(i_block))


def _ext2_file_inode() -> c_ext.ext4_inode:
    # One direct block and one indirect block map entry.
    i_block = bytearray(60)
    _u32(i_block, 0, FILE_DATA_BLOCK)
    _u32(i_block, 12 * 4, INDIRECT_BLOCK)
    return _build_inode(stat.S_IFREG | 0o644, BLOCK_SIZE, 0, bytes(i_block))


def build_seed(flavour: str = EXT4) -> SeedImage:
    """Build a minimal, parser-accepted ext2 or ext4 image."""
    if flavour not in (EXT2, EXT4):
        raise ValueError(f"unknown seed flavour: {flavour}")

    size = TOTAL_BLOCKS * BLOCK_SIZE
    data = bytearray(size)

    data[c_ext.EXT2_SBOFF : c_ext.EXT2_SBOFF + len(c_ext.ext4_super_block())] = _build_superblock(flavour)

    gd_offset = group_desc_offset(BLOCK_SIZE)
    gd_blob = _build_group_desc(flavour)
    data[gd_offset : gd_offset + len(gd_blob)] = gd_blob

    data[ROOT_DIR_BLOCK * BLOCK_SIZE : (ROOT_DIR_BLOCK + 1) * BLOCK_SIZE] = _build_root_dir_block()
    data[FILE_DATA_BLOCK * BLOCK_SIZE : (FILE_DATA_BLOCK + 1) * BLOCK_SIZE] = b"fuzz seed file data\n".ljust(
        BLOCK_SIZE, b"\x00"
    )

    if flavour == EXT4:
        data[EXTENT_LEAF_BLOCK * BLOCK_SIZE : (EXTENT_LEAF_BLOCK + 1) * BLOCK_SIZE] = _extent_leaf_block()
        root_inode = _ext4_root_inode()
        file_inode = _ext4_file_inode()
    else:
        root_inode = _ext2_root_inode()
        file_inode = _ext2_file_inode()
        indirect = bytearray(BLOCK_SIZE)
        _u32(indirect, 0, FILE_DATA_BLOCK)
        data[INDIRECT_BLOCK * BLOCK_SIZE : (INDIRECT_BLOCK + 1) * BLOCK_SIZE] = indirect

    root_off = inode_offset(
        SeedImage(flavour, data, BLOCK_SIZE, INODE_SIZE, INODE_TABLE_BLOCK, ROOT_INUM, FILE_INUM, 0, 0, 0),
        ROOT_INUM,
    )
    file_off = inode_offset(
        SeedImage(flavour, data, BLOCK_SIZE, INODE_SIZE, INODE_TABLE_BLOCK, ROOT_INUM, FILE_INUM, 0, 0, 0),
        FILE_INUM,
    )
    _write_struct(data, root_off, root_inode)
    _write_struct(data, file_off, file_inode)

    return SeedImage(
        flavour=flavour,
        data=data,
        block_size=BLOCK_SIZE,
        inode_size=INODE_SIZE,
        inode_table_block=INODE_TABLE_BLOCK,
        root_inum=ROOT_INUM,
        file_inum=FILE_INUM,
        root_dir_block=ROOT_DIR_BLOCK,
        file_data_block=FILE_DATA_BLOCK,
        extent_leaf_block=EXTENT_LEAF_BLOCK,
    )


def open_seed(flavour: str = EXT4) -> io.BytesIO:
    """Convenience helper returning a fresh binary stream for a seed image."""
    return io.BytesIO(bytes(build_seed(flavour).data))
