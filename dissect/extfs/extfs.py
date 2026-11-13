from __future__ import annotations

import io
import logging
import os
import stat
from functools import cached_property, lru_cache
from typing import TYPE_CHECKING, BinaryIO
from uuid import UUID

from dissect.util import ts
from dissect.util.stream import RangeStream, RunlistStream

from dissect.extfs.c_ext import (
    EXT2,
    EXT3,
    EXT4,
    FILETYPES,
    XATTR_NAME_MAP,
    XATTR_PREFIX_MAP,
    c_ext,
)
from dissect.extfs.exceptions import (
    Error,
    FileNotFoundError,
    MissingDataError,
    NotADirectoryError,
    NotASymlinkError,
)
from dissect.extfs.journal import JDB2

if TYPE_CHECKING:
    from collections.abc import Iterator
    from datetime import datetime

log = logging.getLogger(__name__)
log.setLevel(os.getenv("DISSECT_LOG_EXTFS", "CRITICAL"))


class ExtFS:
    def __init__(self, fh: BinaryIO):
        self.fh = fh

        fh.seek(c_ext.EXT2_SBOFF)
        sb = c_ext.ext4_super_block(fh)
        self.sb = sb

        if sb.s_magic != c_ext.EXT2_FS_MAGIC:
            raise Error("Not a valid ExtFS filesystem (magic mismatch)")

        if sb.s_inodes_count < 10:
            raise Error("Not a valid ExtFS filesystem (inum count < 10)")

        if sb.s_blocks_per_group == 0 or sb.s_inodes_per_group == 0:
            raise Error("Not a valid ExtFS filesystem (blocks or inodes per group is 0)")

        if sb.s_log_block_size != sb.s_log_cluster_size:
            raise NotImplementedError("Different size cluster than blocks is currently not supported")

        self.block_size = c_ext.EXT2_MIN_BLOCK_SIZE << sb.s_log_block_size
        if self.block_size == 0 or self.block_size % 512:
            raise Error("Not a valid ExtFS filesystem (invalid block size)")

        if sb.s_feature_incompat & c_ext.EXT4_FEATURE_INCOMPAT_EXTENTS:
            self.type = EXT4
        elif sb.s_feature_compat & c_ext.EXT3_FEATURE_COMPAT_HAS_JOURNAL:
            self.type = EXT3
        else:
            self.type = EXT2

        if sb.s_feature_incompat & c_ext.EXT2_FEATURE_INCOMPAT_FILETYPE:
            self._dirtype = c_ext.ext2_dir_entry_2
        else:
            self._dirtype = c_ext.ext2_dir_entry

        self.block_count = (sb.s_blocks_count_hi << 32) | sb.s_blocks_count_lo
        self.last_block = self.block_count - 1

        if (
            self.type == EXT4
            and self.sb.s_feature_incompat & c_ext.EXT4_FEATURE_INCOMPAT_64BIT
            and self.sb.s_desc_size >= 64
        ):
            self._group_desc_struct = c_ext.ext4_group_desc
        else:
            self._group_desc_struct = c_ext.ext2_group_desc
        self._group_desc_size = sb.s_desc_size if sb.s_desc_size else len(self._group_desc_struct)

        goff = c_ext.EXT2_SBOFF + self._group_desc_size
        self.groups_offset = goff if goff % self.block_size == 0 else goff + self.block_size - goff % self.block_size
        self.groups_count = ((self.last_block - sb.s_first_data_block) // sb.s_blocks_per_group) + 1

        self.uuid = UUID(bytes=sb.s_uuid)
        self.volume_name = sb.s_volume_name.split(b"\x00")[0].decode(errors="surrogateescape")
        self.last_mount = sb.s_last_mounted.split(b"\x00")[0].decode(errors="surrogateescape")

        self.root = self.get_inode(c_ext.EXT2_ROOT_INO, "/")

        self.get_inode = lru_cache(1024)(self.get_inode)
        self._read_group_desc = lru_cache(356)(self._read_group_desc)

    @cached_property
    def journal(self) -> JDB2:
        if not self.sb.s_feature_compat & c_ext.EXT3_FEATURE_COMPAT_HAS_JOURNAL:
            raise Error("Journal not supported")

        inum = self.sb.s_journal_inum
        if inum == 0:
            raise Error(f"Journal inum is 0, could be on external device (s_journal_uuid = {self.sb.s_journal_uuid})")

        inode = self.get_inode(inum)
        return JDB2(inode.open())

    def get(self, path_or_inum: str | int, node: INode | None = None) -> INode:
        if isinstance(path_or_inum, int):
            return self.get_inode(path_or_inum)

        node = node if node else self.root
        parts = path_or_inum.split("/")
        for part in parts:
            if not part:
                continue

            for entry in node.iterdir():
                if entry.filename == part:
                    node = entry
                    break
            else:
                raise FileNotFoundError(f"File not found: {path_or_inum}")

        return node

    def get_inode(
        self,
        inum: int,
        filename: str | None = None,
        filetype: int | None = None,
    ) -> INode:
        if inum < c_ext.EXT2_BAD_INO or inum > self.sb.s_inodes_count:
            raise Error(f"inum out of range {c_ext.EXT2_BAD_INO}-{self.sb.s_inodes_count}: {inum}")

        return INode(self, inum, filename, filetype)

    def _read_group_desc(self, group_num: int) -> c_ext.ext2_group_desc | c_ext.ext4_group_desc:
        if group_num >= self.groups_count:
            raise Error("Group number exceeds amount of groups")

        offset = self.groups_offset + group_num * self._group_desc_size
        self.fh.seek(offset)
        group_desc = self._group_desc_struct(self.fh)

        if self._group_desc_struct == c_ext.ext4_group_desc:
            block_bitmap = (group_desc.bg_block_bitmap_hi << 32) | group_desc.bg_block_bitmap_lo
            inode_bitmap = (group_desc.bg_inode_bitmap_hi << 32) | group_desc.bg_inode_bitmap_lo
            table_block = (group_desc.bg_inode_table_hi << 32) | group_desc.bg_inode_table_lo
        else:
            block_bitmap = group_desc.bg_block_bitmap_lo
            inode_bitmap = group_desc.bg_inode_bitmap_lo
            table_block = group_desc.bg_inode_table_lo

        if block_bitmap > self.last_block or inode_bitmap > self.last_block or table_block > self.last_block:
            raise Error("Group descriptor block locations exceed last block")

        return group_desc


class INode:
    def __init__(
        self,
        extfs: ExtFS,
        inum: int,
        filename: str | None = None,
        filetype: int | None = None,
    ):
        self.extfs = extfs
        self.inum = inum
        self.filename = filename
        self._filetype = filetype
        self._runlist = None

    def __repr__(self) -> str:
        return f"<inode {self.inum}>"

    @cached_property
    def inode(self) -> c_ext.ext4_inode:
        block_group_num, index = divmod(self.inum - 1, self.extfs.sb.s_inodes_per_group)
        block_group = self.extfs._read_group_desc(block_group_num)

        if self.extfs._group_desc_struct == c_ext.ext4_group_desc:
            table_block = (block_group.bg_inode_table_hi << 32) | block_group.bg_inode_table_lo
        else:
            table_block = block_group.bg_inode_table_lo

        offset = table_block * self.extfs.block_size + index * self.extfs.sb.s_inode_size
        self.extfs.fh.seek(offset)
        return c_ext.ext4_inode(self.extfs.fh)

    @cached_property
    def size(self) -> int:
        return (self.inode.i_size_high << 32) + self.inode.i_size_lo

    @property
    def filetype(self) -> int:
        if not self._filetype:
            self._filetype = stat.S_IFMT(self.inode.i_mode)
        return self._filetype

    @cached_property
    def link(self) -> str:
        if self.filetype != stat.S_IFLNK:
            raise NotASymlinkError(f"{self!r} is not a symlink")

        return self.open().read().decode(errors="surrogateescape")

    @cached_property
    def xattr(self) -> list[XAttr]:
        xattr = []

        if self.inode.i_extra.strip(b"\x00"):
            buf = io.BytesIO(self.inode.i_extra)
            hdr = c_ext.ext4_xattr_ibody_header(buf)
            if hdr.h_magic != c_ext.EXT4_XATTR_MAGIC:
                raise Error("Invalid xattr magic value")

            xattr.extend(_iter_xattr(self, buf, len(self.inode.i_extra), 4))

        if self.inode.i_file_acl_lo:
            block = (self.inode.i_file_acl_high << 32) | self.inode.i_file_acl_lo
            block_offset = block * self.extfs.block_size

            buf = RangeStream(self.extfs.fh, block_offset, self.extfs.block_size)
            hdr = c_ext.ext4_xattr_header(buf)
            if hdr.h_magic != c_ext.EXT4_XATTR_MAGIC:
                raise Error("Invalid xattr magic value")

            xattr.extend(_iter_xattr(self, buf, buf.size))

        return xattr

    @property
    def atime(self) -> datetime:
        return ts.from_unix_ns(self.atime_ns)

    @property
    def atime_ns(self) -> int:
        time = self.inode.i_atime
        time_extra = self.inode.i_atime_extra if self.extfs.sb.s_inode_size > 128 else 0

        return _parse_ns_ts(time, time_extra)

    @property
    def mtime(self) -> datetime:
        return ts.from_unix_ns(self.mtime_ns)

    @property
    def mtime_ns(self) -> int:
        time = self.inode.i_mtime
        time_extra = self.inode.i_mtime_extra if self.extfs.sb.s_inode_size > 128 else 0

        return _parse_ns_ts(time, time_extra)

    @property
    def ctime(self) -> datetime:
        return ts.from_unix_ns(self.ctime_ns)

    @property
    def ctime_ns(self) -> int:
        time = self.inode.i_ctime
        time_extra = self.inode.i_ctime_extra if self.extfs.sb.s_inode_size > 128 else 0

        return _parse_ns_ts(time, time_extra)

    @property
    def dtime(self) -> datetime:
        return ts.from_unix(self.inode.i_dtime)

    @property
    def crtime(self) -> datetime | None:
        time_ns = self.crtime_ns
        if time_ns is None:
            return None
        return ts.from_unix_ns(time_ns)

    @property
    def crtime_ns(self) -> int | None:
        if self.extfs.sb.s_inode_size <= 128:
            return None

        time = self.inode.i_crtime
        time_extra = self.inode.i_crtime_extra

        return _parse_ns_ts(time, time_extra)

    def listdir(self) -> dict[str, INode]:
        return {node.filename: node for node in self.iterdir()}

    dirlist = listdir

    def iterdir(self) -> Iterator[INode]:
        if self.filetype != stat.S_IFDIR:
            raise NotADirectoryError(f"{self!r} is not a directory")

        buf = self.open()
        offset = 0

        while offset < self.size - 12:
            direntry = self.extfs._dirtype(buf)

            if direntry.rec_len == 0:
                log.critical("Zero-length directory entry in %s (offset 0x%x)", self, offset)
                return

            # Sanity check if the direntry is valid
            if 0 < direntry.inode < self.extfs.sb.s_inodes_count:
                fname = buf.read(direntry.name_len).decode(errors="surrogateescape")
                ftype = direntry.file_type if self.extfs._dirtype == c_ext.ext2_dir_entry_2 else None

                if ftype:
                    ftype = FILETYPES[ftype]

                yield self.extfs.get_inode(direntry.inode, fname, ftype)

            offset += direntry.rec_len
            buf.seek(offset)

    def dataruns(self, offset: int | None = None, size: int | None = None) -> list[tuple[int | None, int]]:
        """Return the data runs of this inode, optionally limited to a file-relative byte range.

        Called without arguments this returns the runs for the entire file, like it always did.
        When ``offset`` and/or ``size`` are given, only the runs covering the blocks that intersect
        ``[offset, offset + size)`` are returned. The first returned run then corresponds to the
        block containing ``offset``, i.e. block ``offset // block_size``. For files using indirect
        block addressing (ext2/ext3) only the indirect blocks required for the requested range are
        read from the image, instead of the entire indirect block tree.

        Raises:
            MissingDataError: If the image is incomplete and (part of) the indirect blocks needed
                for the requested range are missing. The exception carries the actual missing
                file-relative byte intervals.
        """
        if offset is None and size is None:
            if not self._runlist:
                self._runlist = self._dataruns()
            return self._runlist

        offset = max(0, min(self.size, offset or 0))
        end = self.size if size is None else min(self.size, offset + max(0, size))
        if end <= offset:
            return []

        block_size = self.extfs.block_size
        first_block = offset // block_size
        num_blocks = (end - 1) // block_size - first_block + 1

        if self.inode.i_flags & c_ext.EXT4_EXTENTS_FL:
            return _slice_runs(self.dataruns(), first_block, num_blocks)
        return self._dataruns_indirect(first_block, num_blocks)

    def _dataruns(self) -> list[tuple[int | None, int]]:
        expected_runs = (self.size + self.extfs.block_size - 1) // self.extfs.block_size

        if self.inode.i_flags & c_ext.EXT4_EXTENTS_FL:
            buf = io.BytesIO(self.inode.i_block)

            runs = []
            run_offset = 0

            for extent in _parse_extents(self, buf):
                # Account for uninitialized extents
                if extent.ee_len > 0x8000:
                    uninitialized_gap = extent.ee_len - 0x8000
                    runs.append((None, uninitialized_gap))
                    run_offset += uninitialized_gap
                    continue

                # Account for sparse gaps
                if extent.ee_block != run_offset:
                    sparse_gap = extent.ee_block - run_offset
                    runs.append((None, sparse_gap))
                    run_offset += sparse_gap

                runs.append(((extent.ee_start_hi << 32) | extent.ee_start_lo, extent.ee_len))
                run_offset += extent.ee_len

            if run_offset < expected_runs:
                runs.append((None, expected_runs - run_offset))

            return runs

        return self._dataruns_indirect(0, expected_runs)

    def _dataruns_indirect(self, first_block: int, num_blocks: int) -> list[tuple[int | None, int]]:
        extfs = self.extfs
        offsets_per_block = extfs.block_size // 4
        i_blocks = c_ext.uint32[15](self.inode.i_block)

        end_block = first_block + num_blocks
        blocks = []
        missing = []

        if first_block < c_ext.EXT2_NDIR_BLOCKS:
            direct_count = min(end_block, c_ext.EXT2_NDIR_BLOCKS) - first_block
            blocks.extend(i_blocks[first_block : first_block + direct_count])

        base = c_ext.EXT2_NDIR_BLOCKS
        for level in range(1, c_ext.EXT2_NIND_BLOCKS + 1):
            if end_block <= base:
                break

            capacity = offsets_per_block**level
            if first_block < base + capacity:
                sub_first = max(first_block, base) - base
                sub_count = min(end_block, base + capacity) - base - sub_first
                offset = i_blocks[c_ext.EXT2_NDIR_BLOCKS + level - 1]
                blocks.extend(_parse_indirect(self, offset, sub_first, sub_count, level, base, missing))

            base += capacity

        if missing:
            intervals = []
            for block, count in sorted(missing):
                start = block * extfs.block_size
                end = min(start + count * extfs.block_size, self.size)
                if intervals and intervals[-1][1] >= start:
                    intervals[-1] = (intervals[-1][0], max(intervals[-1][1], end))
                else:
                    intervals.append((start, end))
            missing_intervals = [(start, end - start) for start, end in intervals]
            raise MissingDataError(
                f"Image is missing data for {self!r} at file-relative intervals (offset, size): {missing_intervals}",
                missing_intervals,
            )

        return _blocks_to_runs(blocks)

    def open(self, offset: int = 0, size: int | None = None) -> BinaryIO:
        """Open this inode as a stream, optionally limited to a file-relative byte range.

        Called without arguments this returns a stream over the entire file, like it always did.
        When ``offset`` and/or ``size`` are given, the returned stream only spans
        ``[offset, offset + size)`` (clamped to the file size). For files using indirect block
        addressing (ext2/ext3) only the indirect blocks required for that range are read.
        """
        if self.inode.i_flags & c_ext.EXT4_INLINE_DATA_FL or (self.filetype == stat.S_IFLNK and self.size < 60):
            offset = max(0, min(self.size, offset))
            end = self.size if size is None else min(self.size, offset + max(0, size))
            buf = io.BytesIO(memoryview(self.inode.i_block)[offset:end])
            # Need to add a size attribute to maintain compatibility with dissect streams
            buf.size = end - offset
            return buf

        if offset == 0 and size is None:
            return RunlistStream(self.extfs.fh, self.dataruns(), self.size, self.extfs.block_size)

        offset = max(0, min(self.size, offset))
        end = self.size if size is None else min(self.size, offset + max(0, size))
        size = end - offset

        block_size = self.extfs.block_size
        runs = self.dataruns(offset, size)
        stream = RunlistStream(self.extfs.fh, runs, sum(count for _, count in runs) * block_size, block_size)
        return RangeStream(stream, offset % block_size, size)


class XAttr:
    def __init__(self, extfs: ExtFS, inode: INode, entry: c_ext.ext4_xattr_entry, value: bytes):
        self.extfs = extfs
        self.inode = inode
        self.entry = entry

        self.prefix = XATTR_PREFIX_MAP.get(entry.e_name_index, "unknown_prefix")
        self._name = XATTR_NAME_MAP.get(entry.e_name_index, entry.e_name.decode(errors="surrogateescape"))
        self.name = self.prefix + self._name
        self.value = value

    def __repr__(self) -> str:
        return f"<xattr name={self.name} value={self.value} inode={self.inode}>"


def _parse_indirect(
    inode: INode,
    offset: int,
    first_block: int,
    num_blocks: int,
    level: int,
    base: int = 0,
    missing: list[tuple[int, int]] | None = None,
) -> list[int]:
    """Parse ``num_blocks`` logical blocks, starting at ``first_block``, from an indirect block tree.

    Args:
        inode: The inode the indirect block tree belongs to.
        offset: The block number of the root of this (sub)tree. ``0`` means a sparse (null) pointer.
        first_block: The first logical block to parse, relative to this (sub)tree.
        num_blocks: The amount of logical blocks to parse.
        level: The indirection level of this (sub)tree (1 = single, 2 = double, 3 = triple).
        base: The file-relative logical block number of this (sub)tree's first logical block.
        missing: Optional list to collect ``(block, count)`` tuples (relative to ``base``) for
            indirect blocks that cannot be read from an incomplete image. When ``None``, the
            ``EOFError`` is propagated instead.

    Returns:
        A list of block numbers, one per requested logical block. Sparse blocks are ``0``.
    """
    extfs = inode.extfs
    offsets_per_block = extfs.block_size // 4
    max_level_blocks = offsets_per_block**level

    read_blocks = min(num_blocks, max_level_blocks - first_block)
    if read_blocks <= 0:
        return []

    # A null pointer at any level means the entire (sub)tree is sparse
    if offset == 0:
        return [0] * read_blocks

    if level == 1:
        extfs.fh.seek(offset * extfs.block_size + first_block * 4)
        try:
            return list(c_ext.uint32[read_blocks](extfs.fh))
        except EOFError:
            if missing is None:
                raise
            missing.append((base + first_block, read_blocks))
            return [0] * read_blocks

    blocks_per_nest = max_level_blocks // offsets_per_block
    first_entry = first_block // blocks_per_nest
    last_entry = (first_block + read_blocks - 1) // blocks_per_nest

    extfs.fh.seek(offset * extfs.block_size + first_entry * 4)
    try:
        entries = c_ext.uint32[last_entry - first_entry + 1](extfs.fh)
    except EOFError:
        if missing is None:
            raise
        missing.append((base + first_block, read_blocks))
        return [0] * read_blocks

    blocks = []
    for index, addr in enumerate(entries):
        entry_start = (first_entry + index) * blocks_per_nest
        sub_start = max(first_block, entry_start)
        sub_first = sub_start - entry_start
        sub_count = min(first_block + read_blocks, entry_start + blocks_per_nest) - sub_start
        blocks.extend(_parse_indirect(inode, addr, sub_first, sub_count, level - 1, base + entry_start, missing))

    return blocks


def _blocks_to_runs(blocks: list[int]) -> list[tuple[int | None, int]]:
    """Convert a list of block numbers (``0`` marks a sparse block) to a runlist."""
    runs = []
    for block in blocks:
        run_block = block if block != 0 else None
        if runs:
            prev_block, prev_size = runs[-1]
            if prev_block is None and run_block is None:
                runs[-1] = (None, prev_size + 1)
                continue
            if prev_block is not None and run_block is not None and prev_block + prev_size == run_block:
                runs[-1] = (prev_block, prev_size + 1)
                continue
        runs.append((run_block, 1))
    return runs


def _slice_runs(runs: list[tuple[int | None, int]], first_block: int, num_blocks: int) -> list[tuple[int | None, int]]:
    """Slice a runlist to the block range ``[first_block, first_block + num_blocks)``."""
    result = []
    pos = 0
    end_block = first_block + num_blocks

    for run_block, run_size in runs:
        run_start = pos
        pos += run_size

        if pos <= first_block or run_start >= end_block:
            continue

        start = max(run_start, first_block)
        end = min(pos, end_block)
        block = None if run_block is None else run_block + (start - run_start)
        result.append((block, end - start))

    return result


def _parse_extents(inode: INode, buf: bytes) -> Iterator[c_ext.ext4_extent]:
    extent_header = c_ext.ext4_extent_header(buf)

    if extent_header.eh_magic != 0xF30A:
        raise Error("Invalid extent_header magic")

    if extent_header.eh_depth == 0:
        for _ in range(extent_header.eh_entries):
            extent = c_ext.ext4_extent(buf)
            yield extent
    else:
        for _ in range(extent_header.eh_entries):
            idx = c_ext.ext4_extent_idx(buf)
            child = (idx.ei_leaf_hi << 32) | idx.ei_leaf_lo

            fh = inode.extfs.fh
            fh.seek(child * inode.extfs.block_size)
            blockbuf = io.BytesIO(fh.read(inode.extfs.block_size))
            yield from _parse_extents(inode, blockbuf)


def _iter_xattr(inode: INode, buf: BinaryIO, end: int, value_offset: int = 0) -> Iterator[XAttr]:
    offset = buf.tell()
    while True:
        try:
            if offset > end:
                break

            buf.seek(offset)
            entry = c_ext.ext4_xattr_entry(buf)

            if (entry.e_name_len, entry.e_name_index, entry.e_value_offs) == (0, 0, 0):
                break

            if entry.e_value_inum:
                value = inode.extfs.get_inode(entry.e_value_inum).open().read(entry.e_value_size)
            else:
                buf.seek(value_offset + entry.e_value_offs)
                value = buf.read(entry.e_value_size)

            yield XAttr(inode.extfs, inode, entry, value)

            offset += (len(entry) + c_ext.EXT4_XATTR_ROUND) & (~c_ext.EXT4_XATTR_ROUND & 0xFFFFFFFF)
        except EOFError:
            break


def _parse_ns_ts(time: int, time_extra: int) -> int:
    # The low 2 bits of time_extra are used to extend the time field
    # The remaining 30 bits are nanoseconds
    time |= (time_extra & 0b11) << 32
    ns = time_extra >> 2

    return (time * 1000000000) + ns
