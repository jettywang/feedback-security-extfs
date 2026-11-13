from __future__ import annotations

import io
import logging
import os
import stat
import warnings
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

        self._inode_cache = lru_cache(1024)(self._create_inode)
        self._read_group_desc = lru_cache(356)(self._read_group_desc)

        self.root = DirectoryEntry(self.get_inode(c_ext.EXT2_ROOT_INO), "/")

    @cached_property
    def journal(self) -> JDB2:
        if not self.sb.s_feature_compat & c_ext.EXT3_FEATURE_COMPAT_HAS_JOURNAL:
            raise Error("Journal not supported")

        inum = self.sb.s_journal_inum
        if inum == 0:
            raise Error(f"Journal inum is 0, could be on external device (s_journal_uuid = {self.sb.s_journal_uuid})")

        inode = self.get_inode(inum)
        return JDB2(inode.open())

    def get(self, path_or_inum: str | int, node: INode | None = None) -> INode | DirectoryEntry:
        """Resolve a path or inode number.

        An integer inode number returns the shared, cached :class:`INode`.
        A path is resolved directory by directory and returns the
        :class:`DirectoryEntry` carrying that path component's name; directory
        entries delegate all inode metadata to their shared :class:`INode`.
        """
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
        """Return the cached :class:`INode` for ``inum``.

        The cache key is the inode number only. Every hard link pointing at the
        same on-disk inode therefore shares one :class:`INode` instance and its
        parsed metadata (inode record, runlist, xattrs), regardless of the
        directory entry through which it was reached. The cache is scoped to
        this :class:`ExtFS` instance, mirroring the previous per-filesystem
        cache size of 1024 entries.

        The ``filename`` and ``filetype`` arguments are accepted for backwards
        compatibility but do not participate in caching or in the inode's
        identity. A non-default ``filename`` is ignored with a warning: names
        belong to :class:`DirectoryEntry` objects, not to inodes. ``filetype``
        only seeds the inode's own type hint until its on-disk inode record is
        read; directory-entry d_type values are stored on DirectoryEntry and
        never mutate the shared inode.
        """
        if inum < c_ext.EXT2_BAD_INO or inum > self.sb.s_inodes_count:
            raise Error(f"inum out of range {c_ext.EXT2_BAD_INO}-{self.sb.s_inodes_count}: {inum}")

        if filename is not None:
            warnings.warn(
                "ExtFS.get_inode() no longer associates a filename with an INode; directory "
                "names are represented by DirectoryEntry objects. The filename argument is "
                "ignored and will be removed in a future release.",
                DeprecationWarning,
                stacklevel=2,
            )

        inode = self._inode_cache(int(inum))
        if filetype is not None:
            inode._filetype = filetype
        return inode

    def _create_inode(self, inum: int) -> INode:
        return INode(self, inum)

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
    """A single on-disk inode, shared by every directory entry that links to it.

    Identity rules:
        An :class:`INode` is uniquely identified by the pair
        ``(extfs, inum)``. :meth:`ExtFS.get_inode` caches on the inode number,
        so all hard links to one inode resolve to the same :class:`INode`
        instance and share all parsed metadata (the inode record, runlist and
        extended attributes), which means the underlying inode block is read
        from disk only once.

        An inode has no name of its own. Names and directory-entry file types
        are properties of :class:`DirectoryEntry` objects; the same inode can be
        referenced by many entries, each with its own independent name.
        Accessing :attr:`filename` on a bare inode therefore raises
        :class:`AttributeError`; use a :class:`DirectoryEntry` (for example the
        result of :meth:`ExtFS.get` with a path or of :meth:`iterdir`) to obtain
        a name.

        Deleting a directory entry (unlinking one hard link) does not change the
        inode's identity or invalidate any :class:`DirectoryEntry` or
        :class:`INode` reference already handed out. A residual reference keeps
        pointing at the same cached inode and, for a directory entry, keeps its
        own name; inode 0 directory entries (free/unlinked slots) are skipped
        during directory traversal rather than returned.
    """

    def __init__(
        self,
        extfs: ExtFS,
        inum: int,
        filetype: int | None = None,
    ):
        self.extfs = extfs
        self.inum = inum
        self._filetype = filetype
        self._runlist = None

    def __repr__(self) -> str:
        return f"<inode {self.inum}>"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, INode):
            return NotImplemented
        return self.extfs is other.extfs and self.inum == other.inum

    def __hash__(self) -> int:
        return hash((id(self.extfs), self.inum))

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

    def listdir(self) -> dict[str, DirectoryEntry]:
        return {entry.filename: entry for entry in self.iterdir()}

    dirlist = listdir

    def iterdir(self) -> Iterator[DirectoryEntry]:
        if self.filetype != stat.S_IFDIR:
            raise NotADirectoryError(f"{self!r} is not a directory")

        buf = self.open()
        offset = 0

        while offset < self.size - 12:
            direntry = self.extfs._dirtype(buf)

            if direntry.rec_len == 0:
                log.critical("Zero-length directory entry in %s (offset 0x%x)", self, offset)
                return

            # Sanity check if the direntry is valid. Inode 0 marks a free
            # directory entry (an unlinked slot) and is never yielded, so
            # callers never get a residual reference without a backing inode.
            if 0 < direntry.inode < self.extfs.sb.s_inodes_count:
                fname = buf.read(direntry.name_len).decode(errors="surrogateescape")
                ftype = direntry.file_type if self.extfs._dirtype == c_ext.ext2_dir_entry_2 else None

                if ftype:
                    ftype = FILETYPES[ftype]

                yield DirectoryEntry(self.extfs.get_inode(direntry.inode), fname, ftype)

            offset += direntry.rec_len
            buf.seek(offset)

    def dataruns(self) -> list[tuple[int | None, int]]:
        if not self._runlist:
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

                self._runlist = runs
            else:
                i_blocks = c_ext.uint32[15](self.inode.i_block)
                num_blocks = (self.size + self.extfs.block_size - 1) // self.extfs.block_size
                num_direct_blocks = min(num_blocks, c_ext.EXT2_NDIR_BLOCKS)

                blocks = i_blocks[:num_direct_blocks]
                num_blocks -= num_direct_blocks

                if num_blocks > 0:
                    for level in range(c_ext.EXT2_NIND_BLOCKS):
                        indirect_offset = i_blocks[num_direct_blocks + level]
                        parsed_blocks = _parse_indirect(self, indirect_offset, num_blocks, level + 1)
                        num_blocks -= len(parsed_blocks)
                        blocks.extend(parsed_blocks)

                        if num_blocks == 0:
                            break

                runs = []
                if blocks:
                    run_offset = None
                    run_size = 1

                    for block in blocks:
                        if run_offset is None:
                            run_offset = block
                            continue

                        if block == run_offset + run_size:
                            run_size += 1
                        else:
                            if run_offset == 0:
                                runs.append((None, run_size))
                            else:
                                runs.append((run_offset, run_size))
                            run_offset = block
                            run_size = 1

                    runs.append((run_offset, run_size))

                self._runlist = runs

        return self._runlist

    def open(self) -> BinaryIO:
        if self.inode.i_flags & c_ext.EXT4_INLINE_DATA_FL or (self.filetype == stat.S_IFLNK and self.size < 60):
            buf = io.BytesIO(memoryview(self.inode.i_block)[: self.size])
            # Need to add a size attribute to maintain compatibility with dissect streams
            buf.size = self.size
            return buf
        return RunlistStream(self.extfs.fh, self.dataruns(), self.size, self.extfs.block_size)


class DirectoryEntry:
    """A named directory entry pointing at a shared :class:`INode`.

    Identity rules:
        A :class:`DirectoryEntry` represents one reference (one hard link) in
        one directory. Its identity is the combination of its backing inode,
        its entry name and the directory it belongs to. Two directory entries
        that link to the same inode through different paths are distinct
        objects with independent names and directory-entry file types, but
        delegate all inode metadata to the one shared :class:`INode`, so names
        can never overwrite each other and the inode's on-disk record is
        parsed once.

        The ``filetype`` reported here comes from the directory entry's d_type
        field and is stored on the entry itself; when an entry has no d_type
        value it falls back to the shared inode's actual mode-derived type.

        Directory entries are value-comparable: entries with the same backing
        inode and name compare equal even when obtained from separate
        :meth:`INode.iterdir` calls, while two hard links of the same inode
        with different names compare different. Removing the entry on disk
        does not mutate or invalidate an already obtained reference, which
        retains its name and inode.
    """

    def __init__(self, inode: INode, filename: str, filetype: int | None = None):
        self._inode = inode
        self.filename = filename
        # The directory-entry file type is per-entry metadata (the d_type field
        # of the dirent) and is intentionally kept off the shared inode, so a
        # hint from one path can never overwrite another path's view. When the
        # entry carries no type it falls back to the inode's actual type.
        self._filetype = filetype

    def __repr__(self) -> str:
        return f"<directory_entry filename={self.filename!r} inode={self._inode!r}>"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, DirectoryEntry):
            return NotImplemented
        return self.filename == other.filename and self._inode == other._inode

    def __hash__(self) -> int:
        return hash((self.filename, self._inode))

    @property
    def inode(self) -> INode:
        return self._inode

    @property
    def inum(self) -> int:
        return self._inode.inum

    @property
    def extfs(self) -> ExtFS:
        return self._inode.extfs

    @property
    def filetype(self) -> int:
        return self._filetype if self._filetype is not None else self._inode.filetype

    def listdir(self) -> dict[str, DirectoryEntry]:
        return self._inode.listdir()

    def iterdir(self) -> Iterator[DirectoryEntry]:
        yield from self._inode.iterdir()

    def __getattr__(self, attr: str) -> object:
        # Delegate every other attribute (size, timestamps, xattr, open(),
        # dataruns(), ...) to the shared inode so that historical code treating
        # directory entries as inodes keeps working. The guard avoids infinite
        # recursion when the inode is not yet set (for example during unpickle).
        if attr == "_inode":
            raise AttributeError(attr)
        return getattr(self._inode, attr)


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


def _parse_indirect(inode: INode, offset: int, num_blocks: int, level: int) -> list[int]:
    offsets_per_block = inode.extfs.block_size // 4

    if level == 1:
        read_blocks = min(num_blocks, offsets_per_block)
        if offset == 0:
            return [0] * read_blocks
        inode.extfs.fh.seek(offset * inode.extfs.block_size)
        return c_ext.uint32[read_blocks](inode.extfs.fh)

    blocks = []

    max_level_blocks = offsets_per_block**level
    blocks_per_nest = max_level_blocks // offsets_per_block
    read_blocks = (num_blocks + blocks_per_nest - 1) // blocks_per_nest
    read_blocks = min(read_blocks, offsets_per_block)

    inode.extfs.fh.seek(offset * inode.extfs.block_size)
    for addr in c_ext.uint32[read_blocks](inode.extfs.fh):
        parsed_blocks = _parse_indirect(inode, addr, num_blocks, level - 1)
        num_blocks -= len(parsed_blocks)
        blocks.extend(parsed_blocks)

    return blocks


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
