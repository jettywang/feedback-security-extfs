from __future__ import annotations

import enum
import io
import logging
import os
import stat
import struct
from dataclasses import dataclass
from functools import cached_property, lru_cache
from typing import TYPE_CHECKING, BinaryIO
from uuid import UUID

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
from dissect.util import ts
from dissect.util.stream import RunlistStream

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
        self.extfs.fh.seek(self.inode_offset())
        return c_ext.ext4_inode(self.extfs.fh)

    def inode_offset(self) -> int:
        """Return the absolute byte offset of this inode record on disk."""
        block_group_num, index = divmod(self.inum - 1, self.extfs.sb.s_inodes_per_group)
        block_group = self.extfs._read_group_desc(block_group_num)

        if self.extfs._group_desc_struct == c_ext.ext4_group_desc:
            table_block = (block_group.bg_inode_table_hi << 32) | block_group.bg_inode_table_lo
        else:
            table_block = block_group.bg_inode_table_lo

        return table_block * self.extfs.block_size + index * self.extfs.sb.s_inode_size

    def inline_xattr_data(self) -> bytes:
        """Return the inline extended-attribute area of this inode record.

        This reads the raw on-disk bytes so the area is bounded exactly by the
        inode's ``i_extra_isize``, independent of how cstruct models the dynamic
        ``i_extra`` field.
        """
        inode_size = self.extfs.sb.s_inode_size
        if inode_size <= 128:
            return b""

        extra_isize = self.inode.i_extra_isize
        if extra_isize > inode_size - 128:
            return b""

        inode_offset = self.inode_offset()
        self.extfs.fh.seek(inode_offset + 128 + extra_isize)
        return self.extfs.fh.read(inode_size - 128 - extra_isize)

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
        """Every extended attribute that could be enumerated, including damaged ones.

        Kept for backwards compatibility: the return type is still the same list
        of :class:`XAttr` objects in on-disk order, and valid attributes expose
        the same ``name`` and ``value`` as before. Use :attr:`xattr_issues` for
        container-level parse errors and inspect each attribute's
        :attr:`~XAttr.status` before trusting its value.
        """
        return self.xattrs()

    def xattrs(self, name: str | None = None) -> list[XAttr]:
        """Return extended attributes, optionally filtered to an exact full name.

        Duplicate names are intentionally preserved: each entry carries its own
        source, value offset and integrity status. When ``name`` is given, all
        occurrences are returned in on-disk order. This returns a copy so callers
        cannot corrupt the cached enumeration.
        """
        if not hasattr(self, "_xattrs"):
            self._xattrs = _read_xattrs(self)

        if name is None:
            return list(self._xattrs)

        return [xattr for xattr in self._xattrs if xattr.name == name]

    def get_xattr(self, name: str) -> XAttr | None:
        """Return the first attribute with ``name``, including a damaged one."""
        matches = self.xattrs(name)
        return matches[0] if matches else None

    def get_xattrs(self, name: str) -> list[XAttr]:
        """Return all attributes with ``name``, preserving duplicate evidence."""
        return self.xattrs(name)

    @cached_property
    def xattr_issues(self) -> tuple[XAttrIssue, ...]:
        """Container-level issues encountered while enumerating extended attributes.

        These describe damage to an inode-body header or an external attribute
        block as a whole. Per-attribute damage is recorded on the individual
        :class:`XAttr` objects instead.
        """
        self.xattrs()
        return self._xattr_issues

    def xattr_report(self) -> XAttrReport:
        """Return a grouped, report-ready view of this inode's extended attributes."""
        return XAttrReport(self, tuple(self.xattrs()), self.xattr_issues)

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


class XAttrSource(enum.Enum):
    """Physical location that supplies an extended attribute value."""

    INODE_BODY = "inode_body"
    EXTERNAL_BLOCK = "external_block"
    EA_INODE = "ea_inode"


class XAttrStatus(enum.Enum):
    """Outcome of reading one extended attribute."""

    OK = "ok"
    INVALID_NAME = "invalid_name"
    UNKNOWN_NAMESPACE = "unknown_namespace"
    DUPLICATE_NAME = "duplicate_name"
    INVALID_VALUE_OFFSET = "invalid_value_offset"
    TRUNCATED_VALUE = "truncated_value"
    INVALID_EA_INODE = "invalid_ea_inode"
    TRUNCATED_EA_VALUE = "truncated_ea_value"
    MALFORMED = "malformed"


_STATUS_PRIORITY = {
    XAttrStatus.OK: 0,
    XAttrStatus.DUPLICATE_NAME: 1,
    XAttrStatus.UNKNOWN_NAMESPACE: 2,
    XAttrStatus.INVALID_NAME: 3,
    XAttrStatus.TRUNCATED_EA_VALUE: 4,
    XAttrStatus.INVALID_EA_INODE: 5,
    XAttrStatus.TRUNCATED_VALUE: 6,
    XAttrStatus.INVALID_VALUE_OFFSET: 7,
    XAttrStatus.MALFORMED: 8,
}


@dataclass(frozen=True, slots=True)
class XAttrIssue:
    """A single reason why an extended attribute could not be read cleanly."""

    status: XAttrStatus
    detail: str


_VALUE_INCOMPLETE = frozenset(
    {
        XAttrStatus.INVALID_VALUE_OFFSET,
        XAttrStatus.TRUNCATED_VALUE,
        XAttrStatus.INVALID_EA_INODE,
        XAttrStatus.TRUNCATED_EA_VALUE,
        XAttrStatus.MALFORMED,
    }
)


@dataclass(frozen=True, slots=True)
class XAttrReport:
    """A report-ready view of an inode's extended attributes.

    Attributes are grouped by their value :attr:`~XAttr.source`, and damaged
    attributes remain in the report alongside their integrity status. A report
    is complete when it has at least one attribute and every attribute has a
    complete value; container-level damage is reported separately.
    """

    inode: INode
    attributes: tuple[XAttr, ...]
    container_issues: tuple[XAttrIssue, ...]

    @property
    def by_source(self) -> dict[XAttrSource, list[XAttr]]:
        result: dict[XAttrSource, list[XAttr]] = {source: [] for source in XAttrSource}
        for attribute in self.attributes:
            result[attribute.source].append(attribute)
        return result

    @property
    def damaged(self) -> list[XAttr]:
        """Attributes whose value could not be read completely."""
        return [attribute for attribute in self.attributes if not attribute.value_complete]

    @property
    def anomalous(self) -> list[XAttr]:
        """Attributes with any issue, including naming and duplicate anomalies."""
        return [attribute for attribute in self.attributes if not attribute.ok]

    @property
    def complete(self) -> bool:
        """Whether every reported attribute has a complete value."""
        return not self.damaged


class XAttr:
    """One extended attribute, with provenance and per-attribute integrity state.

    Attributes are represented even when they could not be read completely.
    ``value`` contains exactly the bytes that were readable, or ``None`` when the
    value could not be located at all. Check :attr:`value_complete` before
    consuming :attr:`value`; an incomplete value must not be treated as a clean
    value. :attr:`ok` is stricter and is ``False`` for naming or duplicate
    anomalies as well.

    :attr:`source` records where the value bytes came from:
    :attr:`XAttrSource.INODE_BODY` for the inode's inline area,
    :attr:`XAttrSource.EXTERNAL_BLOCK` for a referenced attribute block and
    :attr:`XAttrSource.EA_INODE` for an out-of-line value stored in another
    inode. The entry that describes an EA-inode value still lives in an inode
    body or external block; :attr:`entry_source` records that location, while
    :attr:`eainode` and :attr:`eainode_inum` identify the value inode.
    """

    def __init__(
        self,
        extfs: ExtFS,
        inode: INode,
        entry: c_ext.ext4_xattr_entry,
        value: bytes | None,
        source: XAttrSource,
        status: XAttrStatus = XAttrStatus.OK,
        issues: tuple[XAttrIssue, ...] = (),
        *,
        entry_source: XAttrSource | None = None,
        entry_offset: int | None = None,
        value_offset: int | None = None,
        eainode: INode | None = None,
    ):
        self.extfs = extfs
        self.inode = inode
        self.entry = entry

        self.namespace_index = entry.e_name_index
        self.raw_name = bytes(entry.e_name)
        self._name = XATTR_NAME_MAP.get(entry.e_name_index, self.raw_name.decode(errors="surrogateescape"))
        self.prefix = XATTR_PREFIX_MAP.get(entry.e_name_index)
        self.name = self._name if self.prefix is None else self.prefix + self._name
        self.value = value

        self.source = source
        self.entry_source = entry_source if entry_source is not None else source
        self.status = status
        self.issues = issues
        self.entry_offset = entry_offset
        self.value_offset = value_offset
        self.value_size = entry.e_value_size
        self.eainode = eainode

        self.e_value_inum = entry.e_value_inum
        self.e_value_offs = entry.e_value_offs
        self.e_value_size = entry.e_value_size

    @property
    def namespace_known(self) -> bool:
        """Whether the namespace index is one of the known ext4 indexes."""
        return self.prefix is not None

    @property
    def value_complete(self) -> bool:
        """Whether every byte declared by the entry was read from a valid location.

        This is ``True`` for complete values even if the name is unknown or
        duplicated; use :attr:`issues` to inspect those anomalies. It is derived
        from the issues rather than the aggregate status so a value problem is
        never hidden by a naming or duplicate problem.
        """
        return not any(issue.status in _VALUE_INCOMPLETE for issue in self.issues)

    @property
    def complete(self) -> bool:
        """Alias for :attr:`value_complete`."""
        return self.value_complete

    @property
    def ok(self) -> bool:
        """Whether the attribute is entirely clean, including naming and duplicates."""
        return self.status == XAttrStatus.OK

    @property
    def eainode_inum(self) -> int | None:
        """Inode number holding an out-of-line value, if any."""
        return None if self.eainode is None else self.eainode.inum

    def __repr__(self) -> str:
        return (
            f"<xattr name={self.name} source={self.source.value} status={self.status.value} "
            f"value={self.value!r} inode={self.inode}>"
        )


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


def _read_xattrs(inode: INode) -> list[XAttr]:
    """Read all extended attributes for ``inode``, isolating per-attribute damage."""
    xattrs: list[XAttr] = []
    issues: list[XAttrIssue] = []
    seen_names: dict[tuple[int, bytes], tuple[XAttrSource, int]] = {}

    containers = [
        (XAttrSource.INODE_BODY, _inode_body_container(inode, issues)),
        (XAttrSource.EXTERNAL_BLOCK, _external_block_container(inode, issues)),
    ]

    for source, container in containers:
        if container is None:
            continue

        data, value_base, entries_offset = container
        xattrs.extend(_parse_xattr_container(inode, data, value_base, entries_offset, source, seen_names, issues))

    inode._xattr_issues = tuple(issues)
    return xattrs


def _inode_body_container(inode: INode, issues: list[XAttrIssue]) -> tuple[bytes, int, int] | None:
    # A 128-byte inode has no extra area, so anything beyond its end is the next
    # inode's data rather than an inode-body xattr header.
    if inode.extfs.sb.s_inode_size <= 128:
        return None

    extra = inode.inline_xattr_data()
    if not extra or not extra.strip(b"\x00"):
        return None

    if len(extra) < 4:
        issues.append(XAttrIssue(XAttrStatus.MALFORMED, "Truncated inode-body xattr header"))
        return None

    magic = struct.unpack_from("<I", extra, 0)[0]
    if magic != c_ext.EXT4_XATTR_MAGIC:
        issues.append(XAttrIssue(XAttrStatus.MALFORMED, f"Invalid inode-body xattr magic: 0x{magic:08x}"))
        return None

    # Inline values are addressed relative to the byte after the header.
    return extra, 4, 4


def _external_block_container(inode: INode, issues: list[XAttrIssue]) -> tuple[bytes, int, int] | None:
    block = (inode.inode.i_file_acl_high << 32) | inode.inode.i_file_acl_lo
    if not block:
        return None

    if block > inode.extfs.last_block:
        issues.append(
            XAttrIssue(
                XAttrStatus.MALFORMED,
                f"External xattr block {block} exceeds last block {inode.extfs.last_block}",
            )
        )
        return None

    block_offset = block * inode.extfs.block_size
    inode.extfs.fh.seek(block_offset)
    data = inode.extfs.fh.read(inode.extfs.block_size)
    if len(data) < inode.extfs.block_size:
        issues.append(
            XAttrIssue(
                XAttrStatus.MALFORMED,
                f"Truncated external xattr block {block}: read {len(data)} of {inode.extfs.block_size} bytes",
            )
        )
    if len(data) < 4:
        return None

    magic = struct.unpack_from("<I", data, 0)[0]
    if magic != c_ext.EXT4_XATTR_MAGIC:
        issues.append(
            XAttrIssue(
                XAttrStatus.MALFORMED,
                f"Invalid external xattr block magic at block {block}: 0x{magic:08x}",
            )
        )
        return None

    # The external block has a full 32-byte header before the first entry.
    return data, 0, 32


def _iter_xattr_entries(
    data: bytes, entries_offset: int, source: XAttrSource, issues: list[XAttrIssue]
) -> Iterator[tuple[int, int, int, int, int, bytes]]:
    """Yield ``(offset, name_len, name_index, value_offs, value_inum, value_size)`` tuples.

    Stops cleanly at the end marker. A malformed entry is reported once and does
    not prevent earlier entries from being returned.
    """
    end = len(data)
    offset = entries_offset

    while offset + 16 <= end:
        name_len, name_index, value_offs, value_inum, value_size, _hash = struct.unpack_from("<BBHIII", data, offset)

        if (name_len, name_index, value_offs) == (0, 0, 0):
            break

        entry_size = (16 + name_len + c_ext.EXT4_XATTR_ROUND) & ~c_ext.EXT4_XATTR_ROUND
        next_offset = offset + entry_size

        if next_offset > end:
            issues.append(
                XAttrIssue(
                    XAttrStatus.MALFORMED,
                    f"Xattr entry at offset 0x{offset:x} in {source.value} extends past its container",
                )
            )
            break

        yield offset, name_len, name_index, value_offs, value_inum, value_size
        offset = next_offset


def _parse_xattr_container(
    inode: INode,
    data: bytes,
    value_base: int,
    entries_offset: int,
    source: XAttrSource,
    seen_names: dict[tuple[int, bytes], tuple[XAttrSource, int]],
    issues: list[XAttrIssue],
) -> list[XAttr]:
    xattrs: list[XAttr] = []

    entries = list(_iter_xattr_entries(data, entries_offset, source, issues))
    if not entries:
        return xattrs

    last_offset, last_name_len = entries[-1][0], entries[-1][1]
    last_entry_end = last_offset + ((16 + last_name_len + c_ext.EXT4_XATTR_ROUND) & ~c_ext.EXT4_XATTR_ROUND)
    # The entry array ends with one all-zero 4-byte terminator; values follow it.
    entry_table_end = last_entry_end + 4

    for offset, name_len, name_index, value_offs, value_inum, value_size in entries:
        entry_size = (16 + name_len + c_ext.EXT4_XATTR_ROUND) & ~c_ext.EXT4_XATTR_ROUND
        buf = io.BytesIO(data[offset : offset + entry_size])
        try:
            entry = c_ext.ext4_xattr_entry(buf)
        except EOFError:
            issues.append(
                XAttrIssue(
                    XAttrStatus.MALFORMED,
                    f"Truncated xattr entry at offset 0x{offset:x} in {source.value}",
                )
            )
            continue

        entry_issues: list[XAttrIssue] = []

        if name_len > len(entry.e_name):
            entry_issues.append(
                XAttrIssue(
                    XAttrStatus.INVALID_NAME,
                    f"Declared name length {name_len} exceeds available {len(entry.e_name)}",
                )
            )

        if name_index not in XATTR_PREFIX_MAP:
            entry_issues.append(
                XAttrIssue(
                    XAttrStatus.UNKNOWN_NAMESPACE,
                    f"Unknown namespace index {name_index}",
                )
            )

        if value_inum:
            value, value_offset, value_issues, eainode = _read_ea_inode_value(inode, entry)
            value_source = XAttrSource.EA_INODE
        else:
            value, value_offset, value_issues = _read_inline_value(
                data, value_base, entry_table_end, value_offs, value_size, len(data)
            )
            value_source = source
            eainode = None
        entry_issues.extend(value_issues)

        name_key = (name_index, bytes(entry.e_name))
        if name_key in seen_names:
            previous_source, previous_offset = seen_names[name_key]
            entry_issues.append(
                XAttrIssue(
                    XAttrStatus.DUPLICATE_NAME,
                    f"Duplicate name {bytes(entry.e_name)!r} in namespace {name_index}; first seen "
                    f"in {previous_source.value} at offset 0x{previous_offset:x}",
                )
            )
        else:
            seen_names[name_key] = (source, offset)

        status = XAttrStatus.OK
        if entry_issues:
            status = max((issue.status for issue in entry_issues), key=_STATUS_PRIORITY.__getitem__)

        xattrs.append(
            XAttr(
                inode.extfs,
                inode,
                entry,
                value,
                value_source,
                status,
                tuple(entry_issues),
                entry_source=source,
                entry_offset=offset,
                value_offset=value_offset,
                eainode=eainode,
            )
        )

    return xattrs


def _read_inline_value(
    data: bytes, value_base: int, entry_start: int, value_offs: int, value_size: int, end: int
) -> tuple[bytes | None, int | None, list[XAttrIssue]]:
    value_offset = value_base + value_offs

    # A zero-length value has no location to validate; the offset field is unused.
    if value_size == 0:
        return b"", None, []

    if value_offset >= end:
        return (
            None,
            value_offset,
            [
                XAttrIssue(
                    XAttrStatus.INVALID_VALUE_OFFSET,
                    f"Value offset {value_offset} is outside container of size {end}",
                )
            ],
        )

    # Values must be stored after the entry table; an offset pointing back into
    # the entries or header is corrupt and must not be reported as a clean value.
    if value_offset < entry_start:
        return (
            None,
            value_offset,
            [
                XAttrIssue(
                    XAttrStatus.INVALID_VALUE_OFFSET,
                    f"Value offset {value_offset} points into the entry area ending at {entry_start}",
                )
            ],
        )

    available = end - value_offset
    if value_size > available:
        return (
            data[value_offset:end],
            value_offset,
            [
                XAttrIssue(
                    XAttrStatus.TRUNCATED_VALUE,
                    f"Value needs {value_size} bytes but only {available} remain",
                )
            ],
        )

    return data[value_offset : value_offset + value_size], value_offset, []


def _read_ea_inode_value(
    inode: INode, entry: c_ext.ext4_xattr_entry
) -> tuple[bytes | None, int | None, list[XAttrIssue], INode | None]:
    if entry.e_value_inum < c_ext.EXT2_BAD_INO or entry.e_value_inum > inode.extfs.sb.s_inodes_count:
        return (
            None,
            None,
            [
                XAttrIssue(
                    XAttrStatus.INVALID_EA_INODE,
                    f"EA inode number {entry.e_value_inum} is outside "
                    f"{c_ext.EXT2_BAD_INO}-{inode.extfs.sb.s_inodes_count}",
                )
            ],
            None,
        )

    try:
        eainode = inode.extfs.get_inode(entry.e_value_inum)
    except (Error, EOFError) as e:
        return (
            None,
            None,
            [XAttrIssue(XAttrStatus.INVALID_EA_INODE, f"Unable to load EA inode {entry.e_value_inum}: {e}")],
            None,
        )

    if not entry.e_value_size:
        return b"", None, [], eainode

    available = eainode.size
    if entry.e_value_size > available:
        try:
            value = eainode.open().read(available)
        except (Error, EOFError) as e:
            return (
                None,
                None,
                [XAttrIssue(XAttrStatus.TRUNCATED_EA_VALUE, f"Unable to read EA inode {eainode.inum}: {e}")],
                eainode,
            )

        return (
            value,
            None,
            [
                XAttrIssue(
                    XAttrStatus.TRUNCATED_EA_VALUE,
                    f"EA inode {eainode.inum} holds {available} bytes but the attribute needs {entry.e_value_size}",
                )
            ],
            eainode,
        )

    try:
        value = eainode.open().read(entry.e_value_size)
    except (Error, EOFError) as e:
        return (
            None,
            None,
            [XAttrIssue(XAttrStatus.INVALID_EA_INODE, f"Unable to read EA inode {eainode.inum}: {e}")],
            eainode,
        )

    if len(value) < entry.e_value_size:
        return (
            value,
            None,
            [
                XAttrIssue(
                    XAttrStatus.TRUNCATED_EA_VALUE,
                    f"EA inode {eainode.inum} returned {len(value)} of {entry.e_value_size} bytes",
                )
            ],
            eainode,
        )

    return value, None, [], eainode


def _parse_ns_ts(time: int, time_extra: int) -> int:
    # The low 2 bits of time_extra are used to extend the time field
    # The remaining 30 bits are nanoseconds
    time |= (time_extra & 0b11) << 32
    ns = time_extra >> 2

    return (time * 1000000000) + ns
