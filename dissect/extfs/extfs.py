from __future__ import annotations

import io
import json
import logging
import os
import stat
from collections import deque
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
from dissect.extfs.fscrypt import EncryptionContext
from dissect.extfs.journal import JDB2

if TYPE_CHECKING:
    from collections.abc import Iterator
    from datetime import datetime

log = logging.getLogger(__name__)
log.setLevel(os.getenv("DISSECT_LOG_EXTFS", "CRITICAL"))


#: Prefix used for the report-safe representation of names stored in encrypted directories.
ENCRYPTED_NAME_PREFIX = "fscrypt:"


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

            if node.encrypted:
                raise FileNotFoundError(
                    f"File not found: {path_or_inum} (encrypted directory {node.inum} requires a name index lookup)"
                )

            for entry in node.iterdir():
                if entry.filename == part:
                    node = entry
                    break
            else:
                raise FileNotFoundError(f"File not found: {path_or_inum}")

        return node

    def name_index(self, root: INode | None = None) -> NameIndex:
        """Build a reversible name index for the directory tree below ``root``.

        The index includes ordinary and encrypted directories alike. Entries of the encrypted directories retain their
        raw name bytes and the encryption context of their parent directory. Directories marked with the encryption
        flag are still traversed, because their entries remain structurally readable even without a key.
        """
        root = root if root is not None else self.root
        entries = []
        seen = set()
        pending = deque([root])

        while pending:
            directory = pending.popleft()
            if directory.inum in seen or directory.filetype != stat.S_IFDIR:
                continue

            seen.add(directory.inum)
            for entry in directory._iter_entries():
                entries.append(entry)

                if entry.raw_name in (b".", b".."):
                    continue

                try:
                    child = self.get_inode(
                        entry.inum, entry.path_name, entry.filetype, raw_name=entry.raw_name, parent=directory
                    )
                except Exception:
                    continue

                if child.filetype == stat.S_IFDIR:
                    pending.append(child)

        return NameIndex(entries, root_inode=root.inum, source_uuid=str(self.uuid))

    def get_inode(
        self,
        inum: int,
        filename: str | None = None,
        filetype: int | None = None,
        raw_name: bytes | None = None,
        parent: INode | None = None,
    ) -> INode:
        if inum < c_ext.EXT2_BAD_INO or inum > self.sb.s_inodes_count:
            raise Error(f"inum out of range {c_ext.EXT2_BAD_INO}-{self.sb.s_inodes_count}: {inum}")

        return INode(self, inum, filename, filetype, raw_name, parent)

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
        raw_name: bytes | None = None,
        parent: INode | None = None,
    ):
        self.extfs = extfs
        self.inum = inum
        self.filename = filename
        self._filetype = filetype
        self._raw_name = raw_name
        self._parent = parent
        self._runlist = None

    def __repr__(self) -> str:
        return f"<inode {self.inum}>"

    @property
    def raw_name(self) -> bytes | None:
        """The original on-disk name bytes for this inode, if it was reached through a directory entry."""
        return self._raw_name

    @property
    def parent(self) -> INode | None:
        """The directory this inode was reached through, if any."""
        return self._parent

    @property
    def name_encrypted(self) -> bool:
        """Whether the name this inode was reached by is encrypted."""
        if self._parent is None or not self._parent.encrypted or self.raw_name is None:
            return False

        return not (
            (self.raw_name == b"." and self.inum == self._parent.inum)
            or (self.raw_name == b".." and (self._parent.parent is None or self.inum == self._parent.parent.inum))
        )

    @property
    def name_encryption_context(self) -> EncryptionContext | None:
        """The encryption context that applies to this inode's name, if the name is encrypted."""
        if not self.name_encrypted:
            return None
        return self._parent.encryption_context

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

    @property
    def encrypted(self) -> bool:
        """Whether this inode is marked with the ext4 encryption flag."""
        return bool(self.inode.i_flags & c_ext.EXT4_ENCRYPT_FL)

    @cached_property
    def encryption_context(self) -> EncryptionContext:
        """The fscrypt encryption context stored on this inode, if any.

        This is the policy of an encrypted inode. For the policy that applies to a name, use
        :attr:`name_encryption_context` on nodes obtained from a directory listing.
        """
        try:
            xattr = self._encryption_xattr()
        except Exception as e:
            return EncryptionContext(status=EncryptionContext.STATUS_UNREADABLE, error=str(e))

        if xattr is None:
            return EncryptionContext.missing()

        return EncryptionContext.from_raw(xattr.value, xattr_name=xattr.name)

    def _encryption_xattr(self) -> XAttr | None:
        xattrs = self.xattr

        for xattr in xattrs:
            if xattr.entry.e_name_index == c_ext.EXT4_XATTR_INDEX_ENCRYPTION:
                return xattr

        # Some images store the policy under the historical "system.c" name
        for xattr in xattrs:
            if xattr.name in ("encryption.c", "system.c"):
                return xattr

        return None

    def listdir(self) -> dict[str, INode]:
        """Return the directory entries keyed by name.

        For unencrypted directories this keeps the historical display-name mapping. Encrypted entries are not
        resolvable paths: keying them by display name would merge entries and present undecodable bytes as a path.
        Their keys are therefore the reversible entry identifiers from :meth:`name_index`.
        """
        if self.encrypted:
            return {
                (entry.entry_id if entry.is_encrypted else entry.name): entry.inode() for entry in self._iter_entries()
            }

        return {node.filename: node for node in self.iterdir()}

    dirlist = listdir

    def listdir_entries(self) -> DirectoryListing:
        """Return a lossless directory listing that preserves encrypted names.

        Unlike :meth:`listdir`, entries are never keyed or merged by their displayed (decoded) name. Every entry keeps
        its raw on-disk name bytes, its byte offset in the directory data, the parent directory inode and, for
        encrypted directories, the encryption context that applies to the name.
        """
        return DirectoryListing(self, list(self._iter_entries()))

    def name_index(self) -> NameIndex:
        """Return a reversible index of this directory's entries.

        Unlike :meth:`listdir`, index keys never derive from a display name, so encrypted entries that share a name
        remain individually addressable.
        """
        return NameIndex(list(self._iter_entries()), root_inode=self.inum, source_uuid=str(self.extfs.uuid))

    def iterdir_entries(self) -> Iterator[DirectoryEntry]:
        """Iterate directory entries with raw name bytes and encryption metadata preserved."""
        yield from self._iter_entries()

    def iterdir(self) -> Iterator[INode]:
        if self.filetype != stat.S_IFDIR:
            raise NotADirectoryError(f"{self!r} is not a directory")

        for entry in self._iter_entries():
            yield entry.inode()

    def _iter_entries(self) -> Iterator[DirectoryEntry]:
        if self.filetype != stat.S_IFDIR:
            raise NotADirectoryError(f"{self!r} is not a directory")

        buf = self.open()
        offset = 0

        while offset < self.size - 12:
            buf.seek(offset)
            direntry = self.extfs._dirtype(buf)

            if direntry.rec_len == 0:
                log.critical("Zero-length directory entry in %s (offset 0x%x)", self, offset)
                return

            # Sanity check if the direntry is valid
            if 0 < direntry.inode < self.extfs.sb.s_inodes_count:
                fname = buf.read(direntry.name_len)
                ftype = direntry.file_type if self.extfs._dirtype == c_ext.ext2_dir_entry_2 else None

                if ftype:
                    ftype = FILETYPES[ftype]

                yield DirectoryEntry(
                    directory=self,
                    inum=direntry.inode,
                    raw_name=fname,
                    offset=offset,
                    rec_len=direntry.rec_len,
                    filetype=ftype,
                )

            offset += direntry.rec_len

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
    """A single directory entry, including its original on-disk name bytes."""

    def __init__(
        self,
        directory: INode,
        inum: int,
        raw_name: bytes,
        offset: int,
        rec_len: int,
        filetype: int | None = None,
    ):
        self.directory = directory
        self.inum = inum
        self.raw_name = raw_name
        self.offset = offset
        self.rec_len = rec_len
        self.filetype = filetype

    def __repr__(self) -> str:
        return f"<directory_entry inode={self.directory.inum} offset=0x{self.offset:x} raw_name={self.raw_name!r}>"

    @property
    def name(self) -> str:
        """The decoded display name, using surrogate escapes for undecodable bytes."""
        return self.raw_name.decode(errors="surrogateescape")

    @property
    def path_name(self) -> str:
        """A report-safe name.

        Ordinary names are returned unchanged. Names stored in an encrypted directory are returned as an explicit
        ``fscrypt:<hex>`` marker, so a report can never silently present undecodable bytes as an ordinary path.
        """
        if not self.is_encrypted:
            return self.name
        return f"{ENCRYPTED_NAME_PREFIX}{self.raw_name.hex()}"

    @property
    def is_encrypted(self) -> bool:
        """Whether the parent directory stores this name encrypted.

        The ``.`` and ``..`` entries of an encrypted directory are stored in plaintext, as are all names of an
        unencrypted directory. A further entry that happens to carry those bytes is not a plaintext self/parent
        reference and is treated as an encrypted name.
        """
        if not self.directory.encrypted:
            return False

        return not self._is_plaintext_reference

    @property
    def _is_plaintext_reference(self) -> bool:
        if self.raw_name == b".":
            return self.inum == self.directory.inum

        if self.raw_name == b"..":
            parent = self.directory.parent
            return parent is None or self.inum == parent.inum

        return False

    @property
    def encryption_context(self) -> EncryptionContext:
        """The encryption context of the parent directory that applies to this name."""
        return self.directory.encryption_context

    @property
    def entry_id(self) -> str:
        """A stable identity for this entry within its directory."""
        return f"{self.directory.inum}:{self.offset}:{self.inum}"

    @property
    def disk_offset(self) -> int | None:
        """The absolute byte offset of this entry in the evidence, if it is backed by an allocated block."""
        if self.directory.inode.i_flags & c_ext.EXT4_INLINE_DATA_FL:
            return None

        block_index, block_offset = divmod(self.offset, self.directory.extfs.block_size)
        logical_block = 0

        for run_block, run_length in self.directory.dataruns():
            if block_index < logical_block + run_length:
                if run_block is None:
                    return None
                return (run_block + block_index - logical_block) * self.directory.extfs.block_size + block_offset
            logical_block += run_length

        return None

    def inode(self) -> INode:
        """Open the inode this entry points to, carrying the raw name bytes and parent directory."""
        return self.directory.extfs.get_inode(
            self.inum, self.path_name, self.filetype, raw_name=self.raw_name, parent=self.directory
        )

    def to_dict(self) -> dict:
        """Return a JSON-serializable, lossless description of this entry."""
        return {
            "entry_id": self.entry_id,
            "directory_inode": self.directory.inum,
            "directory_path": self.directory.filename,
            "directory_raw_name": self.directory.raw_name.hex() if self.directory.raw_name else None,
            "inode": self.inum,
            "offset": self.offset,
            "disk_offset": self.disk_offset,
            "rec_len": self.rec_len,
            "file_type": self.filetype,
            "encrypted": self.is_encrypted,
            "display_name": self.name,
            "path_name": self.path_name,
            "display_name_is_path": not self.is_encrypted,
            "name_encoding": "surrogateescape",
            "raw_name": self.raw_name.hex(),
            "name_length": len(self.raw_name),
            "encryption_context": self.encryption_context.to_dict() if self.is_encrypted else None,
        }


class DirectoryListing:
    """An ordered, lossless listing of a single directory.

    Iteration and indexing follow the same order as the on-disk directory data. Entries are never keyed by name.
    This is also returned from :meth:`INode.listdir_entries`, which keeps ordinary directory usage separate from the
    historical display-name mapping returned by :meth:`INode.listdir`.
    """

    def __init__(self, directory: INode, entries: list[DirectoryEntry]):
        self.directory = directory
        self.entries = entries

    def __iter__(self) -> Iterator[DirectoryEntry]:
        return iter(self.entries)

    def __len__(self) -> int:
        return len(self.entries)

    def __getitem__(self, index: int) -> DirectoryEntry:
        return self.entries[index]

    def __repr__(self) -> str:
        return f"<DirectoryListing directory={self.directory.inum} entries={len(self.entries)}>"

    def to_dict(self) -> dict:
        return {
            "directory_inode": self.directory.inum,
            "directory_path": self.directory.filename,
            "encrypted": self.directory.encrypted,
            "encryption_context": self.directory.encryption_context.to_dict() if self.directory.encrypted else None,
            "entries": [entry.to_dict() for entry in self.entries],
        }


class NameIndex:
    """A reversible index of directory entries.

    Entries are keyed by a deterministic, unique identifier derived from the parent directory inode, the byte offset of
    the entry inside the directory data and the referenced inode. Display names are intentionally not used as keys, so
    encrypted entries that share (or collide on) a display name remain separate. The index records the source volume
    UUID and root inode so an index can be tied back to the evidence it was built from.
    """

    def __init__(
        self,
        entries: list[DirectoryEntry],
        *,
        root_inode: int | None = None,
        source_uuid: str | None = None,
    ):
        self.entries = entries
        self.root_inode = root_inode
        self.source_uuid = source_uuid
        self._index = {entry.entry_id: entry for entry in entries}

    def __iter__(self) -> Iterator[str]:
        return iter(self._index)

    def __len__(self) -> int:
        return len(self._index)

    def __contains__(self, entry_id: object) -> bool:
        return entry_id in self._index

    def __getitem__(self, entry_id: str) -> DirectoryEntry:
        return self._index[entry_id]

    def __repr__(self) -> str:
        return f"<NameIndex entries={len(self._index)}>"

    def resolve(self, entry_id: str) -> DirectoryEntry:
        """Look up an entry by its index key."""
        return self._index[entry_id]

    def by_display_name(self, name: str) -> list[DirectoryEntry]:
        """Return all entries with the given display name, including ambiguous encrypted names."""
        return [entry for entry in self.entries if entry.name == name]

    def to_dict(self) -> dict:
        """Return a JSON-serializable index that uniquely identifies every underlying entry."""
        directories = {}
        for entry in self.entries:
            directory = entry.directory
            directories.setdefault(
                str(directory.inum),
                {
                    "inode": directory.inum,
                    "path": directory.filename,
                    "raw_name": directory.raw_name.hex() if directory.raw_name else None,
                    "name_encrypted": directory.name_encrypted,
                    "parent_inode": directory.parent.inum if directory.parent else None,
                    "encrypted": directory.encrypted,
                    "encryption_context": directory.encryption_context.to_dict() if directory.encrypted else None,
                },
            )

        return {
            "kind": "extfs.name_index",
            "version": 1,
            "source_uuid": self.source_uuid,
            "root_inode": self.root_inode,
            "entry_count": len(self._index),
            "directories": directories,
            "entries": {entry.entry_id: entry.to_dict() for entry in self.entries},
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=True, indent=2, sort_keys=True)

    @classmethod
    def from_dict(cls, extfs: ExtFS, data: dict) -> NameIndex:
        """Rebuild an index from its JSON representation so it can be checked against the evidence."""
        directories = {}
        for record in data.get("directories", {}).values():
            directory = extfs.get_inode(record["inode"], record.get("path"))
            if record.get("raw_name") is not None:
                directory._raw_name = bytes.fromhex(record["raw_name"])
            directories[record["inode"]] = (directory, record)

        for directory, record in directories.values():
            parent_inode = record.get("parent_inode")
            if parent_inode in directories:
                directory._parent = directories[parent_inode][0]

        entries = []
        for record in data["entries"].values():
            directory = directories[record["directory_inode"]][0]
            entries.append(
                DirectoryEntry(
                    directory=directory,
                    inum=record["inode"],
                    raw_name=bytes.fromhex(record["raw_name"]),
                    offset=record["offset"],
                    rec_len=record["rec_len"],
                    filetype=record["file_type"],
                )
            )

        return cls(
            entries,
            root_inode=data.get("root_inode"),
            source_uuid=data.get("source_uuid"),
        )

    def verify(self) -> list[str]:
        """Re-read every directory and report entries whose bytes no longer match this index.

        An empty result means every index key maps back to the original directory entry bytes in the evidence.
        """
        by_directory = {}
        for entry in self.entries:
            by_directory.setdefault(entry.directory.inum, (entry.directory, []))[1].append(entry)

        mismatches = []
        for directory, expected_entries in by_directory.values():
            current = {entry.offset: entry for entry in directory._iter_entries()}
            for entry in expected_entries:
                found = current.get(entry.offset)
                if (
                    found is None
                    or found.inum != entry.inum
                    or found.raw_name != entry.raw_name
                    or found.rec_len != entry.rec_len
                ):
                    mismatches.append(entry.entry_id)

        return mismatches


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
