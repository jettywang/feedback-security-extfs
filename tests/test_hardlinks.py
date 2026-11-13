from __future__ import annotations

import io
import stat
import struct
from typing import BinaryIO

import pytest

from dissect.extfs import DirectoryEntry, ExtFS, INode
from dissect.extfs.exceptions import Error, FileNotFoundError, NotADirectoryError, NotASymlinkError


class _CountingBytesIO(io.BytesIO):
    """BytesIO that counts read() calls intersecting a byte region."""

    def __init__(self, data: bytes, region_start: int, region_size: int):
        super().__init__(data)
        self._region_start = region_start
        self._region_end = region_start + region_size
        self.region_reads = 0
        self._tracking = False

    def track(self) -> None:
        self._tracking = True

    def read(self, size: int = -1) -> bytes:
        pos = self.tell()
        end = pos + (size if size and size > 0 else 0)
        if self._tracking and pos < self._region_end and end > self._region_start:
            self.region_reads += 1
        return super().read(size)


def _inode_record_span(fs: ExtFS, inum: int) -> tuple[int, int]:
    group, index = divmod(inum - 1, fs.sb.s_inodes_per_group)
    group_desc = fs._read_group_desc(group)
    if fs._group_desc_struct.__name__ == "ext4_group_desc":
        table_block = (group_desc.bg_inode_table_hi << 32) | group_desc.bg_inode_table_lo
    else:
        table_block = group_desc.bg_inode_table_lo
    start = table_block * fs.block_size + index * fs.sb.s_inode_size
    return start, fs.sb.s_inode_size


def test_hardlink_entries_have_independent_names(ext4_hardlink_bin: BinaryIO) -> None:
    fs = ExtFS(ext4_hardlink_bin)

    root_link = fs.get("test_file")
    sibling_link = fs.get("hardlink_name")
    nested_link = fs.get("lost+found/ll_hardlink")

    assert isinstance(root_link, DirectoryEntry)
    assert root_link.filename == "test_file"
    assert sibling_link.filename == "hardlink_name"
    assert nested_link.filename == "ll_hardlink"

    # Interleaved access through the three paths must never cross names.
    for _ in range(5):
        assert root_link.filename == "test_file"
        assert sibling_link.filename == "hardlink_name"
        assert nested_link.filename == "ll_hardlink"
        assert root_link.size == sibling_link.size == nested_link.size == 26


def test_hardlinks_share_one_cached_inode(ext4_hardlink_bin: BinaryIO) -> None:
    fs = ExtFS(ext4_hardlink_bin)

    root_link = fs.get("test_file")
    sibling_link = fs.get("hardlink_name")
    nested_link = fs.get("lost+found/ll_hardlink")
    bare_inode = fs.get_inode(13)

    assert isinstance(bare_inode, INode)
    assert root_link.inode is sibling_link.inode
    assert sibling_link.inode is nested_link.inode
    assert nested_link.inode is bare_inode
    assert fs.get(13) is bare_inode

    # cstruct uint32 inode numbers must still resolve to the same cache key.
    direntry_inum = next(entry.inum for entry in fs.root.iterdir() if entry.filename == "test_file")
    assert fs.get_inode(direntry_inum) is bare_inode


def test_shared_inode_reads_disk_record_once(ext4_hardlink_bin: BinaryIO) -> None:
    raw = ext4_hardlink_bin.read()
    probe = ExtFS(io.BytesIO(raw))
    start, size = _inode_record_span(probe, 13)

    fh = _CountingBytesIO(raw, start, size)
    fs = ExtFS(fh)
    fh.track()

    paths = [
        fs.get("test_file"),
        fs.get("hardlink_name"),
        fs.get("lost+found/ll_hardlink"),
    ]

    # Parsing the on-disk inode record through every path costs one disk read.
    for entry in paths:
        assert entry.inode.inode.i_mode is not None
    assert fs.get_inode(13).inode.i_mode is not None

    assert fh.region_reads == 1
    assert all(entry.open().read() == b"dissect test file in ext4\n" for entry in paths)


def test_bare_inode_has_no_filename(ext4_hardlink_bin: BinaryIO) -> None:
    fs = ExtFS(ext4_hardlink_bin)

    with pytest.raises(AttributeError):
        _ = fs.get_inode(13).filename


def test_get_inode_filename_argument_is_deprecated_and_ignored(ext4_hardlink_bin: BinaryIO) -> None:
    fs = ExtFS(ext4_hardlink_bin)

    with pytest.warns(DeprecationWarning):
        legacy = fs.get_inode(13, "some_name")

    assert legacy is fs.get_inode(13)
    with pytest.raises(AttributeError):
        _ = legacy.filename


def test_directory_entry_identity_and_equality(ext4_hardlink_bin: BinaryIO) -> None:
    fs = ExtFS(ext4_hardlink_bin)

    first = fs.get("test_file")
    second = fs.get("hardlink_name")

    assert first != second
    assert first.inode == second.inode
    assert hash(first.inode) == hash(second.inode)

    repeated = next(entry for entry in fs.root.iterdir() if entry.filename == "test_file")
    assert repeated == first
    assert hash(repeated) == hash(first)
    assert repeated is not first


def test_unlinked_entry_leaves_residual_references_intact(ext4_hardlink_bin: BinaryIO) -> None:
    raw = ext4_hardlink_bin.read()
    fs = ExtFS(io.BytesIO(raw))

    nested_link = fs.get("lost+found/ll_hardlink")
    surviving_link = fs.get("test_file")
    residual_inode = nested_link.inode

    lost_found = fs.get_inode(11)
    block = lost_found.dataruns()[0][0]
    block_offset = block * fs.block_size

    # Locate the ll_hardlink slot by walking the on-disk directory entries,
    # then zero its inode number to mark the slot free.
    offset = 0
    slot_offset = None
    while offset < lost_found.size - 12:
        inum, rec_len, name_len = struct.unpack_from("<IHB", raw, block_offset + offset)
        name = raw[block_offset + offset + 8 : block_offset + offset + 8 + name_len]
        if inum == 13 and name == b"ll_hardlink":
            slot_offset = block_offset + offset
            break
        offset += rec_len
    assert slot_offset is not None

    unlinked = bytearray(raw)
    struct.pack_into("<I", unlinked, slot_offset, 0)

    relinked_fs = ExtFS(io.BytesIO(bytes(unlinked)))
    remaining = [entry.filename for entry in relinked_fs.get("lost+found").iterdir()]
    assert remaining == [".", ".."]

    # References handed out before the unlink keep their name and shared inode.
    assert nested_link.filename == "ll_hardlink"
    assert nested_link.inum == 13
    assert nested_link.inode is residual_inode
    assert residual_inode is surviving_link.inode


def test_directory_entry_delegates_inode_attributes(ext4_bin: BinaryIO) -> None:
    fs = ExtFS(ext4_bin)

    entry = fs.get("test_file")
    assert entry.filetype == stat.S_IFREG
    assert entry.inum == 13
    assert entry.size == 26
    assert entry.open().read() == b"dissect test file in ext4\n"
    assert entry.inode is fs.get_inode(13)
    assert repr(entry) == "<directory_entry filename='test_file' inode=<inode 13>>"


def test_directory_entry_filetype_is_independent_per_entry(ext4_hardlink_bin: BinaryIO) -> None:
    fs = ExtFS(ext4_hardlink_bin)

    first = fs.get("test_file")
    second = fs.get("hardlink_name")

    # Both report the d_type stored on their own directory entry.
    assert first.filetype == stat.S_IFREG
    assert second.filetype == stat.S_IFREG

    # Mutating one entry's type hint never touches the shared inode or the
    # other hard link's entry.
    first._filetype = stat.S_IFDIR
    assert first.filetype == stat.S_IFDIR
    assert second.filetype == stat.S_IFREG
    assert fs.get_inode(13).filetype == stat.S_IFREG
    first._filetype = stat.S_IFREG


def test_directory_entry_without_dtype_falls_back_to_inode(ext4_bin: BinaryIO) -> None:
    fs = ExtFS(ext4_bin)

    # Old ext2 dirents carry no file_type byte, so the entry has no d_type.
    entry = DirectoryEntry(fs.get_inode(13), "old_style", None)
    assert entry._filetype is None
    assert entry.filetype == stat.S_IFREG


def test_root_is_a_directory_entry(ext4_bin: BinaryIO) -> None:
    fs = ExtFS(ext4_bin)
    assert isinstance(fs.root, DirectoryEntry)
    assert fs.root.filename == "/"
    assert fs.root.inum == 2


def test_legacy_exceptions_and_constructor_remain_compatible(ext4_hardlink_bin: BinaryIO) -> None:
    fs = ExtFS(ext4_hardlink_bin)

    with pytest.raises(Error):
        fs.get_inode(0)
    with pytest.raises(Error):
        fs.get_inode(fs.sb.s_inodes_count + 1)
    with pytest.raises(FileNotFoundError):
        fs.get("no/such/path")
    with pytest.raises(NotADirectoryError):
        next(fs.get_inode(13).iterdir())
    with pytest.raises(NotASymlinkError):
        _ = fs.get_inode(13).link

    direct = INode(fs, 13, filetype=stat.S_IFREG)
    assert direct.inum == 13
    assert direct.filetype == stat.S_IFREG
