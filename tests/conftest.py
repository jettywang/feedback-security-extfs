from __future__ import annotations

import gzip
import io
import struct
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

import pytest

from dissect.extfs.extfs import ExtFS

if TYPE_CHECKING:
    from collections.abc import Iterator


def absolute_path(filename: str) -> Path:
    return Path(__file__).parent / filename


def gzip_file(filename: str) -> Iterator[BinaryIO]:
    with gzip.GzipFile(absolute_path(filename), "rb") as fh:
        yield fh


def _add_hardlink(data: bytearray, fs: ExtFS, dir_inum: int, entry_offset: int, name: bytes, target_inum: int) -> None:
    """Split a directory entry's trailing rec_len to insert a hard link.

    The existing entry at ``entry_offset`` keeps its inode and name but gets a
    tight rec_len; a new entry referencing ``target_inum`` takes over the
    remainder of the record.
    """
    dir_inode = fs.get_inode(dir_inum)
    dir_block = dir_inode.dataruns()[0][0]
    block_offset = dir_block * fs.block_size + entry_offset

    filetype = data[block_offset + 7]
    old_rec_len = struct.unpack_from("<H", data, block_offset + 4)[0]
    new_rec_len = 8 + len(name)

    struct.pack_into("<H", data, block_offset + 4, new_rec_len)
    new_entry_offset = block_offset + new_rec_len
    struct.pack_into(
        "<IHBB",
        data,
        new_entry_offset,
        target_inum,
        old_rec_len - new_rec_len,
        len(name),
        filetype,
    )
    data[new_entry_offset + 8 : new_entry_offset + 8 + len(name)] = name


@pytest.fixture
def ext4_hardlink_bin() -> BinaryIO:
    """Ext4 image in which inode 13 (test_file) has three named hard links.

    The links live in two directories:
        - /test_file and /hardlink_name in the root directory
        - /lost+found/ll_hardlink in lost+found
    """
    with gzip.open(absolute_path("data/ext4.bin.gz"), "rb") as fh:
        data = bytearray(fh.read())

    fs = ExtFS(io.BytesIO(bytes(data)))
    _add_hardlink(data, fs, 2, 68, b"hardlink_name", 13)
    _add_hardlink(data, fs, 11, 12, b"ll_hardlink", 13)

    return io.BytesIO(bytes(data))


@pytest.fixture
def ext4_bin() -> Iterator[BinaryIO]:
    yield from gzip_file("data/ext4.bin.gz")


@pytest.fixture
def ext4_sparse_bin() -> Iterator[BinaryIO]:
    yield from gzip_file("data/ext4_sparse.bin.gz")


@pytest.fixture
def ext4_symlink_bin() -> Iterator[BinaryIO]:
    yield from gzip_file("data/ext4_symlink_test.bin.gz")
