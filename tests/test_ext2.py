from __future__ import annotations

import io
import stat
import struct
from typing import TYPE_CHECKING

import pytest

from dissect.extfs.c_ext import c_ext
from dissect.extfs.exceptions import MissingDataError
from dissect.extfs.extfs import ExtFS, _slice_runs

if TYPE_CHECKING:
    from collections.abc import Iterator

BLOCK_SIZE = 1024
PTRS_PER_BLOCK = BLOCK_SIZE // 4

DIRECT_BLOCKS = c_ext.EXT2_NDIR_BLOCKS
SINGLE_START = DIRECT_BLOCKS
DOUBLE_START = SINGLE_START + PTRS_PER_BLOCK
TRIPLE_START = DOUBLE_START + PTRS_PER_BLOCK**2

INUM = 12
SPARSE_INUM = 13

FILE_SIZE = (TRIPLE_START + 3) * BLOCK_SIZE + 123
SPARSE_FILE_SIZE = (TRIPLE_START + 2) * BLOCK_SIZE

# Logical block number -> image block number for the regular file
DATA_BLOCKS = {
    **{logical: 100 + logical for logical in range(DIRECT_BLOCKS)},
    SINGLE_START: 112,
    SINGLE_START + 1: 113,
    SINGLE_START + 255: 114,
    DOUBLE_START: 115,
    DOUBLE_START + 1: 116,
    DOUBLE_START + 255 * PTRS_PER_BLOCK + 255: 117,
    TRIPLE_START: 118,
    TRIPLE_START + 1: 119,
    TRIPLE_START + 2: 120,
}

# Logical block number -> image block number for the (mostly sparse) zero-pointer file
SPARSE_DATA_BLOCKS = {
    0: 130,
    DOUBLE_START + PTRS_PER_BLOCK: 121,
}

# Image block number -> {entry index: target block} for all indirect blocks
INDIRECT_BLOCKS = {
    200: {0: 112, 1: 113, 255: 114},  # single indirect
    201: {0: 202, 255: 203},  # double indirect
    202: {0: 115, 1: 116},
    203: {255: 117},
    204: {0: 205},  # triple indirect
    205: {0: 206},
    206: {0: 118, 1: 119, 2: 120},
    207: {1: 208},  # double indirect of the sparse file, entry 0 is a null pointer
    208: {0: 121},
}


def block_pattern(logical_block: int) -> bytes:
    return logical_block.to_bytes(4, "little") * (BLOCK_SIZE // 4)


def build_image(truncate_block: int | None = None, dense: bool = False) -> bytes:
    total_blocks = 1024
    image = bytearray(total_blocks * BLOCK_SIZE)

    sb = c_ext.ext4_super_block()
    sb.s_inodes_count = 64
    sb.s_blocks_count_lo = total_blocks
    sb.s_first_data_block = 1
    sb.s_log_block_size = 0
    sb.s_log_cluster_size = 0
    sb.s_blocks_per_group = 8192
    sb.s_clusters_per_group = 8192
    sb.s_inodes_per_group = 64
    sb.s_magic = c_ext.EXT2_FS_MAGIC
    sb.s_inode_size = 128
    image[c_ext.EXT2_SBOFF : c_ext.EXT2_SBOFF + len(sb.dumps())] = sb.dumps()

    group_desc = c_ext.ext2_group_desc()
    group_desc.bg_block_bitmap_lo = 3
    group_desc.bg_inode_bitmap_lo = 4
    group_desc.bg_inode_table_lo = 5
    image[2048 : 2048 + len(group_desc.dumps())] = group_desc.dumps()

    def write_inode(inum: int, size: int, i_block: list[int]) -> None:
        inode = c_ext.ext4_inode()
        inode.i_mode = stat.S_IFREG | 0o644
        inode.i_links_count = 1
        inode.i_size_lo = size & 0xFFFFFFFF
        inode.i_size_high = size >> 32
        inode.i_block = struct.pack("<15I", *i_block)
        offset = 5 * BLOCK_SIZE + (inum - 1) * 128
        image[offset : offset + 128] = inode.dumps()[:128]

    write_inode(INUM, FILE_SIZE, [*range(100, 112), 200, 201, 204])
    write_inode(SPARSE_INUM, SPARSE_FILE_SIZE, [130, *([0] * 11), 0, 207, 0])

    indirect_blocks = dict(INDIRECT_BLOCKS)
    if dense:
        # Fully populate the single and double indirect trees with (zero-filled) blocks,
        # so that parsing the whole tree has to read every indirect block
        indirect_blocks[200] = {**indirect_blocks[200], **{index: 218 + index for index in range(2, 255)}}
        indirect_blocks[201] = {**indirect_blocks[201], **{index: 479 + index for index in range(1, 255)}}

    for block, entries in indirect_blocks.items():
        table = [0] * PTRS_PER_BLOCK
        for index, target in entries.items():
            table[index] = target
        image[block * BLOCK_SIZE : (block + 1) * BLOCK_SIZE] = struct.pack(f"<{PTRS_PER_BLOCK}I", *table)

    for logical, block in {**DATA_BLOCKS, **SPARSE_DATA_BLOCKS}.items():
        image[block * BLOCK_SIZE : (block + 1) * BLOCK_SIZE] = block_pattern(logical)

    if truncate_block is not None:
        del image[truncate_block * BLOCK_SIZE :]

    return bytes(image)


def expected_content(data_blocks: dict[int, int], size: int) -> bytes:
    content = bytearray(size)
    for logical in data_blocks:
        start = logical * BLOCK_SIZE
        content[start : start + BLOCK_SIZE] = block_pattern(logical)
    return bytes(content)


class ReadCountingStream:
    """A stream wrapper that counts read calls and bytes read."""

    def __init__(self, fh: io.BytesIO):
        self._fh = fh
        self.reads = 0
        self.bytes_read = 0

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        return self._fh.seek(offset, whence)

    def tell(self) -> int:
        return self._fh.tell()

    def read(self, size: int = -1) -> bytes:
        data = self._fh.read(size)
        self.reads += 1
        self.bytes_read += len(data)
        return data

    def reset(self) -> None:
        self.reads = 0
        self.bytes_read = 0


@pytest.fixture(scope="module")
def image() -> bytes:
    return build_image()


@pytest.fixture(scope="module")
def expected() -> bytes:
    return expected_content(DATA_BLOCKS, FILE_SIZE)


@pytest.fixture(scope="module")
def expected_sparse() -> bytes:
    return expected_content(SPARSE_DATA_BLOCKS, SPARSE_FILE_SIZE)


@pytest.fixture
def extfs(image: bytes) -> ExtFS:
    return ExtFS(io.BytesIO(image))


def test_full_extraction(extfs: ExtFS, expected: bytes, expected_sparse: bytes) -> None:
    inode = extfs.get_inode(INUM)
    assert inode.size == FILE_SIZE
    assert inode.open().read() == expected

    sparse_inode = extfs.get_inode(SPARSE_INUM)
    assert sparse_inode.size == SPARSE_FILE_SIZE
    assert sparse_inode.open().read() == expected_sparse


def test_dataruns_semantics_preserved(extfs: ExtFS) -> None:
    inode = extfs.get_inode(INUM)

    full = inode.dataruns()
    assert inode.dataruns() is full
    assert inode.dataruns(0, FILE_SIZE) == full
    assert inode.dataruns(0) == full

    # A range covering the whole file read through the range API matches a sequential read
    assert inode.open(0, FILE_SIZE).read() == inode.open().read()


RANGES = [
    (0, 100),  # direct blocks
    (11 * BLOCK_SIZE + 500, 2000),  # crossing direct -> single indirect
    (12 * BLOCK_SIZE, 2048),  # single indirect
    (14 * BLOCK_SIZE, 4096),  # sparse hole inside single indirect
    (268 * BLOCK_SIZE - 512, 1024),  # crossing single -> double indirect
    (268 * BLOCK_SIZE, 2048),  # double indirect
    (65803 * BLOCK_SIZE, 1024),  # last block covered by double indirect
    (65804 * BLOCK_SIZE - 512, 1024),  # crossing double -> triple indirect
    (65804 * BLOCK_SIZE, 3072),  # triple indirect
    (FILE_SIZE - 200, 200),  # tail, crossing into a sparse partial block
    (FILE_SIZE - 123, 200),  # clamped beyond EOF
    (FILE_SIZE, 100),  # empty, at EOF
    (FILE_SIZE + 5000, 100),  # empty, beyond EOF
    (1000, 0),  # empty, zero size
]


@pytest.mark.parametrize(("offset", "size"), RANGES)
def test_range_reads(extfs: ExtFS, expected: bytes, offset: int, size: int) -> None:
    inode = extfs.get_inode(INUM)
    assert inode.open(offset, size).read() == expected[offset : offset + size]


@pytest.mark.parametrize("offset", [0, 14 * BLOCK_SIZE, 268 * BLOCK_SIZE, 65804 * BLOCK_SIZE])
def test_range_reads_to_eof(extfs: ExtFS, expected: bytes, offset: int) -> None:
    inode = extfs.get_inode(INUM)
    assert inode.open(offset).read() == expected[offset:]


def test_ranged_dataruns_match_full_dataruns(extfs: ExtFS) -> None:
    inode = extfs.get_inode(INUM)
    full = inode.dataruns()

    for offset, size in RANGES:
        runs = inode.dataruns(offset, size)
        end = min(FILE_SIZE, offset + size)
        if end <= offset:
            assert runs == []
            continue

        first_block = offset // BLOCK_SIZE
        num_blocks = (end - 1) // BLOCK_SIZE - first_block + 1
        assert runs == _slice_runs(full, first_block, num_blocks)


def test_range_read_is_lazy(image: bytes, expected: bytes) -> None:
    stream = ReadCountingStream(io.BytesIO(image))
    extfs = ExtFS(stream)
    inode = extfs.get_inode(INUM)

    # Read the last 4K of a ~67M file living in the triple indirect region
    stream.reset()
    data = inode.open(FILE_SIZE - 4096, 4096).read()
    assert data == expected[FILE_SIZE - 4096 :]

    # Only the inode, the indirect blocks on the path and the data blocks may be read.
    # Expanding the whole file would take ~65k block reads and ~67M of reads.
    assert stream.reads <= 12
    assert stream.bytes_read <= 16 * BLOCK_SIZE

    # A single block in the double indirect region only walks the path to that block
    stream.reset()
    assert inode.open(268 * BLOCK_SIZE, BLOCK_SIZE).read() == expected[268 * BLOCK_SIZE : 269 * BLOCK_SIZE]
    assert stream.reads <= 12
    assert stream.bytes_read <= 16 * BLOCK_SIZE


def test_range_read_does_not_expand_dense_tree(expected: bytes) -> None:
    # Same file, but with fully populated single and double indirect trees
    stream = ReadCountingStream(io.BytesIO(build_image(dense=True)))
    extfs = ExtFS(stream)
    inode = extfs.get_inode(INUM)

    # Parsing the whole tree has to walk every populated indirect block
    stream.reset()
    inode.dataruns()
    assert stream.reads > 100

    # A ranged read only walks the path to the requested blocks
    stream.reset()
    assert inode.open(600 * BLOCK_SIZE, BLOCK_SIZE).read() == b"\x00" * BLOCK_SIZE
    assert stream.reads <= 12
    assert stream.bytes_read <= 16 * BLOCK_SIZE

    # The dense tree still extracts to the exact same content
    assert inode.open().read() == expected


def test_zero_pointers(extfs: ExtFS, expected_sparse: bytes) -> None:
    inode = extfs.get_inode(SPARSE_INUM)

    # Null single indirect pointer
    assert inode.open(SINGLE_START * BLOCK_SIZE, 2048).read() == b"\x00" * 2048
    assert inode.dataruns(SINGLE_START * BLOCK_SIZE, BLOCK_SIZE) == [(None, 1)]

    # Null entry inside the double indirect block
    assert inode.open(DOUBLE_START * BLOCK_SIZE, BLOCK_SIZE).read() == b"\x00" * BLOCK_SIZE

    # Real block behind the second double indirect entry
    offset = (DOUBLE_START + PTRS_PER_BLOCK) * BLOCK_SIZE
    assert inode.open(offset, BLOCK_SIZE).read() == block_pattern(DOUBLE_START + PTRS_PER_BLOCK)

    # Null triple indirect pointer
    assert inode.open(TRIPLE_START * BLOCK_SIZE, 2048).read() == b"\x00" * 2048
    assert inode.dataruns(TRIPLE_START * BLOCK_SIZE, BLOCK_SIZE) == [(None, 1)]

    assert inode.open().read() == expected_sparse


def test_missing_indirect_block_reports_interval() -> None:
    # The level 1 indirect block in the triple indirect region (block 206) is missing
    extfs = ExtFS(io.BytesIO(build_image(truncate_block=206)))
    inode = extfs.get_inode(INUM)

    offset = TRIPLE_START * BLOCK_SIZE
    size = 3 * BLOCK_SIZE + 123
    with pytest.raises(MissingDataError) as excinfo:
        inode.open(offset, size).read()
    assert excinfo.value.missing == [(offset, size)]

    with pytest.raises(MissingDataError) as excinfo:
        inode.dataruns(offset, size)
    assert excinfo.value.missing == [(offset, size)]


def test_missing_indirect_blocks_report_disjoint_intervals() -> None:
    # Everything from block 202 onwards is missing, i.e. both level 1 blocks of the
    # double indirect region, but not the double indirect block itself (block 201)
    extfs = ExtFS(io.BytesIO(build_image(truncate_block=202)))
    inode = extfs.get_inode(INUM)

    offset = DOUBLE_START * BLOCK_SIZE
    size = TRIPLE_START * BLOCK_SIZE - offset
    with pytest.raises(MissingDataError) as excinfo:
        inode.dataruns(offset, size)
    assert excinfo.value.missing == [
        (DOUBLE_START * BLOCK_SIZE, PTRS_PER_BLOCK * BLOCK_SIZE),
        ((DOUBLE_START + 255 * PTRS_PER_BLOCK) * BLOCK_SIZE, PTRS_PER_BLOCK * BLOCK_SIZE),
    ]

    # A full dataruns() call on an incomplete image reports the missing intervals as well.
    # The last two intervals are adjacent and reported as one merged interval.
    merged_offset = (DOUBLE_START + 255 * PTRS_PER_BLOCK) * BLOCK_SIZE
    with pytest.raises(MissingDataError) as excinfo:
        inode.dataruns()
    assert excinfo.value.missing == [
        (DOUBLE_START * BLOCK_SIZE, PTRS_PER_BLOCK * BLOCK_SIZE),
        (merged_offset, FILE_SIZE - merged_offset),
    ]
