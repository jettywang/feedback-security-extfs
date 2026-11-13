from __future__ import annotations

import io
import random
from dataclasses import dataclass
from typing import BinaryIO

from dissect.extfs.c_ext import c_ext
from dissect.extfs.extfs import ExtFS


BS = 1024
INODE_SIZE = 256
N_INODES = 16
TARGET_INO = 12


@dataclass
class Extent:
    logical: int
    length: int
    uninit: bool
    phys: int


def _ext_hdr(entries: int, depth: int, maxv: int = 4) -> bytes:
    return c_ext.ext4_extent_header(
        eh_magic=0xF30A, eh_entries=entries, eh_max=maxv, eh_depth=depth, eh_generation=0
    ).dumps()


def _extent(logical: int, length: int, phys: int, uninit: bool) -> bytes:
    ee_len = length + (0x8000 if uninit else 0)
    return c_ext.ext4_extent(
        ee_block=logical,
        ee_len=ee_len,
        ee_start_hi=(phys >> 32) & 0xFFFF,
        ee_start_lo=phys & 0xFFFFFFFF,
    ).dumps()


def _idx(logical: int, leaf: int) -> bytes:
    return c_ext.ext4_extent_idx(
        ei_block=logical,
        ei_leaf_hi=(leaf >> 32) & 0xFFFF,
        ei_leaf_lo=leaf & 0xFFFFFFFF,
        ei_unused=0,
    ).dumps()


def _dirent(inum: int, name: str, ftype: int, rec_len: int) -> bytes:
    raw = name.encode()
    entry = c_ext.ext2_dir_entry_2(inode=inum, rec_len=rec_len, name_len=len(raw), file_type=ftype).dumps()
    blob = entry + raw
    return blob + b"\x00" * (rec_len - len(blob))


def build_image(leaf1: list[Extent], leaf2: list[Extent], tail_bytes: int) -> tuple[bytes, int, int]:
    """Build a minimal ext4 image whose single target inode has a depth-1 extent tree.

    The uninitialized segment must span both leaves. Physical blocks backing uninitialized
    extents are filled with non-zero garbage so leakage is detectable.
    """
    extents = leaf1 + leaf2
    file_blocks = max(e.logical + e.length for e in extents)
    file_size = (file_blocks - 1) * BS + tail_bytes

    # Fixed metadata locations
    b_gd, b_bmap, b_imap, b_itable = 2, 3, 4, 5
    itable_blocks = (N_INODES * INODE_SIZE + BS - 1) // BS
    cursor = b_itable + itable_blocks
    b_eidx = cursor
    cursor += 1
    b_leaf1 = cursor
    cursor += 1
    b_leaf2 = cursor
    cursor += 1

    # Assign physical data blocks per extent
    garbage_blocks: list[int] = []
    for extent in extents:
        extent.phys = cursor
        if extent.uninit:
            garbage_blocks.extend(range(cursor, cursor + extent.length))
        cursor += extent.length
    b_rootdir = cursor
    total_blocks = b_rootdir + 8

    img = bytearray(total_blocks * BS)

    def wblk(block: int, data: bytes) -> None:
        img[block * BS : (block + 1) * BS] = data[:BS].ljust(BS, b"\x00")

    sb = c_ext.ext4_super_block()
    sb.s_inodes_count = N_INODES
    sb.s_blocks_count_lo = total_blocks
    sb.s_free_blocks_count_lo = 1
    sb.s_free_inodes_count = N_INODES - 2
    sb.s_first_data_block = 0
    sb.s_log_block_size = 0
    sb.s_log_cluster_size = 0
    sb.s_blocks_per_group = total_blocks
    sb.s_clusters_per_group = total_blocks
    sb.s_inodes_per_group = N_INODES
    sb.s_magic = c_ext.EXT2_FS_MAGIC
    sb.s_state = 1
    sb.s_rev_level = 1
    sb.s_inode_size = INODE_SIZE
    sb.s_feature_incompat = (
        c_ext.EXT4_FEATURE_INCOMPAT_EXTENTS | c_ext.EXT2_FEATURE_INCOMPAT_FILETYPE | c_ext.EXT4_FEATURE_INCOMPAT_64BIT
    )
    sb.s_feature_ro_compat = c_ext.EXT4_FEATURE_RO_COMPAT_EXTRA_ISIZE
    sb.s_desc_size = 64
    sb.s_min_extra_isize = 28
    sb.s_want_extra_isize = 28
    wblk(1, sb.dumps())

    gd = c_ext.ext4_group_desc()
    gd.bg_block_bitmap_lo = b_bmap
    gd.bg_inode_bitmap_lo = b_imap
    gd.bg_inode_table_lo = b_itable
    gd.bg_free_inodes_count_lo = N_INODES - 2
    gd.bg_used_dirs_count_lo = 1
    wblk(b_gd, gd.dumps())

    bmap = bytearray(BS)
    for block in range(b_itable, b_rootdir + 1):
        bmap[block // 8] |= 1 << (block % 8)
    wblk(b_bmap, bytes(bmap))
    imap = bytearray(BS)
    for ino in (2, TARGET_INO):
        imap[(ino - 1) // 8] |= 1 << ((ino - 1) % 8)
    wblk(b_imap, bytes(imap))

    # Distinctive non-zero garbage in every preallocated (uninitialized) physical block
    for marker, block in enumerate(garbage_blocks):
        wblk(block, bytes([(0x80 + marker) & 0xFF]) * BS)

    # Initialized payload
    for extent in extents:
        if extent.uninit:
            continue
        for i in range(extent.length):
            logical = extent.logical + i
            payload = bytes([(logical * 31 + j) & 0xFF for j in range(BS)])
            if logical == file_blocks - 1:
                payload = payload[:tail_bytes]
            wblk(extent.phys + i, payload)

    # Extent tree
    root_iblock = _ext_hdr(2, depth=1) + _idx(leaf1[0].logical, b_leaf1) + _idx(leaf2[0].logical, b_leaf2)
    wblk(b_eidx, root_iblock)

    def leaf_bytes(leaf: list[Extent]) -> bytes:
        out = _ext_hdr(len(leaf), depth=0)
        for extent in leaf:
            out += _extent(extent.logical, extent.length, extent.phys, extent.uninit)
        return out

    wblk(b_leaf1, leaf_bytes(leaf1))
    wblk(b_leaf2, leaf_bytes(leaf2))

    # Inode table
    table = bytearray(itable_blocks * BS)

    def put_inode(inum: int, blob: bytes) -> None:
        off = (inum - 1) * INODE_SIZE
        table[off : off + INODE_SIZE] = blob.ljust(INODE_SIZE, b"\x00")

    root = c_ext.ext4_inode()
    root.i_mode = 0o40755
    root.i_size_lo = BS
    root.i_blocks_lo = 2
    root.i_flags = c_ext.EXT4_EXTENTS_FL
    root.i_links_count = 1
    root.i_block = (_ext_hdr(1, depth=0) + _extent(0, 1, b_rootdir, False)).ljust(60, b"\x00")
    root.i_extra_isize = 28
    put_inode(2, root.dumps())

    target = c_ext.ext4_inode()
    target.i_mode = 0o100644
    target.i_size_lo = file_size & 0xFFFFFFFF
    target.i_size_high = file_size >> 32
    target.i_blocks_lo = 2 * (sum(e.length for e in extents) + 3)
    target.i_flags = c_ext.EXT4_EXTENTS_FL
    target.i_links_count = 1
    target.i_block = root_iblock.ljust(60, b"\x00")
    target.i_extra_isize = 28
    put_inode(TARGET_INO, target.dumps())

    for i in range(itable_blocks):
        wblk(b_itable + i, bytes(table[i * BS : (i + 1) * BS]))

    # Root directory
    dot = _dirent(2, ".", 2, 12)
    dotdot = _dirent(2, "..", 2, 12)
    target_rec = BS - len(dot) - len(dotdot)
    wblk(b_rootdir, dot + dotdot + _dirent(TARGET_INO, "target", 1, target_rec))

    return bytes(img), file_blocks, file_size


def expected_content(extents: list[Extent], file_blocks: int, file_size: int, tail_bytes: int) -> bytes:
    logical_phys = {}
    uninit_blocks = set()
    for extent in extents:
        for i in range(extent.length):
            logical = extent.logical + i
            if extent.uninit:
                uninit_blocks.add(logical)
            else:
                logical_phys[logical] = (extent.phys, i)

    out = bytearray()
    for logical in range(file_blocks):
        if logical in uninit_blocks or logical not in logical_phys:
            out += b"\x00" * BS
        else:
            phys, i = logical_phys[logical]
            out += bytes([(logical * 31 + j) & 0xFF for j in range(BS)])
    return bytes(out[:file_size])


def expected_runlist(extents: list[Extent], file_blocks: int) -> list[tuple[int | None, int]]:
    runs = []
    run_offset = 0
    for extent in extents:
        if extent.logical != run_offset:
            gap = extent.logical - run_offset
            runs.append((None, gap))
            run_offset += gap
        if extent.uninit:
            runs.append((None, extent.length))
        else:
            runs.append((extent.phys, extent.length))
        run_offset += extent.length
    if run_offset < file_blocks:
        runs.append((None, file_blocks - run_offset))
    return runs


def _open(img: bytes) -> tuple[ExtFS, BinaryIO]:
    fh = io.BytesIO(img)
    return ExtFS(fh), fh


# Layout 1: leading sparse hole, uninitialized segment split across leaves, partial tail.
def test_uninitialized_extent_split_with_leading_hole() -> None:
    leaf1 = [Extent(logical=4, length=2, uninit=True, phys=0)]
    leaf2 = [
        Extent(logical=6, length=2, uninit=True, phys=0),
        Extent(logical=8, length=5, uninit=False, phys=0),
    ]
    tail = 300
    img, file_blocks, file_size = build_image(leaf1, leaf2, tail)
    extents = leaf1 + leaf2
    expected = expected_content(extents, file_blocks, file_size, tail)

    fs, _ = _open(img)
    node = fs.get("/target")
    assert node.size == file_size
    assert node.dataruns() == expected_runlist(extents, file_blocks)

    data = node.open().read()
    assert data == expected
    assert len(data) == file_size

    # Uninitialized logical region must read back as zero, never stale physical data
    assert node.open().readoffset(4 * BS, 4 * BS) == b"\x00" * (4 * BS)

    rnd = random.Random(0xC0FFEE)
    stream = node.open()
    for _ in range(300):
        pos = rnd.randrange(file_size)
        length = rnd.randrange(1, max(2, file_size - pos))
        stream.seek(pos)
        assert stream.read(length) == expected[pos : pos + length]


# Layout 3: a gap *between* two uninitialized extents, with the physical (initialized) run
# last. The old logic ignored ee_block on uninitialized extents and collapsed the internal
# gap, which shifted the trailing physical run forward and surfaced preallocated-block data
# inside the file body.
def test_gap_between_uninitialized_extents_keeps_physical_run_in_place() -> None:
    leaf1 = [Extent(logical=4, length=2, uninit=True, phys=0)]
    leaf2 = [
        Extent(logical=8, length=2, uninit=True, phys=0),
        Extent(logical=10, length=2, uninit=False, phys=0),
    ]
    tail = 137
    img, file_blocks, file_size = build_image(leaf1, leaf2, tail)
    extents = leaf1 + leaf2
    expected = expected_content(extents, file_blocks, file_size, tail)

    fs, _ = _open(img)
    node = fs.get("/target")
    assert node.size == file_size
    assert node.dataruns() == expected_runlist(extents, file_blocks)

    data = node.open().read()
    assert data == expected

    # Hole 0..3, internal gap 6..7 and the uninitialized region 4..5 / 8..9 read as zeros
    stream = node.open()
    for start, count in ((0, 4), (6, 2), (8, 2)):
        assert stream.readoffset(start * BS, count * BS) == b"\x00" * (count * BS)

    # The physical run must stay anchored at logical block 10, not shift forward
    phys_phys = next(e.phys for e in extents if not e.uninit)
    assert node.dataruns()[-1] == (phys_phys, 2)
    assert node.open().readoffset(10 * BS, 2 * BS) == expected[10 * BS : 12 * BS]

    rnd = random.Random(0x5EED1234)
    seek_stream = node.open()
    for _ in range(300):
        pos = rnd.randrange(file_size)
        length = rnd.randrange(1, max(2, file_size - pos))
        seek_stream.seek(pos)
        assert seek_stream.read(length) == expected[pos : pos + length]


# Layout 2: non-zero logical start, an internal gap before the cross-leaf uninit segment,
# and a partial final block.
def test_uninitialized_extent_after_internal_gap() -> None:
    leaf1 = [
        Extent(logical=2, length=2, uninit=False, phys=0),
        Extent(logical=7, length=2, uninit=True, phys=0),
    ]
    leaf2 = [
        Extent(logical=9, length=2, uninit=True, phys=0),
        Extent(logical=11, length=3, uninit=False, phys=0),
    ]
    tail = 200
    img, file_blocks, file_size = build_image(leaf1, leaf2, tail)
    extents = leaf1 + leaf2
    expected = expected_content(extents, file_blocks, file_size, tail)

    fs, _ = _open(img)
    node = fs.get("/target")
    assert node.size == file_size
    assert node.dataruns() == expected_runlist(extents, file_blocks)

    data = node.open().read()
    assert data == expected

    # Hole (0..1, 4..6) and uninitialized region (7..10) all read as zeros
    stream = node.open()
    for start, count in ((0, 2), (4, 3), (7, 4)):
        assert stream.readoffset(start * BS, count * BS) == b"\x00" * (count * BS)

    rnd = random.Random(0xBADF00D)
    seek_stream = node.open()
    for _ in range(300):
        pos = rnd.randrange(file_size)
        length = rnd.randrange(1, max(2, file_size - pos))
        seek_stream.seek(pos)
        assert seek_stream.read(length) == expected[pos : pos + length]
