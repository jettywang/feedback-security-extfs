"""
Minimal, hand-crafted ext4 image builder for inline_data diagnostics.

Layout (1024-byte blocks, 256-byte inodes, one block group, 16 blocks):
  block 0 : boot
  block 1 : superblock
  block 2 : group descriptor(s)
  block 3 : reserved GDT
  block 4 : block bitmap
  block 5 : inode bitmap
  block 6..: inode table (4 blocks x 4 inodes = 16 inodes)
  block 10: root dir block (inode 2)
The parser only needs: valid superblock, one group descriptor, reachable inode
table and a root directory it can iterdir(). Everything else is minimal.
"""
import struct

BLOCK = 1024
INODE_SIZE = 256
N_INODES = 32
N_BLOCKS = 16
EXT4_INLINE_DATA_FL = 0x10000000
EXT4_EXTENTS_FL = 0x080000
EXT4_XATTR_MAGIC = 0xEA020000
TS = 1700000000  # fixed timestamp for reproducibility

# inode numbers
INO_ROOT = 2
INO_FILL = 12        # exactly fills i_block (60)
INO_SPILL61 = 13     # 1 byte overflow -> system.data
INO_SPILL100 = 14    # 40 bytes overflow -> system.data
INO_LINK = 15        # short symlink (<60), no inline flag
INO_CORRUPT = 16     # inline + xattr, caller decides corruption flavour


def pad(b, n):
    return b + b"\x00" * (n - len(b))


def superblock():
    b = bytearray(1024)
    def w(off, fmt, *v):
        struct.pack_into("<" + fmt, b, off, *v)
    w(0x00, "I", N_INODES)                 # s_inodes_count
    w(0x04, "I", N_BLOCKS)                 # s_blocks_count_lo
    w(0x08, "I", 0)                        # s_r_blocks_count_lo
    w(0x0C, "I", 0)                        # s_free_blocks_count_lo
    w(0x10, "I", 0)                        # s_free_inodes_count
    w(0x14, "I", 1)                        # s_first_data_block
    w(0x18, "I", 0)                        # s_log_block_size (1024)
    w(0x1C, "I", 0)                        # s_log_cluster_size
    w(0x20, "I", 8)                        # s_blocks_per_group
    w(0x24, "I", 8)                        # s_clusters_per_group
    w(0x28, "I", N_INODES)                 # s_inodes_per_group
    w(0x2C, "I", TS)                       # s_mtime
    w(0x30, "I", TS)                       # s_wtime
    w(0x34, "H", 1)                        # s_mnt_count
    w(0x36, "H", 0xFFFF)                   # s_max_mnt_count
    w(0x38, "H", 0xEF52 & 0xFFFF)          # placeholder, fixed below
    struct.pack_into("<H", b, 0x38, 0xEF53)  # s_magic
    w(0x3A, "H", 1)                        # s_state (clean)
    w(0x3C, "H", 1)                        # s_errors (continue)
    w(0x3E, "H", 0)                        # s_minor_rev_level
    w(0x40, "I", TS)                       # s_lastcheck
    w(0x44, "I", 0)                        # s_checkinterval
    w(0x48, "I", 0)                        # s_creator_os (linux)
    w(0x4C, "I", 1)                        # s_rev_level (dynamic)
    w(0x50, "H", 0)                        # s_def_resuid
    w(0x52, "H", 0)                        # s_def_resgid
    w(0x54, "I", 11)                       # s_first_ino
    w(0x58, "H", INODE_SIZE)              # s_inode_size
    w(0x5A, "H", 0)                        # s_block_group_nr
    # Feature flags. On real ext4 media the order is compat(0x5C), ro_compat(0x60),
    # incompat(0x64), but dissect's c_ext.py declares them as compat, incompat, ro_compat,
    # so cstruct lays them out at 0x5C, 0x60, 0x64 in THAT order. Write where the parser
    # under test actually reads from, otherwise the image cannot be opened by this build
    # of dissect. Keep real-ext4 semantics in the values themselves.
    w(0x5C, "I", 0x0008)                   # s_feature_compat: EXT_ATTR
    w(0x60, "I", 0x8000 | 0x0040 | 0x0002) # parsed as s_feature_incompat: INLINE|EXTENTS|FILETYPE
    w(0x64, "I", 0x0000)                   # parsed as s_feature_ro_compat: none
    w(0x68, "16s", b"\x11" * 16)           # s_uuid
    w(0x78, "16s", b"vol")                # s_volume_name
    w(0x88, "64s", b"/mnt")               # s_last_mounted
    struct.pack_into("<IBBH", b, 0xC8,     # s_algorithm_usage_bitmap(u32), prealloc blocks(2xu8),
                     0, 0, 0, 0)           # s_reserved_gdt_blocks(u16)
    w(0xD4, "H", 32)                       # s_desc_size (>=32, 64bit flag off -> ext2 desc used)
    w(0xD8, "I", 0)                        # s_default_mount_opts
    w(0xDC, "I", 0)                        # s_first_meta_bg
    w(0xE0, "I", TS)                       # s_mkfs_time
    w(0x100, "H", 28)                      # s_min_extra_isize
    w(0x102, "H", 28)                      # s_want_extra_isize
    return bytes(b)


def group_desc(inode_table_block, block_bm=4, inode_bm=5):
    # ext2_group_desc, 32 bytes
    return struct.pack("<IIIHHH I12s",
                       block_bm, inode_bm, inode_table_block,
                       0, 0, 0, 0, b"\x00" * 12)


def extent_header(entries=1, depth=0, magic=0xF30A):
    return struct.pack("<HHHHI", magic, entries, 4, depth, 0)


def extent0(start_block):
    # ee_block, ee_len, ee_start_hi, ee_start_lo
    return struct.pack("<IHHI", 0, 1, 0, start_block)


def inode(mode, size, i_block, flags=0, ibody_region=b"", acl_lo=0, links=1):
    """Pack a 256-byte ext4 inode (128-byte base + 128-byte tail).
    The ibody xattr region (magic + entries/values) is placed at tail offset 32,
    i.e. inode offset 160: this build of dissect maps the cstruct char[] i_extra
    there regardless of i_extra_isize. Region is fixed at 96 bytes and zero-padded.
    """
    i_block = pad(i_block, 60)
    ibody_region = pad(ibody_region, IBODY_REGION_SIZE)
    head = struct.pack(
        "<HHIIIIIHHIII60sIIIIHHHHHH",
        mode, 0,                      # i_mode, i_uid
        size,                         # i_size_lo
        TS, TS, TS, 0,                # atime, ctime, mtime, dtime
        0, links,                     # i_gid, i_links_count
        0,                            # i_blocks_lo
        flags,                        # i_flags
        0,                            # i_reserved_1
        i_block,
        0,                            # i_generation
        acl_lo,                       # i_file_acl_lo
        0,                            # i_size_high
        0,                            # i_obso_faddr
        0, 0, 0, 0, 0, 0,             # blocks/file_acl high, uid/gid high, checksum_lo, reserved
    )
    assert len(head) == 128
    tail = bytearray(128)
    struct.pack_into("<HH", tail, 0, 28, 0)   # i_extra_isize, i_checksum_hi
    tail[32:32 + len(ibody_region)] = ibody_region  # lands at inode offset 160 = cstruct i_extra
    return head + bytes(tail)


def direntry(inum, name, rec_len, ftype):
    # ext2_dir_entry_2 header is 8 bytes (name is a flexible array read separately)
    name_b = name.encode()
    # <I H B B>: inode, rec_len, name_len, file_type, then flexible name
    return struct.pack("<IHBB", inum, rec_len, len(name_b), ftype) + name_b


def root_dir_block(entries):
    b = b""
    for inum, name, ftype, last in entries:
        base = 8 + len(name)
        if last:
            rec = BLOCK - len(b)
        else:
            rec = (base + 3) & ~3
        e = pad(direntry(inum, name, rec, ftype), rec)  # (inum, name, rec_len, ftype)
        b += e
    return pad(b, BLOCK)


def xattr_entry(name_index, name, value_offs, value_size, value_inum=0):
    nb = name.encode()
    head = struct.pack("<BBHIII", len(nb), name_index, value_offs, value_inum, value_size, 0) + nb
    # entries padded to 4
    return head + b"\x00" * ((4 - len(head) % 4) % 4)


IBODY_REGION_SIZE = 96   # cstruct maps i_extra at inode offset 160 (256-160)


def ibody(entries_with_values):
    """Build the 100-byte in-inode xattr region (dissect's i_extra).
    entries_with_values: list of (entry_bytes, value_bytes, e_value_offs)
    where e_value_offs is relative to IFIRST, i.e. region offset 4 (the
    convention used by both the kernel and dissect's _iter_xattr).
    Layout: 4-byte magic, entries grow upward; values grow down from the end.
    """
    region = bytearray(IBODY_REGION_SIZE)
    struct.pack_into("<I", region, 0, EXT4_XATTR_MAGIC)
    pos = 4
    for entry, value, voffs in entries_with_values:
        region[pos:pos + len(entry)] = entry
        pos += len(entry)
        region[4 + voffs:4 + voffs + len(value)] = value
    return bytes(region)


def build(corrupt_mode=None):
    img = bytearray(BLOCK * N_BLOCKS)

    def put(block, off, data):
        img[block * BLOCK + off: block * BLOCK + off + len(data)] = data

    put(1, 0, superblock())
    put(2, 0, group_desc(inode_table_block=6))

    # block bitmap (block 4): mark used blocks 0..10
    bm = bytearray(BLOCK)
    for blk in range(0, 11):
        bm[blk >> 3] |= 1 << (blk & 7)
    put(4, 0, bm)
    # inode bitmap (block 5): inodes 1..2 and 12..16 used
    ibm = bytearray(BLOCK)
    for ino in [1, 2, INO_FILL, INO_SPILL61, INO_SPILL100, INO_LINK, INO_CORRUPT]:
        bit = ino - 1
        ibm[bit >> 3] |= 1 << (bit & 7)
    put(5, 0, ibm)

    # ---- content patterns, every byte position identifiable ----
    fill60 = bytes((i % 251 + 1 for i in range(60)))
    spill61 = bytes((i % 251 + 1 for i in range(61)))
    spill100 = bytes((i % 251 + 1 for i in range(100)))
    link_target = b"../short/link/target"  # 20 bytes

    def ibody_for(data):
        # first 60 bytes live in i_block; remainder in system.data xattr
        value = data[60:]
        # value anchored at end of the 100-byte ibody region
        value_region_offs = IBODY_REGION_SIZE - len(value)
        voffs = value_region_offs - 4  # e_value_offs is relative to IFIRST
        entry = xattr_entry(7, "data", voffs, len(value))  # index 7 = system
        return ibody([(entry, value, voffs)])

    # root inode (2): extents, points at block 10
    root_iblock = extent_header() + extent0(10)
    root = inode(0o40755, BLOCK, root_iblock, flags=EXT4_EXTENTS_FL, links=3)

    inodes = {
        INO_ROOT: root,
        INO_FILL: inode(0o100644, 60, fill60, flags=EXT4_INLINE_DATA_FL),
        INO_SPILL61: inode(0o100644, 61, spill61[:60],
                           flags=EXT4_INLINE_DATA_FL, ibody_region=ibody_for(spill61)),
        INO_SPILL100: inode(0o100644, 100, spill100[:60],
                            flags=EXT4_INLINE_DATA_FL, ibody_region=ibody_for(spill100)),
        INO_LINK: inode(0o120777, len(link_target), link_target),  # no inline flag
        INO_CORRUPT: inode(0o100644, 100, spill100[:60],
                           flags=EXT4_INLINE_DATA_FL, ibody_region=ibody_for(spill100)),
    }

    # apply corruption flavour to inode 16's i_extra (inode offset 128..255)
    ibody_start = 160       # inode offset where cstruct maps i_extra / ibody magic
    if corrupt_mode == "bad_magic":
        raw = bytearray(inodes[INO_CORRUPT])
        struct.pack_into("<I", raw, ibody_start, 0xDEADBEEF)
        inodes[INO_CORRUPT] = bytes(raw)
    elif corrupt_mode == "bad_value_offs":
        raw = bytearray(inodes[INO_CORRUPT])
        # first entry at ibody+4; e_value_offs field at entry+2
        struct.pack_into("<H", raw, ibody_start + 4 + 2, 92)  # 4+92=96 -> 0 bytes readable
        inodes[INO_CORRUPT] = bytes(raw)
    elif corrupt_mode == "entry_erased":
        raw = bytearray(inodes[INO_CORRUPT])
        # zero the 16-byte system.data entry right after ibody magic
        raw[ibody_start + 4:ibody_start + 4 + 16] = b"\x00" * 16
        inodes[INO_CORRUPT] = bytes(raw)

    for ino, data in inodes.items():
        put(6, (ino - 1) * INODE_SIZE, pad(data, INODE_SIZE))

    # root directory in block 10
    # tuple: (inum, name, dirent file_type, is_last)
    dents = [
        (2, ".", 2, False),
        (2, "..", 2, False),
        (INO_FILL, "fill60", 1, False),
        (INO_SPILL61, "spill61", 1, False),
        (INO_SPILL100, "spill100", 1, False),
        (INO_LINK, "shortlink", 7, False),
        (INO_CORRUPT, "corrupt", 1, True),
    ]
    put(10, 0, root_dir_block(dents))

    return bytes(img), dict(fill60=fill60, spill61=spill61, spill100=spill100,
                            link_target=link_target)


if __name__ == "__main__":
    import sys
    mode = sys.argv[1] if len(sys.argv) > 1 else None
    img, payloads = build(mode)
    out = sys.argv[2] if len(sys.argv) > 2 else "inline.img"
    open(out, "wb").write(img)
    print("wrote", out, len(img), "corrupt_mode=", mode)
