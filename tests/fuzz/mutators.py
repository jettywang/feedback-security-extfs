"""Structure-aware mutators for ext2/ext4 seed images.

Each mutator modifies a *named* filesystem structure at its real on-disk offset
rather than flipping arbitrary bytes.  Mutations are deliberately correlated
with the image geometry: they touch superblock fields that drive group math,
group-descriptor block pointers, inode block maps and the nested children of
extent trees.

A mutator takes a :class:`~tests.fuzz.image_builder.SeedImage` plus a
:class:`random.Random` instance and returns a fresh, mutated
:class:`~tests.fuzz.image_builder.SeedImage` together with a human readable
description.  Mutators never mutate their input in place, which makes every
case trivially replayable.
"""
from __future__ import annotations

import random
from collections.abc import Callable
from dataclasses import dataclass

from dissect.extfs.c_ext import c_ext

from tests.fuzz.image_builder import (
    BLOCK_SIZE,
    EXT2,
    EXT4,
    SeedImage,
    direntry_field,
    extent_field,
    extent_header_field,
    extent_idx_field,
    group_desc_offset,
    inode_field,
    inode_offset,
    sb_field,
    superblock_offset,
)

# Block numbers that are legal inside the seed image geometry.
MAX_IMAGE_BLOCK = 7


@dataclass
class Mutation:
    """A mutated image paired with a description of what was changed."""

    image: SeedImage
    description: str
    mutator: str
    params: dict[str, object]


Mutator = Callable[[SeedImage, random.Random], Mutation]


def _u16(buf: bytearray, offset: int, value: int) -> None:
    buf[offset : offset + 2] = int(value & 0xFFFF).to_bytes(2, "little")


def _u32(buf: bytearray, offset: int, value: int) -> None:
    buf[offset : offset + 4] = int(value & 0xFFFFFFFF).to_bytes(4, "little")


def _current_u16(buf: bytearray, offset: int) -> int:
    return int.from_bytes(buf[offset : offset + 2], "little")


def _current_u32(buf: bytearray, offset: int) -> int:
    return int.from_bytes(buf[offset : offset + 4], "little")


def _distinct_u16(rng: random.Random, current: int, pool: tuple[int, ...]) -> int:
    """Pick a value from ``pool`` (or a random one) guaranteed to differ."""
    options = [value for value in pool if value & 0xFFFF != current]
    if options:
        return rng.choice(options)
    candidate = rng.randrange(0, 0x10000)
    return candidate if candidate != current else (candidate + 1) & 0xFFFF


def _distinct_u32(rng: random.Random, current: int, pool: tuple[int, ...]) -> int:
    """Pick a 32-bit value guaranteed to differ from ``current``."""
    options = [value & 0xFFFFFFFF for value in pool if (value & 0xFFFFFFFF) != current]
    if options:
        return rng.choice(options)
    candidate = rng.randrange(0, 0x10000)
    return candidate if candidate != current else (candidate + 1) & 0xFFFFFFFF


def _sb_pos(image: SeedImage, field: str) -> int:
    return superblock_offset() + sb_field(field)


def _gd_pos(image: SeedImage, field: str) -> int:
    return group_desc_offset(image.block_size) + {
        EXT4: c_ext.ext4_group_desc.fields[field].offset,
        EXT2: c_ext.ext2_group_desc.fields[field].offset,
    }[image.flavour]


def _inode_pos(image: SeedImage, inum: int, field: str) -> int:
    return inode_offset(image, inum) + inode_field(field)


def _block_pos(image: SeedImage, block: int) -> int:
    return block * image.block_size


# --------------------------------------------------------------------------- #
# Superblock geometry mutators
# --------------------------------------------------------------------------- #
def mutate_superblock_scalar(image: SeedImage, rng: random.Random) -> Mutation:
    """Overwrite one geometric superblock field with a chosen adversarial value."""
    out = image.copy()
    candidates = [
        "s_inodes_count",
        "s_blocks_count_lo",
        "s_first_data_block",
        "s_log_block_size",
        "s_log_cluster_size",
        "s_blocks_per_group",
        "s_inodes_per_group",
        "s_inode_size",
        "s_desc_size",
    ]
    field = rng.choice(candidates)
    pool = (0, 1, 2, 3, 9, 0xFFFF, 0xDEAD, 0xFFFFFFFF, 1 << 20, rng.randrange(0, 1 << 16))
    pos = _sb_pos(out, field)
    if field in ("s_inode_size", "s_desc_size"):
        current = _current_u16(out.data, pos)
        value = _distinct_u16(rng, current, pool)
        _u16(out.data, pos, value)
    else:
        current = _current_u32(out.data, pos)
        value = _distinct_u32(rng, current, pool)
        _u32(out.data, pos, value)
    return Mutation(out, f"superblock.{field}={value}", "superblock_scalar", {"field": field, "value": value})


def mutate_block_size_mismatch(image: SeedImage, rng: random.Random) -> Mutation:
    """Set block/cluster log sizes to inconsistent or unsupported values."""
    out = image.copy()
    block_log = rng.choice([0, 1, 2, 6, 0xFFFFFFFF])
    cluster_log = rng.choice([v for v in (0, 1, 2, 6, 0xFFFFFFFF) if v != block_log] or [1])
    _u32(out.data, _sb_pos(out, "s_log_block_size"), block_log)
    _u32(out.data, _sb_pos(out, "s_log_cluster_size"), cluster_log)
    return Mutation(
        out,
        f"block_log={block_log} cluster_log={cluster_log}",
        "block_size_mismatch",
        {"block_log": block_log, "cluster_log": cluster_log},
    )


def mutate_feature_flags(image: SeedImage, rng: random.Random) -> Mutation:
    """Flip incompat/ro-compat feature bits to change parser code paths."""
    out = image.copy()
    field = rng.choice(["s_feature_incompat", "s_feature_compat", "s_feature_ro_compat"])
    bits = rng.choice(
        [
            c_ext.EXT4_FEATURE_INCOMPAT_64BIT,
            c_ext.EXT4_FEATURE_INCOMPAT_EXTENTS,
            c_ext.EXT2_FEATURE_INCOMPAT_FILETYPE,
            c_ext.EXT3_FEATURE_COMPAT_HAS_JOURNAL,
            c_ext.EXT4_FEATURE_INCOMPAT_INLINE_DATA,
            rng.getrandbits(32),
        ]
    )
    pos = _sb_pos(out, field)
    current = _current_u32(out.data, pos)
    if rng.random() < 0.5:
        new_value = current | bits
    else:
        new_value = current & ~bits
    if new_value == current:
        # Guarantee a real change even if the bit was already in this state.
        new_value = current ^ bits
    _u32(out.data, pos, new_value)
    return Mutation(out, f"{field} -> {new_value:#x}", "feature_flags", {"field": field, "value": new_value})


# --------------------------------------------------------------------------- #
# Group descriptor mutators
# --------------------------------------------------------------------------- #
def mutate_group_descriptor(image: SeedImage, rng: random.Random) -> Mutation:
    """Corrupt a block pointer inside the group descriptor."""
    out = image.copy()
    candidates = ["bg_block_bitmap_lo", "bg_inode_bitmap_lo", "bg_inode_table_lo"]
    field = rng.choice(candidates)
    value = rng.choice([0, 1, MAX_IMAGE_BLOCK, MAX_IMAGE_BLOCK + 1, 0xFFFFFFFE, 0xFFFFFFFF])
    pos = _gd_pos(out, field)
    _u32(out.data, pos, value)

    # Keep the high half consistent when a 64-bit descriptor is in use, so the
    # mutation tests the actual 64-bit combined pointer rather than only its low
    # word.
    if out.flavour == EXT4 and field == "bg_inode_table_lo" and rng.random() < 0.3:
        hi_pos = group_desc_offset(out.block_size) + c_ext.ext4_group_desc.fields["bg_inode_table_hi"].offset
        _u32(out.data, hi_pos, rng.choice([0, 1, 0xFFFFFFFF]))
    return Mutation(out, f"group_desc.{field}={value}", "group_descriptor", {"field": field, "value": value})


# --------------------------------------------------------------------------- #
# Inode and extent-tree mutators
# --------------------------------------------------------------------------- #
def mutate_inode_size_flags(image: SeedImage, rng: random.Random) -> Mutation:
    """Alter inode size/flags so block-map and extent logic desyncs."""
    out = image.copy()
    inum = rng.choice([out.root_inum, out.file_inum])
    field = rng.choice(["i_size_lo", "i_size_high", "i_flags"])
    value = rng.choice([0, 1, BLOCK_SIZE, BLOCK_SIZE * 4, 0xFFFFFFFF, 1 << 20])
    pos = _inode_pos(out, inum, field)
    _u32(out.data, pos, value)
    return Mutation(
        out,
        f"inode{inum}.{field}={value}",
        "inode_size_flags",
        {"inum": inum, "field": field, "value": value},
    )


def _extent_root_pos(image: SeedImage, inum: int) -> int:
    return inode_offset(image, inum) + inode_field("i_block")


def mutate_extent_header(image: SeedImage, rng: random.Random) -> Mutation:
    """Corrupt the in-inode extent header (magic, depth, entry count)."""
    out = image.copy()
    inum = rng.choice([out.root_inum, out.file_inum])
    base = _extent_root_pos(out, inum)
    field = rng.choice(["eh_magic", "eh_entries", "eh_max", "eh_depth"])
    if field == "eh_magic":
        value = rng.choice([0, 0xF309, 0xFFFF])
        _u16(out.data, base + extent_header_field(field), value)
    else:
        value = rng.choice([0, 1, 4, 0xFFFF, rng.randrange(0, 0x10000)])
        _u16(out.data, base + extent_header_field(field), value)
    return Mutation(
        out,
        f"inode{inum}.extent.{field}={value}",
        "extent_header",
        {"inum": inum, "field": field, "value": value},
    )


def mutate_extent_leaf(image: SeedImage, rng: random.Random) -> Mutation:
    """Mutate an extent record living in the depth-0 leaf block."""
    out = image.copy()
    base = _block_pos(out, out.extent_leaf_block) + len(c_ext.ext4_extent_header())
    field = rng.choice(["ee_block", "ee_len", "ee_start_hi", "ee_start_lo"])
    value = rng.choice([0, 1, MAX_IMAGE_BLOCK, MAX_IMAGE_BLOCK + 1, 0x8000, 0xFFFF, 0xFFFFFFFF])
    width = 2 if field in ("ee_len", "ee_start_hi") else 4
    pos = base + extent_field(field)
    if width == 2:
        _u16(out.data, pos, value)
    else:
        _u32(out.data, pos, value)
    return Mutation(out, f"leaf.{field}={value}", "extent_leaf", {"field": field, "value": value})


def mutate_extent_child_pointer(image: SeedImage, rng: random.Random) -> Mutation:
    """Repoint an extent index node's child block (the depth-1 subtree link)."""
    out = image.copy()
    base = _extent_root_pos(out, out.file_inum) + len(c_ext.ext4_extent_header())
    field = rng.choice(["ei_leaf_lo", "ei_leaf_hi"])
    value = rng.choice([0, MAX_IMAGE_BLOCK, MAX_IMAGE_BLOCK + 1, 0xFFFFFFFE, 0xFFFFFFFF])
    pos = base + extent_idx_field(field)
    _u16(out.data, pos, value) if field == "ei_leaf_hi" else _u32(out.data, pos, value)
    return Mutation(out, f"extent_idx.{field}={value}", "extent_child", {"field": field, "value": value})


def make_self_referential_extent(image: SeedImage, rng: random.Random) -> Mutation:
    """Build an extent subtree that loops back onto itself.

    The file inode's depth-1 index points at the extent leaf block, which is
    rewritten to contain *another* depth-1 index whose child points at that same
    leaf block.  Every parser descent therefore re-enters the same node forever,
    modelling a malicious extent tree designed to pin a recursive worker.
    """
    out = image.copy()

    # Rewrite the leaf block as a depth-1 index node that references itself.
    leaf_pos = _block_pos(out, out.extent_leaf_block)
    header = c_ext.ext4_extent_header()
    header.eh_magic = 0xF30A
    header.eh_entries = 1
    header.eh_max = 4
    header.eh_depth = 1
    idx = c_ext.ext4_extent_idx()
    idx.ei_block = 0
    idx.ei_leaf_hi = 0
    idx.ei_leaf_lo = out.extent_leaf_block
    blob = header.dumps() + idx.dumps()
    out.data[leaf_pos : leaf_pos + len(blob)] = blob

    # The in-inode index already targets the leaf block in the valid seed; keep
    # that pointer intact so the loop is reachable from the root inode.
    base = _extent_root_pos(out, out.file_inum) + len(c_ext.ext4_extent_header())
    _u32(out.data, base + extent_idx_field("ei_leaf_lo"), out.extent_leaf_block)
    _u16(out.data, base + extent_idx_field("ei_leaf_hi"), 0)
    return Mutation(
        out,
        "extent leaf block loops back onto itself",
        "extent_self_ref",
        {"child_block": out.extent_leaf_block},
    )


def mutate_indirect_block_map(image: SeedImage, rng: random.Random) -> Mutation:
    """Corrupt a classic ext2 indirect block pointer."""
    out = image.copy()
    target = rng.choice(["direct", "indirect-block", "indirect-entry"])
    if target == "direct":
        pos = inode_offset(out, out.file_inum) + inode_field("i_block")
    elif target == "indirect-block":
        pos = inode_offset(out, out.file_inum) + inode_field("i_block") + 12 * 4
    else:
        pos = _block_pos(out, 7)
    current = _current_u32(out.data, pos)
    value = _distinct_u32(rng, current, (0, MAX_IMAGE_BLOCK + 1, 0xFFFFFFFF))
    _u32(out.data, pos, value)
    return Mutation(out, f"indirect.{target}={value}", "indirect_map", {"target": target, "value": value})


# --------------------------------------------------------------------------- #
# Directory entry mutators
# --------------------------------------------------------------------------- #
def mutate_dir_entry(image: SeedImage, rng: random.Random) -> Mutation:
    """Corrupt directory entry geometry inside the root directory block."""
    out = image.copy()
    base = _block_pos(out, out.root_dir_block)
    field = rng.choice(["inode", "rec_len", "name_len", "file_type"])
    # The third entry starts at byte 24 of the directory block.
    entry_pos = base + 24
    value = rng.choice([0, 1, 4, 8, 12, 0xFFFF, rng.randrange(0, 0x10000)])
    pos = entry_pos + direntry_field(field)
    if field == "name_len" or field == "file_type":
        out.data[pos] = value & 0xFF
    elif field == "rec_len":
        _u16(out.data, pos, value)
    else:
        _u32(out.data, pos, value)
    return Mutation(out, f"direntry.{field}={value}", "dir_entry", {"field": field, "value": value})


def make_zero_rec_len_dir(image: SeedImage, rng: random.Random) -> Mutation:
    """Force a zero rec_len, the classic directory walk stall pattern."""
    out = image.copy()
    base = _block_pos(out, out.root_dir_block)
    _u16(out.data, base + direntry_field("rec_len"), 0)
    return Mutation(out, "first direntry rec_len=0", "dir_zero_reclen", {})


# --------------------------------------------------------------------------- #
# Correlated, multi-structure mutations
# --------------------------------------------------------------------------- #
def mutate_correlated_geometry(image: SeedImage, rng: random.Random) -> Mutation:
    """Change superblock geometry *and* the descriptors that depend on it.

    This is the case a byte flipper cannot reach: the block count and blocks per
    group are changed together, then the group descriptor table size and inode
    table pointer are adjusted to match, pushing the parser through inconsistent
    group math rather than a single bad byte.
    """
    out = image.copy()
    blocks_per_group = rng.choice([1, 2, MAX_IMAGE_BLOCK, MAX_IMAGE_BLOCK * 2])
    block_count = rng.choice([blocks_per_group, blocks_per_group + 1, MAX_IMAGE_BLOCK])
    _u32(out.data, _sb_pos(out, "s_blocks_per_group"), blocks_per_group)
    _u32(out.data, _sb_pos(out, "s_blocks_count_lo"), block_count)
    # Now move the inode table pointer to a block derived from the new geometry,
    # which may land outside the image or overlap other metadata.
    new_table = rng.choice([block_count, block_count + 1, MAX_IMAGE_BLOCK + 1])
    _u32(out.data, _gd_pos(out, "bg_inode_table_lo"), new_table)
    return Mutation(
        out,
        f"geometry bpg={blocks_per_group} blocks={block_count} itable={new_table}",
        "correlated_geometry",
        {"blocks_per_group": blocks_per_group, "block_count": block_count, "inode_table": new_table},
    )


def mutate_combined(image: SeedImage, rng: random.Random) -> Mutation:
    """Apply two independent structure mutators in one case for deeper paths."""
    primary, secondary = rng.sample(ALL_MUTATORS, 2)
    first = primary(image, rng)
    second = secondary(first.image, rng)
    return Mutation(
        second.image,
        f"{first.description} + {second.description}",
        "combined",
        {"first": first.mutator, "second": second.mutator},
    )


ALL_MUTATORS: tuple[Mutator, ...] = (
    mutate_superblock_scalar,
    mutate_block_size_mismatch,
    mutate_feature_flags,
    mutate_group_descriptor,
    mutate_inode_size_flags,
    mutate_extent_header,
    mutate_extent_leaf,
    mutate_extent_child_pointer,
    mutate_indirect_block_map,
    mutate_dir_entry,
    make_zero_rec_len_dir,
    mutate_correlated_geometry,
)

EXT4_MUTATORS: tuple[Mutator, ...] = ALL_MUTATORS + (
    make_self_referential_extent,
    mutate_combined,
)

EXT2_MUTATORS: tuple[Mutator, ...] = tuple(
    mutator
    for mutator in ALL_MUTATORS
    if mutator
    not in (
        mutate_extent_header,
        mutate_extent_leaf,
        mutate_extent_child_pointer,
    )
) + (mutate_combined,)


def mutators_for(flavour: str) -> tuple[Mutator, ...]:
    if flavour == EXT4:
        return EXT4_MUTATORS
    if flavour == EXT2:
        return EXT2_MUTATORS
    raise ValueError(f"unknown flavour: {flavour}")
