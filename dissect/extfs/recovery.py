from __future__ import annotations

import logging
import os
import stat
import struct
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from dissect.extfs.c_ext import c_ext
from dissect.extfs.exceptions import Error, NotADirectoryError

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.extfs.extfs import INode

log = logging.getLogger(__name__)
log.setLevel(os.getenv("DISSECT_LOG_EXTFS", "CRITICAL"))

# Both ext2_dir_entry and ext2_dir_entry_2 have an 8 byte fixed header
DIR_ENTRY_HEADER_LEN = 8
# Directory entry file_type values are 0 (unknown) up to and including 7 (symlink)
EXT2_FT_MAX = 7
# file_type used by the ext4 directory checksum tail (ext4_dir_entry_tail)
DIR_TAIL_FILE_TYPE = 0xDE
# Minimum amount of printable bytes before we consider them a name fragment candidate
MIN_FRAGMENT_LEN = 4


class ResidueKind(Enum):
    """Classification of a directory residue candidate."""

    #: A complete old directory record (header + name) survived in rec_len slack
    COMPLETE_RECORD = "complete_record"
    #: A complete old record, but its inode number is also used by an active entry
    REUSED_INODE = "reused_inode"
    #: Only name bytes survived, there is no valid record header
    NAME_FRAGMENT = "name_fragment"


@dataclass
class DirResidue:
    """A deleted directory entry candidate found in rec_len slack.

    ``offset`` and ``size`` describe the byte range within the directory data,
    ``disk_offset`` the absolute offset in the volume (``None`` if the directory
    data has no direct disk mapping, e.g. inline data). ``name`` always holds
    the raw name bytes as found on disk.
    """

    kind: ResidueKind
    name: bytes
    offset: int
    size: int
    disk_offset: int | None
    inode: int | None = None
    file_type: int | None = None
    note: str = ""

    @property
    def name_text(self) -> str:
        return self.name.decode(errors="surrogateescape")

    @property
    def byte_range(self) -> tuple[int, int]:
        """Byte range within the directory data."""
        return (self.offset, self.offset + self.size)

    @property
    def disk_byte_range(self) -> tuple[int, int] | None:
        """Absolute byte range in the volume, if a disk mapping exists."""
        if self.disk_offset is None:
            return None
        return (self.disk_offset, self.disk_offset + self.size)


def scan_dir_residue(node: INode) -> list[DirResidue]:
    """Scan the rec_len slack of a directory for residue of deleted entries.

    Active entries are walked with the same rules as :meth:`INode.iterdir` and are
    never reported. Every candidate is confined to a single directory block;
    fragments are never stitched across block boundaries.
    """
    if node.filetype != stat.S_IFDIR:
        raise NotADirectoryError(f"{node!r} is not a directory")

    extfs = node.extfs
    block_size = extfs.block_size
    has_file_type = extfs._dirtype == c_ext.ext2_dir_entry_2
    inodes_count = extfs.sb.s_inodes_count

    data = node.open().read()
    blocks = [data[offset : offset + block_size] for offset in range(0, len(data), block_size)]

    # First pass: walk the active record chain of each block, remember the active
    # inode numbers and where the rec_len slack regions are
    active_names: dict[int, bytes] = {}
    slack_regions: list[tuple[int, int, int]] = []
    for block_index, block in enumerate(blocks):
        offset = 0
        while offset + 12 <= len(block):
            inode, rec_len, name_len = _read_header(block, offset, has_file_type)
            if rec_len == 0 or rec_len % 4 or offset + rec_len > len(block):
                log.critical("Corrupt directory record chain in %s (block %d, offset 0x%x)", node, block_index, offset)
                break

            file_type = block[offset + 7] if has_file_type else None
            if inode == 0 and rec_len == 12 and name_len == 0 and file_type == DIR_TAIL_FILE_TYPE:
                # ext4 directory checksum tail, not residue
                offset += rec_len
                continue

            used = _align4(DIR_ENTRY_HEADER_LEN + name_len)
            name = block[offset + DIR_ENTRY_HEADER_LEN : offset + DIR_ENTRY_HEADER_LEN + name_len]
            if (
                0 < inode <= inodes_count
                and 0 < name_len <= c_ext.EXT2_NAME_LEN
                and used <= rec_len
                and _valid_name(name)
            ):
                active_names.setdefault(inode, name)
                if used < rec_len:
                    slack_regions.append((block_index, offset + used, offset + rec_len))
            else:
                # Unused or invalid entry, the whole record is slack space
                slack_regions.append((block_index, offset, offset + rec_len))

            offset += rec_len

    # Second pass: scan each slack region for old records and name fragments
    residues = []
    for block_index, start, end in slack_regions:
        block = blocks[block_index]
        base = block_index * block_size

        fragment_zones = []
        pos = start
        cursor = start
        while pos + DIR_ENTRY_HEADER_LEN <= end:
            inode, rec_len, name_len = _read_header(block, pos, has_file_type)
            file_type = block[pos + 7] if has_file_type else None
            used = _align4(DIR_ENTRY_HEADER_LEN + name_len)
            name = block[pos + DIR_ENTRY_HEADER_LEN : pos + DIR_ENTRY_HEADER_LEN + name_len]

            if (
                0 < inode <= inodes_count
                and 0 < name_len <= c_ext.EXT2_NAME_LEN
                and used <= rec_len
                and rec_len % 4 == 0
                and pos + rec_len <= end
                and (file_type is None or file_type <= EXT2_FT_MAX)
                and _valid_name(name)
            ):
                if cursor < pos:
                    fragment_zones.append((cursor, pos))
                if used < rec_len:
                    # Padding of the old record can hold even older name bytes
                    fragment_zones.append((pos + used, pos + rec_len))

                if inode in active_names:
                    kind = ResidueKind.REUSED_INODE
                    note = (
                        f"inode {inode} is also referenced by active entry "
                        f"{active_names[inode]!r}; the inode number was reused, "
                        "so the inode association of this old record is unreliable"
                    )
                else:
                    kind = ResidueKind.COMPLETE_RECORD
                    note = f"complete old directory record preserved in slack; inode {inode} has no active entry"

                residues.append(
                    DirResidue(
                        kind=kind,
                        name=bytes(name),
                        offset=base + pos,
                        size=rec_len,
                        disk_offset=_disk_offset(node, base + pos),
                        inode=inode,
                        file_type=file_type,
                        note=note,
                    )
                )
                pos += rec_len
                cursor = pos
            else:
                pos += 4

        if cursor < end:
            fragment_zones.append((cursor, end))

        for zone_start, zone_end in fragment_zones:
            residues.extend(_find_fragments(node, block, base, block_index, len(blocks), zone_start, zone_end))

    return sorted(residues, key=lambda residue: (residue.offset, residue.kind.value))


def _read_header(block: bytes, offset: int, has_file_type: bool) -> tuple[int, int, int]:
    inode, rec_len = struct.unpack_from("<IH", block, offset)
    if has_file_type:
        name_len = block[offset + 6]
    else:
        name_len = struct.unpack_from("<H", block, offset + 6)[0]
    return inode, rec_len, name_len


def _align4(value: int) -> int:
    return (value + 3) & ~3


def _valid_name(name: bytes) -> bool:
    return b"\x00" not in name and b"/" not in name


def _is_printable(value: int) -> bool:
    return 0x20 <= value <= 0x7E


def _find_fragments(
    node: INode,
    block: bytes,
    base: int,
    block_index: int,
    num_blocks: int,
    start: int,
    end: int,
) -> Iterator[DirResidue]:
    """Yield name fragment candidates from printable byte runs in a slack zone."""
    run_start = None
    for pos in range(start, end + 1):
        if pos < end and _is_printable(block[pos]):
            if run_start is None:
                run_start = pos
            continue

        if run_start is not None and pos - run_start >= MIN_FRAGMENT_LEN:
            notes = ["name bytes without a valid directory record header; inode association unknown"]
            if run_start == start:
                notes.append("record header missing or overwritten")
            if pos == end and end == len(block) and block_index < num_blocks - 1:
                notes.append(
                    "fragment reaches the end of the directory block; the next block holds an independent "
                    "record chain and must not be concatenated, so the full name cannot be determined"
                )

            yield DirResidue(
                kind=ResidueKind.NAME_FRAGMENT,
                name=bytes(block[run_start:pos]),
                offset=base + run_start,
                size=pos - run_start,
                disk_offset=_disk_offset(node, base + run_start),
                note="; ".join(notes),
            )
        run_start = None


def _disk_offset(node: INode, offset: int) -> int | None:
    """Translate a directory data offset to an absolute volume offset, if possible."""
    if node.inode.i_flags & c_ext.EXT4_INLINE_DATA_FL:
        return None

    block_size = node.extfs.block_size
    block_index, inner = divmod(offset, block_size)

    try:
        runlist = node.dataruns()
    except Error:
        return None

    index = 0
    for run_block, run_length in runlist:
        if index <= block_index < index + run_length:
            if run_block is None:
                return None
            return (run_block + block_index - index) * block_size + inner
        index += run_length
    return None
