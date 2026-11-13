"""Hand-crafted, byte-exact JBD2 journal image builder for offline compatibility tests.

Nothing in this module imports or reuses the parsing logic under test
(``dissect.extfs.journal``). Expected block numbers, payloads, UUID placement and
checksums are produced here from explicit on-disk byte layouts so the reader cannot
back-compute its own expectations.

Checksums follow the Linux kernel ``jbd2`` layout:

* checksum v3 tags store ``crc32c(journal_uuid + sequence_be32 + data_block)``;
* checksum v2 tags store the low 16 bits of
  ``crc32c(journal_uuid + descriptor_header(type=1, sequence) + data_block)``;
* legacy (no checksum feature) tags carry no checksum field.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from io import BytesIO

from dissect.extfs.c_jdb2 import c_jdb2

BLOCK_SIZE = 1024

# include/linux/jbd2.h: JBD2_ESCAPE_HDR. A data block whose first four bytes collide
# with the journal magic is preceded in the log by this 12-byte header.
JBD2_ESCAPE_HDR = 9

TAG_V2 = "v2"
TAG_V3 = "v3"
TAG_LEGACY64 = "legacy64"
TAG_LEGACY32 = "legacy32"

# Two distinct, hard-coded journal users for shared-UUID scenarios.
UUID_A = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
UUID_B = bytes.fromhex("1112131415161718191a1b1c1d1e1f20")

_CRC32C_POLY = 0x82F63B78


def _build_crc32c_table() -> tuple[int, ...]:
    table: list[int] = []
    for byte in range(256):
        crc = byte
        for _ in range(8):
            crc = (crc >> 1) ^ _CRC32C_POLY if crc & 1 else crc >> 1
        table.append(crc)
    return tuple(table)


_CRC32C_TABLE = _build_crc32c_table()


def crc32c(data: bytes, crc: int = 0) -> int:
    """Return the Castagnoli CRC32C of ``data`` (independent, table-driven)."""
    accum = crc ^ 0xFFFFFFFF
    for byte in data:
        accum = _CRC32C_TABLE[(accum ^ byte) & 0xFF] ^ (accum >> 8)
    return accum ^ 0xFFFFFFFF


def _journal_header(blocktype: int, sequence: int) -> bytes:
    return struct.pack(">III", c_jdb2.JBD2_MAGIC_NUMBER, blocktype, sequence)


def _payload(marker: int) -> bytes:
    """A deterministic, unique data block not derived from the reader."""
    base = bytes((b + marker) & 0xFF for b in range(16))
    return (base + bytes([marker & 0xFF]) * (BLOCK_SIZE - 16))[:BLOCK_SIZE]


@dataclass
class Tag:
    """One descriptor entry: explicit on-disk fs block number, payload and layout."""

    fs_block: int
    marker: int
    uuid: bytes | None = UUID_A
    escaped: bool = False
    corrupt_checksum: bool = False
    flags: int = 0


@dataclass
class TagExpectation:
    fs_block: int
    journal_block: int
    marker: int
    same_uuid: bool
    escaped: bool
    payload_journal_block: int


@dataclass
class TransactionExpectation:
    sequence: int
    descriptor_journal_blocks: list[int]
    tags: list[TagExpectation]
    commit_journal_block: int
    commit_sec: int
    commit_nsec: int


class SyntheticJournal:
    """Build a journal image from explicit descriptor/tag/block layouts."""

    def __init__(
        self,
        feature_incompat: int,
        tag_format: str = TAG_V3,
        *,
        nr_users: int = 1,
        journal_uuid: bytes = UUID_A,
    ) -> None:
        self.feature_incompat = feature_incompat
        self.tag_format = tag_format
        self.nr_users = nr_users
        self.journal_uuid = journal_uuid
        self._transactions: list[tuple[int, list[list[Tag]], int, int]] = []

    def add_transaction(
        self,
        sequence: int,
        tag_groups: list[list[Tag]],
        *,
        commit_sec: int,
        commit_nsec: int,
    ) -> None:
        """Append a transaction split into one or more descriptor blocks."""
        self._transactions.append((sequence, tag_groups, commit_sec, commit_nsec))

    def _tag_size(self) -> int:
        if self.tag_format == TAG_V3:
            return 16
        if self.tag_format == TAG_V2:
            return 12
        if self.tag_format == TAG_LEGACY64:
            return 10
        return 6  # TAG_LEGACY32

    def _encode_tag(self, tag: Tag, sequence: int, last: bool, data_block: bytes) -> bytes:
        flags = tag.flags
        if last:
            flags |= c_jdb2.JBD2_FLAG_LAST_TAG
        if tag.uuid is None:
            flags |= c_jdb2.JBD2_FLAG_SAME_UUID
        if tag.escaped:
            flags |= c_jdb2.JBD2_FLAG_ESCAPE

        blocknr_low = tag.fs_block & 0xFFFFFFFF
        blocknr_high = (tag.fs_block >> 32) & 0xFFFFFFFF

        if self.tag_format == TAG_V3:
            checksum = crc32c(self.journal_uuid + struct.pack(">I", sequence) + data_block)
            if tag.corrupt_checksum:
                checksum ^= 0xDEADBEEF
            return struct.pack(">IIII", blocknr_low, flags, blocknr_high, checksum)

        if self.tag_format == TAG_V2:
            descriptor_hdr = _journal_header(c_jdb2.JBD2_DESCRIPTOR_BLOCK, sequence)
            checksum = crc32c(self.journal_uuid + descriptor_hdr + data_block) & 0xFFFF
            if tag.corrupt_checksum:
                checksum ^= 0xABCD
            return struct.pack(">IHHI", blocknr_low, checksum, flags, blocknr_high)

        if self.tag_format == TAG_LEGACY64:
            return struct.pack(">IHI", blocknr_low, flags, blocknr_high)

        return struct.pack(">IH", blocknr_low, flags)

    def _render(self) -> tuple[list[bytes], list[TransactionExpectation]]:
        # Block 0 is the journal superblock; log content numbering starts at 1.
        blocks: list[bytes] = []
        expectations: list[TransactionExpectation] = []

        for sequence, tag_groups, commit_sec, commit_nsec in self._transactions:
            descriptor_journal_blocks: list[int] = []
            tag_expectations: list[TagExpectation] = []

            for group in tag_groups:
                descriptor_journal_blocks.append(len(blocks) + 1)
                body = bytearray()
                descriptor_block = len(blocks)
                blocks.append(b"")  # placeholder, filled after payload layout is known

                running_journal_block = descriptor_block + 2
                for index, tag in enumerate(group):
                    data_block = _payload(tag.marker)
                    if tag.escaped:
                        escape_hdr = _journal_header(JBD2_ESCAPE_HDR, sequence)
                        payload_journal_block = running_journal_block + 1
                        blocks.append(escape_hdr + bytes(BLOCK_SIZE - 12))
                        blocks.append(data_block)
                        running_journal_block += 2
                    else:
                        payload_journal_block = running_journal_block
                        blocks.append(data_block)
                        running_journal_block += 1

                    body += self._encode_tag(tag, sequence, index == len(group) - 1, data_block)
                    if tag.uuid is not None:
                        body += tag.uuid
                    tag_expectations.append(
                        TagExpectation(
                            fs_block=tag.fs_block,
                            journal_block=payload_journal_block,
                            marker=tag.marker,
                            same_uuid=tag.uuid is None,
                            escaped=tag.escaped,
                            payload_journal_block=payload_journal_block,
                        )
                    )
                blocks[descriptor_block] = _journal_header(c_jdb2.JBD2_DESCRIPTOR_BLOCK, sequence) + bytes(body)

            commit_journal_block = len(blocks) + 1
            commit = c_jdb2.commit_header(
                h_magic=c_jdb2.JBD2_MAGIC_NUMBER,
                h_blocktype=c_jdb2.JBD2_COMMIT_BLOCK,
                h_sequence=sequence,
                h_chksum_type=0,
                h_chksum_size=0,
                h_padding=b"\x00\x00",
                h_chksum=b"\x00" * 32,
                h_commit_sec=commit_sec,
                h_commit_nsec=commit_nsec,
            )
            blocks.append(commit.dumps() + bytes(BLOCK_SIZE - 60))
            expectations.append(
                TransactionExpectation(
                    sequence=sequence,
                    descriptor_journal_blocks=descriptor_journal_blocks,
                    tags=tag_expectations,
                    commit_journal_block=commit_journal_block,
                    commit_sec=commit_sec,
                    commit_nsec=commit_nsec,
                )
            )

        return blocks, expectations

    def build(self) -> tuple[BytesIO, list[TransactionExpectation]]:
        """Return the journal image stream plus the independent expected oracle."""
        blocks, expectations = self._render()
        sb = c_jdb2.journal_superblock(
            s_header=c_jdb2.journal_header(
                h_magic=c_jdb2.JBD2_MAGIC_NUMBER,
                h_blocktype=c_jdb2.JBD2_SUPERBLOCK_V2,
                h_sequence=expectations[0].sequence if expectations else 0,
            ),
            s_blocksize=BLOCK_SIZE,
            s_maxlen=len(blocks) + 2,
            s_first=1,
            s_sequence=expectations[0].sequence if expectations else 0,
            s_feature_compat=0,
            s_feature_incompat=self.feature_incompat,
            s_feature_ro_compat=0,
            s_uuid=self.journal_uuid,
            s_nr_users=self.nr_users,
        )
        image = bytearray(sb.dumps())
        for block in blocks:
            image += block + bytes(BLOCK_SIZE - len(block))
        return BytesIO(bytes(image)), expectations

    def raw_bytes(self) -> bytes:
        """Return the assembled image bytes (used for truncation/mutation cases)."""
        stream, _ = self.build()
        return stream.getvalue()
