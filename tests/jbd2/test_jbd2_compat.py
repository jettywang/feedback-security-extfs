"""Offline JBD2 journal reader compatibility tests.

All journal images are synthesized byte-by-byte in ``journal_builder.py`` from
explicit on-disk layouts. Expected fs block numbers, payload bytes, journal block
positions and timestamps come from that independent builder/oracle rather than from
the reader under test, so a misparsing reader cannot satisfy the assertions by
back-computing them.

Coverage map:

* 64-bit block numbers (high dword exercised), checksum v2 and v3 tag layouts;
* shared-UUID tags (``JBD2_FLAG_SAME_UUID`` with the 16-byte UUID omitted);
* multiple descriptor blocks belonging to one transaction;
* truncation, bad end marker and checksum-corruption rejection boundaries;
* legacy non-checksum tag layouts and escaped blocks, which the reader does not yet
  support and which are tracked via strict ``xfail`` gap tests.
"""

from __future__ import annotations

from io import BytesIO
from typing import TYPE_CHECKING

import pytest

from dissect.extfs.c_jdb2 import c_jdb2
from dissect.extfs.exceptions import Error
from dissect.extfs.journal import JDB2
from tests.jbd2.journal_builder import (
    BLOCK_SIZE,
    TAG_LEGACY32,
    TAG_LEGACY64,
    TAG_V2,
    TAG_V3,
    UUID_A,
    UUID_B,
    SyntheticJournal,
    Tag,
    TagExpectation,
    _payload,
    crc32c,
)

if TYPE_CHECKING:
    from dissect.extfs.journal import CommitBlock, DescriptorBlockTag

F_64BIT = c_jdb2.JBD2_FEATURE_INCOMPAT_64BIT
F_CSUM_V2 = c_jdb2.JBD2_FEATURE_INCOMPAT_CSUM_V2
F_CSUM_V3 = c_jdb2.JBD2_FEATURE_INCOMPAT_CSUM_V3

# Hard-coded oracle values; deliberately non-sequential and spanning 64 bits.
BLOCK_LOW = 0x0000000000000042
BLOCK_HIGH = 0x1122334455667788
BLOCK_MIXED = 0xABCDEF0123456789
BLOCK_TINY = 0x9999999999999999
COMMIT_SEC = 1_700_000_000
COMMIT_NSEC = 123_000_000


def _first_commit(journal: JDB2) -> CommitBlock:
    commits = list(journal.commits_all())
    assert len(commits) == 1
    return commits[0]


def _assert_tag_matches(tag: DescriptorBlockTag, expected: TagExpectation) -> None:
    assert tag.block == expected.fs_block
    assert tag.journal_block == expected.journal_block
    assert tag.open().read() == _payload(expected.marker)


def test_crc32c_known_answer_vector() -> None:
    """The builder's independent CRC32C must match the Castagnoli test vector."""
    assert crc32c(b"123456789") == 0xE3069283


def test_superblock_feature_selects_tag3_layout() -> None:
    """CSUM_V3 switches the reader to the 16-byte ``journal_block_tag3`` layout."""
    journal = SyntheticJournal(F_64BIT | F_CSUM_V3, TAG_V3)
    journal.add_transaction(7, [[Tag(BLOCK_HIGH, 0x10)]], commit_sec=COMMIT_SEC, commit_nsec=0)
    reader = JDB2(journal.build()[0])
    assert reader._blocktag is c_jdb2.journal_block_tag3
    assert reader.block_size == BLOCK_SIZE


def test_superblock_feature_selects_tag_v2_layout() -> None:
    """Without CSUM_V3 the reader uses the 12-byte truncated-checksum tag layout."""
    journal = SyntheticJournal(F_64BIT | F_CSUM_V2, TAG_V2)
    journal.add_transaction(7, [[Tag(BLOCK_HIGH, 0x10)]], commit_sec=COMMIT_SEC, commit_nsec=0)
    reader = JDB2(journal.build()[0])
    assert reader._blocktag is c_jdb2.journal_block_tag


@pytest.mark.parametrize(
    ("tag_format", "features"),
    [
        (TAG_V2, F_64BIT | F_CSUM_V2),
        (TAG_V3, F_64BIT | F_CSUM_V3),
    ],
)
def test_64bit_block_numbers_resolve_to_expected_blocks(tag_format: str, features: int) -> None:
    """High and low dwords of the fs block number must combine without truncation."""
    journal = SyntheticJournal(features, tag_format)
    journal.add_transaction(
        7,
        [[Tag(BLOCK_HIGH, 0x10), Tag(BLOCK_LOW, 0x11, uuid=None), Tag(BLOCK_MIXED, 0x12, uuid=UUID_B)]],
        commit_sec=COMMIT_SEC,
        commit_nsec=COMMIT_NSEC,
    )
    image, oracle = journal.build()
    commit = _first_commit(JDB2(image))
    tags = list(commit.descriptors[0].tags())
    assert [tag.block for tag in tags] == [BLOCK_HIGH, BLOCK_LOW, BLOCK_MIXED]
    assert [tag.journal_block for tag in tags] == [2, 3, 4]
    for tag, expected in zip(tags, oracle[0].tags, strict=True):
        _assert_tag_matches(tag, expected)


@pytest.mark.parametrize(
    ("tag_format", "features"),
    [
        (TAG_V2, F_64BIT | F_CSUM_V2),
        (TAG_V3, F_64BIT | F_CSUM_V3),
    ],
)
def test_shared_uuid_omits_sixteen_bytes_per_tag(tag_format: str, features: int) -> None:
    """SAME_UUID tags carry no UUID bytes; explicit and omitted UUIDs must stay aligned."""
    journal = SyntheticJournal(features, tag_format)
    journal.add_transaction(
        7,
        [
            [
                Tag(BLOCK_HIGH, 0x10, uuid=UUID_A),
                Tag(BLOCK_LOW, 0x11, uuid=None),
                Tag(BLOCK_MIXED, 0x12, uuid=UUID_B),
                Tag(BLOCK_TINY, 0x13, uuid=None),
            ]
        ],
        commit_sec=COMMIT_SEC,
        commit_nsec=0,
    )
    image, oracle = journal.build()
    commit = _first_commit(JDB2(image))
    tags = list(commit.descriptors[0].tags())
    assert [tag.block for tag in tags] == [BLOCK_HIGH, BLOCK_LOW, BLOCK_MIXED, BLOCK_TINY]
    assert [expected.same_uuid for expected in oracle[0].tags] == [False, True, False, True]
    for tag, expected in zip(tags, oracle[0].tags, strict=True):
        _assert_tag_matches(tag, expected)


def test_multiple_descriptors_in_one_transaction() -> None:
    """Both descriptor blocks must attach to the same commit and yield all tags."""
    journal = SyntheticJournal(F_64BIT | F_CSUM_V3, TAG_V3)
    journal.add_transaction(
        7,
        [
            [Tag(0x1000, 0x20, uuid=UUID_A), Tag(0x1001, 0x21, uuid=None)],
            [Tag(0x2000, 0x22, uuid=UUID_A), Tag(0x2001, 0x23, uuid=None)],
        ],
        commit_sec=COMMIT_SEC,
        commit_nsec=0,
    )
    image, oracle = journal.build()
    commit = _first_commit(JDB2(image))
    assert [descriptor.journal_block for descriptor in commit.descriptors] == [1, 4]
    tags = [tag for descriptor in commit.descriptors for tag in descriptor.tags()]
    assert [tag.block for tag in tags] == [0x1000, 0x1001, 0x2000, 0x2001]
    expected_tags = [expected for transaction in oracle for expected in transaction.tags]
    for tag, expected in zip(tags, expected_tags, strict=True):
        _assert_tag_matches(tag, expected)


def test_commits_filters_non_consecutive_sequence_gap() -> None:
    """``commits()`` only yields the contiguous run starting at the first sequence."""
    journal = SyntheticJournal(F_64BIT | F_CSUM_V3, TAG_V3)
    journal.add_transaction(7, [[Tag(0x1000, 0x30)]], commit_sec=COMMIT_SEC, commit_nsec=0)
    journal.add_transaction(9, [[Tag(0x2000, 0x31)]], commit_sec=COMMIT_SEC + 1, commit_nsec=0)
    reader = JDB2(journal.build()[0])
    assert [commit.sequence for commit in reader.commits_all()] == [7, 9]
    assert [commit.sequence for commit in reader.commits()] == [7]


def test_commit_timestamp_decoded_from_header() -> None:
    import datetime

    journal = SyntheticJournal(F_64BIT | F_CSUM_V3, TAG_V3)
    journal.add_transaction(7, [[Tag(BLOCK_LOW, 0x40)]], commit_sec=COMMIT_SEC, commit_nsec=COMMIT_NSEC)
    commit = _first_commit(JDB2(journal.build()[0]))
    assert commit.ts == datetime.datetime(2023, 11, 14, 22, 13, 20, 123000, tzinfo=datetime.timezone.utc)


def test_magic_mismatch_is_rejected() -> None:
    journal = SyntheticJournal(F_64BIT | F_CSUM_V3, TAG_V3)
    raw = bytearray(journal.raw_bytes())
    raw[0:4] = b"\x00\x00\x00\x00"
    with pytest.raises(Error, match="magic mismatch"):
        JDB2(BytesIO(bytes(raw)))


def test_truncated_descriptor_tag_is_rejected() -> None:
    """An image cut halfway through a tag must surface an EOFError, not a fake block."""
    journal = SyntheticJournal(F_64BIT | F_CSUM_V3, TAG_V3)
    journal.add_transaction(7, [[Tag(BLOCK_HIGH, 0x50)]], commit_sec=COMMIT_SEC, commit_nsec=0)
    cut = BLOCK_SIZE + c_jdb2.journal_header.size + 8  # 8 of the 16-byte tag3 remain
    reader = JDB2(BytesIO(journal.raw_bytes()[:cut]))
    with pytest.raises(EOFError):
        list(reader.walk())


@pytest.mark.jbd2_gap(
    category="parse_misalignment",
    reason="DescriptorBlock.tags() has no bound and ignores JBD2_FLAG_LAST_TAG absence",
)
@pytest.mark.xfail(strict=True, reason="missing LAST_TAG walks into zero blocks until EOF")
def test_missing_last_tag_flag_must_be_rejected() -> None:
    journal = SyntheticJournal(F_64BIT | F_CSUM_V3, TAG_V3)
    journal.add_transaction(7, [[Tag(BLOCK_HIGH, 0x60)]], commit_sec=COMMIT_SEC, commit_nsec=0)
    raw = bytearray(journal.raw_bytes())
    tag_flags_offset = BLOCK_SIZE + c_jdb2.journal_header.size + 4
    raw[tag_flags_offset : tag_flags_offset + 4] = b"\x00\x00\x00\x00"  # clear LAST_TAG
    raw += bytes(BLOCK_SIZE * 3)
    reader = JDB2(BytesIO(bytes(raw)))
    descriptor = list(reader.commits_all())[0].descriptors[0]
    with pytest.raises(Error):
        list(descriptor.tags())


@pytest.mark.jbd2_gap(
    category="unsupported_format",
    reason="reader never validates the v3 tag t_checksum crc32c field",
)
@pytest.mark.xfail(strict=True, reason="corrupt checksum v3 tag is accepted without error")
def test_corrupt_v3_tag_checksum_must_be_rejected() -> None:
    journal = SyntheticJournal(F_64BIT | F_CSUM_V3, TAG_V3)
    journal.add_transaction(
        7,
        [[Tag(BLOCK_HIGH, 0x70, corrupt_checksum=True)]],
        commit_sec=COMMIT_SEC,
        commit_nsec=0,
    )
    descriptor = _first_commit(JDB2(journal.build()[0])).descriptors[0]
    with pytest.raises(Error):
        list(descriptor.tags())


@pytest.mark.jbd2_gap(
    category="unsupported_format",
    reason="reader never validates the truncated v2 tag t_checksum field",
)
@pytest.mark.xfail(strict=True, reason="corrupt checksum v2 tag is accepted without error")
def test_corrupt_v2_tag_checksum_must_be_rejected() -> None:
    journal = SyntheticJournal(F_64BIT | F_CSUM_V2, TAG_V2)
    journal.add_transaction(
        7,
        [[Tag(BLOCK_HIGH, 0x71, corrupt_checksum=True)]],
        commit_sec=COMMIT_SEC,
        commit_nsec=0,
    )
    with pytest.raises(Error):
        list(list(JDB2(journal.build()[0]).commits_all())[0].descriptors[0].tags())


@pytest.mark.jbd2_gap(
    category="unsupported_format",
    reason="no 6-byte/10-byte legacy tag layout; reader always assumes a checksum tag",
)
@pytest.mark.xfail(strict=True, reason="legacy tags are misread through a wider struct")
@pytest.mark.parametrize(
    ("tag_format", "features", "fs_block"),
    [
        (TAG_LEGACY64, F_64BIT, BLOCK_HIGH),
        (TAG_LEGACY32, 0, 0x87654321),
    ],
)
def test_legacy_non_checksum_tags_must_resolve(tag_format: str, features: int, fs_block: int) -> None:
    journal = SyntheticJournal(features, tag_format)
    journal.add_transaction(7, [[Tag(fs_block, 0x80)]], commit_sec=COMMIT_SEC, commit_nsec=0)
    image, oracle = journal.build()
    tags = list(_first_commit(JDB2(image)).descriptors[0].tags())
    assert tags[0].block == oracle[0].tags[0].fs_block
    assert tags[0].open().read() == _payload(0x80)


@pytest.mark.jbd2_gap(
    category="parse_misalignment",
    reason="JBD2_FLAG_ESCAPE blocks are not skipped, so open() points at the escape header",
)
@pytest.mark.xfail(strict=True, reason="escaped block and every following tag shift by one block")
def test_escaped_block_must_point_at_real_payload() -> None:
    journal = SyntheticJournal(F_64BIT | F_CSUM_V3, TAG_V3)
    journal.add_transaction(
        7,
        [[Tag(0x4000, 0x90, escaped=True), Tag(0x4001, 0x91, uuid=None)]],
        commit_sec=COMMIT_SEC,
        commit_nsec=0,
    )
    image, oracle = journal.build()
    tags = list(_first_commit(JDB2(image)).descriptors[0].tags())
    assert [tag.journal_block for tag in tags] == [expected.payload_journal_block for expected in oracle[0].tags]
    assert tags[0].open().read() == _payload(0x90)
