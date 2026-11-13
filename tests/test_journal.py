from __future__ import annotations

import struct
from io import BytesIO

import pytest

from dissect.extfs.journal import JDB2

BLOCK_SIZE = 1024
MAGIC = 0xC03B3998

DESCRIPTOR_BLOCK = 1
COMMIT_BLOCK = 2
SUPERBLOCK_V2 = 4
REVOKE_BLOCK = 5

FLAG_LAST_TAG = 0x8


def _header(blocktype: int, sequence: int) -> bytes:
    return struct.pack(">III", MAGIC, blocktype, sequence & 0xFFFFFFFF)


def _superblock(maxlen: int, sequence: int, first: int = 1) -> bytes:
    buf = bytearray(BLOCK_SIZE)
    buf[0:12] = _header(SUPERBLOCK_V2, 0)
    struct.pack_into(">IIII", buf, 12, BLOCK_SIZE, maxlen, first, sequence & 0xFFFFFFFF)
    return bytes(buf)


def _descriptor(sequence: int, fs_block: int) -> bytes:
    tag = struct.pack(">IHHI", fs_block, 0, FLAG_LAST_TAG, 0)
    return _header(DESCRIPTOR_BLOCK, sequence) + tag


def _commit(sequence: int, sec: int = 1_700_000_000) -> bytes:
    return _header(COMMIT_BLOCK, sequence) + struct.pack(">BBH", 0, 0, 0) + b"\x00" * 32 + struct.pack(">QI", sec, 0)


def _revoke(sequence: int, *fs_blocks: int) -> bytes:
    count = 16 + 4 * len(fs_blocks)
    entries = b"".join(struct.pack(">I", fs_block) for fs_block in fs_blocks)
    return _header(REVOKE_BLOCK, sequence) + struct.pack(">I", count) + entries


def _journal(sequence: int, blocks: dict[int, bytes]) -> BytesIO:
    maxlen = max(blocks) + 1
    buf = bytearray(BLOCK_SIZE * maxlen)
    buf[0:BLOCK_SIZE] = _superblock(maxlen, sequence)
    for block_num, content in blocks.items():
        buf[block_num * BLOCK_SIZE : (block_num + 1) * BLOCK_SIZE] = content.ljust(BLOCK_SIZE, b"\x00")
    return BytesIO(bytes(buf))


@pytest.fixture
def journal_bin() -> BytesIO:
    """In-memory journal for filesystem block 100 with five transactions.

    - seq 1 and 2: committed updates ("version-1", "version-2")
    - seq 3: committed but block 100 revoked ("version-3-revoked")
    - seq 4: committed rewrite after the revoke ("version-4")
    - seq 5: descriptor without commit ("version-5-uncommitted")
    """
    return _journal(
        1,
        {
            1: _descriptor(1, 100),
            2: b"version-1",
            3: _commit(1, sec=1000),
            4: _descriptor(2, 100),
            5: b"version-2",
            6: _commit(2, sec=2000),
            7: _descriptor(3, 100),
            8: b"version-3-revoked",
            9: _revoke(3, 100),
            10: _commit(3, sec=3000),
            11: _descriptor(4, 100),
            12: b"version-4",
            13: _commit(4, sec=4000),
            14: _descriptor(5, 100),
            15: b"version-5-uncommitted",
        },
    )


def test_block_history(journal_bin: BytesIO) -> None:
    jdb2 = JDB2(journal_bin)
    history = jdb2.block_history(100)

    assert [version.sequence for version in history] == [1, 2, 3, 4, 5]
    assert [version.valid for version in history] == [True, True, False, True, False]

    # Journal and commit locations are preserved per version
    assert [version.journal_block for version in history] == [2, 5, 8, 12, 15]
    assert [version.commit_block for version in history] == [3, 6, 10, 13, None]

    # Every version explains why it is usable or excluded
    assert "committed" in history[0].reason
    assert "revoked" in history[2].reason
    assert "no commit" in history[4].reason

    # Only valid versions are readable as committed content
    valid_data = [version.open().read().rstrip(b"\x00") for version in history if version.valid]
    assert valid_data == [b"version-1", b"version-2", b"version-4"]

    # Revoked and uncommitted versions are still inspectable read-only
    assert history[2].open().read().rstrip(b"\x00") == b"version-3-revoked"
    assert history[4].open().read().rstrip(b"\x00") == b"version-5-uncommitted"


def test_block_history_unknown_block(journal_bin: BytesIO) -> None:
    assert JDB2(journal_bin).block_history(999) == []


def test_transactions(journal_bin: BytesIO) -> None:
    transactions = JDB2(journal_bin).transactions()

    assert [transaction.sequence for transaction in transactions] == [1, 2, 3, 4, 5]
    assert [transaction.committed for transaction in transactions] == [True, True, True, True, False]
    assert transactions[2].revoked_blocks == {100: 9}


def test_scan_order_is_not_commit_order() -> None:
    """A journal that wrapped around the ring stores newer transactions first."""
    journal_bin = _journal(
        1,
        {
            1: _descriptor(2, 100),
            2: b"newer",
            3: _commit(2, sec=2000),
            4: _descriptor(1, 100),
            5: b"older",
            6: _commit(1, sec=1000),
        },
    )

    history = JDB2(journal_bin).block_history(100)

    assert [version.sequence for version in history] == [1, 2]
    assert [version.open().read().rstrip(b"\x00") for version in history] == [b"older", b"newer"]


def test_sequence_number_wraparound() -> None:
    """Sequence numbers wrap at 2**32; ordering must follow the wrap."""
    journal_bin = _journal(
        0xFFFFFFFF,
        {
            1: _descriptor(0xFFFFFFFF, 100),
            2: b"before-wrap",
            3: _commit(0xFFFFFFFF, sec=1000),
            4: _descriptor(0, 100),
            5: b"after-wrap",
            6: _commit(0, sec=2000),
        },
    )

    history = JDB2(journal_bin).block_history(100)

    assert [version.sequence for version in history] == [0xFFFFFFFF, 0]
    assert [version.open().read().rstrip(b"\x00") for version in history] == [b"before-wrap", b"after-wrap"]


def test_half_transaction_only() -> None:
    """A capture that only contains half a transaction yields no valid versions."""
    journal_bin = _journal(
        7,
        {
            1: _descriptor(7, 100),
            2: b"never-committed",
        },
    )

    history = JDB2(journal_bin).block_history(100)

    assert len(history) == 1
    assert not history[0].valid
    assert "no commit" in history[0].reason
    assert history[0].commit_block is None
