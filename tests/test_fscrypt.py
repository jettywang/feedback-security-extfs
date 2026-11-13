from __future__ import annotations

from dissect.extfs.fscrypt import (
    FSCRYPT_CONTEXT_V1_SIZE,
    FSCRYPT_CONTEXT_V2_SIZE,
    EncryptionContext,
)


def test_context_v1() -> None:
    raw = bytes([1, 1, 4, 0]) + bytes.fromhex("0011223344556677") + bytes(range(16))

    context = EncryptionContext.from_raw(raw)

    assert context.status == EncryptionContext.STATUS_PRESENT
    assert context.version == 1
    assert context.contents_encryption_mode == 1
    assert context.filenames_encryption_mode == 4
    assert context.flags == 0
    assert context.master_key_descriptor == bytes.fromhex("0011223344556677")
    assert context.master_key_identifier is None
    assert context.nonce == bytes(range(16))
    assert context.master_key_id == bytes.fromhex("0011223344556677")
    assert context.expected_size == FSCRYPT_CONTEXT_V1_SIZE
    assert context.complete
    assert len(context.raw) == FSCRYPT_CONTEXT_V1_SIZE


def test_context_v2() -> None:
    raw = bytes([2, 1, 4, 0]) + bytes(range(16)) + bytes(range(16, 32))

    context = EncryptionContext.from_raw(raw)

    assert context.status == EncryptionContext.STATUS_PRESENT
    assert context.version == 2
    assert context.master_key_descriptor is None
    assert context.master_key_identifier == bytes(range(16))
    assert context.nonce == bytes(range(16, 32))
    assert context.master_key_id == bytes(range(16))
    assert context.expected_size == FSCRYPT_CONTEXT_V2_SIZE
    assert context.complete


def test_context_unknown_version_is_preserved() -> None:
    raw = bytes([9, 1, 2, 0, 1, 2, 3, 4])

    context = EncryptionContext.from_raw(raw)

    assert context.status == EncryptionContext.STATUS_UNKNOWN_VERSION
    assert context.version == 9
    assert context.raw == raw
    assert not context.known_version
    assert not context.complete
    assert context.expected_size is None
    assert context.to_dict()["raw"] == raw.hex()


def test_context_truncated() -> None:
    raw = bytes([2, 1, 4])

    context = EncryptionContext.from_raw(raw)

    assert context.status == EncryptionContext.STATUS_TRUNCATED
    assert context.version == 2
    assert not context.complete
    assert context.master_key_identifier is None
    assert context.nonce is None
    assert context.to_dict()["raw"] == raw.hex()


def test_context_missing() -> None:
    context = EncryptionContext.missing()

    assert context.status == EncryptionContext.STATUS_MISSING
    assert not context.present
    assert context.raw == b""
