from __future__ import annotations

import json
import stat
from pathlib import Path
from typing import TYPE_CHECKING

from dissect.extfs import EncryptionContext, ExtFS
from dissect.extfs.c_ext import XATTR_PREFIX_MAP, c_ext
from dissect.extfs.fscrypt import FSCRYPT_CONTEXT_V1_SIZE

if TYPE_CHECKING:
    from typing import BinaryIO


def test_plain_directory_unchanged(ext4_encrypted_bin: BinaryIO) -> None:
    extfs = ExtFS(ext4_encrypted_bin)

    root = extfs.root
    assert sorted(root.dirlist().keys()) == [".", "..", "locked", "nocontext", "odd", "plain", "report.txt"]

    plain = extfs.get("plain")
    assert plain.encrypted is False
    assert plain.encryption_context.status == EncryptionContext.STATUS_MISSING
    assert sorted(plain.dirlist().keys()) == [".", "..", "alpha", "beta"]

    assert extfs.get("plain/alpha").open().read() == b"alpha\n"
    assert extfs.get("plain/beta").open().read() == b"beta\n"


def test_encrypted_directory_names_are_explicit(ext4_encrypted_bin: BinaryIO) -> None:
    extfs = ExtFS(ext4_encrypted_bin)
    locked = extfs.get("locked")

    assert locked.encrypted is True
    assert locked.encryption_context.status == EncryptionContext.STATUS_PRESENT
    assert locked.encryption_context.version == 1
    assert locked.encryption_context.complete
    assert len(locked.encryption_context.raw) == FSCRYPT_CONTEXT_V1_SIZE
    assert locked.encryption_context.master_key_descriptor == bytes.fromhex("0011223344556677")

    entries = [entry for entry in locked.iterdir_entries() if entry.is_encrypted]
    assert len(entries) == 3

    for entry in entries:
        assert entry.raw_name is not None
        assert entry.path_name.startswith("fscrypt:")
        assert entry.path_name == f"fscrypt:{entry.raw_name.hex()}"
        assert entry.raw_name.decode(errors="surrogateescape") == entry.name
        assert entry.encryption_context is locked.encryption_context

    # Two entries share the same raw name; neither may be merged away.
    shared = [entry for entry in entries if entry.raw_name == bytes([0x2E, 0x80, 0xFF, 0x41, 0x00, 0x9C])]
    assert len(shared) == 2
    assert shared[0].entry_id != shared[1].entry_id
    assert shared[0].inode().inum != shared[1].inode().inum


def test_encrypted_directory_listdir_does_not_merge(ext4_encrypted_bin: BinaryIO) -> None:
    extfs = ExtFS(ext4_encrypted_bin)
    locked = extfs.get("locked")

    listing = locked.listdir()
    assert len(listing) == 5

    encrypted_keys = [key for key in listing if key.startswith("11:")]
    assert len(encrypted_keys) == 3
    assert len(set(encrypted_keys)) == 3


def test_unknown_and_missing_context_are_preserved(ext4_encrypted_bin: BinaryIO) -> None:
    extfs = ExtFS(ext4_encrypted_bin)

    odd = extfs.get("odd")
    assert odd.encrypted is True
    assert odd.encryption_context.status == EncryptionContext.STATUS_UNKNOWN_VERSION
    assert odd.encryption_context.version == 9
    assert odd.encryption_context.raw == bytes([9, 1, 2, 0, 1, 2, 3, 4])

    nocontext = extfs.get("nocontext")
    assert nocontext.encrypted is True
    assert nocontext.encryption_context.status == EncryptionContext.STATUS_MISSING
    assert nocontext.encryption_context.raw == b""

    entry = next(entry for entry in nocontext.iterdir_entries() if entry.is_encrypted)
    assert entry.encryption_context.status == EncryptionContext.STATUS_MISSING
    assert entry.path_name == f"fscrypt:{entry.raw_name.hex()}"


def test_truncated_context_is_preserved(ext4_encrypted_bin: BinaryIO) -> None:
    extfs = ExtFS(ext4_encrypted_bin)
    locked = extfs.get("locked")

    entry = next(entry for entry in locked.iterdir_entries() if entry.inum == 15)
    inode = entry.inode()
    context = inode.encryption_context

    assert context.status == EncryptionContext.STATUS_TRUNCATED
    assert context.version == 2
    assert not context.complete
    assert context.raw == bytes([2, 1, 2])


def test_path_lookup_does_not_guess_encrypted_names(ext4_encrypted_bin: BinaryIO) -> None:
    extfs = ExtFS(ext4_encrypted_bin)

    try:
        extfs.get("locked/locked")
    except FileNotFoundError as e:
        assert "encrypted directory" in str(e)
    else:
        raise AssertionError("path lookup through an encrypted directory should not guess")


def test_dot_entries_are_not_reported_as_encrypted(ext4_encrypted_bin: BinaryIO) -> None:
    extfs = ExtFS(ext4_encrypted_bin)

    for name in ("locked", "odd", "nocontext"):
        entries = extfs.get(name).iterdir_entries()

        dot = next(entry for entry in entries if entry.raw_name == b".")
        dotdot = next(entry for entry in entries if entry.raw_name == b"..")

        assert dot.is_encrypted is False
        assert dot.path_name == "."
        assert dotdot.is_encrypted is False
        assert dotdot.path_name == ".."


def test_mixed_name_index_is_reversible(ext4_encrypted_bin: BinaryIO) -> None:
    extfs = ExtFS(ext4_encrypted_bin)
    index = extfs.name_index()

    data = index.to_dict()
    assert data["kind"] == "extfs.name_index"
    assert data["source_uuid"] == "00112233-4455-6677-8899-aabbccddeeff"
    assert data["root_inode"] == 2
    assert data["entry_count"] == len(index) == 22

    encrypted = [entry for entry in index.entries if entry.is_encrypted]
    plain = [entry for entry in index.entries if not entry.is_encrypted]
    assert len(encrypted) == 5
    assert len(plain) == 17

    for entry in index.entries:
        record = data["entries"][entry.entry_id]

        assert record["directory_inode"] == entry.directory.inum
        assert record["inode"] == entry.inum
        assert record["offset"] == entry.offset
        assert record["raw_name"] == entry.raw_name.hex()
        assert record["name_length"] == len(entry.raw_name)
        assert record["disk_offset"] == entry.disk_offset

        if entry.is_encrypted:
            assert record["encrypted"] is True
            assert record["display_name_is_path"] is False
            assert record["path_name"] == f"fscrypt:{entry.raw_name.hex()}"
            assert record["encryption_context"] is not None
        else:
            assert record["encrypted"] is False
            assert record["display_name_is_path"] is True
            assert record["path_name"] == entry.name
            assert record["encryption_context"] is None

    # Every entry id resolves to the same raw bytes that are stored at that directory offset.
    for entry_id in index:
        entry = index.resolve(entry_id)
        raw = entry.directory.open().read()

        inum = int.from_bytes(raw[entry.offset : entry.offset + 4], "little")
        rec_len = int.from_bytes(raw[entry.offset + 4 : entry.offset + 6], "little")
        name_len = raw[entry.offset + 6]
        name = raw[entry.offset + 8 : entry.offset + 8 + name_len]

        assert inum == entry.inum
        assert rec_len == entry.rec_len
        assert name == entry.raw_name

    assert index.verify() == []


def test_committed_name_index_matches_evidence(ext4_encrypted_bin: BinaryIO) -> None:
    path = Path(__file__).parent / "data" / "ext4_encrypted.name_index.json"
    data = json.loads(path.read_text())

    extfs = ExtFS(ext4_encrypted_bin)
    assert extfs.name_index().to_dict() == data


def test_mixed_name_index_json_roundtrip(ext4_encrypted_bin: BinaryIO) -> None:
    extfs = ExtFS(ext4_encrypted_bin)
    index = extfs.name_index()
    encoded = index.to_json()

    decoded = json.loads(encoded)
    assert decoded["source_uuid"] == "00112233-4455-6677-8899-aabbccddeeff"
    assert "fscrypt:" in encoded
    # Surrogate escapes must never be emitted as raw invalid characters in the JSON document.
    encoded.encode("utf-8")

    restored = type(index).from_dict(extfs, decoded)
    assert restored.to_dict() == index.to_dict()
    assert restored.verify() == []


def test_encrypted_entries_keep_parent_and_context(ext4_encrypted_bin: BinaryIO) -> None:
    extfs = ExtFS(ext4_encrypted_bin)
    locked = extfs.get("locked")

    for entry in locked.iterdir_entries():
        inode = entry.inode()

        assert inode.parent is locked
        assert inode.raw_name == entry.raw_name
        assert inode.name_encrypted is entry.is_encrypted

        if entry.is_encrypted:
            assert inode.name_encryption_context is locked.encryption_context
        else:
            assert inode.name_encryption_context is None

    # Ordinary entries still resolve normally and keep their plaintext names.
    plain = extfs.get("plain")
    assert [node.inum for node in plain.iterdir()] == [10, 2, 12, 13]
    assert stat.S_ISDIR(plain.filetype)


def test_encryption_xattr_name_is_visible(ext4_encrypted_bin: BinaryIO) -> None:
    extfs = ExtFS(ext4_encrypted_bin)

    assert XATTR_PREFIX_MAP[c_ext.EXT4_XATTR_INDEX_ENCRYPTION] == "encryption."

    locked = extfs.get("locked")
    assert any(xattr.name == "encryption.c" for xattr in locked.xattr)
