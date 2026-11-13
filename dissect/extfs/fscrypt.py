from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping

FSCRYPT_CONTEXT_V1 = 1
FSCRYPT_CONTEXT_V2 = 2

#: Names of the widely deployed fscrypt modes. Unknown numeric modes are preserved unchanged in the context.
FSCRYPT_MODE_NAMES: Mapping[int, str] = {
    0x01: "AES-256-XTS",
    0x02: "AES-256-CTS",
    0x03: "AES-128-CBC",
    0x04: "AES-128-CTS",
}

FSCRYPT_POLICY_FLAG_NAMES: Mapping[int, str] = {
    0x04: "DIRECT_KEY",
    0x08: "IV_INO_LBLK_64",
    0x10: "IV_INO_LBLK_32",
}

FSCRYPT_CONTEXT_V1_SIZE = 28
FSCRYPT_CONTEXT_V2_SIZE = 36


class EncryptionContext:
    """A parsed fscrypt encryption context, as stored in an inode attribute.

    The on-disk format is ``fscrypt_context_v1`` (version 1) or ``fscrypt_context_v2`` (version 2). Version 2
    replaced the 8-byte master key descriptor with a 16-byte master key identifier; the nonce is 16 bytes in both.

    The context is evidence: it is returned even when its version is unknown, it is truncated or a required field
    is not available. The original attribute value is always preserved in :attr:`raw`.
    """

    STATUS_PRESENT = "present"
    STATUS_MISSING = "missing"
    STATUS_UNKNOWN_VERSION = "unknown_version"
    STATUS_TRUNCATED = "truncated"
    STATUS_UNREADABLE = "unreadable"

    def __init__(
        self,
        raw: bytes = b"",
        *,
        status: str = STATUS_MISSING,
        version: int | None = None,
        contents_encryption_mode: int | None = None,
        filenames_encryption_mode: int | None = None,
        flags: int | None = None,
        master_key_descriptor: bytes | None = None,
        master_key_identifier: bytes | None = None,
        nonce: bytes | None = None,
        trailing: bytes = b"",
        xattr_name: str | None = None,
        error: str | None = None,
    ):
        self.raw = raw
        self.status = status
        self.version = version
        self.contents_encryption_mode = contents_encryption_mode
        self.filenames_encryption_mode = filenames_encryption_mode
        self.flags = flags
        self.master_key_descriptor = master_key_descriptor
        self.master_key_identifier = master_key_identifier
        self.nonce = nonce
        self.trailing = trailing
        self.xattr_name = xattr_name
        self.error = error

    def __repr__(self) -> str:
        return f"<EncryptionContext version={self.version!r} status={self.status}>"

    @property
    def present(self) -> bool:
        return self.status != self.STATUS_MISSING

    @property
    def known_version(self) -> bool:
        return self.version in (FSCRYPT_CONTEXT_V1, FSCRYPT_CONTEXT_V2)

    @property
    def complete(self) -> bool:
        if not self.known_version:
            return False

        return self.expected_size is not None and len(self.raw) >= self.expected_size

    @property
    def expected_size(self) -> int | None:
        if self.version == FSCRYPT_CONTEXT_V1:
            return FSCRYPT_CONTEXT_V1_SIZE
        if self.version == FSCRYPT_CONTEXT_V2:
            return FSCRYPT_CONTEXT_V2_SIZE
        return None

    @property
    def contents_encryption_mode_name(self) -> str | None:
        return FSCRYPT_MODE_NAMES.get(self.contents_encryption_mode)

    @property
    def filenames_encryption_mode_name(self) -> str | None:
        return FSCRYPT_MODE_NAMES.get(self.filenames_encryption_mode)

    @property
    def flag_names(self) -> list[str]:
        """The known policy flag names set on this context."""
        if self.flags is None:
            return []
        return [name for bit, name in FSCRYPT_POLICY_FLAG_NAMES.items() if self.flags & bit]

    @property
    def master_key_id(self) -> bytes | None:
        """The v1 descriptor or v2 identifier, whichever is available."""
        if self.master_key_identifier is not None:
            return self.master_key_identifier
        return self.master_key_descriptor

    @classmethod
    def missing(cls) -> EncryptionContext:
        return cls(status=cls.STATUS_MISSING)

    @classmethod
    def from_raw(cls, raw: bytes, *, xattr_name: str | None = None) -> EncryptionContext:
        """Parse an encryption context without rejecting unknown or incomplete data."""
        if not raw:
            return cls(raw=raw, status=cls.STATUS_TRUNCATED, xattr_name=xattr_name)

        version = raw[0]
        if version not in (FSCRYPT_CONTEXT_V1, FSCRYPT_CONTEXT_V2):
            return cls(
                raw=raw,
                status=cls.STATUS_UNKNOWN_VERSION,
                version=version,
                xattr_name=xattr_name,
            )

        common = {
            "raw": raw,
            "version": version,
            "contents_encryption_mode": raw[1] if len(raw) >= 2 else None,
            "filenames_encryption_mode": raw[2] if len(raw) >= 3 else None,
            "flags": raw[3] if len(raw) >= 4 else None,
            "xattr_name": xattr_name,
        }

        expected_size = FSCRYPT_CONTEXT_V1_SIZE if version == FSCRYPT_CONTEXT_V1 else FSCRYPT_CONTEXT_V2_SIZE
        status = cls.STATUS_PRESENT if len(raw) >= expected_size else cls.STATUS_TRUNCATED

        if version == FSCRYPT_CONTEXT_V1:
            common["master_key_descriptor"] = raw[4:12] if len(raw) >= 12 else None
            common["nonce"] = raw[12:28] if len(raw) >= 28 else None
        else:
            common["master_key_identifier"] = raw[4:20] if len(raw) >= 20 else None
            common["nonce"] = raw[20:36] if len(raw) >= 36 else None

        if len(raw) > expected_size:
            # Keep the extra bytes as evidence instead of silently discarding them
            common["trailing"] = raw[expected_size:]

        return cls(status=status, **common)

    def to_dict(self) -> dict:
        """Return a JSON-serializable representation that keeps the original bytes."""
        return {
            "status": self.status,
            "present": self.present,
            "version": self.version,
            "known_version": self.known_version,
            "complete": self.complete,
            "expected_size": self.expected_size,
            "contents_encryption_mode": self.contents_encryption_mode,
            "contents_encryption_mode_name": self.contents_encryption_mode_name,
            "filenames_encryption_mode": self.filenames_encryption_mode,
            "filenames_encryption_mode_name": self.filenames_encryption_mode_name,
            "flags": self.flags,
            "flag_names": self.flag_names,
            "master_key_descriptor": self.master_key_descriptor.hex() if self.master_key_descriptor else None,
            "master_key_identifier": self.master_key_identifier.hex() if self.master_key_identifier else None,
            "nonce": self.nonce.hex() if self.nonce else None,
            "trailing": self.trailing.hex(),
            "xattr_name": self.xattr_name,
            "raw": self.raw.hex(),
            "error": self.error,
        }
