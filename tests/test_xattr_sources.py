from __future__ import annotations

import gzip
import stat
import struct
from pathlib import Path
from typing import BinaryIO

from dissect.extfs.extfs import ExtFS, INode, XAttrReport, XAttrSource, XAttrStatus


def _xattrs(inode: INode) -> dict[str, list]:
    result: dict[str, list] = {}
    for xattr in inode.xattr:
        result.setdefault(xattr.name, []).append(xattr)
    return result


def test_three_sources_are_distinct(ext4_xattr_sources_bin: BinaryIO) -> None:
    extfs = ExtFS(ext4_xattr_sources_bin)
    inode = extfs.get("evidence")

    xattrs = inode.xattr
    by_name = _xattrs(inode)

    assert [xattr.name for xattr in xattrs] == [
        "user.inline",
        "user.shared",
        "user.shared",
        "user.blockonly",
        "security.inline",
        "mystery",
        "user.bad_offset",
        "user.after",
        "user.large",
        "user.eashort",
    ]

    inline = by_name["user.inline"][0]
    assert inline.source is XAttrSource.INODE_BODY
    assert inline.entry_source is XAttrSource.INODE_BODY
    assert inline.value == b"ibody-value"
    assert inline.status is XAttrStatus.OK
    assert inline.entry_offset == 4
    assert inline.value_offset == 4 + inline.e_value_offs

    block = by_name["user.blockonly"][0]
    assert block.source is XAttrSource.EXTERNAL_BLOCK
    assert block.value == b"external-block-value"
    assert block.status is XAttrStatus.OK
    assert block.entry_offset > 0
    assert block.value_offset == block.e_value_offs

    eainode = by_name["user.large"][0]
    assert eainode.source is XAttrSource.EA_INODE
    assert eainode.entry_source is XAttrSource.EXTERNAL_BLOCK
    assert eainode.value == b"EA" * 100
    assert eainode.status is XAttrStatus.OK
    assert eainode.eainode_inum == 15
    assert eainode.eainode is not None
    assert eainode.eainode.inum == 15
    assert eainode.value_offset is None

    # Every attribute resolves to exactly one of the three value sources.
    assert inline.source is XAttrSource.INODE_BODY
    assert block.source is XAttrSource.EXTERNAL_BLOCK
    assert eainode.source is XAttrSource.EA_INODE


def test_duplicate_names_keep_separate_evidence(ext4_xattr_sources_bin: BinaryIO) -> None:
    extfs = ExtFS(ext4_xattr_sources_bin)
    inode = extfs.get("evidence")

    duplicates = inode.get_xattrs("user.shared")
    assert len(duplicates) == 2
    assert inode.get_xattr("user.shared") is duplicates[0]

    assert duplicates[0].source is XAttrSource.INODE_BODY
    assert duplicates[0].value == b"from-inode"
    assert duplicates[1].source is XAttrSource.EXTERNAL_BLOCK
    assert duplicates[1].value == b"from-block"
    assert duplicates[0].status is XAttrStatus.OK
    assert duplicates[1].status is XAttrStatus.DUPLICATE_NAME
    assert duplicates[1].value_complete
    assert duplicates[1].issues[0].status is XAttrStatus.DUPLICATE_NAME


def test_same_name_in_another_namespace_is_not_a_duplicate(ext4_xattr_sources_bin: BinaryIO) -> None:
    extfs = ExtFS(ext4_xattr_sources_bin)
    inode = extfs.get("evidence")

    inline = inode.get_xattr("user.inline")
    security = inode.get_xattr("security.inline")
    assert inline is not None and security is not None
    assert inline.status is XAttrStatus.OK
    assert security.status is XAttrStatus.OK
    assert security.namespace_index == 6
    assert security.value == b"security-inline"


def test_unknown_namespace_is_preserved(ext4_xattr_sources_bin: BinaryIO) -> None:
    extfs = ExtFS(ext4_xattr_sources_bin)
    inode = extfs.get("evidence")

    unknown = inode.get_xattr("mystery")
    assert unknown is not None
    assert unknown.namespace_index == 12
    assert unknown.namespace_known is False
    assert unknown.prefix is None
    assert unknown.name == "mystery"
    assert unknown.raw_name == b"mystery"
    assert unknown.value == b"raw-ns-value"
    assert unknown.status is XAttrStatus.UNKNOWN_NAMESPACE
    assert unknown.value_complete
    assert unknown.issues[0].status is XAttrStatus.UNKNOWN_NAMESPACE


def test_out_of_range_value_offset_is_not_truncated(ext4_xattr_sources_bin: BinaryIO) -> None:
    extfs = ExtFS(ext4_xattr_sources_bin)
    inode = extfs.get("evidence")

    bad = inode.get_xattr("user.bad_offset")
    assert bad is not None
    assert bad.source is XAttrSource.EXTERNAL_BLOCK
    assert bad.status is XAttrStatus.INVALID_VALUE_OFFSET
    assert bad.value is None
    assert bad.value_complete is False
    assert bad.issues[0].status is XAttrStatus.INVALID_VALUE_OFFSET


def test_short_external_value_keeps_readable_prefix(ext4_xattr_sources_bin: BinaryIO) -> None:
    extfs = ExtFS(ext4_xattr_sources_bin)
    inode = extfs.get("short_value")

    short = inode.get_xattr("user.short")
    assert short is not None
    assert short.source is XAttrSource.EXTERNAL_BLOCK
    assert short.status is XAttrStatus.TRUNCATED_VALUE
    assert short.value == b"0123456789"
    assert short.value_size == 40
    assert len(short.value) < short.value_size
    assert short.value_complete is False
    assert short.issues[0].status is XAttrStatus.TRUNCATED_VALUE


def test_short_ea_inode_value_is_marked(ext4_xattr_sources_bin: BinaryIO) -> None:
    extfs = ExtFS(ext4_xattr_sources_bin)
    inode = extfs.get("evidence")

    short_ea = inode.get_xattr("user.eashort")
    assert short_ea is not None
    assert short_ea.eainode_inum == 16
    assert short_ea.status is XAttrStatus.TRUNCATED_EA_VALUE
    assert short_ea.value == b"0123456789"
    assert short_ea.value_complete is False
    assert short_ea.issues[0].status is XAttrStatus.TRUNCATED_EA_VALUE


def test_damaged_block_does_not_hide_inode_body(ext4_xattr_sources_bin: BinaryIO) -> None:
    extfs = ExtFS(ext4_xattr_sources_bin)
    inode = extfs.get("damaged_block")

    assert inode.inode.i_file_acl_lo == 102
    assert [issue.status for issue in inode.xattr_issues] == [XAttrStatus.MALFORMED]
    assert "Invalid external xattr block magic" in inode.xattr_issues[0].detail

    assert [xattr.name for xattr in inode.xattr] == ["user.ibody_ok"]
    ok = inode.xattr[0]
    assert ok.source is XAttrSource.INODE_BODY
    assert ok.value == b"ibody-value"
    assert ok.status is XAttrStatus.OK


def test_damaged_inode_body_does_not_hide_external_block(ext4_xattr_sources_bin: BinaryIO) -> None:
    extfs = ExtFS(ext4_xattr_sources_bin)
    inode = extfs.get("damaged_ibody")

    assert [issue.status for issue in inode.xattr_issues] == [XAttrStatus.MALFORMED]
    assert "Invalid inode-body xattr magic" in inode.xattr_issues[0].detail

    assert [xattr.name for xattr in inode.xattr] == ["system.posix_acl_access"]
    acl = inode.xattr[0]
    assert acl.source is XAttrSource.EXTERNAL_BLOCK
    assert acl.value == b"\x02\x00\x00\x00"
    assert acl.status is XAttrStatus.OK


def test_inode_with_only_external_block(ext4_xattr_sources_bin: BinaryIO) -> None:
    extfs = ExtFS(ext4_xattr_sources_bin)
    inode = extfs.get("block_only")

    assert not inode.inode.i_extra.strip(b"\x00")
    assert [xattr.name for xattr in inode.xattr] == ["system.posix_acl_access"]
    assert inode.xattr[0].source is XAttrSource.EXTERNAL_BLOCK


def test_legacy_list_still_works(ext4_bin: BinaryIO) -> None:
    extfs = ExtFS(ext4_bin)
    inode = extfs.get("xattr_cap")

    assert isinstance(inode.xattr, list)
    assert inode.xattr is inode.xattr
    assert inode.xattr is not inode.xattrs()
    xattrs = inode.xattr
    assert len(xattrs) == 2
    assert xattrs[0].name == "security.selinux"
    assert xattrs[0].value == b"unconfined_u:object_r:unlabeled_t:s0\x00"
    assert xattrs[1].name == "security.capability"
    # Old callers did not see provenance; both attributes came from the same block.
    assert {xattr.source for xattr in xattrs} == {XAttrSource.EXTERNAL_BLOCK}


def test_inode_body_sample_reports_source(ext4_sparse_bin: BinaryIO) -> None:
    extfs = ExtFS(ext4_sparse_bin)
    inode = extfs.get_inode(12)

    assert len(inode.xattr) == 1
    xattr = inode.xattr[0]
    assert xattr.source is XAttrSource.INODE_BODY
    assert xattr.name == "security.selinux"
    assert xattr.value == b"unconfined_u:object_r:unlabeled_t:s0\x00"
    assert xattr.status is XAttrStatus.OK
    assert xattr.value_offset == 56


def test_filetype_unchanged(ext4_xattr_sources_bin: BinaryIO) -> None:
    extfs = ExtFS(ext4_xattr_sources_bin)
    assert extfs.get("evidence").filetype == stat.S_IFREG
    assert extfs.get("block_only").filetype == stat.S_IFREG


def test_damage_in_one_attribute_keeps_others_readable(ext4_xattr_sources_bin: BinaryIO) -> None:
    extfs = ExtFS(ext4_xattr_sources_bin)
    inode = extfs.get("evidence")

    names = [xattr.name for xattr in inode.xattr]
    assert "user.bad_offset" in names
    assert "user.eashort" in names
    assert "user.after" in names

    bad = inode.get_xattr("user.bad_offset")
    assert bad is not None and not bad.value_complete
    short = inode.get_xattr("user.eashort")
    assert short is not None and not short.value_complete

    for name in ("user.inline", "user.blockonly", "user.after", "user.large"):
        xattr = inode.get_xattr(name)
        assert xattr is not None
        assert xattr.value_complete
        assert xattr.value is not None

    assert inode.get_xattr("user.after").value == b"read-after-damage"


def test_invalid_ea_inode_number_is_isolated() -> None:
    """An out-of-range EA inode must not abort sibling attributes."""
    from dissect.extfs import extfs as extfs_module

    class FakeExtFS:
        sb = type("SB", (), {"s_inodes_count": 32, "s_inode_size": 256})()
        block_size = 1024
        last_block = 2047

        def get_inode(self, inum: int) -> INode:
            if inum != 12:
                raise extfs_module.Error("inode out of range")
            return INode(self, 12)  # type: ignore[arg-type]

    inode = INode(FakeExtFS(), 12)  # type: ignore[arg-type]
    data = bytearray(1024)
    data[0:4] = (0xEA020000).to_bytes(4, "little")

    def entry(at: int, name: bytes, *, offs: int = 0, inum: int = 0, size: int = 0) -> int:
        header = bytes([len(name), 1, offs & 0xFF, offs >> 8])
        header += inum.to_bytes(4, "little") + size.to_bytes(4, "little") + b"\x00" * 4
        raw = header + name
        data[at : at + len(raw)] = raw
        padded = (len(raw) + 3) & ~3
        data[at + len(raw) : at + padded] = b"\x00" * (padded - len(raw))
        return at + padded

    first = entry(32, b"valid", offs=1000, size=5)
    second = entry(first, b"broken", inum=99, size=4)
    data[second : second + 4] = b"\x00" * 4
    data[1000:1005] = b"hello"

    issues: list = []
    seen: dict = {}
    xattrs = extfs_module._parse_xattr_container(
        inode, bytes(data), 0, 32, extfs_module.XAttrSource.EXTERNAL_BLOCK, seen, issues
    )
    assert [x.name for x in xattrs] == ["user.valid", "user.broken"]
    assert xattrs[0].status is extfs_module.XAttrStatus.OK
    assert xattrs[0].value == b"hello"
    assert xattrs[1].status is extfs_module.XAttrStatus.INVALID_EA_INODE


def test_report_groups_by_source_and_surfaces_damage(ext4_xattr_sources_bin: BinaryIO) -> None:
    extfs = ExtFS(ext4_xattr_sources_bin)
    report = extfs.get("evidence").xattr_report()

    assert isinstance(report, XAttrReport)
    assert [x.name for x in report.by_source[XAttrSource.INODE_BODY]] == ["user.inline", "user.shared"]
    assert [x.name for x in report.by_source[XAttrSource.EA_INODE]] == ["user.large", "user.eashort"]
    assert report.complete is False
    assert {x.name for x in report.damaged} == {"user.bad_offset", "user.eashort"}
    assert {x.name for x in report.anomalous} == {
        "user.shared",
        "mystery",
        "user.bad_offset",
        "user.eashort",
    }
    assert report.container_issues == ()


def test_value_damage_is_not_hidden_by_naming_status(ext4_xattr_sources_bin: BinaryIO) -> None:
    extfs = ExtFS(ext4_xattr_sources_bin)
    inode = extfs.get("short_value")

    truncated = inode.get_xattr("mystery_truncated")
    assert truncated is not None
    assert truncated.namespace_known is False
    assert truncated.status is XAttrStatus.TRUNCATED_VALUE
    assert truncated.value_complete is False
    issue_statuses = {issue.status for issue in truncated.issues}
    assert issue_statuses == {XAttrStatus.UNKNOWN_NAMESPACE, XAttrStatus.TRUNCATED_VALUE}


def test_values_match_physical_bytes_for_each_source(ext4_xattr_sources_bin: BinaryIO) -> None:
    """Every intact value must equal the bytes at the location its source names."""
    raw = gzip.open(Path(__file__).parent / "data" / "xattr_sources.bin.gz", "rb").read()
    extfs = ExtFS(ext4_xattr_sources_bin)
    block_size = extfs.block_size

    verified = 0
    for name in ("evidence", "short_value"):
        inode = extfs.get(name)
        inode_offset = inode.inode_offset()
        extra_isize = inode.inode.i_extra_isize
        for xattr in inode.xattr:
            if not xattr.value_complete:
                continue

            if xattr.entry_source is XAttrSource.INODE_BODY:
                physical = inode_offset + 128 + extra_isize + xattr.value_offset
            elif xattr.source is XAttrSource.EXTERNAL_BLOCK:
                physical = inode.inode.i_file_acl_lo * block_size + xattr.value_offset
            else:
                assert xattr.eainode is not None
                physical = struct.unpack("<I", xattr.eainode.inode.i_block[0:4])[0] * block_size

            assert raw[physical : physical + xattr.e_value_size] == xattr.value, xattr.name
            verified += 1

    assert verified >= 8


def test_short_external_block_read_preserves_inode_body(ext4_xattr_sources_bin: BinaryIO) -> None:
    import io

    raw = gzip.open(Path(__file__).parent / "data" / "xattr_sources.bin.gz", "rb").read()
    # Truncate just after the start of external block 100 so its read is short.
    truncated = io.BytesIO(raw[: 100 * 1024 + 8])

    extfs = ExtFS(truncated)
    inode = extfs.get("evidence")

    assert [issue.status for issue in inode.xattr_issues] == [XAttrStatus.MALFORMED]
    assert "Truncated external xattr block 100" in inode.xattr_issues[0].detail
    assert [(x.name, x.source) for x in inode.xattr] == [
        ("user.inline", XAttrSource.INODE_BODY),
        ("user.shared", XAttrSource.INODE_BODY),
    ]
