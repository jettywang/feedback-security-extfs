"""
Reference implementation of correct ext4 inline_data read semantics, used only
to demonstrate recoverability. It does NOT modify dissect's product code.

Kernel rule (fs/ext4/inline.c, ext4_read_inline_data):
  * bytes [0, min(size, 60)) always come from i_block ("IFIRST" area).
  * any bytes beyond 60 are stored in the system.data xattr, which may live
    in the in-inode xattr area (i_extra / ibody) OR an external xattr block.
  * If the overflow xattr is missing/corrupt, only the i_block prefix is
    trustworthy; report how far recovery reaches instead of silently lying.
"""
import io
import stat

from dissect.extfs.c_ext import c_ext
from dissect.extfs.exceptions import Error

IFIRST = 60


def reference_open(node):
    ino = node.inode
    is_inline = bool(ino.i_flags & c_ext.EXT4_INLINE_DATA_FL)
    is_short_symlink = node.filetype == stat.S_IFLNK and node.size <= IFIRST
    if not (is_inline or is_short_symlink):
        return None  # caller falls back to RunlistStream (extents/indirect)

    head = bytes(ino.i_block[: min(node.size, IFIRST)])
    if node.size <= IFIRST:
        return io.BytesIO(head), "i_block only", 0, None

    # Need the overflow tail from system.data (name index SYSTEM, name "data").
    tail = b""
    diag = None
    try:
        for x in node.xattr:
            ent = x.entry
            if ent.e_name_index == c_ext.EXT4_XATTR_INDEX_SYSTEM and x._name == "data":
                tail = x.value
                break
        else:
            diag = "system.data xattr not found"
    except Error as exc:
        diag = f"xattr parse error: {exc}"

    recovered = head + tail[: node.size - IFIRST]
    return io.BytesIO(recovered), "i_block + system.data", len(tail), diag


if __name__ == "__main__":
    from dissect.extfs.extfs import ExtFS
    import summary as S

    for label, path in S.VARIANTS.items():
        print("=" * 88)
        print("REFERENCE RECOVERY:", label)
        e = ExtFS(open(path, "rb"))
        for name in S.TARGETS:
            node = e.get(name)
            out = reference_open(node)
            if out is None:
                print(f"  {name:10s} -> RunlistStream fallback (not inline)")
                continue
            fh, source, tail_len, diag = out
            data = fh.read()
            exp = S.expected(name)
            print(f"  {name:10s} declared={node.size:4d} recovered={len(data):4d} "
                  f"complete={data == exp} source={source:24s} tail_bytes={tail_len} "
                  f"warning={diag}")
