"""
Reproducible diagnostic for dissect.extfs ext4 inline_data extraction.

For each target inode it reports, per logical byte segment:
  - declared i_size
  - what INode.open() actually returns (length + bytes)
  - where each segment physically lives (i_block[0:60] vs system.data xattr)
  - what the generic INode.xattr parser independently recovers
Run against the clean image and the three corruption variants.
"""
import io
import sys
import traceback

from dissect.extfs.extfs import ExtFS
from dissect.extfs.c_ext import c_ext
import stat

TARGETS = ["fill60", "spill61", "spill100", "shortlink", "corrupt"]


def hx(b, n=16):
    return b[:n].hex() + ("..." if len(b) > n else "")


def expected_payload(name):
    # mirror build_image.py deterministic pattern
    if name == "shortlink":
        return b"../short/link/target"
    size = {"fill60": 60, "spill61": 61, "spill100": 100, "corrupt": 100}[name]
    return bytes((i % 251 + 1 for i in range(size)))


def diagnose(path):
    print("#" * 78)
    print(f"# image: {path}")
    print("#" * 78)
    e = ExtFS(open(path, "rb"))
    print(f"block_size={e.block_size} inode_size={e.sb.s_inode_size} "
          f"incompat=0x{e.sb.s_feature_incompat:x} "
          f"(INLINE_DATA bit set: {bool(e.sb.s_feature_incompat & 0x8000)})")

    for name in TARGETS:
        node = e.get(name)
        ino = node.inode
        declared = node.size
        expected = expected_payload(name)
        is_inline = bool(ino.i_flags & c_ext.EXT4_INLINE_DATA_FL)
        is_short_symlink = node.filetype == stat.S_IFLNK and declared < 60

        print("\n" + "=" * 70)
        print(f"[{name}] inum={node.inum} mode=0o{ino.i_mode:o} i_size={declared} "
              f"flags=0x{ino.i_flags:08x} inline_flag={is_inline} "
              f"short_symlink_rule={is_short_symlink}")
        print(f"  physical i_block[0:60] = {hx(ino.i_block, 60)}")
        print(f"  i_extra (ibody region) = {hx(ino.i_extra, 100)}")

        # independent xattr view
        try:
            xattrs = node.xattr
            if xattrs:
                for x in xattrs:
                    ent = x.entry
                    print(f"  xattr[{x.name}] idx={ent.e_name_index} "
                          f"e_value_offs={ent.e_value_offs} e_value_size={ent.e_value_size} "
                          f"value={hx(x.value, 48)}")
            else:
                print("  xattr[] = <none>")
        except Exception as exc:  # noqa: BLE001
            print(f"  xattr[] RAISED {type(exc).__name__}: {exc}")

        # the reader under test
        try:
            fh = node.open()
            got = fh.read()
            print(f"  open().read() -> len={len(got)} bytes={hx(got, 72)}")
            print(f"  stream has .size attr: {hasattr(fh, 'size')} value={getattr(fh, 'size', None)}")
        except Exception as exc:  # noqa: BLE001
            print(f"  open().read() RAISED {type(exc).__name__}: {exc}")
            got = b""

        # segment-level provenance comparison
        head_expected = expected[:60]
        tail_expected = expected[60:]
        head_got = got[:min(60, len(got))]
        print("  -- segment provenance --")
        print(f"  bytes[0:min(60,size)] source=i_block   "
              f"match={head_got == head_expected} ({len(head_got)}/{len(head_expected)} bytes)")
        if tail_expected:
            tail_got = got[60:]
            print(f"  bytes[60:{declared}]       source=system.data xattr "
                  f"recovered={len(tail_got)}/{len(tail_expected)} "
                  f"match={tail_got == tail_expected}")
            print(f"  => truncation: {len(tail_expected) - len(tail_got)} byte(s) of tail lost")
        else:
            print("  bytes[60:..]           <no tail; payload fits i_block>")
        print(f"  full payload match: {got == expected}")


if __name__ == "__main__":
    for p in sys.argv[1:]:
        try:
            diagnose(p)
        except Exception:  # noqa: BLE001
            traceback.print_exc()
