"""Concise reproducible summary table across all image variants."""
import stat
from dissect.extfs.extfs import ExtFS
from dissect.extfs.c_ext import c_ext

VARIANTS = {
    "clean": "img_none.img",
    "xattr magic corrupted": "img_bad_magic.img",
    "xattr value offset corrupted": "img_bad_value_offs.img",
    "xattr entry erased": "img_entry_erased.img",
}
TARGETS = ["fill60", "spill61", "spill100", "shortlink", "corrupt"]
DECLARED = {"fill60": 60, "spill61": 61, "spill100": 100, "shortlink": 20, "corrupt": 100}


def expected(name):
    if name == "shortlink":
        return b"../short/link/target"
    return bytes((i % 251 + 1 for i in range(DECLARED[name])))


def xattr_state(node):
    # Distinguish three states: fully-zero area (no xattr), valid magic, or
    # non-zero area with a broken magic (genuine corruption).
    region = node.inode.i_extra
    magic_ok = region[:4] == c_ext.EXT4_XATTR_MAGIC.to_bytes(4, "little")
    area_in_use = any(region[:4])  # magic slot all-zero => no ibody xattr
    try:
        xs = node.xattr
        if not xs:
            return "no ibody xattr (clean)" if not area_in_use else "xattr area empty"
        x = xs[0]
        return f"{x.name} present (vsize={x.entry.e_value_size}, read={len(x.value)})"
    except Exception as exc:  # noqa: BLE001
        if not area_in_use:
            return "no ibody xattr (clean; parser raises on absent magic)"
        return f"CORRUPT: {type(exc).__name__} (magic_ok={magic_ok})"


for label, path in VARIANTS.items():
    print("=" * 92)
    print(f"VARIANT: {label}  ({path})")
    print("=" * 92)
    e = ExtFS(open(path, "rb"))
    print(f"{'inode':10s} {'rule':22s} {'declared':>8s} {'read_len':>8s} "
          f"{'head(0:60)':>11s} {'tail(60:)':>10s}  xattr view")
    for name in TARGETS:
        node = e.get(name)
        ino = node.inode
        rule = []
        if ino.i_flags & c_ext.EXT4_INLINE_DATA_FL:
            rule.append("INLINE_DATA_FL")
        if node.filetype == stat.S_IFLNK and node.size < 60:
            rule.append("short-symlink")
        got = node.open().read()
        exp = expected(name)
        head_ok = got[:60] == exp[:60]
        tail_ok = got[60:] == exp[60:] if len(exp) > 60 else "n/a"
        print(f"{name:10s} {','.join(rule) or '-':22s} {node.size:8d} {len(got):8d} "
              f"{str(head_ok):>11s} {str(tail_ok):>10s}  {xattr_state(node)}")
    print()
