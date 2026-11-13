"""Print the reversible name index for an ext4 image.

Usage::

    python tests/data/dump_ext4_name_index.py tests/data/ext4_encrypted.bin.gz
"""

from __future__ import annotations

import gzip
import io
import sys
from pathlib import Path

from dissect.extfs import ExtFS


def main() -> None:
    with gzip.open(Path(sys.argv[1]), "rb") as fh:
        extfs = ExtFS(io.BytesIO(fh.read()))

    print(extfs.name_index().to_json())


if __name__ == "__main__":
    main()
