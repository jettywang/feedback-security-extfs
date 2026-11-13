# dissect.extfs

A Dissect module implementing a parser for the ExtFS file system, the native filesystem for Linux operating systems. For
more information, please see [the documentation](https://docs.dissect.tools/en/latest/projects/dissect.extfs/index.html).

## Extended attributes

An extended attribute (`xattr`) value can be stored in one of three places: inline in the inode's extra area, in a
separate attribute block referenced by the inode, or in a dedicated EA inode referenced by the attribute entry.
`INode.xattr` keeps returning a plain list of attributes, but each `XAttr` now records where its value came from and
whether the value was read completely:

```python
from dissect.extfs import ExtFS

extfs = ExtFS(fh)
inode = extfs.get("/some/path")

for xattr in inode.xattr:
    print(xattr.name, xattr.source, xattr.status, xattr.value)

# Find a specific attribute, including damaged duplicates.
xattr = inode.get_xattr("security.capability")
if xattr is not None and not xattr.value_complete:
    print(xattr.issues)

# Group attributes by storage location for a forensic report.
report = inode.xattr_report()
print(report.by_source)
print(report.damaged)
```

`XAttr.source` is one of `XAttrSource.INODE_BODY`, `XAttrSource.EXTERNAL_BLOCK` or `XAttrSource.EA_INODE`. For EA-inode
values, `entry_source` still records where the attribute entry itself lives. `XAttr.status` is `XAttrStatus.OK` only for
a clean attribute; duplicate names, unknown namespaces, out-of-range value offsets, truncated inline values, short EA
inode reads and malformed containers each have their own status and are not silently truncated into a normal value.
Container-wide damage (for example an invalid external block magic) is reported through `INode.xattr_issues` without
preventing other readable attributes from being returned.

## Requirements

This project is part of the Dissect framework and requires Python.

Information on the supported Python versions can be found in the Getting Started section of [the documentation](https://docs.dissect.tools/en/latest/index.html#getting-started).

## Installation

`dissect.extfs` is available on [PyPI](https://pypi.org/project/dissect.extfs/).

```bash
pip install dissect.extfs
```

This module is also automatically installed if you install the `dissect` package.

## Build and test instructions

This project uses `tox` to build source and wheel distributions. Run the following command from the root folder to build
these:

```bash
tox -e build
```

The build artifacts can be found in the `dist/` directory.

`tox` is also used to run linting and unit tests in a self-contained environment. To run both linting and unit tests
using the default installed Python version, run:

```bash
tox
```

For a more elaborate explanation on how to build and test the project, please see [the
documentation](https://docs.dissect.tools/en/latest/contributing/tooling.html).

## Contributing

The Dissect project encourages any contribution to the codebase. To make your contribution fit into the project, please
refer to [the development guide](https://docs.dissect.tools/en/latest/contributing/developing.html).

## Copyright and license

Dissect is released as open source by Fox-IT (<https://www.fox-it.com>) part of NCC Group Plc
(<https://www.nccgroup.com>).

Developed by the Dissect Team (<dissect@fox-it.com>) and made available at <https://github.com/fox-it/dissect>.

License terms: AGPL3 (<https://www.gnu.org/licenses/agpl-3.0.html>). For more information, see the LICENSE file.
