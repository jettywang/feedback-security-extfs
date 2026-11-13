"""Structure-aware fuzzing helpers for :mod:`dissect.extfs`.

This package contains a self-contained, dependency-free ext2/ext4 image
synthesizer plus a budgeted, outcome-classifying fuzzing harness.  It exists to
find malicious images that can stall or confuse a forensic worker: the mutators
understand superblock geometry, group descriptors and extent subtrees instead of
blindly flipping the first bytes of a file.
"""
