"""Hand-built control samples with *known* expected detector outcomes.

A fuzzer that never reports a failure is worthless, so alongside the random
campaign this module ships deterministic controls that must trigger each
failure class.  The pytest suite asserts these alarms fire, which guards against
an accidentally permissive harness (e.g. one that swallows every exception as a
format rejection).
"""
from __future__ import annotations

import random
from dataclasses import dataclass

from tests.fuzz.harness import BUG, OOB, TimeBudgetExceeded, Watchdog
from tests.fuzz.image_builder import EXT4, build_seed, sb_field, superblock_offset
from tests.fuzz.mutators import (
    _extent_root_pos,
    extent_idx_field,
    make_self_referential_extent,
)


@dataclass(frozen=True)
class ControlSample:
    name: str
    expected_outcome: str
    description: str


def self_referential_extent_control() -> tuple[bytes, ControlSample]:
    """Malicious looping extent tree -> parser non-termination defect (BUG).

    The parser recurses into the same extent block until the interpreter aborts
    with :class:`RecursionError`.  It is a worker-stall defect, not a clean
    format rejection.
    """
    image = make_self_referential_extent(build_seed(EXT4), random.Random(0))
    return bytes(image.image.data), ControlSample(
        "self_referential_extent",
        BUG,
        "extent subtree loops until RecursionError",
    )


def out_of_bounds_group_desc_control() -> tuple[bytes, ControlSample]:
    """Extent index child past the image -> out-of-bounds subtree read.

    The parser validates group-descriptor block locations but follows extent
    child pointers without a bounds check, so a huge ``ei_leaf`` makes it seek
    far beyond the forensic input.  The guarded file handle turns that into an
    explicit OOB alarm.
    """
    image = build_seed(EXT4)
    data = bytearray(image.data)
    from dissect.extfs.c_ext import c_ext

    base = _extent_root_pos(image, image.file_inum) + len(c_ext.ext4_extent_header())
    pos = base + extent_idx_field("ei_leaf_lo")
    data[pos : pos + 4] = (0xFFFFFFFF).to_bytes(4, "little")
    return bytes(data), ControlSample(
        "oob_extent_child",
        OOB,
        "extent index child references a block far past the image end",
    )


def invalid_magic_control() -> tuple[bytes, ControlSample]:
    """Corrupted magic -> clean format rejection (negative control).

    This proves the harness still distinguishes a legitimate, safe rejection
    from the alarm conditions above.
    """
    image = build_seed(EXT4)
    data = bytearray(image.data)
    magic_pos = superblock_offset() + sb_field("s_magic")
    data[magic_pos : magic_pos + 2] = b"\x00\x00"
    return bytes(data), ControlSample(
        "bad_magic",
        "rejected",
        "superblock magic mismatch must be a clean rejection",
    )


def watchdog_control() -> None:
    """Directly verify the wall-clock watchdog interrupts non-termination.

    The ext parser expresses runaway recursion via :class:`RecursionError`,
    which is covered by the extent control; this control proves the underlying
    timer also stops a plain ``while True`` loop so a future non-recursive stall
    would be reported as :data:`TIMEOUT` instead of hanging the test run.
    """
    try:
        with Watchdog(0.2):
            while True:
                pass
    except TimeBudgetExceeded:
        return
    raise AssertionError("watchdog failed to interrupt an infinite loop")


ALL_CONTROLS = (
    self_referential_extent_control,
    out_of_bounds_group_desc_control,
    invalid_magic_control,
)
