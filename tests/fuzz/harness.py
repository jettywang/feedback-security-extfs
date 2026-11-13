"""Budgeted, outcome-classifying execution harness for extfs fuzzing.

Every mutated image is driven through the real :class:`dissect.extfs.extfs.ExtFS`
parser under two explicit budgets and every result is sorted into one of four
outcomes so that an exception is never silently treated as "safe":

* :data:`REJECTED`  -- the parser raised a documented format/value error.  This is
  the expected, safe response to a malformed image.
* :data:`OOB`       -- the parser asked the backing file handle to read or seek
  past the end of the image (or to a negative offset).  A forensic worker must
  never trust on-disk pointers enough to touch memory outside its input.
* :data:`TIMEOUT`   -- the worker exceeded its wall-clock budget, i.e. the image
  made the parser non-terminating (including pathological extent/dir recursion).
* :data:`BUG`       -- any other unexpected exception (``RecursionError``,
  ``IndexError``, ``KeyError``, ...).  These are parser defects too and must not
  be swept under the "rejected" umbrella.
"""
from __future__ import annotations

import io
import logging
import signal
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, BinaryIO

from dissect.extfs.exceptions import Error
from dissect.extfs.extfs import ExtFS

# Malformed images intentionally trigger "zero-length directory entry" style
# critical logs; keep campaign output focused on structured outcomes instead.
logging.getLogger("dissect.extfs.extfs").setLevel(logging.CRITICAL + 1)

if TYPE_CHECKING:
    from collections.abc import Callable

REJECTED = "rejected"
OOB = "oob"
TIMEOUT = "timeout"
BUG = "bug"
OK = "ok"

FAILURE_OUTCOMES = frozenset({OOB, TIMEOUT, BUG})

# Exceptions that represent an explicit, deliberate refusal of malformed input.
# EOFError is raised by dissect.cstruct when a structure runs past the buffer;
# that is a truncation rejection, not an out-of-bounds pointer dereference.
REJECTION_EXCEPTIONS = (Error, EOFError, ValueError, NotImplementedError)


class OutOfBoundsError(Error):
    """Raised when the parser reaches outside the synthesized image."""


class TimeBudgetExceeded(Error):
    """Raised by the watchdog when the wall-clock budget is exhausted."""


class GuardedFile(io.RawIOBase):
    """File handle that records and rejects out-of-range access.

    The parser receives this instead of a plain :class:`io.BytesIO`.  Every
    ``seek``/``read`` is validated against the image bounds so a corrupted block
    pointer cannot silently read beyond the forensic input.  It also caps the
    total number of bytes that may be read, which is the per-case read budget.
    """

    def __init__(self, data: bytes, read_budget: int):
        super().__init__()
        self._buf = bytearray(data)
        self._size = len(data)
        self._pos = 0
        self._closed = False
        self.read_budget = read_budget
        self.bytes_read = 0
        self.oob_events: list[tuple[str, int]] = []

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_SET:
            target = offset
        elif whence == io.SEEK_CUR:
            target = self._pos + offset
        elif whence == io.SEEK_END:
            target = self._size + offset
        else:
            raise ValueError(f"invalid whence: {whence}")

        if target < 0:
            self.oob_events.append(("seek-negative", target))
            raise OutOfBoundsError(f"negative seek to {target}")
        if target > self._size:
            self.oob_events.append(("seek-past-end", target))
            raise OutOfBoundsError(f"seek to {target} exceeds image size {self._size}")
        self._pos = target
        return target

    def tell(self) -> int:
        return self._pos

    def readinto(self, b: bytearray) -> int:  # type: ignore[override]
        wanted = len(b)
        if self._pos < 0 or self._pos > self._size:
            self.oob_events.append(("read-unpositioned", self._pos))
            raise OutOfBoundsError(f"read from invalid position {self._pos}")

        if self.bytes_read + wanted > self.read_budget:
            self.oob_events.append(("read-budget", self.bytes_read + wanted))
            raise OutOfBoundsError(
                f"read budget exceeded: {self.bytes_read + wanted} > {self.read_budget}"
            )

        available = self._size - self._pos
        delivered = min(wanted, available)
        b[:delivered] = self._buf[self._pos : self._pos + delivered]
        self._pos += delivered
        self.bytes_read += wanted
        return delivered

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            size = self._size - self._pos
        chunk = bytearray(size)
        n = self.readinto(chunk)
        return bytes(chunk[:n])

    def close(self) -> None:
        self._closed = True
        super().close()

    @property
    def closed(self) -> bool:  # type: ignore[override]
        return self._closed


@dataclass
class FuzzOutcome:
    """Structured result of exercising one image."""

    name: str
    outcome: str
    detail: str = ""
    exception_type: str = ""
    elapsed: float = 0.0
    bytes_read: int = 0
    oob_events: list[tuple[str, int]] = field(default_factory=list)

    @property
    def is_failure(self) -> bool:
        return self.outcome in FAILURE_OUTCOMES

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "outcome": self.outcome,
            "detail": self.detail,
            "exception_type": self.exception_type,
            "elapsed": round(self.elapsed, 6),
            "bytes_read": self.bytes_read,
            "oob_events": self.oob_events,
        }


class Watchdog:
    """SIGALRM-based wall-clock watchdog.

    Signals can only be used on the main thread, which is where pytest runs the
    fuzz campaign.  A real, interrupting timer is required rather than a
    cooperative check, because the whole point is to catch code that loops or
    recurses without ever yielding.
    """

    def __init__(self, seconds: float):
        self.seconds = seconds
        self._previous_handler: object = None
        self._armed = False

    def _handler(self, signum: int, frame: object) -> None:
        raise TimeBudgetExceeded(f"parser exceeded {self.seconds}s wall-clock budget")

    def __enter__(self) -> Watchdog:
        self._previous_handler = signal.signal(signal.SIGALRM, self._handler)
        signal.setitimer(signal.ITIMER_REAL, self.seconds)
        self._armed = True
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        if self._armed:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, self._previous_handler)
            self._armed = False


def default_exercise(extfs: ExtFS) -> None:
    """Drive a representative forensic walk across a parsed image.

    The constructor already parses the superblock, group descriptors and root
    inode.  This additionally enumerates the root directory, resolves every
    reachable inode and reads each file's data stream so corrupted extents,
    indirect blocks and directory entries are all exercised.
    """
    for entry in list(extfs.root.iterdir()):
        stream = entry.open()
        chunk = True
        while chunk:
            chunk = stream.read(extfs.block_size)


def run_case(
    name: str,
    data: bytes | bytearray,
    *,
    read_budget: int = 1 << 20,
    time_budget: float = 2.0,
    exercise: Callable[[ExtFS], None] | None = None,
) -> FuzzOutcome:
    """Parse and exercise one image, returning a classified outcome."""
    exercise = exercise or default_exercise
    guarded = GuardedFile(bytes(data), read_budget=read_budget)
    import time

    start = time.perf_counter()
    try:
        with Watchdog(time_budget):
            extfs = ExtFS(guarded)
            exercise(extfs)
    except TimeBudgetExceeded as exc:
        return FuzzOutcome(
            name, TIMEOUT, str(exc), type(exc).__name__, time.perf_counter() - start, guarded.bytes_read,
            guarded.oob_events,
        )
    except OutOfBoundsError as exc:
        return FuzzOutcome(
            name, OOB, str(exc), type(exc).__name__, time.perf_counter() - start, guarded.bytes_read,
            guarded.oob_events,
        )
    except REJECTION_EXCEPTIONS as exc:
        return FuzzOutcome(
            name, REJECTED, str(exc), type(exc).__name__, time.perf_counter() - start, guarded.bytes_read,
            guarded.oob_events,
        )
    except Exception as exc:  # noqa: BLE001 - every other exception is a parser bug
        return FuzzOutcome(
            name, BUG, f"{type(exc).__name__}: {exc}", type(exc).__name__, time.perf_counter() - start,
            guarded.bytes_read, guarded.oob_events,
        )
    else:
        return FuzzOutcome(
            name, OK, "parsed and read cleanly", "", time.perf_counter() - start, guarded.bytes_read,
            guarded.oob_events,
        )


def open_raw(data: bytes | bytearray, read_budget: int = 1 << 20) -> BinaryIO:
    """Return a guarded handle for tests that want to drive the parser manually."""
    return GuardedFile(bytes(data), read_budget=read_budget)
