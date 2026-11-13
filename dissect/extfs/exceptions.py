from __future__ import annotations


class Error(Exception):
    pass


class MissingDataError(Error):
    """Raised when (part of) the requested data is missing from an incomplete image.

    The ``missing`` attribute holds a sorted list of ``(offset, size)`` tuples with the
    file-relative byte intervals that could not be read from the image.
    """

    def __init__(self, message: str, missing: list[tuple[int, int]] | None = None):
        super().__init__(message)
        self.missing = missing or []


class FileNotFoundError(Error, FileNotFoundError):
    pass


class IsADirectoryError(Error, IsADirectoryError):
    pass


class NotADirectoryError(Error, NotADirectoryError):
    pass


class NotASymlinkError(Error):
    pass
