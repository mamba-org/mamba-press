import dataclasses
import fnmatch
from typing import Iterable


@dataclasses.dataclass(frozen=True)
class UnixFilesFilter:
    """Filter files from the wheel.

    The patterns are applied individually to every file path (as a relative to the prefix root).
    If exclude is true, then a file is kept if and only if no glob pattern matches it.
    If exclude is false, then a file is kept if and only if any glob pattern matches it.
    """

    patterns: list[str]
    exclude: bool = True

    def filter_file(self, path: str) -> bool:
        """Whether the file should be kept i.e. not filtered out."""
        return any(fnmatch.fnmatch(path, pat) for pat in self.patterns) != self.exclude

    def filter_files(self, paths: Iterable[str]) -> Iterable[str]:
        """Return the sequence of files not filtered out."""
        return (p for p in paths if self.filter_file(p))
