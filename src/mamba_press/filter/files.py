import dataclasses
import fnmatch
import pathlib

import mamba_press.platform

from .protocol import FilesFilter


@dataclasses.dataclass(frozen=True, slots=True)
class UnixFilesFilter(FilesFilter):
    """Filter files from the wheel.

    The patterns are applied individually to every file path (as a relative to the prefix root).
    If exclude is true, then a file is kept if and only if no glob pattern matches it.
    If exclude is false, then a file is kept if and only if any glob pattern matches it.
    """

    patterns: list[str]
    exclude: bool = True

    def filter_file(self, path: pathlib.PurePath) -> bool:
        """Whether the file should be kept i.e. not filtered out."""
        return any(fnmatch.fnmatch(str(path), pat) for pat in self.patterns) != self.exclude


@dataclasses.dataclass(frozen=True, slots=True)
class CombinedFilesFilter(FilesFilter):
    """Combine multiple file filters into one.

    If ``all`` is true, then a file is kept if it is kept by all filters.
    Otherwise, a file is kept if it is kept by any filter.
    """

    filters: list[FilesFilter]
    all: bool = True

    def filter_file(self, path: pathlib.PurePath) -> bool:
        """Whether the file should be kept i.e. not filtered out."""
        if self.all:
            return all(f.filter_file(path) for f in self.filters)
        return any(f.filter_file(path) for f in self.filters)


class ManyLinuxWhitelist(FilesFilter):
    """Whitelist library allowed by manylinux spec."""

    def __init__(self, platform: str) -> None:
        import auditwheel.policy

        split = mamba_press.platform.WheelPlatformSplit.parse(platform)
        self.policy = auditwheel.policy.WheelPolicies(
            libc=auditwheel.libc.Libc.GLIBC,  # Always on conda-forge
            arch=getattr(auditwheel.architecture.Architecture, split.arch),
        ).get_policy_by_name(platform)

    def filter_file(self, path: pathlib.PurePath) -> bool:
        """Filter libraries using autiwheel policies."""
        return path.name in self.policy.whitelist
