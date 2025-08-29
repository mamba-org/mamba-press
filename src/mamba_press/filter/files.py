import dataclasses
import fnmatch
import pathlib
from typing import Self

import mamba_press.platform
import mamba_press.recipe
from mamba_press.platform import WheelPlatformSplit
from mamba_press.recipe import DynamicParams, FromRecipeConfig, Source

from .protocol import FilesFilter


@dataclasses.dataclass(frozen=True, slots=True)
class UnixGlobFilesFilter(FilesFilter, FromRecipeConfig):
    """Filter files from the wheel.

    The patterns are applied individually to every file path (as a relative to the prefix root).
    If exclude is true, then a file is kept if and only if no glob pattern matches it.
    If exclude is false, then a file is kept if and only if any glob pattern matches it.
    """

    patterns: list[str]
    exclude: bool = True

    @classmethod
    def from_config(cls, params: DynamicParams, source: Source, wheel_split: WheelPlatformSplit) -> Self:
        """Construct from simple parameters typically found in configurations."""
        patterns = mamba_press.recipe.get_param_as("patterns", params=params, type_=list)
        params.pop("patterns")

        return cls(
            patterns=patterns,
            **params,  # type: ignore[arg-type]
        )

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

    def __init__(self, platform: str | WheelPlatformSplit, keep: bool = True) -> None:
        import auditwheel.policy

        if isinstance(platform, str):
            split = mamba_press.platform.WheelPlatformSplit.parse(platform)
        else:
            split = platform
        self.policy = auditwheel.policy.WheelPolicies(
            libc=auditwheel.libc.Libc.GLIBC,  # Always on conda-forge
            arch=getattr(auditwheel.architecture.Architecture, split.arch),
        ).get_policy_by_name(str(platform))
        self.keep = keep  # TODO would be nicer to have not/and/or operators on filters

    def filter_file(self, path: pathlib.PurePath) -> bool:
        """Filter libraries using autiwheel policies."""
        return (path.name in self.policy.whitelist) == self.keep
