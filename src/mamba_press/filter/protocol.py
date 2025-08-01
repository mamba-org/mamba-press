import pathlib
from typing import Protocol

import libmambapy as mamba


class SolutionFilter(Protocol):
    """Filter packages from solution packages.

    This happens before the packages are collected/downloaded and extracted.
    """

    def filter_solution(self, solution: mamba.solver.Solution) -> mamba.solver.Solution:
        """Filter packages from solution packages to install."""
        ...


class FilesFilter(Protocol):
    """Filter packages from solution packages.

    This happens before the packages are collected/downloaded and extracted.
    """

    def filter_file(self, path: pathlib.PurePath) -> bool:
        """Whether the file should be kept i.e. not filtered out."""
        ...
