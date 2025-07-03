from typing import Iterable, Protocol

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

    def filter_files(self, paths: Iterable[str]) -> Iterable[str]:
        """Return the sequence of files not filted out."""
        ...
