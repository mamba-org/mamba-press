import abc
import pathlib
from typing import Protocol

import libmambapy as mamba

from mamba_press.recipe import DynamicParams, Source


class SolutionFilter(metaclass=abc.ABCMeta):
    """Filter packages from solution packages.

    This happens before the packages are collected/downloaded and extracted.
    """

    @classmethod
    @abc.abstractmethod
    def from_config(cls, params: DynamicParams, source: Source) -> "SolutionFilter":
        """Construct from simple parameters typically found in configurations."""
        ...

    @abc.abstractmethod
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
