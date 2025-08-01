import dataclasses

import libmambapy as mamba

import mamba_press.recipe
import mamba_press.solution_utils
from mamba_press.filter.abc import SolutionFilter
from mamba_press.recipe import DynamicParams, Source, SourceConfigurable


@dataclasses.dataclass(frozen=True, slots=True)
class PackagesSolutionFilter(SolutionFilter, SourceConfigurable):
    """Remove packages from the the final wheel.

    This is used for removing dependencies of a package that we know should not be part of the
    final wheel, such as Python itself, other Python runtime dependencies such as NumPy, or
    system dependencies not assumed by conda-forge, such as a C++ standard library.

    If ``recursive`` is True, the given packages dependencies that do not fulfill any other
    dependency in the remaining packages are recursively removed.
    """

    requested_packages: list[mamba.specs.MatchSpec]
    to_prune: list[mamba.specs.MatchSpec]
    recursive: bool = True

    @classmethod
    def from_config(cls, params: DynamicParams, source: Source) -> "PackagesSolutionFilter":
        """Construct from simple parameters typically found in configurations."""
        to_prune = [
            mamba.specs.MatchSpec.parse(ms)
            for ms in mamba_press.recipe.get_param_as("to_prune", params=params, type_=list)
        ]
        params.pop("to_prune")

        return PackagesSolutionFilter(
            requested_packages=source.packages,
            to_prune=to_prune,
            **params,  # type: ignore[arg-type]
        )

    def filter_solution(self, solution: mamba.solver.Solution) -> mamba.solver.Solution:
        """Filter packages from solution packages to install."""
        return mamba_press.solution_utils.prune_packages_from_solution_installs(
            solution=solution,
            to_prune=self.to_prune,
            to_prune_if_depending_on=[],
            requested_packages=self.requested_packages,
        )


@dataclasses.dataclass(frozen=True, slots=True)
class PythonPackagesSolutionFilter(SolutionFilter, SourceConfigurable):
    """Remove Python and all Python packages except the ones requested."""

    requested_packages: list[mamba.specs.MatchSpec]
    python_packages: list[mamba.specs.MatchSpec] = dataclasses.field(
        default_factory=lambda: [
            mamba.specs.MatchSpec.parse("python"),
            mamba.specs.MatchSpec.parse("python_abi"),
        ]
    )
    recursive: bool = True

    @classmethod
    def from_config(cls, params: DynamicParams, source: Source) -> "PythonPackagesSolutionFilter":
        """Construct from simple parameters typically found in configurations."""
        return PythonPackagesSolutionFilter(
            requested_packages=source.packages,
            **params,  # type: ignore[arg-type]
        )

    def filter_solution(self, solution: mamba.solver.Solution) -> mamba.solver.Solution:
        """Filter packages from solution packages to install."""
        return mamba_press.solution_utils.prune_packages_from_solution_installs(
            solution=solution,
            to_prune=self.python_packages,
            to_prune_if_depending_on=self.python_packages,
            requested_packages=self.requested_packages,
        )
