import dataclasses

import libmambapy as mamba

import mamba_press.solution_utils


@dataclasses.dataclass(frozen=True, slots=True)
class PackagesFilter:
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

    def filter_solution(self, solution: mamba.solver.Solution) -> mamba.solver.Solution:
        """Filter packages from solution packages to install."""
        return mamba_press.solution_utils.prune_packages_from_solution_installs(
            solution=solution,
            to_prune=self.to_prune,
            to_prune_if_depending_on=[],
            requested_packages=self.requested_packages,
        )


@dataclasses.dataclass(frozen=True, slots=True)
class PythonPackagesFilter:
    """Remove Python and all Python packages except the ones requested."""

    requested_packages: list[mamba.specs.MatchSpec]
    python_package: list[mamba.specs.MatchSpec] = dataclasses.field(
        default_factory=lambda: [
            mamba.specs.MatchSpec.parse("python"),
            mamba.specs.MatchSpec.parse("python_abi"),
        ]
    )
    recursive: bool = True

    def filter_solution(self, solution: mamba.solver.Solution) -> mamba.solver.Solution:
        """Filter packages from solution packages to install."""
        return mamba_press.solution_utils.prune_packages_from_solution_installs(
            solution=solution,
            to_prune=self.python_package,
            to_prune_if_depending_on=self.python_package,
            requested_packages=self.requested_packages,
        )
