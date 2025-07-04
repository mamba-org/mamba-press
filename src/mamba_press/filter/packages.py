import dataclasses
from typing import Callable, Iterable, Sequence

import libmambapy as mamba

PackageIndex = int
FulfillmentIndexGraph = dict[PackageIndex, set[PackageIndex] | None]


class FulfillmentGraph:
    """A reverse dependency graph."""

    def __init__(self, fulfills: FulfillmentIndexGraph) -> None:
        self._fulfills = fulfills
        self._package_count = len(fulfills)

    @property
    def package_count(self) -> int:
        """Number of packages in the graph before removal."""
        return self._package_count

    @property
    def package_indices(self) -> Sequence[int]:
        """Indices of all the packages in the graph before removal."""
        return range(self.package_count)

    def has_package(self, idx: PackageIndex) -> bool:
        """Check if a package is in the graph."""
        return idx in self._fulfills

    def is_user_requested(self, idx: PackageIndex) -> bool:
        """Check if a node is an explicit user request."""
        return self._fulfills[idx] is None

    def is_orphan(self, idx: PackageIndex) -> bool:
        """Check if a node does not fulfill any other package dependency."""
        if (fulfillment := self._fulfills[idx]) is not None:
            return len(fulfillment) == 0
        return False

    @property
    def orphans(self) -> Iterable[PackageIndex]:
        """Return all orphan packages in the graph."""
        return filter(lambda idx: self.has_package(idx) and self.is_orphan(idx), self.package_indices)

    def mark_package_as_user_requested(self, idx: PackageIndex) -> None:
        """Mark a package as requested by the user."""
        self._fulfills[idx] = None

    def fulfills(self, idx: PackageIndex) -> Iterable[PackageIndex] | None:
        """Return what packages this package fulfills."""
        return self._fulfills[idx]

    def remove_package(self, idx: PackageIndex) -> bool:
        """Remove a given package from the graph altogether.

        :returns: Whether the item has been removed.
        """
        if not self.has_package(idx):
            return False
        del self._fulfills[idx]
        for fulfillment in self._fulfills.values():
            if isinstance(fulfillment, set) and idx in fulfillment:
                fulfillment.remove(idx)
        return True

    def remove_orphans(self) -> bool:
        """Remove all orphan packages from the graph altogether.

        :returns: Whether any item has been removed.
        """
        return any(self.remove_package(idx) for idx in self.orphans)

    def prune_orphans(self) -> bool:
        """Recursively remove orphan packages from the graph.

        :returns: Whether any item has been removed.
        """
        removed = False
        while self.remove_orphans():
            removed = True
        return removed


def __packages_matcher(
    to_match: Iterable[mamba.specs.MatchSpec] | set[mamba.specs.PackageInfo],
) -> Callable[[mamba.specs.PackageInfo], bool]:
    if isinstance(to_match, set):
        return lambda pkg: pkg in to_match
    return lambda pkg: any(dep.contains_except_channel(pkg) for dep in to_match)


def make_packages_fulfillemnt_graph(
    requested_packages: list[mamba.specs.MatchSpec],
    packages: list[mamba.specs.PackageInfo],
) -> FulfillmentGraph:
    """Create a :class:`FulfillementGraph` from a list of :class:`libmambapy.specs.PackageInfo`."""
    is_requested = __packages_matcher(requested_packages)

    fulfills: FulfillmentIndexGraph = {
        idx: (None if is_requested(pkg) else set()) for idx, pkg in enumerate(packages)
    }

    for idx, pkg in enumerate(packages):
        dependencies = [mamba.specs.MatchSpec.parse(dep) for dep in pkg.dependencies]
        is_in_dependencies = __packages_matcher(dependencies)
        for candidate_pkg_id, candidate_pkg in enumerate(packages):
            if is_in_dependencies(candidate_pkg):
                fulfillment = fulfills[candidate_pkg_id]
                if fulfillment is not None:
                    fulfillment.add(idx)

    return FulfillmentGraph(fulfills)


def prune_packages_from_solution_installs(
    solution: mamba.solver.Solution,
    requested_packages: list[mamba.specs.MatchSpec],
    to_prune: Iterable[mamba.specs.MatchSpec] | set[mamba.specs.PackageInfo],
    to_prune_if_depending_on: Iterable[mamba.specs.MatchSpec] | set[mamba.specs.PackageInfo],
    recursive: bool = True,
) -> mamba.solver.Solution:
    """Prune the given MatchSpec from a :class:`libmambapy.solver.Solution`.

    Return a new  :class:`libmambapy.solver.Solution` from the installs of the input.
    Packages matching one of the given :class:`libmambapy.specs.MatchSpec` are
    removed, as well as their dependencies that does not serve any other package.
    """
    packages = solution.to_install()
    is_to_prune = __packages_matcher(to_prune)
    is_to_prune_if_depending_on = __packages_matcher(to_prune_if_depending_on)

    graph = make_packages_fulfillemnt_graph(requested_packages=requested_packages, packages=packages)

    for dep_idx, dep_pkg in enumerate(packages):
        if is_to_prune_if_depending_on(dep_pkg):
            fulfills = graph.fulfills(dep_idx)
            if fulfills is None:
                raise RuntimeError(
                    f'Package "{dep_pkg.name}" cannot be both requested and a forbidden dependency'
                )
            for idx in list(fulfills):
                if not graph.is_user_requested(idx):
                    graph.remove_package(idx)

    for idx, pkg in enumerate(packages):
        if is_to_prune(pkg):
            graph.remove_package(idx)

    if recursive:
        graph.prune_orphans()

    return mamba.solver.Solution(
        [mamba.solver.Solution.Install(pkg) for idx, pkg in enumerate(packages) if graph.has_package(idx)]
    )


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
        return prune_packages_from_solution_installs(
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
        return prune_packages_from_solution_installs(
            solution=solution,
            to_prune=self.python_package,
            to_prune_if_depending_on=self.python_package,
            requested_packages=self.requested_packages,
        )
