import dataclasses
from typing import Literal, TypeAlias

import cattrs.preconf.pyyaml
import cattrs.strategies
import libmambapy as mamba

from mamba_press.typing import Default as Default
from mamba_press.typing import DefaultType as DefaultType

# Any dynamic JSON/YAML-like object
DynamicEntry: TypeAlias = str | int | float | bool | None | dict[str, "DynamicEntry"] | list["DynamicEntry"]

# A dynamic JSON/YAML-like object with a single key used as a name.
# This is used for separating a dynamic class name from its parameters.
NamedDynamicEntry: TypeAlias = dict[str, DynamicEntry]


@dataclasses.dataclass
class Source:
    """Specify what Conda packages to get."""

    packages: list[mamba.specs.MatchSpec]
    python: mamba.specs.MatchSpec


@dataclasses.dataclass
class TargetPlatform:
    """Specify the wheel target platform.

    All attributes follow wheel conventions (e.g. ``manylinux``, ``2.28``, ``x86_64``).
    """

    os: str
    version: str
    arch: str


@dataclasses.dataclass
class Target:
    """Specify what wheel to build.

    Attributes not provided will be defaulted, if explicitly marked as such.

    Attributes:
        platform: See :ref:TargetPlatform
        python: The whel python tag
        name: The wheel name

    """

    platform: TargetPlatform
    python: str | DefaultType = Default
    name: str | DefaultType = Default


@dataclasses.dataclass
class Filter:
    """Specify what to remove from the Conda packages.

    Attributes not provided will be defaulted, if explicitly marked as such.

    Attributes:
        packages: A syntaxic sugar entry key for the :ref:mamba_press.filter.PackagesFilter kind
            of :ref:mamba_press.filter.SolutionFilter, since it is the most (only?) useful of its
            type so far.
        files: List of dynamic dispatched mamba_press.filter.FilesFilter

    """

    packages: list[str] | DefaultType = Default
    files: list[NamedDynamicEntry] | DefaultType = Default
    # If we add general solution filters:
    #  solution: list[NamedDynamic] | None


@dataclasses.dataclass
class Transform:
    """Specify how to transform path and data.

    Attributes not provided will be defaulted, if explicitly marked as such.

    Attributes:
        path: List of dynamic dispatched mamba_press.filter.FilesFilter

    """

    path: list[str] | DefaultType = Default  # FIXME
    dynlib: DefaultType | None = Default  # No args so far
    # If we add general data transform:
    #  data: list[NamedDynamic] | DefaultType


@dataclasses.dataclass
class Build:
    """Configure how to build the wheel.

    Attributes not provided will be defaulted, if explicitly marked as such.
    """

    filter: Filter | DefaultType = Default
    transform: Transform | DefaultType = Default


@dataclasses.dataclass
class RecipeV0:
    """The schema for recipe format in version 0."""

    source: Source
    target: Target
    build: Build | DefaultType = Default
    version: Literal[0] = 0  # Union tag for disambiuation

    @staticmethod
    def parse_yaml(yaml: str) -> "RecipeV0":
        """Parse the yaml recipe data."""
        converter = cattrs.preconf.pyyaml.make_converter()

        cattrs.strategies.configure_union_passthrough(Build | DefaultType, converter)

        @converter.register_structure_hook
        def _parse_ms(value: str, type: type[object]) -> mamba.specs.MatchSpec:
            return mamba.specs.MatchSpec.parse(value)

        return converter.loads(yaml, RecipeV0)


Recipe = RecipeV0
