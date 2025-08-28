import dataclasses
import types
import typing
from collections.abc import Mapping
from typing import Literal, Protocol, TypeAlias

import cattrs
import cattrs.preconf.pyyaml
import cattrs.strategies
import libmambapy as mamba

import mamba_press.utils
from mamba_press.typing import Default as Default
from mamba_press.typing import DefaultType as DefaultType
from mamba_press.typing import DynamicEntry as DynamicEntry

# A dynamic named parameters
DynamicParams: TypeAlias = dict[str, DynamicEntry]

# A dynamic JSON/YAML-like object with a single key used as a name.
# This is used for separating a dynamic class name from its parameters.
NamedDynamicEntry: TypeAlias = dict[str, DynamicParams]


def interpolate_params(params: DynamicEntry, context: Mapping[str, str]) -> DynamicEntry:
    """Recursively interpolate all strings in a dynamic entry."""
    if isinstance(params, str):
        return mamba_press.utils.interpolate(params, context)
    if isinstance(params, list):
        return [interpolate_params(p, context) for p in params]
    if isinstance(params, dict):
        return {k: interpolate_params(v, context) for k, v in params.items()}

    return params


def get_param_as[T](key: str, params: DynamicParams, type_: type[T], default: DefaultType | T = Default) -> T:
    """Return the parameter in the correct type of raise an exception."""
    if key not in params:
        if default != Default:
            return default
        raise ValueError(f"Key {key} not provided")

    if isinstance((value := params[key]), type_):
        return value

    raise ValueError(f"A {type(value).__name__} was given for key {key} but expected {type_.__name__}")


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
        python: The wheel python tag
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
        packages: List of dynamic dispatched :ref:mamba_press.filter.PackagesFilter
        files: List of dynamic dispatched :ref:mamba_press.filter.FilesFilter

    """

    packages: list[NamedDynamicEntry] | DefaultType = Default
    files: list[NamedDynamicEntry] | DefaultType = Default


@dataclasses.dataclass
class Transform:
    """Specify how to transform path and data.

    Attributes not provided will be defaulted, if explicitly marked as such.

    Attributes:
        path: List of dynamic dispatched mamba_press.transform.PathTransform

    """

    path: list[NamedDynamicEntry] | DefaultType = Default
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

        def _union_with_default_structure(o: type) -> object:
            def union_hook(data: object, type_: type[object]) -> object:
                args = typing.get_args(type_)

                # we don't try to coerce None into anything
                if data is None:
                    return None

                # Try to coerce into any types by order
                for t in args:
                    try:
                        return converter.structure(data, t)
                    except Exception:
                        continue
                raise ValueError(f"Could not cast {data} to {type_}")

            return union_hook

        converter.register_structure_hook_factory(
            _is_union_with_default,
            _union_with_default_structure,  # type: ignore[type-var]
        )

        converter.register_structure_hook(_parse_ms)

        return converter.loads(yaml, RecipeV0)


Recipe = RecipeV0


class SourceConfigurable(Protocol):
    """An object that can be created from a simple configuration and recipe source info."""

    @classmethod
    def from_config(cls, params: DynamicParams, source: Source) -> "SourceConfigurable":
        """Construct from simple parameters typically found in configurations."""
        ...


def _parse_ms(value: str, type: type[object]) -> mamba.specs.MatchSpec:
    return mamba.specs.MatchSpec.parse(value)


def _filter_union_with_default[T, U](type_: type[T]) -> type[object]:
    type_origin = typing.get_origin(type_)
    if type_origin is types.UnionType or type_origin is typing.Union:
        args = [t for t in typing.get_args(type_) if t is not DefaultType]
        if len(args) == 1:
            return args[0]  # type: ignore[no-any-return]
        else:
            raise NotImplementedError("Default Union with more than one")
    return type_


def _is_union_with_default[T](type_: type[T]) -> bool:
    type_origin = typing.get_origin(type_)
    return (type_origin is types.UnionType or type_origin is typing.Union) and any(
        t is DefaultType for t in typing.get_args(type_) if t is not type(None)
    )
