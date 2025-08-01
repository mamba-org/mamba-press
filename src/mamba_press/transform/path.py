import dataclasses
import pathlib
from typing import Self

import mamba_press.recipe
from mamba_press.recipe import DynamicParams, Source, SourceConfigurable

from .protocol import PathTransform


@dataclasses.dataclass(frozen=True, slots=True)
class ExplicitPathTransform(PathTransform, SourceConfigurable):
    """Relocate file and folder from the given mapping.

    Search for the most specific mapping to apply at each transformation.
    """

    mapping: dict[pathlib.PurePath, pathlib.PurePath]

    @classmethod
    def from_config(cls, params: DynamicParams, source: Source) -> Self:
        """Construct from simple parameters typically found in configurations."""
        mapping: dict[pathlib.PurePath, pathlib.PurePath] = {}
        for entry in mamba_press.recipe.get_param_as("mapping", params=params, type_=list):
            from_ = mamba_press.recipe.get_param_as("from", params=entry, type_=str)
            to = mamba_press.recipe.get_param_as("to", params=entry, type_=str)
            mapping[pathlib.PurePath(from_)] = pathlib.PurePath(to)
        params.pop("mapping")

        return cls(mapping=mapping, **params)

    def transform_path(self, path: pathlib.PurePath) -> pathlib.PurePath:
        """Compute a new relative path from the working environment path."""
        best_size = float("inf")
        best_dest = None
        for src, dest in self.mapping.items():
            if path.is_relative_to(src):
                candidate = path.relative_to(src)
                candidate_size = len(candidate.parts)
                if candidate_size < best_size:
                    best_size = candidate_size
                    best_dest = dest / candidate

        if best_dest is not None:
            return best_dest

        return path
