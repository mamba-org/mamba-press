import os
import pathlib
from typing import Iterable


def path_in_ensemble(path: str | pathlib.Path, ensemble: Iterable[str | pathlib.Path]) -> bool:
    """Check if a path is in an ensemble with path comparison."""
    return any(pathlib.Path(path) == pathlib.Path(p) for p in ensemble)


def relative_relocation_path(
    lib_path: pathlib.PurePath, dep_path: pathlib.PurePath, origin: str
) -> pathlib.PurePath:
    """Create a relative load path between two paths."""
    relative = os.path.relpath(dep_path.parent, lib_path.parent)
    return pathlib.PurePath(origin) / relative
