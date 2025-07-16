import logging
import os
import pathlib
from typing import Callable

import lief

from . import utils

__logger__ = logging.getLogger(__name__)


def dynamic_libraries(lib: lief.ELF.Binary) -> list[lief.ELF.DynamicEntryLibrary]:
    """Return the dynamic libraries required byte ELF."""
    return [entry for entry in lib.dynamic_entries if isinstance(entry, lief.ELF.DynamicEntryLibrary)]


def rpaths_runpaths(lib: lief.ELF.Binary) -> list[lief.ELF.DynamicEntryRunPath | lief.ELF.DynamicEntryRpath]:
    """Return the RPATH and RUNPATH entries."""
    return [
        entry
        for entry in lib.dynamic_entries
        if isinstance(entry, lief.ELF.DynamicEntryRpath) or isinstance(entry, lief.ELF.DynamicEntryRunPath)
    ]


def resolve_rpath(path: str, origin: str) -> pathlib.Path:
    """Resolve special keywords and rpaths in loading path."""
    return pathlib.Path(os.path.normpath(path.replace("$ORIGIN", origin)))


def resolve_dynamic_library(filename: str, rpaths: list[pathlib.Path]) -> pathlib.Path | None:
    """Find which file or symlink on the system a dynamic path is pointing to."""
    for rp in rpaths:
        candidate = rp / filename
        if candidate.exists():
            return candidate
    return None


def relocate_lib(
    lib: lief.ELF.Binary,
    lib_path: pathlib.Path,
    prefix_path: pathlib.Path,
    path_transform: Callable[[pathlib.Path], pathlib.Path],
) -> None:
    """Relocate the given library to load dynamic libraries with relative path."""
    lib_path_relative = lib_path.relative_to(prefix_path)
    new_lib_path = path_transform(lib_path)

    origin_path = str(lib_path.parent)
    original_rpaths = [rp for entry in rpaths_runpaths(lib) for rp in entry.paths]
    resolved_rpaths = [resolve_rpath(rp, origin=origin_path) for rp in original_rpaths]

    # We would need to find how RPATH are used before correcting them.
    # Instead we remove them and let the follow-up add them.
    for entry in rpaths_runpaths(lib):
        for rpath in entry.paths:
            if pathlib.Path(rpath).is_relative_to(prefix_path):
                entry.remove(rpath)
                __logger__.info(f"{lib_path_relative}: Removing RPATH {rpath}")

    # Fix all the dynamic import libraries
    added_rpaths: list[str] = []
    for dep in dynamic_libraries(lib):
        dep_name = str(dep.name)

        # Find where the dependency is pointing to
        dep_path = resolve_dynamic_library(dep_name, rpaths=resolved_rpaths)
        if dep_path is None:
            # TODO: configure behaviour
            # We could also read from the dso whitelist on the recipe but we would need
            # to be able to parse the old recipe format.
            __logger__.warning(f"""Cannot find library "{dep_name}" in "{lib_path}".""")
            continue

        new_dep_path = path_transform(dep_path)
        new_dep_name = new_dep_path.name
        if not utils.path_in_ensemble(new_dep_name, [dep_name]):
            dep.name = str(new_dep_name)
            __logger__.info(f"{lib_path_relative}: Patching dependency {dep_name} -> {new_dep_name}")

        new_rpath = str(
            utils.relative_relocation_path(
                lib_path=new_lib_path,
                dep_path=new_dep_path,
                origin="$ORIGIN",
            )
        )
        if not utils.path_in_ensemble(new_rpath, original_rpaths + added_rpaths):
            # Conda-build seems to prefer RPATHs
            lib.add(lief.ELF.DynamicEntryRpath(new_rpath))
            added_rpaths.append(new_rpath)
            __logger__.info(f"{lib_path_relative}: Adding RPATH {new_rpath}")
