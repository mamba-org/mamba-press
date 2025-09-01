import dataclasses
import logging
import os
import pathlib
from typing import Callable

import lief

from . import utils
from .abc import DynamicLibRelocate
from .params import DynamicLibRelocateParams

__logger__ = logging.getLogger(__name__)


def dynamic_libraries(lib: lief.ELF.Binary) -> list[lief.ELF.DynamicEntryLibrary]:
    """Return the dynamic libraries required byte ELF."""
    return [
        entry
        for entry in lib.dynamic_entries
        if isinstance(entry, lief.ELF.DynamicEntryLibrary) and entry.tag == lief.ELF.DynamicEntry.TAG.NEEDED
    ]


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


def lib_name(lib: lief.ELF.Binary) -> str | None:
    """Return the SONAME of the binary, if any."""
    if (soname := lib.get(lief.ELF.DynamicEntry.TAG.SONAME)) is not None:
        return soname.name  # type: ignore
    return None


def relocate_bin(
    bin: lief.ELF.Binary,
    bin_path: pathlib.Path,
    prefix_path: pathlib.Path,
    path_transform: Callable[[pathlib.Path], pathlib.Path],
    overrides: DynamicLibRelocateParams,
) -> None:
    """Relocate the given binary to load dynamic libraries with relative path."""
    bin_path_relative = bin_path.relative_to(prefix_path)
    new_bin_path = path_transform(bin_path)

    origin_path = str(bin_path.parent)
    original_rpaths = [rp for entry in rpaths_runpaths(bin) for rp in entry.paths]
    resolved_rpaths = [resolve_rpath(rp, origin=origin_path) for rp in original_rpaths]

    # We would need to find how RPATH are used before correcting them.
    # Instead we remove them and let the follow-up add them.
    for entry in rpaths_runpaths(bin):
        for rpath in entry.paths:
            if pathlib.Path(rpath).is_relative_to(prefix_path):
                entry.remove(rpath)
                __logger__.info(f"{bin_path_relative}: Removing RPATH {rpath}")

    # Fix all the dynamic import libraries
    added_rpaths: list[str] = []
    for dep in dynamic_libraries(bin):
        dep_name = str(dep.name)

        if overrides.whitelist_rpaths.filter_file(pathlib.PurePath(dep_name)):
            __logger__.debug(f"{bin_path_relative}: Whitelisting dependency {dep_name}")
            continue

        # Find where the dependency is pointing to
        dep_path = resolve_dynamic_library(dep_name, rpaths=resolved_rpaths)

        if dep_path is not None:
            # Note that this may not have the proper SONAME associated with path_transform, but since
            # the filename is not in the RPATH, we can base the changes on it.
            new_dep_path = path_transform(dep_path)
        elif (r := overrides.add_rpaths.get(dep_name, None)) is not None:
            new_dep_path = pathlib.Path(r)
            __logger__.debug(f"""Library "{dep_name}" is configured to "{new_dep_path}".""")
        else:
            __logger__.warning(f"""Cannot find library "{dep_name}" in "{bin_path}".""")
            continue

        if new_dep_path.is_absolute():
            new_rpath = str(new_dep_path)
        else:
            new_rpath = str(
                utils.relative_relocation_path(
                    bin_path=new_bin_path,
                    dep_path=new_dep_path,
                    origin="$ORIGIN",
                )
            )

        if not utils.path_in_ensemble(new_rpath, original_rpaths + added_rpaths):
            # Conda-build seems to prefer RPATHs, but they did not seem to work.
            bin.add(lief.ELF.DynamicEntryRunPath(new_rpath))
            added_rpaths.append(new_rpath)
            __logger__.info(f"{bin_path_relative}: Adding RPATH {new_rpath}")


@dataclasses.dataclass
class ElfDynamicLibRelocate(DynamicLibRelocate[lief.ELF.Binary]):
    """Relocate Mach-O dynamic libraries RPATHs."""

    overrides: DynamicLibRelocateParams

    @classmethod
    def binary_type(self) -> type[lief.ELF.Binary]:
        """Return the type of the binary."""
        return lief.ELF.Binary

    def _needed(self, data: str | list[int]) -> bool:
        return lief.is_elf(data)

    def lib_name(self, bin: lief.ELF.Binary) -> str | None:
        """Return the filename in the Mach-O library id."""
        return lib_name(bin)

    def relocate_binary(
        self,
        bin: lief.ELF.Binary,
        data_path: pathlib.Path,
        prefix_path: pathlib.Path,
        path_transform: Callable[[pathlib.Path], pathlib.Path],
    ) -> None:
        """Transform the data inside the file."""
        __logger__.debug(f'Relocating ELF "{data_path}"')
        relocate_bin(
            bin=bin,
            bin_path=data_path,
            prefix_path=prefix_path,
            path_transform=path_transform,
            overrides=self.overrides,
        )
