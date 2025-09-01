import dataclasses
import logging
import os
import pathlib
from typing import Callable, Self

import lief

import mamba_press.filter.files
import mamba_press.recipe
from mamba_press.filter.protocol import FilesFilter
from mamba_press.platform import WheelPlatformSplit
from mamba_press.recipe import DynamicParams, FromRecipeConfig, Source

from . import utils
from .abc import DynamicLibRelocate

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
    library_whitelist: FilesFilter,
    add_rpaths: dict[str, pathlib.PurePath],
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

        if library_whitelist.filter_file(pathlib.PurePath(dep_name)):
            __logger__.debug(f"{bin_path_relative}: Whitelisting dependency {dep_name}")
            continue

        # Find where the dependency is pointing to
        dep_path = resolve_dynamic_library(dep_name, rpaths=resolved_rpaths)

        if dep_path is not None:
            # Note that this may not have the proper SONAME associated with path_transform, but since
            # the filename is not in the RPATH, we can base the changes on it.
            new_dep_path = path_transform(dep_path)
        elif dep_name in add_rpaths:
            new_dep_path = pathlib.Path(add_rpaths[dep_name])
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


def make_default_library_whitelist(wheel_split: WheelPlatformSplit) -> FilesFilter:
    """Return the default library allowed to link with on Linux, as a filter."""
    return mamba_press.filter.CombinedFilesFilter(
        [
            mamba_press.filter.ManyLinuxWhitelist(wheel_split),
            # Sometimes this is marked as explicitly needed
            mamba_press.filter.UnixGlobFilesFilter(["*ld-linux-x86-64.so*"], exclude=False),
        ],
        all=False,
    )


@dataclasses.dataclass
class ElfDynamicLibRelocate(DynamicLibRelocate[lief.ELF.Binary], FromRecipeConfig):
    """Relocate Mach-O dynamic libraries RPATHs."""

    library_whitelist: FilesFilter
    add_rpath: dict[str, pathlib.PurePath] = dataclasses.field(default_factory=dict)

    @classmethod
    def from_config(cls, params: DynamicParams, source: Source, wheel_split: WheelPlatformSplit) -> Self:
        """Construct from simple parameters typically found in configurations."""
        add_rpath_str: list[str] = mamba_press.recipe.get_param_as(
            "add-rpath", params=params, type_=list, default=[]
        )
        add_rpath_map = {(p := pathlib.PurePath(path)).name: p for path in add_rpath_str}

        return cls(
            library_whitelist=make_default_library_whitelist(wheel_split),
            add_rpath=add_rpath_map,
        )

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
            library_whitelist=self.library_whitelist,
            add_rpaths=self.add_rpath,
        )
