import dataclasses
import logging
import os
import pathlib
import subprocess
from typing import Callable, Iterable, Self, cast, override

import lief

import mamba_press.filter.files
from mamba_press.filter.protocol import FilesFilter
from mamba_press.platform import WheelPlatformSplit
from mamba_press.recipe import DynamicParams, FromRecipeConfig, Source

from . import utils
from .abc import DynamicLibRelocate

__logger__ = logging.getLogger(__name__)


def normalize_load_path(path: str, origin: str, rpaths: list[pathlib.Path]) -> list[pathlib.Path]:
    """Resolve special keywords and rpaths in loading path."""
    if "@rpath" not in path:
        path = path.replace("@loader_path", origin).replace("@executable_path", origin)
        return [pathlib.Path(os.path.normpath(path))]
    return [pathlib.Path(os.path.normpath(path.replace("@rpath", str(r)))) for r in rpaths]


def normalize_rpaths(rpaths: Iterable[str], origin: str) -> list[pathlib.Path]:
    """Resolve special keyword in rpaths."""
    return [p for r in rpaths for p in normalize_load_path(r, origin=origin, rpaths=[])]


def resolve_load_path(path: str, origin: str, rpaths: list[pathlib.Path]) -> pathlib.Path | None:
    """Find which file or symlink on the system a load path is pointing to."""
    for p in normalize_load_path(path, origin=origin, rpaths=rpaths):
        if p.exists():
            return p
    return None


def simple_rpath_load_command(lib_path: pathlib.PurePath | str) -> str:
    """Return simple load command with ``@rpath`` followed by the filename."""
    return "@rpath/{}".format(pathlib.PurePath(lib_path).name)


def load_commands(lib: lief.MachO.Binary) -> list[lief.MachO.DylibCommand]:
    """Return dynamic load commands from library.

    These can be inspected with ``otool -L lib.so`` in the terminal.
    """
    return [
        cmd
        for cmd in lib.commands
        if (cmd.command == lief.MachO.LoadCommand.TYPE.LOAD_DYLIB)
        and isinstance(cmd, lief.MachO.DylibCommand)
    ]


def lib_name(lib: lief.MachO.Binary) -> str | None:
    """Return MacOS binary name command LC_ID_DYLIB or install-name.

    There is typically only one for libraries, and none for executables.
    These can be inspected with ``otool -D lib.so`` in the terminal.
    """
    names = [
        cmd
        for cmd in lib.commands
        if (cmd.command == lief.MachO.LoadCommand.TYPE.ID_DYLIB) and isinstance(cmd, lief.MachO.DylibCommand)
    ]
    if len(names) == 0:
        return None
    if len(names) == 1:
        return os.path.basename(names[0].name)
    return None


def relocate_bin(
    bin: lief.MachO.Binary,
    bin_path: pathlib.Path,
    prefix_path: pathlib.Path,
    path_transform: Callable[[pathlib.Path], pathlib.Path],
    library_whitelist: FilesFilter,
    add_rpaths: dict[str, pathlib.PurePath],
) -> None:
    """Relocate the given binary to load dynamic libraries with relative path."""
    bin.remove_signature()

    bin_path_relative = bin_path.relative_to(prefix_path)
    new_lib_path = path_transform(bin_path)

    origin_path = str(bin_path.parent)
    original_rpaths = [r.path for r in bin.rpaths]
    resolved_rpaths = normalize_rpaths(original_rpaths, origin=origin_path)

    # We would need to find how RPATH are used before correcting them.
    # Instead we remove them and let the follow-up add them.
    for rpath in bin.rpaths:
        if pathlib.Path(rpath.path).is_relative_to(prefix_path):
            bin.remove(rpath)
            __logger__.info(f"{bin_path_relative}: Removing RPATH {rpath}")

    # Fix all the dynamic import libraries
    added_rpaths: list[str] = []
    for cmd in load_commands(bin):
        cmd_name = cmd.name
        # Note that some whitelisted libs don't exist but are embedded in the linker
        if library_whitelist.filter_file(pathlib.PurePath(cmd_name)):
            __logger__.debug(f"{bin_path_relative}: Whitelisting dependency {cmd.name}")
            continue

        # Find where the dependency is pointing to
        dep_path = resolve_load_path(cmd_name, origin=origin_path, rpaths=resolved_rpaths)

        if dep_path is not None:
            # Note that this may not have the proper lib ID associated with path_transform, but since
            # the filename is not in the RPATH, we can base the changes on it.
            new_dep_path = path_transform(dep_path)
        elif cmd_name in add_rpaths:
            new_dep_path = pathlib.Path(add_rpaths[cmd_name])
            __logger__.debug(f"""Library "{cmd_name}" is configured to "{new_dep_path}".""")

        else:
            __logger__.warning(f"""Cannot find library "{cmd_name}" in "{bin_path}".""")
            continue

        if new_dep_path.is_absolute():
            new_rpath = str(new_dep_path)
        else:
            new_rpath = str(
                utils.relative_relocation_path(
                    bin_path=new_lib_path,
                    dep_path=new_dep_path,
                    origin="@loader_path",
                )
            )

        if not utils.path_in_ensemble(new_rpath, original_rpaths + added_rpaths):
            bin.add(cast(lief.MachO.LoadCommand, lief.MachO.RPathCommand.create(new_rpath)))
            added_rpaths.append(new_rpath)
            __logger__.info(f"{bin_path_relative}: Adding RPATH {new_rpath}")


def codesign(path: str) -> None:
    """Code sign an executable using the system codesign utility.

    See also apple-codesign for a portable option.
    https://github.com/indygreg/apple-platform-rs
    """
    cmd = ["/usr/bin/codesign", "-s", "-", "-f", path]
    subprocess.run(cmd, capture_output=True, check=True, env={})


def make_default_library_whitelist() -> FilesFilter:
    """Return the default library allowed to link with on MacOS, as a filter."""
    return mamba_press.filter.UnixGlobFilesFilter(
        [
            # https://github.com/conda/conda-build/blob/main/conda_build/post.py
            "/opt/X11/*.dylib",
            "/usr/lib/libcrypto.0.9.8.dylib",
            "/usr/lib/libobjc.A.dylib",
            "/System/Library/Frameworks/*.framework/*",
            "/usr/lib/libSystem.B.dylib",
            # Common low-level DSO whitelist from
            "/usr/lib/libc++abi.dylib",
            "/usr/lib/libresolv*.dylib",
        ],
        exclude=False,
    )


@dataclasses.dataclass
class MachODynamicLibRelocate(DynamicLibRelocate[lief.MachO.Binary], FromRecipeConfig):
    """Relocate Mach-O dynamic libraries RPATHs."""

    library_whitelist: FilesFilter = dataclasses.field(default_factory=make_default_library_whitelist)
    add_rpath: dict[str, pathlib.PurePath] = dataclasses.field(default_factory=dict)

    @classmethod
    def from_config(cls, params: DynamicParams, source: Source, wheel_split: WheelPlatformSplit) -> Self:
        """Construct from simple parameters typically found in configurations."""
        add_rpath_str: list[str] = mamba_press.recipe.get_param_as(
            "add-rpath", params=params, type_=list, default=[]
        )
        add_rpath_map = {(p := pathlib.PurePath(path)).name: p for path in add_rpath_str}

        return cls(add_rpath=add_rpath_map)

    @classmethod
    def binary_type(self) -> type[lief.MachO.Binary]:
        """Return the type of the binary."""
        return lief.MachO.Binary

    def _needed(self, data: str | list[int]) -> bool:
        return lief.is_macho(data)

    def lib_name(self, bin: lief.MachO.Binary) -> str | None:
        """Return the filename in the Mach-O library id."""
        return lib_name(bin)

    @override
    def write_binary(self, bin: lief.MachO.Binary, path: pathlib.Path) -> None:
        """Write the binary to file and codesign it."""
        super().write_binary(bin, path)
        __logger__.info(f"codesign {path}")
        codesign(str(path.resolve()))

    def relocate_binary(
        self,
        bin: lief.MachO.Binary,
        data_path: pathlib.Path,
        prefix_path: pathlib.Path,
        path_transform: Callable[[pathlib.Path], pathlib.Path],
    ) -> None:
        """Transform the data inside the file."""
        __logger__.debug(f'Relocating Mach-O "{data_path}"')
        relocate_bin(
            bin=bin,
            bin_path=data_path,
            prefix_path=prefix_path,
            path_transform=path_transform,
            library_whitelist=self.library_whitelist,
            add_rpaths=self.add_rpath,
        )
