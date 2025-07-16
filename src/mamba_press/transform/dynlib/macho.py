import logging
import os
import pathlib
import re
from typing import Callable, Final, Iterable, cast

import lief

from . import utils

__logger__ = logging.getLogger(__name__)

# https://github.com/conda/conda-build/blob/main/conda_build/post.py
MACOS_DYLIB_WHITELIST: Final = [
    re.compile(r"/opt/X11/.*\.dylib"),
    re.compile(r"/usr/lib/libcrypto\.0\.9\.8\.dylib"),
    re.compile(r"/usr/lib/libobjc\.A\.dylib"),
    re.compile(r"/System/Library/Frameworks/.*\.framework/"),
    re.compile(r"/usr/lib/libSystem\.B\.dylib"),
]


def lib_is_whitelisted(lib: str) -> bool:
    """Check if a shared library is expected on the system."""
    return any(system_lib.match(lib) is not None for system_lib in MACOS_DYLIB_WHITELIST)


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


def binary_name(lib: lief.MachO.Binary) -> lief.MachO.DylibCommand | None:
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
        return names[0]
    return None


def relocate_lib(
    lib: lief.MachO.Binary,
    lib_path: pathlib.Path,
    prefix_path: pathlib.Path,
    path_transform: Callable[[pathlib.Path], pathlib.Path],
) -> None:
    """Relocate the given library to load dynamic libraries with relative path."""
    lib_path_relative = lib_path.relative_to(prefix_path)
    new_lib_path = path_transform(lib_path)

    # Fix library name: this is MacOS specific
    if (old_name_cmd := binary_name(lib)) is not None:
        old_name: str = old_name_cmd.name
        new_name = simple_rpath_load_command(new_lib_path)
        if not utils.path_in_ensemble(new_name, [old_name]):
            old_name_cmd.name = new_name
            __logger__.info(f"{lib_path_relative}: Patching name {old_name} -> {new_name}")

    origin_path = str(lib_path.parent)
    original_rpaths = [r.path for r in lib.rpaths]
    resolved_rpaths = normalize_rpaths(original_rpaths, origin=origin_path)

    # We would need to find how RPATH are used before correcting them.
    # Instead we remove them and let the follow-up add them.
    for rpath in lib.rpaths:
        if pathlib.Path(rpath.path).is_relative_to(prefix_path):
            lib.remove(rpath)
            __logger__.info(f"{lib_path_relative}: Removing RPATH {rpath}")

    # Fix all the dynamic import libraries
    added_rpaths: list[str] = []
    for cmd in load_commands(lib):
        cmd_name = cmd.name
        # Note that some whitelisted libs don't exist but are embedded in the linker
        if lib_is_whitelisted(cmd_name):
            __logger__.debug(f"{lib_path_relative}: Whitelisting dependency {cmd.name}")
            continue

        # Find where the dependency is pointing to
        dep_path = resolve_load_path(cmd_name, origin=origin_path, rpaths=resolved_rpaths)
        if dep_path is None:
            # TODO: configure behaviour
            # We could also read from the dso whitelist on the recipe but we would need
            # to be able to parse the old recipe format.
            __logger__.warning(f"""Cannot find library "{cmd_name}" in "{lib_path}".""")
            continue

        new_dep_path = path_transform(dep_path)
        new_cmd_name = simple_rpath_load_command(new_dep_path)
        if not utils.path_in_ensemble(new_cmd_name, [cmd_name]):
            cmd.name = str(new_cmd_name)
            __logger__.info(f"{lib_path_relative}: Patching dependency {cmd_name} -> {new_cmd_name}")

        new_rpath = str(
            utils.relative_relocation_path(
                lib_path=new_lib_path,
                dep_path=new_dep_path,
                origin="@loader_path",
            )
        )
        if not utils.path_in_ensemble(new_rpath, original_rpaths + added_rpaths):
            lib.add(cast(lief.MachO.LoadCommand, lief.MachO.RPathCommand.create(new_rpath)))
            added_rpaths.append(new_rpath)
            __logger__.info(f"{lib_path_relative}: Adding RPATH {new_rpath}")
