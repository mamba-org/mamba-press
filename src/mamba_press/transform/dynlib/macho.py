import logging
import os
import pathlib
import re
from typing import Callable, Final, Iterable, cast

import lief

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


def relative_relocation_path(
    lib_path: pathlib.Path, dep_path: pathlib.Path, origin: str = "@rpath"
) -> pathlib.Path:
    """Create a relative load path between two paths."""
    relative = os.path.relpath(dep_path.parent, lib_path.parent)
    return pathlib.Path(origin) / relative / dep_path.name


def load_commands(lib: lief.MachO.Binary) -> list[lief.MachO.DylibCommand]:
    """Return load commands from library."""
    return [command for command in lib.commands if isinstance(command, lief.MachO.DylibCommand)]


def path_in_ensemble(path: str | pathlib.Path, ensemble: Iterable[str | pathlib.Path]) -> bool:
    """Check if a path is in an ensemble with path comparison."""
    return any(pathlib.Path(path) == pathlib.Path(p) for p in ensemble)


def relocate_lib(
    lib: lief.MachO.Binary,
    lib_path: pathlib.Path,
    prefix_path: pathlib.Path,
    path_transform: Callable[[pathlib.Path], pathlib.Path],
) -> None:
    """Relocate the given library to load dynamic libraries with relative path."""
    lib_path_relative = lib_path.relative_to(prefix_path)

    origin_path = str(lib_path.parent)
    original_rpaths = [r.path for r in lib.rpaths]
    resolved_rpaths = normalize_rpaths(original_rpaths, origin=origin_path)

    # We would need to find how RPATH are used before correcting them.
    # Instead we remove them and let the follow-up add them.
    for rpath in lib.rpaths:
        if pathlib.Path(rpath.path).is_relative_to(prefix_path):
            lib.remove(rpath)

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
            # raise RuntimeError(f"""Cannot find library "{cmd_name}" in "{lib_path}".""")

        new_lib_path = path_transform(lib_path)
        new_dep_path = path_transform(dep_path)
        new_cmd = relative_relocation_path(lib_path=new_lib_path, dep_path=new_dep_path)
        if not path_in_ensemble(new_cmd, [cmd_name]):
            lib.remove(cmd)
            lib.add(lief.MachO.DylibCommand.load_dylib(str(new_cmd)))
            __logger__.info(f"{lib_path_relative}: Patching dependency {cmd_name} -> {new_cmd}")

        new_rpath = "@loader_path/"
        if not path_in_ensemble(new_rpath, original_rpaths):
            lib.add(cast(lief.MachO.LoadCommand, lief.MachO.RPathCommand.create(new_rpath)))
            __logger__.info(f"{lib_path_relative}: Adding RPATH {new_rpath}")
