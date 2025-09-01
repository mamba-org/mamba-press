import dataclasses
import pathlib
from typing import Self

import mamba_press.filter
import mamba_press.recipe
from mamba_press.filter.protocol import FilesFilter
from mamba_press.platform import WheelPlatformSplit
from mamba_press.recipe import DynamicParams, FromRecipeConfig, Source


def macos_make_default_library_whitelist() -> FilesFilter:
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


def linux_make_default_library_whitelist(wheel_split: WheelPlatformSplit) -> FilesFilter:
    """Return the default library allowed to link with on Linux, as a filter."""
    return mamba_press.filter.CombinedFilesFilter(
        [
            mamba_press.filter.ManyLinuxWhitelist(wheel_split),
            # Sometimes this is marked as explicitly needed
            mamba_press.filter.UnixGlobFilesFilter(["*ld-linux-x86-64.so*"], exclude=False),
        ],
        all=False,
    )


def make_default_library_whitelist(wheel_split: WheelPlatformSplit) -> FilesFilter:
    """Return the default library allowed to link with depending on the platform."""
    whitelist_rpaths: FilesFilter = mamba_press.filter.NoFilesFilter()
    if wheel_split.is_macos:
        whitelist_rpaths = macos_make_default_library_whitelist()
    elif wheel_split.is_manylinux:
        whitelist_rpaths = linux_make_default_library_whitelist(wheel_split)
    return whitelist_rpaths


@dataclasses.dataclass
class DynamicLibRelocateParams(FromRecipeConfig):
    """Parameters typically used for relocating dynamic libraries.

    Attributes:
    whitelist_rpaths: Ignore these missing RPATHs when found in any library.
    add_rpaths: RPATHs to add or modify when missing. When the filename provided as key is
        missing, replace it with the given path value. If the given path is relative, it
        is interpreted as relative to the created wheel root.
    remove_rpaths: RPATHs to always remove from any libraries. Use when wrongfuly linking with a
        library or when linking with a library that will already be loaded (e.g. `libpython`).

    """

    whitelist_rpaths: FilesFilter = mamba_press.filter.NoFilesFilter()
    add_rpaths: dict[str, pathlib.PurePath] = dataclasses.field(default_factory=dict)
    remove_rpaths: FilesFilter = mamba_press.filter.NoFilesFilter()

    @classmethod
    def from_config(cls, params: DynamicParams, source: Source, wheel_split: WheelPlatformSplit) -> Self:
        """Construct from simple parameters typically found in configurations."""
        add_rpaths_raw: list[str] = mamba_press.recipe.get_param_as(
            "add-rpaths", params=params, type_=list, default=[]
        )
        add_rpaths = {(p := pathlib.PurePath(path)).name: p for path in add_rpaths_raw}

        remove_rpaths_raw = params.get("remove-rpaths", None)
        remove_rpaths: FilesFilter = mamba_press.filter.NoFilesFilter()
        if remove_rpaths_raw is not None:
            # Pragmatic we make it a glob, but we could also call the plugin factory
            # to dispatch different type of filters
            remove_rpaths = mamba_press.filter.UnixGlobFilesFilter.from_config(
                {"patterns": remove_rpaths_raw, "exclude": False},
                source=source,
                wheel_split=wheel_split,
            )

        return cls(
            add_rpaths=add_rpaths,
            whitelist_rpaths=make_default_library_whitelist(wheel_split),
            remove_rpaths=remove_rpaths,
        )
