import importlib
from collections.abc import Mapping

import lief

import mamba_press.filter
import mamba_press.recipe
import mamba_press.transform.dynlib
import mamba_press.utils
from mamba_press.filter.protocol import FilesFilter, PackagesFilter
from mamba_press.platform import WheelPlatformSplit
from mamba_press.recipe import FromRecipeConfig, NamedDynamicEntry, Recipe
from mamba_press.transform.dynlib.abc import DynamicLibRelocate
from mamba_press.transform.protocol import PathTransform
from mamba_press.typing import Default


def make_plugin(  # type: ignore
    entry: NamedDynamicEntry,
    module_name: str,
    class_suffix: str = "",
    **kwargs,
) -> object:
    """Import and instantiate a plugin."""
    if len(entry) != 1:
        raise ValueError("Plugin entries must use a single top level name.")

    name, params = entry.popitem()
    # A mamba_press standard filter
    if name.count(".") == 0:
        class_name = mamba_press.utils.kebab_to_pascal(name) + class_suffix
    # A plugin filter
    else:
        class_name = name.rsplit(".", 1)[-1]
        module_name = ".".join(name.split(".")[:-1])

    module = importlib.import_module(module_name)
    class_ = getattr(module, class_name, None)
    if class_ is None:
        raise ValueError(f"No plugin named {class_name}")

    return class_.from_config(params, **kwargs)


def make_filter_package_default_config() -> list[NamedDynamicEntry]:
    """Return the default package filter config."""
    return [
        {
            "by-name": {
                "to_prune": ["python", "python_abi"],
                "recursive": True,
            }
        },
    ]


def make_filter_packages(recipe: Recipe, wheel_split: WheelPlatformSplit) -> list[PackagesFilter]:
    """Import and instantiate required packages filters."""
    entries = make_filter_package_default_config()
    if recipe.build != Default and recipe.build.filter != Default and recipe.build.filter.packages != Default:
        entries = recipe.build.filter.packages

    return [
        make_plugin(
            e,
            module_name="mamba_press.filter",
            class_suffix="PackagesFilter",
            source=recipe.source,
            wheel_split=wheel_split,
        )  # type: ignore[misc]
        for e in entries
    ]


def make_filter_files_default_config() -> list[NamedDynamicEntry]:
    """Return the default file filter config."""
    return [
        {
            "unix-glob": {
                "patterns": [
                    "conda-meta/*",
                    "etc/conda/*",
                    "man/*",
                    "ssl/*",
                    "share/man/*",
                    "share/terminfo/*",
                    "share/locale/*",
                    "bin/*",
                    "sbin/*",
                    "include/*",
                    "lib/pkgconfig/*",
                    "lib/cmake/*",
                    "*.a",
                    "*.pyc",
                    "*/__pycache__/*",
                    "${{ site_packages }}/*.dist-info/RECORD",
                    "${{ site_packages }}/*.dist-info/INSTALLER",
                    "${{ site_packages }}/*.dist-info/REQUESTED",
                ],
                "exclude": True,
            }
        },
    ]


def make_filter_files(
    recipe: Recipe, wheel_split: WheelPlatformSplit, interpolation_context: Mapping[str, str]
) -> list[FilesFilter]:
    """Import and instantiate required files filters."""
    entries = make_filter_files_default_config()
    if recipe.build != Default and recipe.build.filter != Default and recipe.build.filter.files != Default:
        entries = recipe.build.filter.files

    entries = mamba_press.recipe.interpolate_params(
        entries,  # type: ignore[arg-type]
        interpolation_context,
    )  # type: ignore[assignment]

    return [
        make_plugin(
            e,
            module_name="mamba_press.filter",
            class_suffix="FilesFilter",
            source=recipe.source,
            wheel_split=wheel_split,
        )  # type: ignore[misc]
        for e in entries
    ]


def make_transform_path_default_config() -> list[NamedDynamicEntry]:
    """Return the default path trnasform config."""
    return [
        {
            "explicit": {
                "mapping": [
                    {"from": "${{ site_packages }}/", "to": "."},
                    # Due to lowest specificity, this will only be applied to remaining files
                    {"from": ".", "to": "${{ package_name }}/data/"},
                ]
            }
        },
    ]


def make_transform_paths(
    recipe: Recipe, wheel_split: WheelPlatformSplit, interpolation_context: Mapping[str, str]
) -> list[PathTransform]:
    """Import and instantiate required path transforms."""
    entries = make_transform_path_default_config()
    if (
        recipe.build != Default
        and recipe.build.transform != Default
        and recipe.build.transform.path != Default
    ):
        entries = recipe.build.transform.path

    entries = mamba_press.recipe.interpolate_params(
        entries,  # type: ignore[arg-type]
        interpolation_context,
    )  # type: ignore[assignment]

    return [
        make_plugin(
            e,
            module_name="mamba_press.transform",
            class_suffix="PathTransform",
            source=recipe.source,
            wheel_split=wheel_split,
        )  # type: ignore[misc]
        for e in entries
    ]


def make_transform_dynlib(
    recipe: Recipe, wheel_split: WheelPlatformSplit, interpolation_context: Mapping[str, str]
) -> DynamicLibRelocate[lief.MachO.Binary] | DynamicLibRelocate[lief.ELF.Binary]:
    """Import and instantiate required dynlib transforms."""
    klass: FromRecipeConfig | None = None
    if wheel_split.is_macos:
        klass = mamba_press.transform.dynlib.MachODynamicLibRelocate
    elif wheel_split.is_manylinux:
        klass = mamba_press.transform.dynlib.ElfDynamicLibRelocate

    if klass is not None:
        return klass.from_config({}, source=recipe.source, wheel_split=wheel_split)  # type: ignore[return-value]

    raise ValueError(f'Invalid or unsupported platform "{wheel_split}"')
