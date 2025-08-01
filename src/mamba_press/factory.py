import importlib
from collections.abc import Mapping
from typing import Final

import mamba_press.filter
import mamba_press.recipe
import mamba_press.utils
from mamba_press.filter.protocol import FilesFilter, PackagesFilter
from mamba_press.recipe import NamedDynamicEntry, Recipe
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


DEFAULT_SOLUTION_FILTERS: Final[list[NamedDynamicEntry]] = [
    {
        "by-name": {
            "to_prune": ["python", "python_abi"],
            "recursive": True,
        }
    },
]


def make_solution_filters(recipe: Recipe) -> list[PackagesFilter]:
    """Import and instantiate required solution filters."""
    entries = DEFAULT_SOLUTION_FILTERS
    if recipe.build != Default and recipe.build.filter != Default and recipe.build.filter.packages != Default:
        entries = recipe.build.filter.packages

    return [
        make_plugin(
            e,
            module_name="mamba_press.filter",
            class_suffix="PackagesFilter",
            source=recipe.source,
        )  # type: ignore[misc]
        for e in entries
    ]


DEFAULT_FILES_FILTERS: Final[list[NamedDynamicEntry]] = [
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


def make_files_filters(recipe: Recipe, interpolation_context: Mapping[str, str]) -> list[FilesFilter]:
    """Import and instantiate required files filters."""
    entries = DEFAULT_FILES_FILTERS
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
        )  # type: ignore[misc]
        for e in entries
    ]
