import importlib

import mamba_press.filter
import mamba_press.utils
from mamba_press.filter.abc import SolutionFilter
from mamba_press.recipe import NamedDynamicEntry, Recipe
from mamba_press.typing import Default


def make_plugin(  # type: ignore
    entry: NamedDynamicEntry,
    module_name: str,
    **kwargs,
) -> object:
    """Import and instantiate a plugin."""
    if len(entry) != 1:
        raise ValueError("Plugin entries must use a single top level name.")

    name, params = entry.popitem()
    # A mamba_press standard filter
    if name.count(".") == 0:
        class_name = mamba_press.utils.kebab_to_pascal(name)
    # A plugin filter
    else:
        class_name = name.rsplit(".", 1)[-1]
        module_name = ".".join(name.split(".")[:-1])

    module = importlib.import_module(module_name)
    class_ = getattr(module, class_name, None)
    if class_ is None:
        raise ValueError(f"No plugin named {class_name}")

    return class_.from_config(params, **kwargs)


def make_solution_filters(recipe: Recipe) -> list[SolutionFilter]:
    """Import and instantiate required solution filters."""
    packages = ["python", "python_abi"]

    if recipe.build != Default and recipe.build.filter != Default and recipe.build.filter.packages != Default:
        packages = mamba_press.recipe.get_param_as(
            "packages",
            params=recipe.build.filter.packages,  # type: ignore[arg-type]
            type_=list[str],
        )

    plugin = make_plugin(
        {
            "PackagesFilter": {
                "to_prune": packages,  # type: ignore[dict-item]
            }
        },
        module_name="mamba_press.filter",
        source=recipe.source,
    )
    return [plugin]  # type: ignore[list-item]
