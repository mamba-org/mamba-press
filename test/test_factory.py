import unittest.mock

import mamba_press
from mamba_press.typing import Default


def test_make_plugin() -> None:
    """Plugin work in standard and module mode."""
    source = unittest.mock.MagicMock()

    plugin1 = mamba_press.factory.make_plugin(
        {"PackagesFilter": {"to_prune": ["foo"]}},
        module_name="mamba_press.filter",
        source=source,
    )

    plugin2 = mamba_press.factory.make_plugin(
        {"mamba_press.filter.PackagesFilter": {"to_prune": ["foo"]}},
        module_name="unused",
        source=source,
    )

    # FIXME Cheap comparison since MatchSpec currently does not have equality comparison
    assert str(plugin1.to_prune[0]) == str(plugin2.to_prune[0])  # type: ignore[attr-defined]


def test_make_solution_filter() -> None:
    """The default solution filter is properly created."""
    source = unittest.mock.MagicMock()
    recipe = mamba_press.Recipe(
        source=source,
        target=unittest.mock.MagicMock(),
        build=Default,
    )

    plugins = mamba_press.factory.make_solution_filters(recipe)
    assert len(plugins) == 1
    assert isinstance(plugins[0], mamba_press.filter.PackagesFilter)
    # FIXME Cheap comparison since MatchSpec currently does not have equality comparison
    assert set(str(ms) for ms in plugins[0].to_prune) == {"python", "python_abi"}
