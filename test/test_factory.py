import pathlib
import unittest.mock

import libmambapy as mamba
import pytest

import mamba_press
from mamba_press.typing import Default, DynamicEntry


def test_interpolate_params() -> None:
    """String values, not keys, are interpolated recursively."""
    params: DynamicEntry = {
        "${{ foo }}": "bar",
        "recursive": {
            "a": True,
            "b": ["${{ bar }}/baz", "baz"],
            "c": 33,
        },
    }
    context = {"bar": "BAR"}
    expected = {
        "${{ foo }}": "bar",
        "recursive": {
            "a": True,
            "b": ["BAR/baz", "baz"],
            "c": 33,
        },
    }

    assert mamba_press.recipe.interpolate_params(params, context) == expected


def test_make_plugin() -> None:
    """Plugin work in standard and module mode."""
    source = unittest.mock.MagicMock()
    wheel_split = unittest.mock.MagicMock()

    plugin1 = mamba_press.factory.make_plugin(
        {"by-name": {"to_prune": ["foo"]}},
        module_name="mamba_press.filter",
        class_suffix="PackagesFilter",
        source=source,
        wheel_split=wheel_split,
    )

    plugin2 = mamba_press.factory.make_plugin(
        {"mamba_press.filter.ByNamePackagesFilter": {"to_prune": ["foo"]}},
        module_name="unused",
        source=source,
        wheel_split=wheel_split,
    )

    assert plugin1.to_prune[0] == plugin2.to_prune[0]  # type: ignore[attr-defined]


def test_make_filter_packages_default() -> None:
    """The default packages filter is properly created."""
    source = unittest.mock.MagicMock()
    recipe = mamba_press.Recipe(
        source=source,
        target=unittest.mock.MagicMock(),
        build=Default,
    )

    plugins = mamba_press.factory.make_filter_packages(recipe, wheel_split=unittest.mock.MagicMock())
    assert len(plugins) == 1
    assert isinstance(plugins[0], mamba_press.filter.ByNamePackagesFilter)
    assert plugins[0].to_prune == [
        mamba.specs.MatchSpec.parse("python"),
        mamba.specs.MatchSpec.parse("python_abi"),
    ]


def test_make_filer_files_default() -> None:
    """The default files filter is properly created."""
    source = unittest.mock.MagicMock()
    recipe = mamba_press.Recipe(
        source=source,
        target=unittest.mock.MagicMock(),
        build=Default,
    )

    plugins = mamba_press.factory.make_filter_files(
        recipe, interpolation_context={"site_packages": "TEST_STR"}, wheel_split=unittest.mock.MagicMock()
    )
    assert len(plugins) == 1
    assert isinstance(plugins[0], mamba_press.filter.UnixGlobFilesFilter)
    # Test interpolation has been applied
    assert any("TEST" in p for p in plugins[0].patterns)


def test_make_transform_paths_default() -> None:
    """The default path transforms is properly created."""
    source = unittest.mock.MagicMock()
    recipe = mamba_press.Recipe(
        source=source,
        target=unittest.mock.MagicMock(),
        build=Default,
    )

    plugins = mamba_press.factory.make_transform_paths(
        recipe,
        interpolation_context={"site_packages": "TEST_STR1", "package_name": "TEST_STR2"},
        wheel_split=unittest.mock.MagicMock(),
    )
    assert len(plugins) == 1
    assert isinstance(plugins[0], mamba_press.transform.ExplicitPathTransform)
    # Test interpolation has been applied
    assert any("TEST_STR1" in str(p) for p in plugins[0].mapping.keys())
    assert any("TEST_STR2" in str(p) for p in plugins[0].mapping.values())


@pytest.mark.parametrize(
    "wheel_split",
    [
        mamba_press.platform.WheelPlatformSplit.parse("macosx_11_1_x86_64"),
        mamba_press.platform.WheelPlatformSplit.parse("manylinux_2_17_x86_64"),
    ],
)
def test_make_transform_dynlib_default(wheel_split: mamba_press.platform.WheelPlatformSplit) -> None:
    """The default dynlib transforms is properly created."""
    recipe = mamba_press.Recipe(
        source=unittest.mock.MagicMock(),
        target=unittest.mock.MagicMock(),
        build=Default,
    )

    dynlib = mamba_press.factory.make_transform_dynlib(
        recipe,
        interpolation_context={"site_packages": "TEST_STR1", "package_name": "TEST_STR2"},
        wheel_split=wheel_split,
    )
    assert isinstance(dynlib, mamba_press.transform.dynlib.DynamicLibRelocate)


@pytest.mark.parametrize(
    "wheel_split",
    [
        mamba_press.platform.WheelPlatformSplit.parse("macosx_11_1_x86_64"),
        mamba_press.platform.WheelPlatformSplit.parse("manylinux_2_17_x86_64"),
    ],
)
def test_make_transform_dynlib(wheel_split: mamba_press.platform.WheelPlatformSplit) -> None:
    """The dynlib transform argument are properly parsed and interpolated."""
    recipe = mamba_press.Recipe(
        source=unittest.mock.MagicMock(),
        target=unittest.mock.MagicMock(),
        build=mamba_press.recipe.Build(
            transform=mamba_press.recipe.Transform(
                dynlib={
                    "add-rpaths": ["${{ foo }}/test1.so", "bar/test2.so"],
                    "remove-rpaths": ["baz/*.so"],
                }
            ),
        ),
    )

    dynlib = mamba_press.factory.make_transform_dynlib(
        recipe,
        interpolation_context={"foo": "TEST_STR1"},
        wheel_split=wheel_split,
    )
    assert isinstance(dynlib, mamba_press.transform.dynlib.DynamicLibRelocate)
    assert hasattr(dynlib, "overrides")
    assert len(dynlib.overrides.add_rpaths) == 2
    assert dynlib.overrides.add_rpaths["test1.so"] == pathlib.PurePath("TEST_STR1/test1.so")
    assert dynlib.overrides.remove_rpaths.filter_file("baz/lib.so")
    assert not dynlib.overrides.remove_rpaths.filter_file("not/lib.so")
