import unittest.mock as mock
from pathlib import PurePath

import mamba_press


def test_explicit_transform_from_config() -> None:
    """Can be created from a dictionary."""
    transform = mamba_press.transform.ExplicitPathTransform.from_config(
        {"mapping": [{"from": "a", "to": "b"}, {"from": "c", "to": "d"}]},
        source=mock.MagicMock(),
        wheel_split=mock.MagicMock(),
    )

    assert transform.mapping == {
        PurePath("a"): PurePath("b"),
        PurePath("c"): PurePath("d"),
    }


def test_path_relocate() -> None:
    """Relocate according to mapping."""
    relocator = mamba_press.transform.ExplicitPathTransform(
        {
            PurePath("lib/libamazing.so"): PurePath("pkg/libamazing.so"),
            PurePath("lib/"): PurePath("pkg/lib/"),
            PurePath("lib/python3.8/site-packages"): PurePath(""),
        }
    )

    # Explicit file relocation
    assert relocator.transform_path(PurePath("lib/libamazing.so")) == PurePath("pkg/libamazing.so")
    # Folder relocation
    assert relocator.transform_path(PurePath("lib/libother.so")) == PurePath("pkg/lib/libother.so")
    # Most specific relocation found
    assert relocator.transform_path(PurePath("lib/python3.8/site-packages/foo/libfoo.so")) == PurePath(
        "foo/libfoo.so"
    )
    # Leave other path unchanged
    assert relocator.transform_path(PurePath("bin/bar")) == PurePath("bin/bar")
