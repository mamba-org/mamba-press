import pytest

import mamba_press.utils as utils


def test_kebab_to_pascal() -> None:
    """Transform kebab-case to PascalCase."""
    assert utils.kebab_to_pascal("kebab-case") == "KebabCase"
    assert utils.kebab_to_pascal("k-e-b-ab") == "KEBAb"
    assert utils.kebab_to_pascal("word") == "Word"
    assert utils.kebab_to_pascal("") == ""


def test_interpolate() -> None:
    """Interpolation works without bad substitutions."""
    for var in ["name", " name", "name  ", "  name "]:
        assert utils.interpolate("Hello ${{" + var + "}}!", {"name": "Foo"}) == "Hello Foo!"
        assert utils.interpolate("Hello ${{" + var + "}}!", {"name": "Foo", "other": "here"}) == "Hello Foo!"

    assert utils.interpolate("Hello {{ name }}!", {"name": "Foo"}) == "Hello {{ name }}!"
    assert utils.interpolate("Hello ${{ first }} ${{ last}}!", {"first": "A", "last": "B"}) == "Hello A B!"

    with pytest.raises(KeyError):
        utils.interpolate("Hello ${{ name }}!", {"other": "here"})
