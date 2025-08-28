import libmambapy as mamba

import mamba_press


def test_recipe_parse_no_build() -> None:
    """Parse recipe from yaml format, with missing keys."""
    yaml = """
        version: 0
        source:
          packages:
            - libmamba
          python: "python==3.13"
        target:
          name: libmamba
          platform:
            os: manylinux
            version: "2.17"
            arch: x86_64
    """

    recipe = mamba_press.recipe.RecipeV0.parse_yaml(yaml)
    assert recipe.version == 0
    assert recipe.build == mamba_press.recipe.Default
    assert recipe.target.python == mamba_press.recipe.Default
    assert recipe.target.name == "libmamba"
    assert isinstance(recipe.source.python, mamba.specs.MatchSpec)


def test_recipe_parse_filter_packages() -> None:
    """Parse recipe from yaml format, with partial build filter."""
    yaml = """
        version: 0
        source:
          packages:
            - libmamba
          python: "python==3.13"
        target:
          name: libmamba
          platform:
            os: manylinux
            version: "2.17"
            arch: x86_64
        build:
          filter:
             packages:
               - python-dependencies: {}

    """

    recipe = mamba_press.recipe.RecipeV0.parse_yaml(yaml)
    assert recipe.build != mamba_press.recipe.Default
    #  assert recipe.build.transform == mamba_press.recipe.Default
    assert recipe.build.filter != mamba_press.recipe.Default
    assert isinstance(recipe.build.filter.packages, list)
    assert len(recipe.build.filter.packages) == 1
