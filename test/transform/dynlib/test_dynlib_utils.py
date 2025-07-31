import pathlib

import mamba_press.transform.dynlib.utils as utils


def test_relative_relocation_path() -> None:
    """Relocation paths uses special keywords."""
    assert utils.relative_relocation_path(
        pathlib.PurePath("/lib/liba.dylib"),
        pathlib.PurePath("/lib/libc.dylib"),
        origin="@loader_path",
    ) == pathlib.PurePath("@loader_path/")

    assert utils.relative_relocation_path(
        pathlib.PurePath("/lib/liba.dylib"),
        pathlib.PurePath("/lib/hidden/libc.dylib"),
        origin="@loader_path",
    ) == pathlib.PurePath("@loader_path/hidden")

    assert utils.relative_relocation_path(
        pathlib.PurePath("/lib/python3.8/site-packages/pkg/liba.dylib"),
        pathlib.PurePath("/lib/libc.dylib"),
        origin="@loader_path",
    ) == pathlib.PurePath("@loader_path/../../..")

    assert utils.relative_relocation_path(
        pathlib.PurePath("/lib/python3.8/site-packages/pkg/liba.so"),
        pathlib.PurePath("/lib/libc.so"),
        origin="$ORIGIN",
    ) == pathlib.PurePath("$ORIGIN/../../..")


def test_path_in_ensemble() -> None:
    """Ensemble path is semantically correct."""
    ensemble = ["/foo/bar", "/baz/qux"]
    assert utils.path_in_ensemble("/foo/bar", ensemble)

    ensemble1 = [pathlib.Path("/foo/bar"), pathlib.Path("/baz/qux")]
    assert utils.path_in_ensemble(pathlib.Path("/baz/qux"), ensemble1)
    assert utils.path_in_ensemble(pathlib.Path("/baz/qux/"), ensemble1)
    assert not utils.path_in_ensemble("/not/here", ensemble1)

    ensemble2: list[str | pathlib.Path] = ["/foo/bar", pathlib.Path("/baz/qux")]
    assert utils.path_in_ensemble(pathlib.Path("/baz/qux/"), ensemble2)

    assert not utils.path_in_ensemble("/foo/bar", [])
