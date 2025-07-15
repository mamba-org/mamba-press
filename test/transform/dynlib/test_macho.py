import pathlib

import mamba_press.transform.dynlib.macho as macho


def test_lib_is_whitelisted() -> None:
    """System libraries are whitelisted."""
    assert macho.lib_is_whitelisted("/usr/lib/libSystem.B.dylib")


def test_normalize_load_path() -> None:
    """Load paths are properly resolved."""
    assert macho.normalize_load_path(path="/usr/lib/libfoo.dylib", origin="/origin", rpaths=[]) == [
        pathlib.Path("/usr/lib/libfoo.dylib")
    ]

    assert macho.normalize_load_path(path="@loader_path/libfoo.dylib", origin="/my/origin", rpaths=[]) == [
        pathlib.Path("/my/origin/libfoo.dylib")
    ]

    assert macho.normalize_load_path(
        path="@executable_path/libfoo.dylib", origin="/bin/origin", rpaths=[]
    ) == [pathlib.Path("/bin/origin/libfoo.dylib")]

    assert macho.normalize_load_path(
        path="@rpath/libfoo.dylib", origin="/origin", rpaths=[pathlib.Path("/opt/rpath1")]
    ) == [pathlib.Path("/opt/rpath1/libfoo.dylib")]

    assert macho.normalize_load_path(
        path="@rpath/libfoo.dylib",
        origin="/origin",
        rpaths=[pathlib.Path("/opt/rpath1"), pathlib.Path("/opt/rpath2")],
    ) == [
        pathlib.Path("/opt/rpath1/libfoo.dylib"),
        pathlib.Path("/opt/rpath2/libfoo.dylib"),
    ]

    assert macho.normalize_load_path(
        path="@rpath/libfoo.dylib",
        origin="/origin",
        rpaths=[
            pathlib.Path("/opt/rpath1"),
            pathlib.Path("/opt/rpath2"),
            pathlib.Path("/opt/rpath3"),
        ],
    ) == [
        pathlib.Path("/opt/rpath1/libfoo.dylib"),
        pathlib.Path("/opt/rpath2/libfoo.dylib"),
        pathlib.Path("/opt/rpath3/libfoo.dylib"),
    ]

    assert macho.normalize_load_path(
        path="@rpath/libfoo.dylib",
        origin="/origin",
        rpaths=[
            pathlib.Path("relative/rpath1"),
            pathlib.Path("relative/rpath2"),
        ],
    ) == [
        pathlib.Path("relative/rpath1/libfoo.dylib"),
        pathlib.Path("relative/rpath2/libfoo.dylib"),
    ]

    assert macho.normalize_load_path(
        path="@rpath/libfoo.dylib", origin="/origin", rpaths=[pathlib.Path("../rpath1")]
    ) == [
        pathlib.Path("../rpath1/libfoo.dylib"),
    ]

    assert macho.normalize_load_path(
        path="@rpath/libfoo.dylib", origin="/origin", rpaths=[pathlib.Path("../../rpath2")]
    ) == [
        pathlib.Path("../../rpath2/libfoo.dylib"),
    ]

    assert macho.normalize_load_path(
        path="/usr/lib/libfoo.dylib", origin="/origin", rpaths=[pathlib.Path("/opt/rpath1")]
    ) == [pathlib.Path("/usr/lib/libfoo.dylib")]

    assert macho.normalize_load_path(
        path="@loader_path/@executable_path/libfoo.dylib", origin="/origin", rpaths=[]
    ) == [pathlib.Path("/origin//origin/libfoo.dylib")]

    assert macho.normalize_load_path(path="@rpath/libfoo.dylib", origin="/origin", rpaths=[]) == []
