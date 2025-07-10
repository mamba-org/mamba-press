import pathlib

import mamba_press.transform.dynlib.macho as macho


def test_lib_is_whitelisted() -> None:
    """System libraries are whitelisted."""
    assert macho.lib_is_whitelisted("/usr/lib/libSystem.B.dylib")


def test_relative_relocation_path() -> None:
    """Relocation paths uses special keywords."""
    assert macho.relative_relocation_path(
        pathlib.Path("/lib/liba.dylib"), pathlib.Path("/lib/libc.dylib")
    ) == pathlib.Path("@rpath/libc.dylib")

    assert macho.relative_relocation_path(
        pathlib.Path("/lib/liba.dylib"), pathlib.Path("/lib/hidden/libc.dylib")
    ) == pathlib.Path("@rpath/hidden/libc.dylib")

    assert macho.relative_relocation_path(
        pathlib.Path("/lib/python3.8/site-pacakges/pkg/liba.dylib"), pathlib.Path("/lib/libc.dylib")
    ) == pathlib.Path("@rpath/../../../libc.dylib")
