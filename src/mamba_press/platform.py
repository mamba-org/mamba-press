import libmambapy as mamba


def is_linux(plat: mamba.specs.KnownPlatform) -> bool:
    """Whether the platform OS is Linux."""
    return plat.name.startswith("linux")


def is_osx(plat: mamba.specs.KnownPlatform) -> bool:
    """Whether the platform OS is MacOs."""
    return plat.name.startswith("osx")


def is_win(plat: mamba.specs.KnownPlatform) -> bool:
    """Whether the platform OS is Windows."""
    return plat.name.startswith("win")


def osx_arm64_virtual_packages(os_version: str) -> list[mamba.specs.PackageInfo]:
    """Virtual packages available on MacOS Apple CPU."""
    return [
        mamba.specs.PackageInfo(
            name="__unix",
            version="0",
            build_string="0",
        ),
        mamba.specs.PackageInfo(
            name="__osx",
            version=os_version,
            build_string="0",
        ),
        mamba.specs.PackageInfo(
            name="__archspec",
            version="1",
            build_string="m1",
        ),
    ]


def osx_64_virtual_packages(os_version: str) -> list[mamba.specs.PackageInfo]:
    """Virtual packages available on MacOS Intel CPU."""
    return [
        mamba.specs.PackageInfo(
            name="__unix",
            version="0",
            build_string="0",
        ),
        mamba.specs.PackageInfo(
            name="__osx",
            version=os_version,
            build_string="0",
        ),
        mamba.specs.PackageInfo(
            name="__archspec",
            version="1",
            build_string="x86_64",
        ),
    ]


def platform_virtual_packages(
    plat: mamba.specs.KnownPlatform, os_version: str
) -> list[mamba.specs.PackageInfo]:
    """Virtual packages for the desired platform."""
    return globals()[f"{plat.name}_virtual_packages"](os_version=os_version)
