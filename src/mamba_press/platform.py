import dataclasses
import re
import sys
from typing import Final

import libmambapy as mamba

PLATFORM_WHEEL_RE: Final = re.compile(
    r"(?P<os>macosx|manylinux|musllinux|win)_(?P<major>\d+)_(?P<minor>\d+)_(?P<arch>.+)",
    re.IGNORECASE,
)

PLATFORM_WHEEL_TO_CONDA: Final = {
    ("macosx", "x86_64"): mamba.specs.KnownPlatform.osx_64,
    ("macosx", "arm64"): mamba.specs.KnownPlatform.osx_arm64,
    ("manylinux", "x86_64"): mamba.specs.KnownPlatform.linux_64,
    ("manylinux", "aarch64"): mamba.specs.KnownPlatform.linux_aarch64,
}


@dataclasses.dataclass(slots=True)
class WheelPlatformSplit:
    """Components of a wheel platform tag."""

    os: str
    major: str
    minor: str
    arch: str

    @staticmethod
    def parse(platform: str) -> "WheelPlatformSplit":
        """Split a wheel platform tag."""
        match = PLATFORM_WHEEL_RE.fullmatch(platform)
        if match is None:
            raise ValueError(f'Unknown platform tag "{platform}"')

        return WheelPlatformSplit(**{k: v.lower() for k, v in match.groupdict().items()})

    @property
    def version(self) -> str:
        """Return the full version."""
        return f"{self.major}.{self.minor}"

    @property
    def is_macos(self) -> bool:
        """Return true is the wheel platform is MacOS."""
        return self.os.strip().lower() == "macosx"

    @property
    def is_manylinux(self) -> bool:
        """Return true is the wheel platform is manylinux."""
        return self.os.strip().lower() == "manylinux"

    def __str__(self) -> str:
        """Return the wheel platform tag."""
        return f"{self.os}_{self.major}_{self.minor}_{self.arch}"


def platform_conda_string(platform: mamba.specs.KnownPlatform) -> str:
    """Return the string representation of a Conda platform."""
    return platform.name.replace("_", "-")


def platform_wheel_to_conda(os: str, arch: str) -> mamba.specs.KnownPlatform | None:
    """Convert a wheel platform tag to a Conda platform."""
    os = os.strip().lower()
    arch = arch.strip().lower()
    return PLATFORM_WHEEL_TO_CONDA.get((os, arch), None)


def platform_wheel_is_macos(tag: str) -> bool:
    """Return true is the wheel platform is MacOS."""
    return tag.lower().startswith("macosx")


def platform_wheel_is_manylinux(tag: str) -> bool:
    """Return true is the wheel platform is manylinux."""
    return tag.lower().startswith("manylinux")


def platform_wheel_requirements(
    platform: WheelPlatformSplit | str,
) -> tuple[mamba.specs.KnownPlatform, list[mamba.specs.PackageInfo]]:
    """Convert a wheel platform attributes to a Conda platform."""
    split = WheelPlatformSplit.parse(platform) if isinstance(platform, str) else platform

    conda_platform = platform_wheel_to_conda(os=split.os, arch=split.arch)
    packages_func = getattr(sys.modules[__name__], f"{split.os}_{split.arch}_virtual_packages", None)

    if conda_platform is None or packages_func is None:
        raise NotImplementedError(f'Missing implementation for "{split.os}_{split.arch}"')
    packages: list[mamba.specs.PackageInfo] = packages_func(split.version)
    return conda_platform, packages


def macosx_arm64_virtual_packages(os_version: str) -> list[mamba.specs.PackageInfo]:
    """Virtual packages available on MacOS arm CPU."""
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


def macosx_x86_64_virtual_packages(os_version: str) -> list[mamba.specs.PackageInfo]:
    """Virtual packages available on MacOS x86_64 CPU."""
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


def manylinux_x86_64_virtual_packages(glibc_version: str) -> list[mamba.specs.PackageInfo]:
    """Virtual packages available on manylinux x86_64 CPU."""
    return [
        mamba.specs.PackageInfo(
            name="__unix",
            version="0",
            build_string="0",
        ),
        mamba.specs.PackageInfo(
            name="__linux",
            version="4.0",  # FIXME: What should we put here
            build_string="0",
        ),
        mamba.specs.PackageInfo(
            name="__glibc",
            version=glibc_version,
            build_string="0",
        ),
        mamba.specs.PackageInfo(
            name="__archspec",
            version="1",
            build_string="x86_64",
        ),
    ]


def manylinux_aarch64_virtual_packages(glibc_version: str) -> list[mamba.specs.PackageInfo]:
    """Virtual packages available on manylinux aarch64 CPU."""
    return [
        mamba.specs.PackageInfo(
            name="__unix",
            version="0",
            build_string="0",
        ),
        mamba.specs.PackageInfo(
            name="__linux",
            version="4.0",  # FIXME: What should we put here
            build_string="0",
        ),
        mamba.specs.PackageInfo(
            name="__glibc",
            version=glibc_version,
            build_string="0",
        ),
        mamba.specs.PackageInfo(
            name="__archspec",
            version="1",
            build_string="aarch64",
        ),
    ]


def site_packages_dir(python: mamba.specs.PackageInfo) -> str:
    """Get the site-package relative directory."""
    if python.platform.startswith("win"):
        return "Lib/site-packages"
    major, minor, *_ = python.version.split(".", maxsplit=2)
    tag = "t" if python.build_string.endswith("t") else ""
    return f"lib/python{major}.{minor}{tag}/site-packages"
