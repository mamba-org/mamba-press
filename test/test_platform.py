import libmambapy as mamba
import pytest

import mamba_press


def test_wheel_platform_split() -> None:
    """Wheel platform tags are parsed properly."""
    split = mamba_press.platform.WheelPlatformSplit.parse("macosx_11_1_x86_64")
    assert split.os == "macosx"
    assert split.is_macos
    assert not split.is_manylinux
    assert split.major == "11"
    assert split.minor == "1"
    assert split.version == "11.1"
    assert split.arch == "x86_64"

    split = mamba_press.platform.WheelPlatformSplit.parse("macosx_15_0_arm64")
    assert split.os == "macosx"
    assert split.is_macos
    assert not split.is_manylinux
    assert split.major == "15"
    assert split.minor == "0"
    assert split.version == "15.0"
    assert split.arch == "arm64"

    split = mamba_press.platform.WheelPlatformSplit.parse("manylinux_2_17_x86_64")
    assert split.os == "manylinux"
    assert not split.is_macos
    assert split.is_manylinux
    assert split.major == "2"
    assert split.minor == "17"
    assert split.version == "2.17"
    assert split.arch == "x86_64"

    split = mamba_press.platform.WheelPlatformSplit.parse("manylinux_2_28_aarch64")
    assert split.os == "manylinux"
    assert not split.is_macos
    assert split.is_manylinux
    assert split.major == "2"
    assert split.minor == "28"
    assert split.version == "2.28"
    assert split.arch == "aarch64"


@pytest.mark.parametrize(
    ("tag", "expected_platform"),
    [
        ("macosx_11_1_x86_64", mamba.specs.KnownPlatform.osx_64),
        ("macosx_15_0_arm64", mamba.specs.KnownPlatform.osx_arm64),
        ("manylinux_2_17_x86_64", mamba.specs.KnownPlatform.linux_64),
        ("manylinux_2_28_aarch64", mamba.specs.KnownPlatform.linux_aarch64),
    ],
)
def test_platform_wheel_requirements(tag: str, expected_platform: mamba.specs.KnownPlatform) -> None:
    """Successful tag parsing."""
    platform, packages = mamba_press.platform.platform_wheel_requirements(tag)
    assert platform == expected_platform
    assert len(packages) > 0
