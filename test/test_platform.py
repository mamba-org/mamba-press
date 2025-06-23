import libmambapy as mamba
import pytest

import mamba_press


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
