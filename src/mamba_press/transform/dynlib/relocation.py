import lief

import mamba_press.platform
import mamba_press.transform.dynlib.elf
import mamba_press.transform.dynlib.macho

from .abc import DynamicLibRelocate


def make_relocator(
    platform: str,
) -> DynamicLibRelocate[lief.MachO.Binary] | DynamicLibRelocate[lief.ELF.Binary]:
    """Create platform specific DynamicLibRelocate."""
    if mamba_press.platform.platform_wheel_is_macos(platform):
        return mamba_press.transform.dynlib.macho.MachODynamicLibRelocate()
    if mamba_press.platform.platform_wheel_is_manylinux(platform):
        return mamba_press.transform.dynlib.elf.ElfDynamicLibRelocate()

    raise ValueError(f'Invalid or unsupported platform "{platform}"')
