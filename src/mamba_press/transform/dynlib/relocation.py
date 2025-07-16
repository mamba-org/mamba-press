import logging
import pathlib
from typing import Callable

import lief

import mamba_press.transform.dynlib.elf
import mamba_press.transform.dynlib.macho

__logger__ = logging.getLogger(__name__)

Binary = lief.MachO.Binary | lief.ELF.Binary


class DynamicLibRelocate:
    """Relocate dynamic libraries RPATHs."""

    # TODO: this should really be made into an ABC

    def needed(self, data: pathlib.Path | bytes) -> bool:
        """Return whether the data is a MachO binary."""
        # TODO: check if lief supports bytes directly in versions >0.17
        data_converted: str | list[int]
        if isinstance(data, bytes):
            data_converted = list(data)
        else:
            data_converted = str(data)
        return lief.is_macho(data_converted) or lief.is_elf(data_converted)

    def parse_binary(self, data: bytes) -> Binary:
        """Use Lief to parse the binary."""
        bin = lief.parse(data)
        if bin is None:
            raise ValueError("Data is not a recognized Lief binary format.")
        if not isinstance(bin, Binary):
            raise NotImplementedError(f"Data type {type(bin)} is not implemented.")
        return bin

    def write_binary(self, bin: Binary, path: pathlib.Path) -> None:
        """Write the binary to file."""
        bin.write(str(path))

    def lib_name(self, bin: Binary) -> str | None:
        """Return the filename encoded in the library, if any.

        In linux, this would be the SONAME, in MacOS, this would be the filename of the library id.
        """
        if isinstance(bin, lief.MachO.Binary):
            return mamba_press.transform.dynlib.macho.lib_name(bin)
        if isinstance(bin, lief.ELF.Binary):
            return mamba_press.transform.dynlib.elf.lib_name(bin)
        return None

    def relocate_binary(
        self,
        bin: Binary,
        data_path: pathlib.Path,
        prefix_path: pathlib.Path,
        path_transform: Callable[[pathlib.Path], pathlib.Path],
    ) -> None:
        """Transform the data inside the file."""
        if isinstance(bin, lief.MachO.Binary):
            __logger__.debug(f'Relocating Mach-O "{data_path}"')
            mamba_press.transform.dynlib.macho.relocate_bin(
                bin=bin,
                bin_path=data_path,
                prefix_path=prefix_path,
                path_transform=path_transform,
            )

        if isinstance(bin, lief.ELF.Binary):
            __logger__.debug(f'Relocating ELF "{data_path}"')
            mamba_press.transform.dynlib.elf.relocate_bin(
                bin=bin,
                bin_path=data_path,
                prefix_path=prefix_path,
                path_transform=path_transform,
            )
