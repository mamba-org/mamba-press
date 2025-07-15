import logging
import pathlib
from typing import Callable

import lief

import mamba_press.transform.dynlib.macho

__logger__ = logging.getLogger(__name__)


class DynamicLibRelocate:
    """Relocate dynamic libraries RPATHs."""

    def needed(self, data: pathlib.Path | bytes) -> bool:
        """Return whether the data is a MachO binary."""
        # TODO: check if lief supports bytes directly in versions >0.17
        data_converted: str | list[int]
        if isinstance(data, bytes):
            data_converted = list(data)
        else:
            data_converted = str(data)
        return lief.is_macho(data_converted)

    def transform_data(
        self,
        data: bytes,
        data_path: pathlib.Path,
        prefix_path: pathlib.Path,
        path_transform: Callable[[pathlib.Path], pathlib.Path],
    ) -> bytes:
        """Transform the data inside the file."""
        # Also lief.MachO.parse return a FatBinary
        lib = lief.parse(data)

        if lib is None:
            return data

        if isinstance(lib, lief.MachO.Binary):
            __logger__.debug(f'Relocating Mach-O "{data_path}"')
            mamba_press.transform.dynlib.macho.relocate_lib(
                lib=lib,
                lib_path=data_path,
                prefix_path=prefix_path,
                path_transform=path_transform,
            )
            # Also fat.raw with a MacOS Fat binary
            return lib.write_to_bytes()

        raise NotImplementedError(f"Library relocation not implemented for {type(lib)} format")
