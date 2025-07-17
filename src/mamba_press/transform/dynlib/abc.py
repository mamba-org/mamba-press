import abc
import pathlib
from typing import Callable, Generic, TypeVar

import lief

Binary = TypeVar("Binary", lief.MachO.Binary, lief.ELF.Binary)


class DynamicLibRelocate(Generic[Binary], metaclass=abc.ABCMeta):
    """Relocate dynamic libraries RPATHs."""

    @classmethod
    @abc.abstractmethod
    def binary_type(self) -> type[Binary]:
        """Return the type of the binary."""
        ...

    def needed(self, data: pathlib.Path | bytes) -> bool:
        """Return whether the data is a valid binary of the binary type."""
        data_converted: str | list[int]
        if isinstance(data, bytes):
            # TODO bytes accepted in lief>=0.17
            data_converted = list(data)
        else:
            data_converted = str(data)
        return self._needed(data_converted)

    @abc.abstractmethod
    def _needed(self, data: str | list[int]) -> bool:
        """Low-level hook with Lief compatible data."""
        ...

    def parse_binary(self, data: bytes) -> Binary:
        """Use Lief to parse the binary."""
        bin = lief.parse(data)
        if bin is None:
            raise ValueError("Data is not a recognized Lief binary format.")
        if not isinstance(bin, self.binary_type()):
            raise NotImplementedError(
                f"Received wrong binary format: expected {self.binary_type()}, found {type(bin)}"
            )
        return bin

    def write_binary(self, bin: Binary, path: pathlib.Path) -> None:
        """Write the binary to file."""
        bin.write(str(path))

    @abc.abstractmethod
    def lib_name(self, bin: Binary) -> str | None:
        """Return the filename encoded in the library, if any.

        In linux, this would be the SONAME, in MacOS, this would be the filename of the library id.
        """
        ...

    @abc.abstractmethod
    def relocate_binary(
        self,
        bin: Binary,
        data_path: pathlib.Path,
        prefix_path: pathlib.Path,
        path_transform: Callable[[pathlib.Path], pathlib.Path],
    ) -> None:
        """Transform the data inside the file."""
        ...
