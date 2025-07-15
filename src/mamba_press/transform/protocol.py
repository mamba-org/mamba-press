import pathlib
from typing import Protocol


class PathTransform(Protocol):
    """Transform the path from the working environment to the wheel working directory.

    Used to describe the relocation of files between a Conda environment and a wheel.
    For instance, Python packages are installed in a site-packages directory in a Conda environment,
    but need to be moved at the root for a wheel.
    """

    def transform_path(self, path: pathlib.PurePath) -> pathlib.PurePath:
        """Compute a new relative path from the working environment path."""
        ...


class DataTransform(Protocol):
    """Transform the data from the working environment files.

    Used to change the data of Conda environment files and the ones in the wheel.
    For instance this is used to change RPATH when relocating a library.
    """

    def needed(self, path: pathlib.Path | bytes) -> bool:
        """Return whether the transformation is needed for the current file.

        This is an optimization skip loading files on which no transformations will
        be applied.
        """
        ...

    def transform_data(self, data: bytes) -> bytes:
        """Transform the data inside the file."""
        ...
