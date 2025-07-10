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
