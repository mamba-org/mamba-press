import dataclasses
import pathlib

from .protocol import PathTransform


@dataclasses.dataclass(frozen=True, slots=True)
class ExplicitPathTransform(PathTransform):
    """Relocate file and folder from the given mapping.

    Search for the most specific mapping to apply at each transformation.
    """

    mapping: dict[pathlib.PurePath, pathlib.PurePath]

    def transform_path(self, path: pathlib.PurePath) -> pathlib.PurePath:
        """Compute a new relative path from the working environment path."""
        best_size = float("inf")
        best_dest = None
        for src, dest in self.mapping.items():
            if path.is_relative_to(src):
                candidate = path.relative_to(src)
                candidate_size = len(candidate.parts)
                if candidate_size < best_size:
                    best_size = candidate_size
                    best_dest = dest / candidate

        if best_dest is not None:
            return best_dest

        return path
