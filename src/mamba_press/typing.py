import enum
from typing import Literal


class Sentinel(enum.Enum):
    """Strongly typed constants."""

    Default = enum.auto()


DefaultType = Literal[Sentinel.Default]
Default: DefaultType = Sentinel.Default
