import enum
from typing import Literal, TypeAlias


class Sentinel(enum.Enum):
    """Strongly typed constants."""

    Default = enum.auto()


DefaultType = Literal[Sentinel.Default]
Default: DefaultType = Sentinel.Default

# Any dynamic JSON/YAML-like object
DynamicEntry: TypeAlias = str | int | float | bool | None | dict[str, "DynamicEntry"] | list["DynamicEntry"]
