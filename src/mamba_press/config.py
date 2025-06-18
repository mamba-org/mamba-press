import dataclasses
import enum
from typing import Callable, Literal


class Sentinel(enum.Enum):
    """Strongly typed constants."""

    Default = enum.auto()


DefaultType = Literal[Sentinel.Default]
Default: DefaultType = Sentinel.Default


@dataclasses.dataclass(frozen=True, slots=True)
class Configurable[T]:
    """Describe how a value can be configured by the user."""

    description: str
    name: str | DefaultType = Default
    convert: Callable[[str], T] | DefaultType = Default
    cli: str | None | DefaultType = Default
    env: str | None | DefaultType = None


@dataclasses.dataclass(frozen=True, slots=True)
class ExplicitConfigurable[T]:
    """Describe how a value can be configured by the user, with default resolved."""

    name: str
    description: str
    convert: Callable[[str], T]
    cli: str | None
    env: str | None
    default_factory: Callable[[], T] | None

    @staticmethod
    def resolve[U](field: dataclasses.Field) -> "ExplicitConfigurable[U]":
        """Resolve defaults from data class field annotated with a :class:`Configurable`."""
        if isinstance((type_ := field.type), str):
            raise ValueError("Type must be Python type")

        if hasattr(type_, "__metadata__"):
            metadata = type_.__metadata__
        else:
            raise ValueError("Type must use `typing.Annotated`")

        configurable: Configurable[U] = next(a for a in metadata if isinstance(a, Configurable))

        name: str = field.name if configurable.name == Default else configurable.name

        convert: Callable[[str], U]
        if configurable.convert == Default:
            convert = lambda s: type_(s)  # noqa: E731
        else:
            convert = configurable.convert

        cli: str | None
        if configurable.cli == Default:
            cli = f"--{name.lower().replace('_', '-')}"
        else:
            cli = configurable.cli

        env: str | None
        if configurable.env == Default:
            env = f"MAMBA_PRESS_{name.upper()}"
        else:
            env = configurable.env

        if field.default_factory != dataclasses.MISSING:
            default_factory = field.default_factory
        elif field.default != dataclasses.MISSING:
            default_factory = lambda: field.default  # noqa: E731
        else:
            default_factory = None

        return ExplicitConfigurable(
            name=name,
            description=configurable.description,
            convert=convert,
            cli=cli,
            env=env,
            default_factory=default_factory,
        )
