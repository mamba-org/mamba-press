import dataclasses
import enum
import types
import typing
from collections.abc import Mapping
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
    type_: type[T]

    @staticmethod
    def __make_convert[U](configurable: Configurable[U], type_) -> Callable[[str], U]:
        type_origin = typing.get_origin(type_)

        if configurable.convert == Default:
            if type_origin is types.UnionType or type_origin is typing.Union:
                args = [t for t in typing.get_args(type_) if t is not type(None)]
                if len(args) == 1:
                    return lambda s: args[0](s)
                raise ValueError(f'Cannot create conversion for "{configurable.name}"')
            return lambda s: type_(s)
        return configurable.convert

    @staticmethod
    def resolve[U](field: dataclasses.Field) -> "ExplicitConfigurable[U]":
        """Resolve defaults from data class field annotated with a :class:`Configurable`."""
        if isinstance((annotated_type := field.type), str):
            raise ValueError("Type must be Python type")

        if hasattr(annotated_type, "__metadata__"):
            metadata = annotated_type.__metadata__
            type_ = annotated_type.__origin__
        else:
            raise ValueError("Type must use `typing.Annotated`")

        configurable: Configurable[U] = next(a for a in metadata if isinstance(a, Configurable))

        name: str = field.name if configurable.name == Default else configurable.name

        cli: str | None
        if configurable.cli == Default:
            cli_name = name.lower().replace("_", "-")
            if typing.get_origin(type_) is list:
                cli_name = cli_name.removesuffix("s")  # Poor man's singular
            cli = f"--{cli_name}"
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
            convert=ExplicitConfigurable.__make_convert(configurable, type_),
            cli=cli,
            env=env,
            default_factory=default_factory,
            type_=type_,
        )

    def load(self, cli: Mapping[str, object], env: Mapping[str, str]) -> T:
        """Load the configured value from all the given inputs."""
        if value := cli.get(self.name):
            return value  # type: ignore
        if value := env.get(self.name):
            return self.convert(value)
        if (factory := self.default_factory) is not None:
            return factory()

        raise RuntimeError(f"""Configuration entry "{self.name}" is not provided""")
