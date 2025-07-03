import dataclasses
from typing import Annotated

from mamba_press.config import Configurable, Default, ExplicitConfigurable


def test_explicit_configurable_full() -> None:
    """Explicit configurations are respected."""

    @dataclasses.dataclass
    class S:
        channel: Annotated[
            str,
            Configurable(
                description="description",
                name="name",
                convert=lambda x: f"convert({x})",
                cli="cli",
                env="env",
            ),
        ] = dataclasses.field(default_factory=lambda: "hello")

    explicit: ExplicitConfigurable[str] = ExplicitConfigurable.resolve(dataclasses.fields(S)[0])

    assert explicit.description == "description"
    assert explicit.name == "name"
    assert explicit.convert("33") == "convert(33)"
    assert explicit.cli == "cli"
    assert explicit.env == "env"
    assert (factory := explicit.default_factory) is not None
    assert factory() == "hello"


def test_explicit_configurable_default() -> None:
    """Default are computed."""

    @dataclasses.dataclass
    class S:
        ttl: Annotated[int, Configurable(description="description")]

    explicit: ExplicitConfigurable[int] = ExplicitConfigurable.resolve(dataclasses.fields(S)[0])

    assert explicit.description == "description"
    assert explicit.name == "ttl"
    assert explicit.convert("33") == 33
    assert explicit.cli == "--ttl"
    assert explicit.env is None
    assert explicit.default_factory is None


def test_explicit_configurable_default_factory() -> None:
    """A default factory is created from default."""

    @dataclasses.dataclass
    class S:
        ttl: Annotated[int, Configurable(description="description")] = 24

    explicit: ExplicitConfigurable[int] = ExplicitConfigurable.resolve(dataclasses.fields(S)[0])

    assert (factory := explicit.default_factory) is not None
    assert factory() == 24


def test_explicit_configurable_default_env() -> None:
    """Default environment variable name is used."""

    @dataclasses.dataclass
    class S:
        ttl: Annotated[int, Configurable(description="description", env=Default)]

    explicit: ExplicitConfigurable[int] = ExplicitConfigurable.resolve(dataclasses.fields(S)[0])

    assert explicit.env == "MAMBA_PRESS_TTL"


def test_explicit_configurable_optional_convert() -> None:
    """Default convert with optional type created a value."""

    @dataclasses.dataclass
    class S:
        ttl: Annotated[int | None, Configurable(description="description")]

    explicit: ExplicitConfigurable[int | None] = ExplicitConfigurable.resolve(dataclasses.fields(S)[0])

    assert explicit.convert("33") == 33


def test_explicit_configurable_list() -> None:
    """Default convert with optional type created a value."""

    @dataclasses.dataclass
    class S:
        foos: Annotated[list[int], Configurable(description="description")]

    explicit: ExplicitConfigurable[int | None] = ExplicitConfigurable.resolve(dataclasses.fields(S)[0])

    assert explicit.cli == "--foo"
