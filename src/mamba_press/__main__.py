import argparse
import dataclasses
import os
import pathlib
import tempfile
import typing
from collections.abc import Mapping
from typing import Annotated

import libmambapy as mamba

import mamba_press
from mamba_press.config import Configurable


@dataclasses.dataclass(frozen=True, slots=True)
class ExecutionParams:
    """Parameters controlling the execution of the program."""

    platform: Annotated[str, Configurable(description="The wheel platform tag to build")]

    packages: Annotated[
        list[mamba.specs.MatchSpec],
        Configurable(
            description="The Conda packages used to build the wheel",
            convert=lambda c: [mamba.specs.MatchSpec.parse(c)],
        ),
    ]

    working_dir: Annotated[
        pathlib.Path | None, Configurable(description="Where working environment is created")
    ] = None


def main(
    execution_params: ExecutionParams,
    channel_params: mamba_press.packages.ChannelParams,
    cache_params: mamba_press.packages.CacheParams,
) -> None:
    """Press Conda packages into wheels."""
    platform, virtual_packages = mamba_press.platform.platform_wheel_requirements(execution_params.platform)

    channel_resolve_params = mamba_press.packages.make_channel_resolve_params(channel_params, platform)
    channels = mamba_press.packages.make_channels(
        channels=channel_params.channels,
        channel_resolve_params=channel_resolve_params,
    )
    caches = mamba_press.packages.make_package_cache(cache_params=cache_params)
    subdir_indices = mamba_press.packages.make_subdir_index_loaders(
        [(c, mamba_press.platform.platform_conda_string(platform)) for c in channels],
        caches=caches,
    )

    print("Loading channel subdirectory indices")
    mamba_press.packages.download_required_subdir_indices(subdir_indices)
    database = mamba.solver.libsolv.Database(channel_resolve_params)
    mamba_press.packages.load_subdirs_in_database(
        database=database,
        installed_packages=virtual_packages,
        subdir_indices=subdir_indices,
    )

    print("Solving package requirements")
    request = mamba_press.packages.make_request(execution_params.packages)
    solution = mamba_press.packages.solve_for_packages(
        request=request,
        database=database,
    )

    python_package = mamba_press.packages.find_package_in_solution_installs(
        solution, mamba.specs.MatchSpec.parse("python")
    )
    if python_package is None:
        raise RuntimeError("Could not detect python package")

    solution = mamba_press.pruning.prune_packages_from_solution_installs(
        solution,
        # TODO: place in default package pruning
        [
            mamba.specs.MatchSpec.parse("python"),
            mamba.specs.MatchSpec.parse("python_abi"),
            mamba.specs.MatchSpec.parse("numpy"),
        ],
    )

    if execution_params.working_dir is None:
        tmp = tempfile.TemporaryDirectory(prefix="mamba-press")
        target_prefix = pathlib.Path(tmp.name)
    else:
        target_prefix = execution_params.working_dir

    print("Creating wheel environment")
    mamba_press.packages.create_wheel_environment(
        database=database,
        request=request,
        solution=solution,
        caches=caches,
        target_prefix=target_prefix,
        channel_resolve_params=channel_resolve_params,
    )

    site_package_dir = mamba_press.platform.site_package_dir(python_package)
    print("Site package is ", site_package_dir)


def add_configurable_to_parser[T](
    parser: argparse.ArgumentParser, configurable: mamba_press.config.ExplicitConfigurable[T]
) -> None:
    """Add a single configurable to the argument parser."""
    if configurable.cli is None:
        raise ValueError("Cli argument name cannot be None")

    name = configurable.cli
    args: dict[str, object] = {}
    if configurable.default_factory is None and configurable.env is None:
        args["required"] = True

    if configurable.convert is not None:
        # TODO better handling as a ConfigurableSequence type
        if typing.get_origin(configurable.type_) is list:
            args["type"] = lambda s: configurable.convert(s)[0]  # type: ignore
        else:
            args["type"] = configurable.convert

    if typing.get_origin(configurable.type_) is list:
        args["action"] = "append"

    parser.add_argument(
        name,
        help=configurable.description,
        dest=configurable.name,
        **args,  # type: ignore
    )


def add_params_to_parser(parser: argparse.ArgumentParser, klass) -> None:
    """Add a parameter dataclass as an argument group to the argument parser."""
    group = parser.add_argument_group(klass.__name__.replace("Params", " Options"), klass.__doc__)
    for field in dataclasses.fields(klass):
        configurable = mamba_press.config.ExplicitConfigurable.resolve(field)  # type: ignore
        if configurable.cli is not None:
            add_configurable_to_parser(group, configurable)  # type: ignore


def load_params[T](cli: Mapping[str, object], env: Mapping[str, str], klass: type[T]) -> T:
    """Load a parameters dataclass from inputs."""
    values = {}
    for field in dataclasses.fields(klass):  # type: ignore
        configurable = mamba_press.config.ExplicitConfigurable.resolve(field)  # type: ignore
        values[configurable.name] = configurable.load(cli, env)

    return klass(**values)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="python -m mamba_press",
        description="Press Conda packages into wheels",
        formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=40),
    )

    add_params_to_parser(parser, ExecutionParams)
    add_params_to_parser(parser, mamba_press.packages.ChannelParams)
    add_params_to_parser(parser, mamba_press.packages.CacheParams)

    cli = vars(parser.parse_args())
    env = os.environ

    execution_params = load_params(cli=cli, env=env, klass=ExecutionParams)
    channel_params = load_params(cli=cli, env=env, klass=mamba_press.packages.ChannelParams)
    cache_params = load_params(cli=cli, env=env, klass=mamba_press.packages.CacheParams)

    main(
        execution_params=execution_params,
        channel_params=channel_params,
        cache_params=cache_params,
    )
