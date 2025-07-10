import argparse
import dataclasses
import os
import pathlib
import re
import typing
from collections.abc import Iterable, Mapping

import libmambapy as mamba

import mamba_press
from mamba_press.filter.protocol import FilesFilter, SolutionFilter

INTERPOLATE_VAR_PATTERN = re.compile(r"\${{\s*(\w+)\s*}}")


def interpolate(template: str, context: Mapping[str, object]) -> str:
    """Replace variables with a simple JinJa-like syntax."""
    return INTERPOLATE_VAR_PATTERN.sub(lambda m: str(context.get(m.group(1), "")), template)


def make_solution_filters(requested_packages: list[mamba.specs.MatchSpec]) -> list[SolutionFilter]:
    """Return default filters on solution."""
    return [
        mamba_press.filter.PackagesFilter(
            to_prune=[
                mamba.specs.MatchSpec.parse("python"),
                mamba.specs.MatchSpec.parse("python_abi"),
            ],
            requested_packages=requested_packages,
        )
    ]


def make_files_filters(context: Mapping[str, object]) -> list[FilesFilter]:
    """Return default filters on files."""
    return [
        mamba_press.filter.UnixFilesFilter(
            [
                "conda-meta/*",
                "etc/conda/*",
                "man/*",
                "share/man/*",
                "bin/*",
                "sbin/*",
                "include/*",
                "lib/pkgconfig/*",
                "lib/cmake/*",
                "*.a",
                interpolate("${{ site_packages }}/*.dist-info", context),
                interpolate("${{ site_packages }}/*.egg-info", context),
                "*.pyc",
                "*/__pycache__/",
            ],
            exclude=True,
        ),
    ]


def read_env_files(path: pathlib.Path) -> Iterable[pathlib.Path]:
    """Read all the files in the environment."""
    for p in path.glob("**/*"):
        if p.is_file():
            yield p.relative_to(path)


def main(
    execution_params: mamba_press.execution.ExecutionParams,
    channel_params: mamba_press.packages.ChannelParams,
    cache_params: mamba_press.packages.CacheParams,
) -> None:
    """Press Conda packages into wheels."""
    solution_filters = make_solution_filters(execution_params.packages)

    working_artifacts = mamba_press.execution.create_working_env(
        execution_params=execution_params,
        channel_params=channel_params,
        cache_params=cache_params,
        solution_filters=solution_filters,
    )

    context = mamba_press.execution.create_interpolation_context(working_artifacts)
    files_filters = make_files_filters(context)

    mamba_press.execution.create_working_wheel(
        working_artifacts=working_artifacts, files_filters=files_filters
    )


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


def add_params_to_parser(parser: argparse.ArgumentParser, klass: type) -> None:
    """Add a parameter dataclass as an argument group to the argument parser."""
    group = parser.add_argument_group(klass.__name__.replace("Params", " Options"), klass.__doc__)
    for field in dataclasses.fields(klass):
        configurable = mamba_press.config.ExplicitConfigurable.resolve(field)
        if configurable.cli is not None:
            add_configurable_to_parser(group, configurable)  # type: ignore


def load_params[T](cli: Mapping[str, object], env: Mapping[str, str], klass: type[T]) -> T:
    """Load a parameters dataclass from inputs."""
    values = {}
    for field in dataclasses.fields(klass):  # type: ignore
        configurable = mamba_press.config.ExplicitConfigurable.resolve(field)
        values[configurable.name] = configurable.load(cli, env)

    return klass(**values)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="python -m mamba_press",
        description="Press Conda packages into wheels",
        formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=40),
    )

    add_params_to_parser(parser, mamba_press.execution.ExecutionParams)
    add_params_to_parser(parser, mamba_press.packages.ChannelParams)
    add_params_to_parser(parser, mamba_press.packages.CacheParams)

    cli = vars(parser.parse_args())
    env = os.environ

    execution_params = load_params(cli=cli, env=env, klass=mamba_press.execution.ExecutionParams)
    channel_params = load_params(cli=cli, env=env, klass=mamba_press.packages.ChannelParams)
    cache_params = load_params(cli=cli, env=env, klass=mamba_press.packages.CacheParams)

    main(
        execution_params=execution_params,
        channel_params=channel_params,
        cache_params=cache_params,
    )
