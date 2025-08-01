import argparse
import dataclasses
import logging
import os
import pathlib
import typing
from collections.abc import Iterable, Mapping

import lief

import mamba_press
from mamba_press.platform import WheelPlatformSplit
from mamba_press.transform.dynlib.abc import DynamicLibRelocate
from mamba_press.transform.protocol import PathTransform


def make_path_transforms(context: Mapping[str, str]) -> list[PathTransform]:
    """Return default path transforms."""
    return [
        mamba_press.transform.ExplicitPathTransform(
            {
                pathlib.PurePath(
                    mamba_press.utils.interpolate("${{ site_packages }}/", context)
                ): pathlib.PurePath("."),
                # Due to lowest specificity, this will oonly be applied to remaining files
                pathlib.PurePath("."): pathlib.PurePath(
                    mamba_press.utils.interpolate("${{ package_name }}/data/", context)
                ),
            }
        ),
    ]


def make_relocator(
    wheel_split: WheelPlatformSplit,
) -> DynamicLibRelocate[lief.MachO.Binary] | DynamicLibRelocate[lief.ELF.Binary]:
    """Create platform specific DynamicLibRelocate."""
    if wheel_split.is_macos:
        return mamba_press.transform.dynlib.MachODynamicLibRelocate(
            mamba_press.filter.UnixGlobFilesFilter(
                [
                    # https://github.com/conda/conda-build/blob/main/conda_build/post.py
                    "/opt/X11/*.dylib",
                    "/usr/lib/libcrypto.0.9.8.dylib",
                    "/usr/lib/libobjc.A.dylib",
                    "/System/Library/Frameworks/*.framework/*",
                    "/usr/lib/libSystem.B.dylib",
                    # Common low-level DSO whitelist from
                    "/usr/lib/libc++abi.dylib",
                    "/usr/lib/libresolv*.dylib",
                ],
                exclude=False,
            )
        )
    if wheel_split.is_manylinux:
        return mamba_press.transform.dynlib.ElfDynamicLibRelocate(
            mamba_press.filter.CombinedFilesFilter(
                [
                    mamba_press.filter.ManyLinuxWhitelist(wheel_split),
                    # Sometimes this is marked as explicitly needed
                    mamba_press.filter.UnixGlobFilesFilter(["*ld-linux-x86-64.so*"], exclude=False),
                ],
                all=False,
            )
        )

    raise ValueError(f'Invalid or unsupported platform "{wheel_split}"')


def read_env_files(path: pathlib.Path) -> Iterable[pathlib.Path]:
    """Read all the files in the environment."""
    for p in path.glob("**/*"):
        if p.is_file():
            yield p.relative_to(path)


def make_wheel_split(platform: mamba_press.recipe.TargetPlatform) -> mamba_press.platform.WheelPlatformSplit:
    """Convert from the recipe target platform to a full split."""
    version = platform.version.replace("_", ".").split(".")

    return mamba_press.platform.WheelPlatformSplit(
        os=platform.os,
        arch=platform.arch,
        major=version[0] if len(version) > 0 else "",
        minor=version[1] if len(version) > 1 else "",
    )


def main(
    execution_params: mamba_press.execution.ExecutionParams,
    channel_params: mamba_press.packages.ChannelParams,
    cache_params: mamba_press.packages.CacheParams,
    recipe: mamba_press.Recipe,
) -> None:
    """Press Conda packages into wheels."""
    wheel_split = make_wheel_split(recipe.target.platform)

    solution_filters = mamba_press.factory.make_solution_filters(recipe)

    packages_data, caches, channel_resolve_params = mamba_press.execution.compute_solution(
        execution_params=execution_params,
        channel_params=channel_params,
        cache_params=cache_params,
        solution_filters=solution_filters,
        source=recipe.source,
        wheel_split=wheel_split,
    )

    working_artifacts = mamba_press.execution.create_working_env(
        execution_params=execution_params,
        caches=caches,
        channel_resolve_params=channel_resolve_params,
        packages_data=packages_data,
    )

    context = mamba_press.execution.create_interpolation_context(working_artifacts)
    files_filters = mamba_press.factory.make_files_filters(recipe, context)

    path_transforms = make_path_transforms(context)

    mamba_press.execution.create_working_wheel(
        working_artifacts=working_artifacts,
        files_filters=files_filters,
        path_transforms=path_transforms,
        relocator=make_relocator(wheel_split),  # type: ignore[misc]
    )

    mamba_press.execution.pack_wheel(
        execution_params=execution_params,
        working_artifacts=working_artifacts,
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


class ColoredLoggingFormatter(logging.Formatter):
    """A logging formatter with optiniated color printing.

    The primary use is to turn the logs into a CLI output.
    """

    BLUE = "\x1b[34;20m"
    YELLOW = "\x1b[33;20m"
    RED = "\x1b[31;20m"
    BOLD_RED = "\x1b[31;1m"
    RESET = "\x1b[0m"

    def __init__(self, base_format: str = "%(message)s") -> None:
        self.formatters = {
            logging.DEBUG: logging.Formatter(self.BLUE + base_format + self.BLUE),
            logging.INFO: logging.Formatter(base_format),
            logging.WARNING: logging.Formatter(self.YELLOW + base_format + self.RESET),
            logging.ERROR: logging.Formatter(self.RED + base_format + self.RESET),
            logging.CRITICAL: logging.Formatter(self.BOLD_RED + base_format + self.RESET),
        }

    def format(self, record: logging.LogRecord) -> str:
        """Format the specified record as text."""
        return self.formatters[record.levelno].format(record)


def setup_cli_logging(logger: logging.Logger, level: str | int = logging.INFO) -> None:
    """Initialize logger to print to stdout with color formatting."""
    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(level)
    stream_handler.setFormatter(ColoredLoggingFormatter())

    logger.setLevel(level)
    logger.addHandler(stream_handler)


if __name__ == "__main__":
    setup_cli_logging(logging.getLogger("mamba_press"))

    parser = argparse.ArgumentParser(
        prog="python -m mamba_press",
        description="Press Conda packages into wheels",
        formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=40),
    )

    parser.add_argument("recipe_path", type=pathlib.Path)

    add_params_to_parser(parser, mamba_press.execution.ExecutionParams)
    add_params_to_parser(parser, mamba_press.packages.ChannelParams)
    add_params_to_parser(parser, mamba_press.packages.CacheParams)

    cli = vars(parser.parse_args())
    env = os.environ

    execution_params = load_params(cli=cli, env=env, klass=mamba_press.execution.ExecutionParams)
    channel_params = load_params(cli=cli, env=env, klass=mamba_press.packages.ChannelParams)
    cache_params = load_params(cli=cli, env=env, klass=mamba_press.packages.CacheParams)

    with open(cli["recipe_path"]) as f:
        recipe = mamba_press.Recipe.parse_yaml(f.read())

    main(
        execution_params=execution_params,
        channel_params=channel_params,
        cache_params=cache_params,
        recipe=recipe,
    )
