import argparse
import dataclasses
import logging
import os
import pathlib
import re
import typing
from collections.abc import Iterable, Mapping

import libmambapy as mamba
import lief

import mamba_press
from mamba_press.filter.protocol import FilesFilter, SolutionFilter
from mamba_press.transform.dynlib.abc import DynamicLibRelocate
from mamba_press.transform.protocol import PathTransform

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
    # We would want to filter Manylinux whitelisted libraries but the libstdc++ on
    # conda-forge is too recent to even match a manylinux tag.
    return [
        mamba_press.filter.UnixFilesFilter(
            [
                "conda-meta/*",
                "etc/conda/*",
                "man/*",
                "ssl/*",
                "share/man/*",
                "share/terminfo/*",
                "share/locale/*",
                "bin/*",
                "sbin/*",
                "include/*",
                "lib/pkgconfig/*",
                "lib/cmake/*",
                "*.a",
                "*.pyc",
                "*/__pycache__/*",
                interpolate("${{ site_packages }}/*.dist-info/INSTALLER", context),
                interpolate("${{ site_packages }}/*.dist-info/REQUESTED", context),
            ],
            exclude=True,
        ),
    ]


def make_path_transforms(context: Mapping[str, object]) -> list[PathTransform]:
    """Return default path transforms."""
    return [
        mamba_press.transform.PathRelocate(
            {
                pathlib.PurePath(interpolate("${{ site_packages }}/", context)): pathlib.PurePath("."),
                # Due to lowest specificity, this will oonly be applied to remaining files
                pathlib.PurePath("."): pathlib.PurePath(interpolate("${{ package_name }}/data/", context)),
            }
        ),
    ]


def make_relocator(
    platform: str,
) -> DynamicLibRelocate[lief.MachO.Binary] | DynamicLibRelocate[lief.ELF.Binary]:
    """Create platform specific DynamicLibRelocate."""
    if mamba_press.platform.platform_wheel_is_macos(platform):
        return mamba_press.transform.dynlib.MachODynamicLibRelocate(
            mamba_press.filter.UnixFilesFilter(
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
    if mamba_press.platform.platform_wheel_is_manylinux(platform):
        return mamba_press.transform.dynlib.ElfDynamicLibRelocate(
            mamba_press.filter.CombinedFilesFilter(
                [
                    mamba_press.filter.ManyLinuxWhitelist(platform),
                    # Sometimes this is marked as explicitly needed
                    mamba_press.filter.UnixFilesFilter(["*ld-linux-x86-64.so*"], exclude=False),
                ],
                all=False,
            )
        )

    raise ValueError(f'Invalid or unsupported platform "{platform}"')


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
    path_transforms = make_path_transforms(context)

    mamba_press.execution.create_working_wheel(
        working_artifacts=working_artifacts,
        files_filters=files_filters,
        path_transforms=path_transforms,
        relocator=make_relocator(execution_params.platform),  # type: ignore[misc]
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
