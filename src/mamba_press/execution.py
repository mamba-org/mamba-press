import dataclasses
import itertools
import logging
import pathlib
import tempfile
from typing import Annotated, Iterable

import libmambapy as mamba

import mamba_press.packages
from mamba_press.config import Configurable
from mamba_press.filter.protocol import FilesFilter, SolutionFilter

__logger__ = logging.getLogger(__name__)


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


@dataclasses.dataclass
class WorkingArtifacts:
    """Object to describe and manage the working environment."""

    working_dir: pathlib.Path | tempfile.TemporaryDirectory
    python_package: mamba.specs.PackageInfo

    @property
    def working_dir_path(self) -> pathlib.Path:
        """The root path of all the working artifacts manipulated by mamba_press."""
        if isinstance(self.working_dir, tempfile.TemporaryDirectory):
            return pathlib.Path(self.working_dir.name)
        return self.working_dir

    @property
    def working_env_path(self) -> pathlib.Path:
        """The root path of all the initial Conda environment."""
        return self.working_dir_path / "env"


def create_working_env(
    execution_params: ExecutionParams,
    channel_params: mamba_press.packages.ChannelParams,
    cache_params: mamba_press.packages.CacheParams,
    solution_filters: list[SolutionFilter],
) -> WorkingArtifacts:
    """Create the working environment with packages filtered.

    This environment is the initial collection of files that mamba_press is working with to create
    a wheel.
    It is later refined into a working wheel folder by filtering and transforming the files.
    """
    platform, virtual_packages = mamba_press.platform.platform_wheel_requirements(execution_params.platform)

    channel_resolve_params = mamba_press.packages.make_channel_resolve_params(channel_params, platform)
    channels = mamba_press.packages.make_channels(
        channels=channel_params.channels,
        channel_resolve_params=channel_resolve_params,
    )
    caches = mamba_press.packages.make_package_cache(cache_params=cache_params)
    subdir_indices = mamba_press.packages.make_subdir_index_loaders(
        itertools.product(channels, [platform, mamba_press.packages.NOARCH_PLATFORM]),
        caches=caches,
    )

    __logger__.info("Loading channel subdirectory indices")
    mamba_press.packages.download_required_subdir_indices(subdir_indices)
    database = mamba.solver.libsolv.Database(channel_resolve_params)
    mamba_press.packages.load_subdirs_in_database(
        database=database,
        installed_packages=virtual_packages,
        subdir_indices=subdir_indices,
    )

    __logger__.info("Solving package requirements")
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

    for filter in solution_filters:
        solution = filter.filter_solution(solution)

    working_dir: pathlib.Path | tempfile.TemporaryDirectory
    if execution_params.working_dir is None:
        working_dir = tempfile.TemporaryDirectory(prefix="mamba-press")
    else:
        working_dir = execution_params.working_dir

    artifacts = WorkingArtifacts(
        working_dir=working_dir,
        python_package=python_package,
    )

    __logger__.info("Creating wheel environment")
    mamba_press.packages.create_wheel_environment(
        database=database,
        request=request,
        solution=solution,
        caches=caches,
        target_prefix=artifacts.working_env_path,
        channel_resolve_params=channel_resolve_params,
    )

    return artifacts


Context = dict[str, str | int]


def create_interpolation_context(working_artifacts: WorkingArtifacts) -> Context:
    """Create the variable used for interpolation in the configuration."""
    return {
        "site_packages": mamba_press.platform.site_packages_dir(working_artifacts.python_package),
    }


def read_env_files(path: pathlib.Path) -> Iterable[pathlib.Path]:
    """Read all the files in the environment."""
    for p in path.glob("**/*"):
        if p.is_file():
            yield p.relative_to(path)


def create_working_wheel(
    working_artifacts: WorkingArtifacts,
    files_filters: list[FilesFilter],
):
    """Filter and transform files from the working environment to the wheel folder."""
    files: list[pathlib.Path] = []
    for file in read_env_files(working_artifacts.working_env_path):
        file_str = str(file)
        if not any(filter.filter_file(file_str) for filter in files_filters):
            files.append(file)
