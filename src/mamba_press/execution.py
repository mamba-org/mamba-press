import dataclasses
import functools
import itertools
import logging
import os
import pathlib
import tempfile
from typing import Annotated, Callable, Iterable

import libmambapy as mamba

import mamba_press.packages
import mamba_press.solution_utils
from mamba_press.config import Configurable
from mamba_press.filter.protocol import FilesFilter, SolutionFilter
from mamba_press.transform.dynlib.abc import Binary, DynamicLibRelocate
from mamba_press.transform.protocol import PathTransform

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
        pathlib.Path | None,
        Configurable(description="Where working environment is created"),
    ] = None

    out_dir: Annotated[
        pathlib.Path,
        Configurable(description="Where final wheels will be saved"),
    ] = pathlib.Path("dist/")


# TODO must be a full class
@dataclasses.dataclass(frozen=True)
class PackagesData:
    """The objects to describe the Conda packages that where needed, available, and chosen."""

    database: mamba.solver.libsolv.Database
    request: mamba.solver.Request
    full_solution: mamba.solver.Solution
    filtered_solution: mamba.solver.Solution

    @functools.cached_property
    def python(self) -> mamba.specs.PackageInfo | None:
        """Return the Python package matching the required packages."""
        return mamba_press.solution_utils.find_package_in_solution_installs(
            self.full_solution, mamba.specs.MatchSpec.parse("python")
        )


def compute_solution(
    execution_params: ExecutionParams,
    channel_params: mamba_press.packages.ChannelParams,
    cache_params: mamba_press.packages.CacheParams,
    solution_filters: list[SolutionFilter],
) -> tuple[PackagesData, mamba.MultiPackageCache, mamba.specs.ChannelResolveParams]:
    """Download the packages index and compute the packages required."""
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

    filtered_solution = functools.reduce(
        lambda sol, filt: filt.filter_solution(sol),
        solution_filters,
        solution,
    )

    packages_data = PackagesData(
        database=database,
        request=request,
        full_solution=solution,
        filtered_solution=filtered_solution,
    )

    return packages_data, caches, channel_resolve_params


@dataclasses.dataclass
class WorkingArtifacts:
    """Object to describe and manage the working environment."""

    working_dir: pathlib.Path | tempfile.TemporaryDirectory[str]
    python: mamba.specs.PackageInfo

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

    @property
    def working_wheel_path(self) -> pathlib.Path:
        """The root path of all the files in the wheel."""
        return self.working_dir_path / "wheel"

    @property
    def site_packages(self) -> pathlib.PurePath:
        """The relative directory of python module installs."""
        return pathlib.PurePath(mamba_press.platform.site_packages_dir(self.python))

    @property
    def working_wheel_dist_info_path(self) -> pathlib.Path:
        """The path to the .dist-info directory in the working wheel folder, if unique."""
        candidates = [
            p
            for p in (self.working_env_path / self.site_packages).iterdir()
            if not p.name.endswith(".dist-info")
        ]

        if len(candidates) != 1:
            count = "no" if len(candidates) == 0 else "multiple"
            pkgs = '", "'.join(str(c) for c in candidates)
            raise ValueError(f'Found {count} python packages: "{pkgs}"')

        return candidates[0]

    @property
    def unique_package_name(self) -> str:
        """Return the name of the python package, if unique."""
        return self.working_wheel_dist_info_path.name


def create_working_env(
    execution_params: ExecutionParams,
    caches: mamba.MultiPackageCache,
    channel_resolve_params: mamba.specs.ChannelResolveParams,
    packages_data: PackagesData,
) -> WorkingArtifacts:
    """Create the working environment with packages filtered.

    This environment is the initial collection of files that mamba_press is working with to create
    a wheel.
    It is later refined into a working wheel folder by filtering and transforming the files.
    """
    working_dir: pathlib.Path | tempfile.TemporaryDirectory[str]
    if execution_params.working_dir is None:
        working_dir = tempfile.TemporaryDirectory(prefix="mamba-press")
    else:
        working_dir = execution_params.working_dir

    python = packages_data.python
    if python is None:
        raise ValueError("No Python package found")

    artifacts = WorkingArtifacts(
        working_dir=working_dir,
        python=python,
    )

    __logger__.info("Creating wheel environment")
    mamba_press.packages.create_wheel_environment(
        database=packages_data.database,
        request=packages_data.request,
        solution=packages_data.filtered_solution,
        caches=caches,
        target_prefix=artifacts.working_env_path,
        channel_resolve_params=channel_resolve_params,
    )

    return artifacts


Context = dict[str, str | int]


def create_interpolation_context(working_artifacts: WorkingArtifacts) -> Context:
    """Create the variable used for interpolation in the configuration."""
    return {
        "site_packages": str(working_artifacts.site_packages),
        "package_name": str(working_artifacts.unique_package_name),
    }


def read_env_files(path: pathlib.Path) -> Iterable[pathlib.PurePath]:
    """Read all the files in the environment."""
    for p in path.glob("**/*"):
        if p.is_file():
            yield p.relative_to(path)


def __make_path_transform(
    working_env_path: pathlib.Path, path_transforms: list[PathTransform]
) -> Callable[[pathlib.Path], pathlib.Path]:
    def transform(path: pathlib.Path) -> pathlib.Path:
        if not path.is_relative_to(working_env_path):
            return path

        if path.is_symlink():
            path = path.resolve()
        rel_src = pathlib.PurePath(path.relative_to(working_env_path))
        dest = functools.reduce(lambda p, t: t.transform_path(p), path_transforms, rel_src)
        return pathlib.Path(dest)

    return transform


def create_working_wheel(
    working_artifacts: WorkingArtifacts,
    files_filters: list[FilesFilter],
    path_transforms: list[PathTransform],
    relocator: DynamicLibRelocate[Binary],
) -> None:
    """Filter and transform files from the working environment to the wheel folder."""
    # FIXME: note that in reading the files from the environment, some are generated by the mamba
    # client, such as Python entry points and should be excluded in some form.
    # See PrefixData json data in conda-meta/ subfolder.
    files: dict[pathlib.PurePath, pathlib.PurePath] = {}
    for rel_src in read_env_files(working_artifacts.working_env_path):
        if any(not filter.filter_file(rel_src) for filter in files_filters):
            __logger__.debug(f'Filtering out file "{rel_src}"')
            continue

        rel_dest = functools.reduce(lambda p, t: t.transform_path(p), path_transforms, rel_src)
        __logger__.debug(f'Transforming "{rel_src}" -> "{rel_dest}"')
        files[rel_src] = pathlib.PurePath(rel_dest)

    # TODO: Could we use a general enough DataTransform Protocol?
    # This is why the relocator was made into a class even though it does not have any
    # instance data.
    for rel_src, rel_dest in files.items():
        abs_src = working_artifacts.working_env_path / rel_src
        abs_dest = working_artifacts.working_wheel_path / rel_dest

        abs_dest.parent.mkdir(parents=True, exist_ok=True)

        if relocator.needed(abs_src):
            # Symlinks are not supported in wheels, we relocate the libs to point to
            # their exact library name versions.
            if abs_src.is_symlink():
                continue
            with open(abs_src, "rb") as f:
                bin = relocator.parse_binary(f.read())
            # A previous version was modifying the library name (soname, id) and dynamic loading
            # but resulted in invalid binaries.
            # Instead, we leave the all names unchanged and set the file name to the library name.
            # This is less flexible and more error-prone, but works for now.
            if (name := relocator.lib_name(bin)) is not None:
                abs_dest = abs_dest.with_name(name)
                # Need to check again since the name changed
                if any(not filter.filter_file(rel_src.with_name(name)) for filter in files_filters):
                    __logger__.debug(f'Filtering out file "{rel_src}"')
                    continue

            relocator.relocate_binary(
                bin=bin,
                data_path=abs_src,
                prefix_path=working_artifacts.working_env_path,
                path_transform=__make_path_transform(working_artifacts.working_env_path, path_transforms),
            )
            relocator.write_binary(bin, abs_dest)

        else:
            os.link(abs_src, abs_dest)
