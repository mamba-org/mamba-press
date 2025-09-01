import dataclasses
import os
import pathlib
from typing import Annotated, Callable, Final, Iterable, cast

import libmambapy as mamba

import mamba_press.platform
from mamba_press.config import Configurable

NOARCH_PLATFORM_STR: Final = "noarch"
NOARCH_PLATFORM: Final = mamba.specs.KnownPlatform.noarch


@dataclasses.dataclass(frozen=True, slots=True)
class ChannelParams:
    """Parameters controlling the packages source."""

    channels: Annotated[
        list[mamba.specs.UnresolvedChannel],
        Configurable(
            description="The Conda channels to fetch packages from",
            convert=lambda c: [mamba.specs.UnresolvedChannel.parse(c)],
        ),
    ] = dataclasses.field(default_factory=lambda: [mamba.specs.UnresolvedChannel.parse("conda-forge")])

    channel_alias: Annotated[
        mamba.specs.CondaURL,
        Configurable(description="Base channel url"),
    ] = dataclasses.field(default_factory=lambda: mamba.specs.CondaURL.parse("https://conda.anaconda.org"))


def make_channel_resolve_params(
    params: ChannelParams, platform: mamba.specs.KnownPlatform
) -> mamba.specs.ChannelResolveParams:
    """Convert channel parameters to libmambapy parameters."""
    return mamba.specs.ChannelResolveParams(
        platforms={mamba_press.platform.platform_conda_string(platform), NOARCH_PLATFORM_STR},
        channel_alias=params.channel_alias,
        home_dir=os.path.expanduser("~"),
        current_working_dir=os.getcwd(),
    )


def make_channels(
    channels: Iterable[mamba.specs.UnresolvedChannel],
    channel_resolve_params: mamba.specs.ChannelResolveParams,
) -> list[mamba.specs.Channel]:
    """Create the channel object from the parameters."""
    return [
        channel
        for unresolved_channel in channels
        for channel in mamba.specs.Channel.resolve(
            unresolved_channel,
            params=channel_resolve_params,
        )
    ]


@dataclasses.dataclass(frozen=True, slots=True)
class CacheParams:
    """Parameters controlling the packages caching location."""

    package_dirs: Annotated[
        list[pathlib.Path],
        Configurable(
            description="The Conda platform to fetch packages from",
            env="CONDA_PKGS_DIRS",
            convert=lambda p: [pathlib.Path(p)],
        ),
    ] = dataclasses.field(default_factory=lambda: [pathlib.Path("~/.cache/mamba/").expanduser()])


def make_package_cache(cache_params: CacheParams) -> mamba.MultiPackageCache:
    """Create the cache object from the parameters."""
    validation_params = mamba.Context.ValidationParams(
        safety_checks=mamba.VerificationLevel.Enabled,
        extra_safety_checks=True,
    )

    return mamba.MultiPackageCache(
        validation_params=validation_params,
        pkgs_dirs=cast(list[os.PathLike[str]], cache_params.package_dirs),
    )


def make_subdir_index_loaders(
    locations: Iterable[tuple[mamba.specs.Channel, mamba.specs.KnownPlatform]],
    caches: mamba.MultiPackageCache,
) -> list[mamba.SubdirIndexLoader]:
    """Create loader channel subdirectory index loader objects."""
    subdir_params = mamba.SubdirParams()

    return [
        mamba.SubdirIndexLoader.create(
            params=subdir_params,
            channel=channel,
            platform=mamba_press.platform.platform_conda_string(platform),
            caches=caches,
        )
        for channel, platform in locations
    ]


def download_required_subdir_indices(subdir_indices: list[mamba.SubdirIndexLoader]) -> None:
    """Download the channel subidrectory indices as needed."""
    subdir_download_params = mamba.SubdirDownloadParams()
    auth_info = mamba.specs.AuthenticationDataBase()
    mirrors = mamba.MirrorMap.from_names_and_urls(
        {
            (
                (channel := subdir.channel()).display_name,
                channel.url.str(credentials=mamba.specs.CondaURL.Credentials.Show),
            )
            for subdir in subdir_indices
        }
    )
    download_options = mamba.DownloadOptions()
    remote_fetch_params = mamba.RemoteFetchParams()

    mamba.SubdirIndexLoader.download_required_indexes(
        subdir_indices=subdir_indices,
        subdir_params=subdir_download_params,
        auth_info=auth_info,
        mirrors=mirrors,
        download_options=download_options,
        remote_fetch_params=remote_fetch_params,
    )


def load_subdirs_in_database(
    database: mamba.solver.libsolv.Database,
    installed_packages: list[mamba.specs.PackageInfo],
    subdir_indices: list[mamba.SubdirIndexLoader],
) -> None:
    """Add packages to the database from subdir indexes and available packages."""
    repo = database.add_repo_from_packages(
        packages=installed_packages,
        name="installed",
        add_pip_as_python_dependency=mamba.solver.libsolv.PipAsPythonDependency.No,
    )
    database.set_installed_repo(repo)

    for index in subdir_indices:
        database.add_repo_from_repodata_json(
            path=index.valid_json_cache_path(),
            url=index.channel().platform_url(index.platform()).str(),
            channel_id=index.channel_id(),
            add_pip_as_python_dependency=mamba.solver.libsolv.PipAsPythonDependency.No,
        )


def make_request(
    needed: Iterable[mamba.specs.MatchSpec],
    constraints: Iterable[mamba.specs.MatchSpec],
) -> mamba.solver.Request:
    """Make a solver request to install all the needed packages."""
    jobs = mamba.solver.Request.JobList(mamba.solver.Request.Install(s) for s in needed)
    for cons in constraints:
        jobs.append(mamba.solver.Request.Pin(cons))
    return mamba.solver.Request(jobs)


def solve_for_packages(
    request: mamba.solver.Request, database: mamba.solver.libsolv.Database
) -> mamba.solver.Solution:
    """Solve the required packages into a list of packages to install."""
    solver = mamba.solver.libsolv.Solver()
    outcome = solver.solve(request=request, database=database)

    if isinstance(outcome, mamba.solver.libsolv.UnSolvable):
        message = outcome.explain_problems(
            database=database,
            format=mamba.solver.ProblemsMessageFormat(),
        )
        raise ValueError("Cannot solve for packages:\n" + message)

    return outcome


def __make_context_getter() -> Callable[[], mamba.Context]:
    ctx = mamba.Context()

    def get_context() -> mamba.Context:
        nonlocal ctx
        return ctx

    return get_context


# Must be earerly created to avoid issues in libmamba
__get_context = __make_context_getter()


def create_wheel_environment(
    database: mamba.solver.libsolv.Database,
    request: mamba.solver.Request,
    solution: mamba.solver.Solution,
    caches: mamba.MultiPackageCache,
    target_prefix: pathlib.Path,
    channel_resolve_params: mamba.specs.ChannelResolveParams,
) -> None:
    """Create the environment that will be the basis for the wheel data."""
    channel_context = mamba.ChannelContext(channel_resolve_params, has_zst=[])
    prefix = mamba.PrefixData(
        target_prefix,
        channel_context=channel_context,
    )

    # TODO: Refactor transaction to remove Context
    ctx = __get_context()
    ctx.prefix_params.target_prefix = target_prefix
    ctx.link_params.allow_softlinks = False
    ctx.link_params.compile_pyc = False

    request = mamba.solver.Request([])

    transaction = mamba.Transaction(
        ctx,
        database,
        request,
        solution,
        caches,
    )

    transaction.execute(
        ctx,
        channel_context,
        prefix,
    )
