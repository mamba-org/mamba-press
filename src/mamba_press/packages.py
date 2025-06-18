import dataclasses
import os
import pathlib
from typing import Annotated, Final, Iterable, cast

import libmambapy as mamba

from mamba_press.config import Configurable

NOARCH_PLATFORM_STR: Final = "noarch"


@dataclasses.dataclass(frozen=True, slots=True)
class ChannelParams:
    """Parameters controlling the packages source."""

    platform: Annotated[
        str,
        Configurable(description="The Conda platform to fetch packages from"),
    ]

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


def make_channels(params: ChannelParams) -> list[mamba.specs.Channel]:
    """Create the channel object from the parameters."""
    resolve_params = mamba.specs.ChannelResolveParams(
        platforms={params.platform, NOARCH_PLATFORM_STR},
        channel_alias=params.channel_alias,
        home_dir=os.path.expanduser("~"),
        current_working_dir=os.getcwd(),
    )
    return [
        channel
        for unresolved_channel in params.channels
        for channel in mamba.specs.Channel.resolve(
            unresolved_channel,
            params=resolve_params,
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
    ] = dataclasses.field(default_factory=lambda: [pathlib.Path("~/.cache/mamba/")])


def make_package_cache(params: CacheParams) -> mamba.MultiPackageCache:
    """Create the cache object from the parameters."""
    validation_params = mamba.Context.ValidationParams(
        safety_checks=mamba.VerificationLevel.Enabled,
        extra_safety_checks=True,
    )

    return mamba.MultiPackageCache(
        validation_params=validation_params,
        pkgs_dirs=cast(list, params.package_dirs),
    )


def make_subdir_index_loaders(
    locations: Iterable[tuple[mamba.specs.Channel, str]], caches: mamba.MultiPackageCache
) -> list[mamba.SubdirIndexLoader]:
    """Create loader channel subdirectory index loader objects."""
    subdir_params = mamba.SubdirParams()

    return [
        mamba.SubdirIndexLoader.create(
            params=subdir_params,
            channel=channel,
            platform=platform,
            caches=caches,
        )
        for channel, platform in locations
    ]


def download_required_subdir_indices(subdir_indices: list[mamba.SubdirIndexLoader]):
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
