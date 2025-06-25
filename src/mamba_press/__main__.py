import pathlib

import libmambapy as mamba

import mamba_press


def main(
    tag: str,
    packages: list[mamba.specs.MatchSpec],
    wheel_env_dir: pathlib.Path,
) -> None:
    """Press Conda packages into wheels."""
    platform, virtual_packages = mamba_press.platform.platform_wheel_requirements(tag)

    channel_params = mamba_press.packages.ChannelParams(platform=platform)
    cache_params = mamba_press.packages.CacheParams()

    channel_resolve_params = mamba_press.packages.make_channel_resolve_params(channel_params)
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
    request = mamba_press.packages.make_request(packages)
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

    print("Creating wheel environment")
    mamba_press.packages.create_wheel_environment(
        database=database,
        request=request,
        solution=solution,
        caches=caches,
        target_prefix=wheel_env_dir,
        channel_resolve_params=channel_resolve_params,
    )

    site_package_dir = mamba_press.platform.site_package_dir(python_package)
    print("Site package is ", site_package_dir)


if __name__ == "__main__":
    import sys
    import tempfile

    wheel_env_dir = tempfile.TemporaryDirectory(prefix="mamba-press")
    main(sys.argv[1], [mamba.specs.MatchSpec.parse(sys.argv[2])], pathlib.Path(wheel_env_dir.name))
