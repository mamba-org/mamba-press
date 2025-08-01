import pathlib

import mamba_press
import mamba_press.__main__

__project_root__ = pathlib.Path(__file__).parent.parent


def test_libmambapy(tmp_path: pathlib.Path) -> None:
    """The the build of libmambapy."""
    with open(__project_root__ / "examples/libmambapy.yaml") as f:
        recipe = mamba_press.Recipe.parse_yaml(f.read())

    working_dir = tmp_path / "build"
    out_dir = tmp_path / "dist"
    execution_params = mamba_press.execution.ExecutionParams(
        working_dir=working_dir,
        out_dir=out_dir,
    )
    channel_params = mamba_press.packages.ChannelParams()
    cache_params = mamba_press.packages.CacheParams()

    mamba_press.__main__.main(
        execution_params=execution_params,
        channel_params=channel_params,
        cache_params=cache_params,
        recipe=recipe,
    )

    assert next(out_dir.glob("libmambapy-2.3.1-*311*.whl"))
    # Looking into the internals
    assert (working_dir / "env").exists()
    assert (working_dir / "wheel").exists()
    top_dirs = list((working_dir / "wheel").glob("*"))
    assert len(top_dirs) == 2
    assert all(p.name.startswith("libmambapy") for p in top_dirs)
    assert next((working_dir / "wheel/libmambapy").glob("bindings*"))
    assert (working_dir / "wheel/libmambapy/data").exists()
    assert next((working_dir / "wheel/libmambapy/data/lib").glob("libsolv*"))
