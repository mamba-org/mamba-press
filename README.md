# Mamba-Press
[![Conda Version](https://img.shields.io/conda/vn/conda-forge/mamba-press.svg)](https://anaconda.org/conda-forge/mamba-press) [![Conda Recipe](https://img.shields.io/badge/recipe-mamba--press-green.svg)](https://github.com/conda-forge/mamba-press-feedstock)
Press Conda packages into wheels.

> [!WARNING]
This project is in alpha, undergoing broader testing.


## Installation
The latest Mamba-press release can be installed from Conda-Forge with Conda/Mamba/Pixi.
It ships a ``mamba_press`` Python library and a ``mamba-press`` executable.

```bash
mamba install -c conda-forge mamba-press
```

The development version can be run from within the Git repository using [Pixi](https://pixi.sh).
- `pixi run mamba-press` to run the executable.
- `pixi run mamba-press-dev` adds some options to inspect intermediary files.

## What it does
The project takes one or more Conda packages to press into a single wheel with all its
dependencies.

The pressing steps are roughly:
- Solve the defined conda specs into a set of Conda packages.
- Remove unwanted packages and their exclusive dependencies (e.g. Python itself).
- Download and install all these packages into a working (broken) Conda environment.
- Filter unwanted files (headers, Conda metadata, _etc_.).
- Rearrange files:
  - Change their path (for instance a Python package will be under ``lib/pythonX.YY/site-packages``
    in Conda but needs to be at the root of the wheel).
  - Change file data (e.g. relocate dynamic libraries that have been moved).
- Upsert wheel metadata.
- Zip final directory into a wheel file.


## Limitations
There are incompressible limitations due to the differences between Conda and wheels:
- Conda can rewrite absolute path present in files, which PyPI clients (``pip``, ``uv``) cannot do.
  We can sometimes convert them to relative paths when we know how they are used, such as when used
  as ``RPATH`` in dynamic libraries. The project could however easily provide a way for user to
  configure how they should be treated.
- Symlinks are not allowed in wheels and need to be removed or copied (currently removed).
- Conda-forge builds with recent dependencies (such as ``libstdc++``), which means that they either
  need to to be shipped for (not so) old systems.
- If depending on the binary interface of other Python packages, these dependencies need to be
  pinned has hard as their [ABI](https://en.wikipedia.org/wiki/Application_binary_interface) is
  unstable.
  In the Conda ecosystem, this is not an issue because the
  [build variant](https://docs.conda.io/projects/conda-build/en/stable/resources/variants.html)
  make it possible to ship multiple versions of a packages from which an exact solver
  will pick.
  With ``pip`` the solver is approximate and may violate these constraints.
  What's more, many wheel ship their own dynamic libraries, which makes it even more likely to run
  into program corruption when exchanging underlying dynamic libraries objects through Python.

There are current limitations to this project:
- Among all the packages and dependencies, only one can be Python package (this will be the one used
for the wheel name).
- This package must ship a ``.dist-info`` (and not a ``.egg-info``).
- Library sonames/id currently cannot be changed and therefore so do their filename.
- Due to failure to change name ids on MacOS, absolute dynamic libraries dependencies cannot be
replaced with a relative path.


## Development
[Pixi](https://pixi.sh/) is recommended for development. It is the only tool needed and will
install all the project dependencies (Python included) automatically.

A number of tasks are provided
- `pixi run test` to run the test.
- `pixi run fmt` to run the code formatter.
- `pixi run fmt` to run the code formatter.
- `pixi run ci` to combine all these checks in a one stop task.

[Pre-commit](https://pre-commit.com/) is configured with the specificity that it will actually run
a number of checks trough Pixi.
It can be set up with
- `pixi run pre-commit install`
