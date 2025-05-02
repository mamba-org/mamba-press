# Mamba-Press
Press Conda packages into wheels.

> [!WARNING]
This project is under development and not usable in any way.

## Possible requirements
- Works on all major platforms: Windows, MacOS, Linux.
- Build wheel from a single package without dependencies (more of a utility).
- Build wheel from a package with its dependencies.
- Prune undesirable dependencies:
    - Python itself,
    - System dependencies, see for instance [PEP 600](https://peps.python.org/pep-0600/) for Linux,
    - Other Python code / modules (use Conda-forge to PyPI map available in Pixi).
- Expose required executables (filtered by name or package).
- Expose Python packages.
- Expose dynamic library (HARD).
- Test created wheel ``import``s.

## Suggested workflow
This suggestion workflow aims to architect Mamba-Press around the possible requirements and
plan missing APIs in Mamba.

- Read simple user configuration (CLI, env, files) without libmamba for simplicity and due to the
  presence of specific options.
- Get channel repodatas:
  - Resolve channels,
  - Download repodatas (in any format readable by Mamba), share cache with Mamba by default.
- Solve the "_would have been_" environment using direct Mamba ``Solver`` and ``Database`` API.
- Compute list of required packages from ``Solution``:
    - Create dependency graph of required packages,
    - Apply filters to dependency graph i.e. package to ignore,
    - Prune packages not available from user request.
- Download and extract packages from filtered ``Solution``, share cache with Mamba by default.
- Create "_would have been_" environment. This is still unsure if easily doable by extending Mamba
  or if too far-fetched.
  - Apply "smart" prefix substitution:
    - Shared lib use RPATH,
    - Otherwise relative path.
  - Apply directory mappings to match wheel:
    - ``bin/`` -> ``?``
    - ``lib/`` -> ``?``
    - ``lib/pythonX.YY/site-packages/`` -> ``?``
    - ``info/`` -> ``?``
- Create wheel from "_would have been_" environment.
- Optionally test wheel:
  - Create Mamba environment with ``python`` and ``pip``/``uv``,
  - Install the wheel,
  - Test ``import``s.

## Mamba missing APIs
- [x] Context
- [x] ChannelContext
- [ ] ``load_channels``
- [x] ``Database``
- [x] ``Request``
- [x] ``Solver``
- [x] ``Solution``
- [x] ``MTransaction::fetch_extract_packages``
- [ ] ``LinkPackage``, ``PathData``, TBD
