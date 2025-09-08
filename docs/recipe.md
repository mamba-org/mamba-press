# The recipe file
The recipe file is a yaml configuration detailling how to build a *single* wheel file.
The file enable deep customization of the different steps used by Mamba-press to build a wheel.

> [!NOTE]
> Currently, the recipe file only allows for building a single wheel.
> Different versions and Python support need to be made in multiple files that may vary only slightly.
> We prefer to focus our efforts on a single output for the time being to avoid creating creating a
> system that limits more than it helps.
> Users can make use of templating tools like [Jinja](https://jinja.palletsprojects.com/) to automate
> the writing of multiple recipe files.


## The `version` entry
The version is asingle digit of the recipe format meant for future proofing.
Only the version `0` exists for now.
The version `0` recipe schema may change in a breaking fashion without leading to a version increase.

```yaml
version: 0
```


## The `source` section
This section specifies what Conda packages to build the wheel from.

```yaml
source:
  packages:
    - pkgA==3.7.0[build_string="Variant1"]
    - pkgB
  constraints:
    - otherlib==2.0
  python: python=3.13
```

### The `source.packages` entry
This is the list of [MatchSpec](https://mamba.readthedocs.io/en/latest/usage/specs.html#matchspec)
that will be the basis for the wheel.
The `MatchSpec` include the package name and can use all its flexibility (build string *etc*.) to
select the package of interest.
Multiple `MatchSpec`s can be specified to accommodate cases where multiple packages need to be merged
into one single wheel.
It also marks the matching Conda packages as explicitly requested, preventing them to be removing
in filtering phases.

### The `source.constraints` entry (optional)
Constraints are similar to pins in a Conda environment.
They are not explicitly installed, but constraint the solver to pick packages that would be
compatible with it.
It is useful to select variant of the package that must be compatible with a library that will be
found on the user system outside of this wheel, such as binary dynamic libraries.
If Conda provides `otherlib` as a package, but that we are not packging it inside our wheel, we
may need to specify that we create a wheel from a set of Conda packages compatible
with `otherlib==2.0`.

### The `source.python` entry
This is an alias for a constraint on Python itself.
It takes a single `MatchSpec` (with the name `python` included) to specify which Python version
to build the wheel for.
Just like other binary shared libraries, native Python extensions use symbols from the Python
interpreter that need to be of the proper version.

> [!NOTE]
> That version is actually part of the wheel Tag and filename, enabling easy management of wheels
> built for different version of Python of a single package.


## The `target` section
This section specifies information about the wheel to build.

```yaml
target:
  name: pkgA
  platform:
    os: manylinux
    version: "2.17"
    arch: x86_64
```

### The `target.name` entry (optional)
The package name of the wheel we are building.
In many cases this can be inferred from the name of the top level Python modulen when available and
unique.

### The `target.platform` entry
Specify the target platform for which we are building the wheel.
There are three string entries in that section.
They need to be given as Python wheel
[platform tags](https://packaging.python.org/en/latest/specifications/platform-compatibility-tags/#platform-tag)
and vary depending on the operating system.
- `os` the name of operating system, or operating system group (e.g. `manylinux`),
-`version` the relevant oerpating system version (the `libc` version for `manylinux`),
- `arch` the CPU architecture.

> [!WARNING]
> Because the Conda packages contain many libraries typically found on the system, it is not simple
> (if at all possible) to infer what OS version will be compatible with the source packages.
> It is the responsibility of the user to provide the platform tag that express the needs of the
> wheel that are not vendored.


## The `build` section (optional)
The build section provide deep customization of the Mamba-press execution.
To do so it relies on plugin to do part of the work.

### Plugins
There are different types of plugins for different sub-sections but they are all created the same
way in yaml.

When a plugin is required it can be given by its name.
Built-in plugin have a custom name that maps to Mamba-press classes, but any plugin (including
external ones) can be used by giving they full import and class name (such as `pkg.module.Plugin`).

The name is a unique key in a map, whose value is a map of parameter names to values.
There is no restrictions (except the ones of YAML) to what parameter values can be.

> [!WARNING]
> Any customization of a plugin automatically remove the default behaviour.

When a plugin is required, the special string `default` can also be provided to explicitly
ask to use the default plugin(s) with default parameters for that section.

```yaml
plugin-name:
  parameter-A: value
  parameter-B:
   - 1
   - 2
```

> [!NOTE]
Basic plugin can feel verbose at time. We reserve simpler aliases for future recipe format.

Plugin input parameters strings may contain special keys to be substituted by the relevant data
detected by Mamba-press if the information is known at that time in the execution.
They use a Jinja-like syntax (but no advanced functionalites exist).

Current keys are:
- `${{ package_name }}` the name of the unique top level Python package found, or `target.name`.
- `"${{site_packages }}` the path, relative to the root of the work environment, of the Python
  installation directory.


## The `build.filter.packages` entry (optional)
After the Conda environment is solved and before packages are downloaded, a first list
of [`PackagesFilter`](src/mamba_press/filter/protocol.py) can be specified to remove entire Conda
packages from what is included in the wheel.

The default behaviour is to remove Python itself and all its dependencies not (transitively) needed
by the specified packages in `source.packages`.

Different package filters are chained such that a package must not be filtered out by any filter
plugin to remain available.

A built-in package filter to remove more Conda packages is available as `by-name`.

```yaml
build:
  filter:
    packages:
      # Apply the default packages filter (removes Python itself)
      - default
      # Also remove these packages
      - by-name:
         # Also removed their dependencies if not needed by source.packages
         recursive: true
         to-prune:
            - numpy
            - scipy
```


## The `build.filter.files` entry (optional)
Once the remaining Conda packages are installed in a work environment, a list
of [`FilesFilter`](src/mamba_press/filter/protocol.py) can be specified to exclude files from the
wheel based on their path in the work Conda environment.
The default behaviour is to remove files not needed in a Python context (Conda specific files,
headers, manuals, CMake files) as well as Python files that must not be in the wheel (`.pyc`,
`dist-info/REQUESTED`...).

Different files filters are chained such that a file must not be filtered out by any filter plugin
to remain.

A built-in files filter to remove files based on glob is available as `unix-glob`.

```yaml
build:
  filter:
    files:
      # Apply the default files filter
      - default
      # Also exclude these globs
      - unix-glob:
          # If true exclude the files matching the any of the pattern,
          # otherwise keep only the files matching any of the pattern.
          exclude: true
          patterns:
            - "lib/libnotneeded*.so*"
```


## The `build.transform.path` entry (optional)
Files in the work environment need to be moved to create the directory layout needed for the wheel.
The [`PathTransform`](src/mamba_press/transform/protocol.py) specify how the directory layout
changes between the work environment and the wheel directory.

The default behaviour is to move everything inside the Python install directory (*e.g.*
`lib/python3.13/site-packages`) at the root of the wheel and move all the rest inside the main
wheel package, under a `data` subdirectory (*e.g.* `pkgA/data/lib`...).

Different path transforms are chained so that the downstream transform has to account for the
transformation of the previous ones.

```yaml
build:
  transform:
    path:
      # Apply the default path relocation
      - default
      # Then also move a library from the inside a Python module to the data dir
      - explicit:
          mapping:
            - from: "${{ package_name }}/module/libsomething.so"
              to:  "${{ package_name }}/data/lib/libsomething.so"
```


## The `build.transform.dynlib` entry (optional)
This transformation requires careful handling and is therefore not a plugin.
When dynamic libraries are moved around, their `RPATH` become invalid, this transoformation
rewrites the valid path of the files after they have been moved into the wheel folder.

Two options can be used for adding or removing `RPATH`.
Adding `RPATH` is useful for relying on a dynamic library that will be found on the system, either
because it is found in another Python package that is already providing wheel, or because it is
the responsibility of the final user to install it.
Remove `RPATH` is less common, it may be because it was wrongfully added, or for `libpython` itself.

```yaml
build:
  transform:
    dynlib:
      # Add these RPATH to libraries found on the system / other wheels
      add-rpaths:
        - "../otherwheel/libother.so.3.7"
      # Python extensions must not link with libpython
      remove-rpaths:
        - "libpython*.so*"
```
