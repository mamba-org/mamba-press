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
The version is a single digit of the recipe format meant for future proofing.
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
