import libmambapy as mamba

import mamba_press


def test_package_filter_pyarrow():
    """Test that packages and orphans are pruned correctly on a pyarrow case."""
    to_prune = [
        mamba.specs.MatchSpec.parse("python"),
        mamba.specs.MatchSpec.parse("libcxx"),
        mamba.specs.MatchSpec.parse("bzip2"),
    ]
    requested_packages = [
        mamba.specs.MatchSpec.parse("pyarrow"),
    ]
    solution = make_pyarrow_solution()

    filter = mamba_press.filter.PackagesFilter(
        to_prune=to_prune,
        requested_packages=requested_packages,
    )
    pruned = filter.filter_solution(solution)

    assert len(pruned.to_install()) < len(solution.to_install())

    python_only_deps = [mamba.specs.MatchSpec.parse("libffi")]
    common_deps = [mamba.specs.MatchSpec.parse("libzlib")]

    # Python-only dependencies
    for ms in to_prune + python_only_deps:
        assert not any(ms.contains_except_channel(p) for p in pruned.to_install())

    # Python and libarrow (indirect) dependencies
    for ms in common_deps + requested_packages:
        assert any(ms.contains_except_channel(p) for p in pruned.to_install())


def test_python_filter_pinocchio():
    """Test that python packages and orphans are pruned correctly on a pinocchio case."""
    requested_packages = [mamba.specs.MatchSpec.parse("pinocchio")]
    solution = make_pinocchio_solution()

    filter = mamba_press.filter.PythonPackagesFilter(
        requested_packages=requested_packages,
    )
    pruned = filter.filter_solution(solution)

    assert len(pruned.to_install()) < len(solution.to_install())

    must_prune = [
        # A Python only dependency
        mamba.specs.MatchSpec.parse("libffi"),
        # A Python package dependency of pinocchio
        mamba.specs.MatchSpec.parse("numpy"),
        mamba.specs.MatchSpec.parse("scipy"),
    ]
    for ms in must_prune:
        assert not any(ms.contains_except_channel(p) for p in pruned.to_install())

    must_not_prune = [
        # A transitive dependency of pinocchio
        mamba.specs.MatchSpec.parse("libcblas"),
        # Any requested package
        *requested_packages,
    ]
    for ms in must_not_prune:
        assert any(ms.contains_except_channel(p) for p in pruned.to_install())


def make_pinocchio_solution() -> mamba.solver.Solution:
    """Return a Solution to create an osx-arm64 pinocchio 3.2.0 environment."""
    PackageInfo = mamba.specs.PackageInfo

    packages = [
        PackageInfo(
            name="tinyxml2",
            version="10.0.0",
            build_string="ha1acc90_2",
            depends=["__osx >=11.0", "libcxx >=18"],
        ),
        PackageInfo(
            name="libcblas",
            version="3.9.0",
            build_string="20_osxarm64_openblas",
            depends=["libblas 3.9.0 20_osxarm64_openblas"],
        ),
        PackageInfo(
            name="liblzma-devel",
            version="5.8.1",
            build_string="h39f12f2_2",
            depends=["__osx >=11.0", "liblzma 5.8.1 h39f12f2_2"],
        ),
        PackageInfo(
            name="numpy",
            version="1.24.4",
            build_string="py38ha84db1f_0",
            depends=[
                "libblas >=3.9.0,<4.0a0",
                "libcblas >=3.9.0,<4.0a0",
                "libcxx >=15.0.7",
                "liblapack >=3.9.0,<4.0a0",
                "python >=3.8,<3.9.0a0",
                "python >=3.8,<3.9.0a0 *_cpython",
                "python_abi 3.8.* *_cp38",
            ],
        ),
        PackageInfo(name="libboost-headers", version="1.86.0", build_string="hce30654_1", depends=[]),
        PackageInfo(
            name="libboost-devel",
            version="1.86.0",
            build_string="hf450f58_1",
            depends=["libboost 1.86.0 h610977f_1", "libboost-headers 1.86.0 hce30654_1"],
        ),
        PackageInfo(name="mumps-include", version="5.7.3", build_string="h8c5b6c6_9", depends=[]),
        PackageInfo(name="metis", version="5.1.0", build_string="h15f6cfe_1007", depends=["__osx >=11.0"]),
        PackageInfo(name="ncurses", version="6.5", build_string="h5e97a16_3", depends=["__osx >=11.0"]),
        PackageInfo(name="libffi", version="3.4.6", build_string="h1da3d7d_1", depends=["__osx >=11.0"]),
        PackageInfo(
            name="casadi",
            version="3.6.5",
            build_string="py38h1d34bfc_4",
            depends=[
                "__osx >=11.0",
                "ipopt >=3.14.16,<3.14.17.0a0",
                "libblas >=3.9.0,<4.0a0",
                "libcblas >=3.9.0,<4.0a0",
                "libcxx >=14",
                "libgfortran >=5",
                "libgfortran5 >=12.3.0",
                "libgfortran5 >=13.2.0",
                "libosqp >=0.6.3,<0.6.4.0a0",
                "numpy >=1.22.4,<2.0a0",
                "proxsuite >=0.6.4,<0.7.0a0",
                "python >=3.8,<3.9.0a0",
                "python >=3.8,<3.9.0a0 *_cpython",
                "python_abi 3.8.* *_cp38",
                "tinyxml2 >=10.0.0,<10.1.0a0",
            ],
        ),
        PackageInfo(
            name="assimp",
            version="5.4.2",
            build_string="ha985da9_1",
            depends=[
                "__osx >=11.0",
                "libboost >=1.86.0,<1.87.0a0",
                "libcxx >=16",
                "libzlib >=1.3.1,<2.0a0",
                "zlib",
            ],
        ),
        PackageInfo(
            name="scipy",
            version="1.9.3",
            build_string="py38h7b4f323_2",
            depends=[
                "libblas >=3.9.0,<4.0a0",
                "libcblas >=3.9.0,<4.0a0",
                "libcxx >=14.0.4",
                "libgfortran >=5",
                "libgfortran5 >=11.3.0",
                "liblapack >=3.9.0,<4.0a0",
                "numpy >=1.20.3,<1.26",
                "numpy >=1.20.3,<2.0a0",
                "python >=3.8,<3.9.0a0",
                "python >=3.8,<3.9.0a0 *_cpython",
                "python_abi 3.8.* *_cp38",
            ],
        ),
        PackageInfo(
            name="libsqlite",
            version="3.50.2",
            build_string="h6fb428d_0",
            depends=["__osx >=11.0", "libzlib >=1.3.1,<2.0a0"],
        ),
        PackageInfo(
            name="libgfortran",
            version="15.1.0",
            build_string="hfdf1602_0",
            depends=["libgfortran5 15.1.0 hb74de2c_0"],
        ),
        PackageInfo(
            name="libgfortran5", version="15.1.0", build_string="hb74de2c_0", depends=["llvm-openmp >=8.0.0"]
        ),
        PackageInfo(name="libcxx", version="20.1.7", build_string="ha82da77_0", depends=["__osx >=11.0"]),
        PackageInfo(
            name="ampl-asl",
            version="1.0.0",
            build_string="h286801f_2",
            depends=["__osx >=11.0", "libcxx >=18"],
        ),
        PackageInfo(
            name="openssl",
            version="3.5.1",
            build_string="h81ee809_0",
            depends=["__osx >=11.0", "ca-certificates"],
        ),
        PackageInfo(
            name="libosqp",
            version="0.6.3",
            build_string="h5833ebf_1",
            depends=["__osx >=11.0", "libcxx >=17", "libqdldl >=0.1.7,<0.1.8.0a0"],
        ),
        PackageInfo(name="bzip2", version="1.0.8", build_string="h99b78c6_7", depends=["__osx >=11.0"]),
        PackageInfo(
            name="ipopt",
            version="3.14.16",
            build_string="h3e4dc2c_11",
            depends=[
                "__osx >=11.0",
                "ampl-asl >=1.0.0,<1.0.1.0a0",
                "libblas >=3.9.0,<4.0a0",
                "libcxx >=18",
                "libgfortran >=5",
                "libgfortran5 >=13.2.0",
                "liblapack >=3.9.0,<4.0a0",
                "mumps-seq >=5.7.3,<5.7.4.0a0",
            ],
        ),
        PackageInfo(name="eigen", version="3.4.0", build_string="h1995070_0", depends=["libcxx >=15.0.7"]),
        PackageInfo(
            name="console_bridge", version="1.0.2", build_string="h3e96240_1", depends=["libcxx >=12.0.1"]
        ),
        PackageInfo(
            name="libboost-python-devel",
            version="1.86.0",
            build_string="py38h255c162_1",
            depends=[
                "libboost-devel 1.86.0 hf450f58_1",
                "libboost-python 1.86.0 py38he25cb4c_1",
                "numpy >=1.22.4,<2.0a0",
                "python >=3.8,<3.9.0a0",
                "python_abi 3.8.* *_cp38",
            ],
        ),
        PackageInfo(
            name="pinocchio",
            version="3.2.0",
            build_string="py38hb3a1659_0",
            depends=[
                "__osx >=11.0",
                "casadi >=3.6.5,<3.7.0a0",
                "console_bridge >=1.0.2,<1.1.0a0",
                "eigen",
                "eigenpy >=3.8.0,<3.8.1.0a0",
                "hpp-fcl >=2.4.5,<2.4.6.0a0",
                "libboost >=1.86.0,<1.87.0a0",
                "libboost-python >=1.86.0,<1.87.0a0",
                "libcxx >=17",
                "llvm-openmp >=17.0.6",
                "llvm-openmp >=18.1.8",
                "numpy >=1.22.4,<2.0a0",
                "python >=3.8,<3.9.0a0",
                "python >=3.8,<3.9.0a0 *_cpython",
                "python_abi 3.8.* *_cp38",
                "qhull >=2020.2,<2020.3.0a0",
                "qhull-static",
                "urdfdom >=4.0.0,<4.1.0a0",
            ],
        ),
        PackageInfo(
            name="zlib",
            version="1.3.1",
            build_string="h8359307_2",
            depends=["__osx >=11.0", "libzlib 1.3.1 h8359307_2"],
        ),
        PackageInfo(
            name="readline", version="8.2", build_string="h1d1bf99_2", depends=["ncurses >=6.5,<7.0a0"]
        ),
        PackageInfo(
            name="libboost-python",
            version="1.86.0",
            build_string="py38he25cb4c_1",
            depends=[
                "__osx >=11.0",
                "libcxx >=16",
                "numpy >=1.22.4,<2.0a0",
                "python >=3.8,<3.9.0a0",
                "python >=3.8,<3.9.0a0 *_cpython",
                "python_abi 3.8.* *_cp38",
            ],
        ),
        PackageInfo(
            name="hpp-fcl",
            version="2.4.5",
            build_string="py38hdbe40bd_2",
            depends=[
                "__osx >=11.0",
                "assimp >=5.4.2,<5.4.3.0a0",
                "eigen",
                "eigenpy >=3.8.0,<3.8.1.0a0",
                "libboost-python >=1.86.0,<1.87.0a0",
                "libcxx >=17",
                "numpy >=1.22.4,<2.0a0",
                "octomap >=1.9.8,<1.10.0a0",
                "python >=3.8,<3.9.0a0",
                "python >=3.8,<3.9.0a0 *_cpython",
                "python_abi 3.8.* *_cp38",
                "qhull >=2020.2,<2020.3.0a0",
                "qhull-static",
            ],
        ),
        PackageInfo(name="icu", version="73.2", build_string="hc8870d7_0", depends=[]),
        PackageInfo(
            name="urdfdom",
            version="4.0.1",
            build_string="h090268e_2",
            depends=[
                "urdfdom_headers",
                "__osx >=11.0",
                "libcxx >=18",
                "tinyxml2 >=10.0.0,<10.1.0a0",
                "console_bridge >=1.0.2,<1.1.0a0",
            ],
        ),
        PackageInfo(name="libzlib", version="1.3.1", build_string="h8359307_2", depends=["__osx >=11.0"]),
        PackageInfo(
            name="python",
            version="3.8.20",
            build_string="h7d35d02_2_cpython",
            depends=[
                "__osx >=11.0",
                "bzip2 >=1.0.8,<2.0a0",
                "libffi >=3.4,<4.0a0",
                "libsqlite >=3.46.1,<4.0a0",
                "libzlib >=1.3.1,<2.0a0",
                "ncurses >=6.5,<7.0a0",
                "openssl >=3.3.2,<4.0a0",
                "readline >=8.2,<9.0a0",
                "tk >=8.6.13,<8.7.0a0",
                "xz >=5.2.6,<6.0a0",
            ],
        ),
        PackageInfo(
            name="libboost",
            version="1.86.0",
            build_string="h610977f_1",
            depends=[
                "__osx >=11.0",
                "bzip2 >=1.0.8,<2.0a0",
                "icu >=73.2,<74.0a0",
                "libcxx >=16",
                "libzlib >=1.3.1,<2.0a0",
                "xz >=5.2.6,<6.0a0",
                "zstd >=1.5.6,<1.6.0a0",
            ],
        ),
        PackageInfo(name="octomap", version="1.9.8", build_string="hffc8910_0", depends=["libcxx >=14.0.6"]),
        PackageInfo(name="liblzma", version="5.8.1", build_string="h39f12f2_2", depends=["__osx >=11.0"]),
        PackageInfo(
            name="libopenblas",
            version="0.3.25",
            build_string="openmp_h6c19121_0",
            depends=["libgfortran >=5", "libgfortran5 >=12.3.0", "llvm-openmp >=16.0.6"],
        ),
        PackageInfo(
            name="eigenpy",
            version="3.8.0",
            build_string="py38heb46f84_0",
            depends=[
                "__osx >=11.0",
                "eigen",
                "libboost-python >=1.86.0,<1.87.0a0",
                "libboost-python-devel",
                "libcxx >=13.0.1",
                "numpy >=1.22.4,<2.0a0",
                "python >=3.8,<3.9.0a0",
                "python >=3.8,<3.9.0a0 *_cpython",
                "python_abi 3.8.* *_cp38",
                "scipy",
            ],
        ),
        PackageInfo(
            name="urdfdom_headers",
            version="1.1.2",
            build_string="h7b3277c_0",
            depends=["__osx >=11.0", "libcxx >=17"],
        ),
        PackageInfo(
            name="llvm-openmp", version="20.1.7", build_string="hdb05f8b_0", depends=["__osx >=11.0"]
        ),
        PackageInfo(
            name="libblas",
            version="3.9.0",
            build_string="20_osxarm64_openblas",
            depends=["libopenblas >=0.3.25,<0.3.26.0a0", "libopenblas >=0.3.25,<1.0a0"],
        ),
        PackageInfo(
            name="tk",
            version="8.6.13",
            build_string="h892fb3f_2",
            depends=["__osx >=11.0", "libzlib >=1.3.1,<2.0a0"],
        ),
        PackageInfo(
            name="zstd",
            version="1.5.7",
            build_string="h6491c7d_2",
            depends=["__osx >=11.0", "libzlib >=1.3.1,<2.0a0"],
        ),
        PackageInfo(name="simde", version="0.8.2", build_string="h7b3277c_0", depends=["__osx >=11.0"]),
        PackageInfo(
            name="xz-tools",
            version="5.8.1",
            build_string="h39f12f2_2",
            depends=["__osx >=11.0", "liblzma 5.8.1 h39f12f2_2"],
        ),
        PackageInfo(
            name="xz",
            version="5.8.1",
            build_string="h9a6d368_2",
            depends=[
                "__osx >=11.0",
                "liblzma 5.8.1 h39f12f2_2",
                "liblzma-devel 5.8.1 h39f12f2_2",
                "xz-gpl-tools 5.8.1 h9a6d368_2",
                "xz-tools 5.8.1 h39f12f2_2",
            ],
        ),
        PackageInfo(
            name="qhull", version="2020.2", build_string="h420ef59_5", depends=["__osx >=11.0", "libcxx >=16"]
        ),
        PackageInfo(
            name="mumps-seq",
            version="5.7.3",
            build_string="h29d90bc_9",
            depends=[
                "mumps-include ==5.7.3 h8c5b6c6_9",
                "libgfortran >=5",
                "libgfortran5 >=13.2.0",
                "llvm-openmp >=18.1.8",
                "__osx >=11.0",
                "libscotch >=7.0.6,<7.0.7.0a0",
                "liblapack >=3.9.0,<4.0a0",
                "metis >=5.1.0,<5.1.1.0a0",
                "libblas >=3.9.0,<4.0a0",
            ],
        ),
        PackageInfo(name="ca-certificates", version="2025.1.31", build_string="hf0a4a13_0", depends=[]),
        PackageInfo(
            name="qhull-static",
            version="2020.2",
            build_string="h420ef59_5",
            depends=["__osx >=11.0", "libcxx >=16", "qhull 2020.2 h420ef59_5"],
        ),
        PackageInfo(name="libqdldl", version="0.1.7", build_string="hb7217d7_0", depends=["libcxx >=14.0.6"]),
        PackageInfo(name="python_abi", version="3.8", build_string="6_cp38", depends=[]),
        PackageInfo(
            name="xz-gpl-tools",
            version="5.8.1",
            build_string="h9a6d368_2",
            depends=["__osx >=11.0", "liblzma 5.8.1 h39f12f2_2"],
        ),
        PackageInfo(
            name="proxsuite",
            version="0.6.7",
            build_string="py38hfeac08a_0",
            depends=[
                "__osx >=11.0",
                "eigen",
                "libcxx >=17",
                "numpy",
                "python >=3.8,<3.9.0a0",
                "python >=3.8,<3.9.0a0 *_cpython",
                "python_abi 3.8.* *_cp38",
                "scipy",
                "simde",
            ],
        ),
        PackageInfo(
            name="liblapack",
            version="3.9.0",
            build_string="20_osxarm64_openblas",
            depends=["libblas 3.9.0 20_osxarm64_openblas"],
        ),
        PackageInfo(
            name="libscotch",
            version="7.0.6",
            build_string="he56f69b_1",
            depends=[
                "__osx >=11.0",
                "bzip2 >=1.0.8,<2.0a0",
                "libgfortran >=5",
                "libgfortran5 >=13.2.0",
                "liblzma >=5.6.3,<6.0a0",
                "libzlib >=1.3.1,<2.0a0",
            ],
        ),
    ]

    return mamba.solver.Solution([mamba.solver.Solution.Install(p) for p in packages])


def make_pyarrow_solution() -> mamba.solver.Solution:
    """Return a Solution to create an osx-arm64 pyarrow 20.0.0 environment."""
    PackageInfo = mamba.specs.PackageInfo
    Install = mamba.solver.Solution.Install

    return mamba.solver.Solution(
        [
            Install(PackageInfo(name="python_abi", version="3.13", build_string="7_cp313", depends=[])),
            Install(
                PackageInfo(
                    name="libcxx", version="20.1.6", build_string="ha82da77_0", depends=["__osx >=11.0"]
                )
            ),
            Install(
                PackageInfo(
                    name="libzlib", version="1.3.1", build_string="h8359307_2", depends=["__osx >=11.0"]
                )
            ),
            Install(
                PackageInfo(
                    name="bzip2", version="1.0.8", build_string="h99b78c6_7", depends=["__osx >=11.0"]
                )
            ),
            Install(
                PackageInfo(
                    name="libexpat", version="2.7.0", build_string="h286801f_0", depends=["__osx >=11.0"]
                )
            ),
            Install(
                PackageInfo(
                    name="libffi", version="3.4.6", build_string="h1da3d7d_1", depends=["__osx >=11.0"]
                )
            ),
            Install(
                PackageInfo(
                    name="liblzma", version="5.8.1", build_string="h39f12f2_1", depends=["__osx >=11.0"]
                )
            ),
            Install(
                PackageInfo(
                    name="libmpdec", version="4.0.0", build_string="h5505292_0", depends=["__osx >=11.0"]
                )
            ),
            Install(
                PackageInfo(
                    name="ncurses", version="6.5", build_string="h5e97a16_3", depends=["__osx >=11.0"]
                )
            ),
            Install(PackageInfo(name="tzdata", version="2025b", build_string="h78e105d_0", depends=[])),
            Install(
                PackageInfo(
                    name="libutf8proc", version="2.10.0", build_string="h74a6958_0", depends=["__osx >=11.0"]
                )
            ),
            Install(
                PackageInfo(
                    name="ca-certificates", version="2025.4.26", build_string="hbd8a1cb_0", depends=["__unix"]
                )
            ),
            Install(
                PackageInfo(
                    name="aws-c-common", version="0.12.3", build_string="h5505292_0", depends=["__osx >=11.0"]
                )
            ),
            Install(
                PackageInfo(
                    name="libbrotlicommon",
                    version="1.1.0",
                    build_string="hd74edd7_2",
                    depends=["__osx >=11.0"],
                )
            ),
            Install(
                PackageInfo(
                    name="libopentelemetry-cpp-headers",
                    version="1.21.0",
                    build_string="hce30654_0",
                    depends=[],
                )
            ),
            Install(
                PackageInfo(name="nlohmann_json", version="3.12.0", build_string="ha1acc90_0", depends=[])
            ),
            Install(
                PackageInfo(
                    name="c-ares", version="1.34.5", build_string="h5505292_0", depends=["__osx >=11.0"]
                )
            ),
            Install(PackageInfo(name="libev", version="4.33", build_string="h93a5062_2", depends=[])),
            Install(
                PackageInfo(
                    name="libiconv", version="1.18", build_string="hfe07756_1", depends=["__osx >=11.0"]
                )
            ),
            Install(
                PackageInfo(
                    name="libcrc32c", version="1.1.2", build_string="hbdafb3b_0", depends=["libcxx >=11.1.0"]
                )
            ),
            Install(
                PackageInfo(
                    name="gflags",
                    version="2.2.2",
                    build_string="hf9b8971_1005",
                    depends=["__osx >=11.0", "libcxx >=17"],
                )
            ),
            Install(
                PackageInfo(
                    name="snappy",
                    version="1.2.1",
                    build_string="h98b9ce2_1",
                    depends=["__osx >=11.0", "libcxx >=18"],
                )
            ),
            Install(
                PackageInfo(
                    name="lz4-c",
                    version="1.10.0",
                    build_string="h286801f_1",
                    depends=["__osx >=11.0", "libcxx >=18"],
                )
            ),
            Install(
                PackageInfo(
                    name="libabseil",
                    version="20250127.1",
                    build_string="cxx17_h07bc746_0",
                    depends=["__osx >=11.0", "libcxx >=18"],
                )
            ),
            Install(
                PackageInfo(
                    name="zlib",
                    version="1.3.1",
                    build_string="h8359307_2",
                    depends=["__osx >=11.0", "libzlib 1.3.1 h8359307_2"],
                )
            ),
            Install(
                PackageInfo(
                    name="zstd",
                    version="1.5.7",
                    build_string="h6491c7d_2",
                    depends=["__osx >=11.0", "libzlib >=1.3.1,<2.0a0"],
                )
            ),
            Install(
                PackageInfo(
                    name="tk",
                    version="8.6.13",
                    build_string="h892fb3f_2",
                    depends=["__osx >=11.0", "libzlib >=1.3.1,<2.0a0"],
                )
            ),
            Install(
                PackageInfo(
                    name="libsqlite",
                    version="3.50.0",
                    build_string="h3f77e49_0",
                    depends=["__osx >=11.0", "libzlib >=1.3.1,<2.0a0"],
                )
            ),
            Install(
                PackageInfo(
                    name="libedit",
                    version="3.1.20250104",
                    build_string="pl5321hafb1f1b_0",
                    depends=["ncurses", "__osx >=11.0", "ncurses >=6.5,<7.0a0"],
                )
            ),
            Install(
                PackageInfo(
                    name="readline",
                    version="8.2",
                    build_string="h1d1bf99_2",
                    depends=["ncurses >=6.5,<7.0a0"],
                )
            ),
            Install(
                PackageInfo(
                    name="openssl",
                    version="3.5.0",
                    build_string="h81ee809_1",
                    depends=["__osx >=11.0", "ca-certificates"],
                )
            ),
            Install(
                PackageInfo(
                    name="aws-c-compression",
                    version="0.3.1",
                    build_string="hca07070_5",
                    depends=["__osx >=11.0", "aws-c-common >=0.12.3,<0.12.4.0a0"],
                )
            ),
            Install(
                PackageInfo(
                    name="aws-checksums",
                    version="0.2.7",
                    build_string="hca07070_1",
                    depends=["__osx >=11.0", "aws-c-common >=0.12.3,<0.12.4.0a0"],
                )
            ),
            Install(
                PackageInfo(
                    name="aws-c-sdkutils",
                    version="0.2.4",
                    build_string="hca07070_0",
                    depends=["__osx >=11.0", "aws-c-common >=0.12.3,<0.12.4.0a0"],
                )
            ),
            Install(
                PackageInfo(
                    name="aws-c-cal",
                    version="0.9.1",
                    build_string="h03444cf_0",
                    depends=["__osx >=11.0", "aws-c-common >=0.12.3,<0.12.4.0a0"],
                )
            ),
            Install(
                PackageInfo(
                    name="libbrotlienc",
                    version="1.1.0",
                    build_string="hd74edd7_2",
                    depends=["__osx >=11.0", "libbrotlicommon 1.1.0 hd74edd7_2"],
                )
            ),
            Install(
                PackageInfo(
                    name="libbrotlidec",
                    version="1.1.0",
                    build_string="hd74edd7_2",
                    depends=["__osx >=11.0", "libbrotlicommon 1.1.0 hd74edd7_2"],
                )
            ),
            Install(
                PackageInfo(
                    name="libxml2",
                    version="2.13.8",
                    build_string="hcc23dba_0",
                    depends=[
                        "__osx >=11.0",
                        "libiconv >=1.18,<2.0a0",
                        "liblzma >=5.8.1,<6.0a0",
                        "libzlib >=1.3.1,<2.0a0",
                    ],
                )
            ),
            Install(
                PackageInfo(
                    name="glog",
                    version="0.7.1",
                    build_string="heb240a5_0",
                    depends=["__osx >=11.0", "gflags >=2.2.2,<2.3.0a0", "libcxx >=16"],
                )
            ),
            Install(
                PackageInfo(
                    name="libre2-11",
                    version="2024.07.02",
                    build_string="hd41c47c_3",
                    depends=[
                        "__osx >=11.0",
                        "libabseil * cxx17*",
                        "libabseil >=20250127.0,<20250128.0a0",
                        "libcxx >=18",
                    ],
                )
            ),
            Install(
                PackageInfo(
                    name="libprotobuf",
                    version="5.29.3",
                    build_string="hccd9074_1",
                    depends=[
                        "__osx >=11.0",
                        "libabseil * cxx17*",
                        "libabseil >=20250127.1,<20250128.0a0",
                        "libcxx >=18",
                        "libzlib >=1.3.1,<2.0a0",
                    ],
                )
            ),
            Install(
                PackageInfo(
                    name="libssh2",
                    version="1.11.1",
                    build_string="h1590b86_0",
                    depends=["libzlib >=1.3.1,<2.0a0", "openssl >=3.5.0,<4.0a0"],
                )
            ),
            Install(
                PackageInfo(
                    name="libnghttp2",
                    version="1.64.0",
                    build_string="h6d7220d_0",
                    depends=[
                        "__osx >=11.0",
                        "c-ares >=1.34.2,<2.0a0",
                        "libcxx >=17",
                        "libev >=4.33,<4.34.0a0",
                        "libev >=4.33,<5.0a0",
                        "libzlib >=1.3.1,<2.0a0",
                        "openssl >=3.3.2,<4.0a0",
                    ],
                )
            ),
            Install(
                PackageInfo(
                    name="krb5",
                    version="1.21.3",
                    build_string="h237132a_0",
                    depends=[
                        "__osx >=11.0",
                        "libcxx >=16",
                        "libedit >=3.1.20191231,<3.2.0a0",
                        "libedit >=3.1.20191231,<4.0a0",
                        "openssl >=3.3.1,<4.0a0",
                    ],
                )
            ),
            Install(
                PackageInfo(
                    name="libevent",
                    version="2.1.12",
                    build_string="h2757513_1",
                    depends=["openssl >=3.1.1,<4.0a0"],
                )
            ),
            Install(
                PackageInfo(
                    name="python",
                    version="3.13.3",
                    build_string="h81fe080_101_cp313",
                    depends=[
                        "__osx >=11.0",
                        "bzip2 >=1.0.8,<2.0a0",
                        "libexpat >=2.7.0,<3.0a0",
                        "libffi >=3.4.6,<3.5.0a0",
                        "liblzma >=5.8.1,<6.0a0",
                        "libmpdec >=4.0.0,<5.0a0",
                        "libsqlite >=3.49.1,<4.0a0",
                        "libzlib >=1.3.1,<2.0a0",
                        "ncurses >=6.5,<7.0a0",
                        "openssl >=3.5.0,<4.0a0",
                        "python_abi 3.13.* *_cp313",
                        "readline >=8.2,<9.0a0",
                        "tk >=8.6.13,<8.7.0a0",
                        "tzdata",
                    ],
                )
            ),
            Install(
                PackageInfo(
                    name="aws-c-io",
                    version="0.19.1",
                    build_string="h465c264_3",
                    depends=[
                        "__osx >=11.0",
                        "aws-c-cal >=0.9.1,<0.9.2.0a0",
                        "aws-c-common >=0.12.3,<0.12.4.0a0",
                    ],
                )
            ),
            Install(
                PackageInfo(
                    name="re2",
                    version="2024.07.02",
                    build_string="h6589ca4_3",
                    depends=["libre2-11 2024.07.02 hd41c47c_3"],
                )
            ),
            Install(
                PackageInfo(
                    name="orc",
                    version="2.1.2",
                    build_string="hd90e43c_0",
                    depends=[
                        "__osx >=11.0",
                        "libcxx >=18",
                        "libprotobuf >=5.29.3,<5.29.4.0a0",
                        "libzlib >=1.3.1,<2.0a0",
                        "lz4-c >=1.10.0,<1.11.0a0",
                        "snappy >=1.2.1,<1.3.0a0",
                        "tzdata",
                        "zstd >=1.5.7,<1.6.0a0",
                    ],
                )
            ),
            Install(
                PackageInfo(
                    name="libcurl",
                    version="8.14.1",
                    build_string="h73640d1_0",
                    depends=[
                        "__osx >=11.0",
                        "krb5 >=1.21.3,<1.22.0a0",
                        "libnghttp2 >=1.64.0,<2.0a0",
                        "libssh2 >=1.11.1,<2.0a0",
                        "libzlib >=1.3.1,<2.0a0",
                        "openssl >=3.5.0,<4.0a0",
                        "zstd >=1.5.7,<1.6.0a0",
                    ],
                )
            ),
            Install(
                PackageInfo(
                    name="libthrift",
                    version="0.21.0",
                    build_string="h64651cc_0",
                    depends=[
                        "__osx >=11.0",
                        "libcxx >=17",
                        "libevent >=2.1.12,<2.1.13.0a0",
                        "libzlib >=1.3.1,<2.0a0",
                        "openssl >=3.3.2,<4.0a0",
                    ],
                )
            ),
            Install(
                PackageInfo(
                    name="aws-c-http",
                    version="0.10.1",
                    build_string="hd6e4345_3",
                    depends=[
                        "__osx >=11.0",
                        "aws-c-io >=0.19.1,<0.19.2.0a0",
                        "aws-c-common >=0.12.3,<0.12.4.0a0",
                        "aws-c-compression >=0.3.1,<0.3.2.0a0",
                        "aws-c-cal >=0.9.1,<0.9.2.0a0",
                    ],
                )
            ),
            Install(
                PackageInfo(
                    name="aws-c-event-stream",
                    version="0.5.4",
                    build_string="hb369d5e_10",
                    depends=[
                        "__osx >=11.0",
                        "libcxx >=18",
                        "aws-c-io >=0.19.1,<0.19.2.0a0",
                        "aws-checksums >=0.2.7,<0.2.8.0a0",
                        "aws-c-common >=0.12.3,<0.12.4.0a0",
                    ],
                )
            ),
            Install(
                PackageInfo(
                    name="libgrpc",
                    version="1.71.0",
                    build_string="h857da87_1",
                    depends=[
                        "__osx >=11.0",
                        "c-ares >=1.34.5,<2.0a0",
                        "libabseil * cxx17*",
                        "libabseil >=20250127.1,<20250128.0a0",
                        "libcxx >=18",
                        "libprotobuf >=5.29.3,<5.29.4.0a0",
                        "libre2-11 >=2024.7.2",
                        "libzlib >=1.3.1,<2.0a0",
                        "openssl >=3.5.0,<4.0a0",
                        "re2",
                    ],
                )
            ),
            Install(
                PackageInfo(
                    name="prometheus-cpp",
                    version="1.3.0",
                    build_string="h0967b3e_0",
                    depends=[
                        "__osx >=11.0",
                        "libcurl >=8.10.1,<9.0a0",
                        "libcxx >=18",
                        "libzlib >=1.3.1,<2.0a0",
                        "zlib",
                    ],
                )
            ),
            Install(
                PackageInfo(
                    name="azure-core-cpp",
                    version="1.14.0",
                    build_string="hd50102c_0",
                    depends=[
                        "__osx >=11.0",
                        "libcurl >=8.10.1,<9.0a0",
                        "libcxx >=17",
                        "openssl >=3.3.2,<4.0a0",
                    ],
                )
            ),
            Install(
                PackageInfo(
                    name="aws-c-mqtt",
                    version="0.13.1",
                    build_string="h8e407d2_0",
                    depends=[
                        "__osx >=11.0",
                        "aws-c-io >=0.19.1,<0.19.2.0a0",
                        "aws-c-common >=0.12.3,<0.12.4.0a0",
                        "aws-c-http >=0.10.1,<0.10.2.0a0",
                    ],
                )
            ),
            Install(
                PackageInfo(
                    name="aws-c-auth",
                    version="0.9.0",
                    build_string="heec1a4a_10",
                    depends=[
                        "__osx >=11.0",
                        "aws-c-cal >=0.9.1,<0.9.2.0a0",
                        "aws-c-common >=0.12.3,<0.12.4.0a0",
                        "aws-c-http >=0.10.1,<0.10.2.0a0",
                        "aws-c-io >=0.19.1,<0.19.2.0a0",
                        "aws-c-sdkutils >=0.2.4,<0.2.5.0a0",
                    ],
                )
            ),
            Install(
                PackageInfo(
                    name="libgoogle-cloud",
                    version="2.36.0",
                    build_string="h9484b08_1",
                    depends=[
                        "__osx >=11.0",
                        "libabseil * cxx17*",
                        "libabseil >=20250127.0,<20250128.0a0",
                        "libcurl >=8.12.1,<9.0a0",
                        "libcxx >=18",
                        "libgrpc >=1.71.0,<1.72.0a0",
                        "libprotobuf >=5.29.3,<5.29.4.0a0",
                        "openssl >=3.4.1,<4.0a0",
                    ],
                )
            ),
            Install(
                PackageInfo(
                    name="libopentelemetry-cpp",
                    version="1.21.0",
                    build_string="h0181452_0",
                    depends=[
                        "libabseil * cxx17*",
                        "libabseil >=20250127.1,<20250128.0a0",
                        "libcurl >=8.14.0,<9.0a0",
                        "libgrpc >=1.71.0,<1.72.0a0",
                        "libopentelemetry-cpp-headers 1.21.0 hce30654_0",
                        "libprotobuf >=5.29.3,<5.29.4.0a0",
                        "libzlib >=1.3.1,<2.0a0",
                        "nlohmann_json",
                        "prometheus-cpp >=1.3.0,<1.4.0a0",
                    ],
                )
            ),
            Install(
                PackageInfo(
                    name="azure-storage-common-cpp",
                    version="12.8.0",
                    build_string="h9ca1f76_1",
                    depends=[
                        "__osx >=11.0",
                        "azure-core-cpp >=1.14.0,<1.14.1.0a0",
                        "libcxx >=17",
                        "libxml2 >=2.12.7,<2.14.0a0",
                        "openssl >=3.3.2,<4.0a0",
                    ],
                )
            ),
            Install(
                PackageInfo(
                    name="azure-identity-cpp",
                    version="1.10.0",
                    build_string="hc602bab_0",
                    depends=[
                        "__osx >=11.0",
                        "azure-core-cpp >=1.14.0,<1.14.1.0a0",
                        "libcxx >=17",
                        "openssl >=3.3.2,<4.0a0",
                    ],
                )
            ),
            Install(
                PackageInfo(
                    name="aws-c-s3",
                    version="0.8.0",
                    build_string="h0bc1dd9_1",
                    depends=[
                        "__osx >=11.0",
                        "aws-c-common >=0.12.3,<0.12.4.0a0",
                        "aws-c-http >=0.10.1,<0.10.2.0a0",
                        "aws-c-cal >=0.9.1,<0.9.2.0a0",
                        "aws-c-auth >=0.9.0,<0.9.1.0a0",
                        "aws-checksums >=0.2.7,<0.2.8.0a0",
                        "aws-c-io >=0.19.1,<0.19.2.0a0",
                    ],
                )
            ),
            Install(
                PackageInfo(
                    name="libgoogle-cloud-storage",
                    version="2.36.0",
                    build_string="h7081f7f_1",
                    depends=[
                        "__osx >=11.0",
                        "libabseil",
                        "libcrc32c >=1.1.2,<1.2.0a0",
                        "libcurl",
                        "libcxx >=18",
                        "libgoogle-cloud 2.36.0 h9484b08_1",
                        "libzlib >=1.3.1,<2.0a0",
                        "openssl",
                    ],
                )
            ),
            Install(
                PackageInfo(
                    name="azure-storage-blobs-cpp",
                    version="12.13.0",
                    build_string="h7585a09_1",
                    depends=[
                        "__osx >=11.0",
                        "azure-core-cpp >=1.14.0,<1.14.1.0a0",
                        "azure-storage-common-cpp >=12.8.0,<12.8.1.0a0",
                        "libcxx >=17",
                    ],
                )
            ),
            Install(
                PackageInfo(
                    name="aws-crt-cpp",
                    version="0.32.8",
                    build_string="hd1dc5eb_1",
                    depends=[
                        "__osx >=11.0",
                        "libcxx >=18",
                        "aws-c-sdkutils >=0.2.4,<0.2.5.0a0",
                        "aws-c-event-stream >=0.5.4,<0.5.5.0a0",
                        "aws-c-cal >=0.9.1,<0.9.2.0a0",
                        "aws-c-io >=0.19.1,<0.19.2.0a0",
                        "aws-c-s3 >=0.8.0,<0.8.1.0a0",
                        "aws-c-mqtt >=0.13.1,<0.13.2.0a0",
                        "aws-c-http >=0.10.1,<0.10.2.0a0",
                        "aws-c-common >=0.12.3,<0.12.4.0a0",
                        "aws-c-auth >=0.9.0,<0.9.1.0a0",
                    ],
                )
            ),
            Install(
                PackageInfo(
                    name="azure-storage-files-datalake-cpp",
                    version="12.12.0",
                    build_string="hcdd55da_1",
                    depends=[
                        "__osx >=11.0",
                        "azure-core-cpp >=1.14.0,<1.14.1.0a0",
                        "azure-storage-blobs-cpp >=12.13.0,<12.13.1.0a0",
                        "azure-storage-common-cpp >=12.8.0,<12.8.1.0a0",
                        "libcxx >=17",
                    ],
                )
            ),
            Install(
                PackageInfo(
                    name="aws-sdk-cpp",
                    version="1.11.510",
                    build_string="h8888cfc_10",
                    depends=[
                        "__osx >=11.0",
                        "libcxx >=18",
                        "aws-c-common >=0.12.3,<0.12.4.0a0",
                        "aws-c-event-stream >=0.5.4,<0.5.5.0a0",
                        "libcurl >=8.14.0,<9.0a0",
                        "aws-crt-cpp >=0.32.8,<0.32.9.0a0",
                        "libzlib >=1.3.1,<2.0a0",
                    ],
                )
            ),
            Install(
                PackageInfo(
                    name="libarrow",
                    version="20.0.0",
                    build_string="h76b72fb_6_cpu",
                    depends=[
                        "__osx >=11.0",
                        "aws-crt-cpp >=0.32.8,<0.32.9.0a0",
                        "aws-sdk-cpp >=1.11.510,<1.11.511.0a0",
                        "azure-core-cpp >=1.14.0,<1.14.1.0a0",
                        "azure-identity-cpp >=1.10.0,<1.10.1.0a0",
                        "azure-storage-blobs-cpp >=12.13.0,<12.13.1.0a0",
                        "azure-storage-files-datalake-cpp >=12.12.0,<12.12.1.0a0",
                        "bzip2 >=1.0.8,<2.0a0",
                        "glog >=0.7.1,<0.8.0a0",
                        "libabseil * cxx17*",
                        "libabseil >=20250127.1,<20250128.0a0",
                        "libbrotlidec >=1.1.0,<1.2.0a0",
                        "libbrotlienc >=1.1.0,<1.2.0a0",
                        "libcxx >=18",
                        "libgoogle-cloud >=2.36.0,<2.37.0a0",
                        "libgoogle-cloud-storage >=2.36.0,<2.37.0a0",
                        "libopentelemetry-cpp >=1.21.0,<1.22.0a0",
                        "libprotobuf >=5.29.3,<5.29.4.0a0",
                        "libre2-11 >=2024.7.2",
                        "libutf8proc >=2.10.0,<2.11.0a0",
                        "libzlib >=1.3.1,<2.0a0",
                        "lz4-c >=1.10.0,<1.11.0a0",
                        "orc >=2.1.2,<2.1.3.0a0",
                        "re2",
                        "snappy >=1.2.1,<1.3.0a0",
                        "zstd >=1.5.7,<1.6.0a0",
                    ],
                )
            ),
            Install(
                PackageInfo(
                    name="pyarrow-core",
                    version="20.0.0",
                    build_string="py313hf9431ad_0_cpu",
                    depends=[
                        "__osx >=11.0",
                        "libarrow 20.0.0.* *cpu",
                        "libcxx >=18",
                        "libzlib >=1.3.1,<2.0a0",
                        "python >=3.13,<3.14.0a0",
                        "python >=3.13,<3.14.0a0 *_cp313",
                        "python_abi 3.13.* *_cp313",
                    ],
                )
            ),
            Install(
                PackageInfo(
                    name="libparquet",
                    version="20.0.0",
                    build_string="h636d7b7_6_cpu",
                    depends=[
                        "__osx >=11.0",
                        "libarrow 20.0.0 h76b72fb_6_cpu",
                        "libcxx >=18",
                        "libthrift >=0.21.0,<0.21.1.0a0",
                        "openssl >=3.5.0,<4.0a0",
                    ],
                )
            ),
            Install(
                PackageInfo(
                    name="libarrow-acero",
                    version="20.0.0",
                    build_string="hf07054f_6_cpu",
                    depends=["__osx >=11.0", "libarrow 20.0.0 h76b72fb_6_cpu", "libcxx >=18"],
                )
            ),
            Install(
                PackageInfo(
                    name="libarrow-dataset",
                    version="20.0.0",
                    build_string="hf07054f_6_cpu",
                    depends=[
                        "__osx >=11.0",
                        "libarrow 20.0.0 h76b72fb_6_cpu",
                        "libarrow-acero 20.0.0 hf07054f_6_cpu",
                        "libcxx >=18",
                        "libparquet 20.0.0 h636d7b7_6_cpu",
                    ],
                )
            ),
            Install(
                PackageInfo(
                    name="libarrow-substrait",
                    version="20.0.0",
                    build_string="he749cb8_6_cpu",
                    depends=[
                        "__osx >=11.0",
                        "libabseil * cxx17*",
                        "libabseil >=20250127.1,<20250128.0a0",
                        "libarrow 20.0.0 h76b72fb_6_cpu",
                        "libarrow-acero 20.0.0 hf07054f_6_cpu",
                        "libarrow-dataset 20.0.0 hf07054f_6_cpu",
                        "libcxx >=18",
                        "libprotobuf >=5.29.3,<5.29.4.0a0",
                    ],
                )
            ),
            Install(
                PackageInfo(
                    name="pyarrow",
                    version="20.0.0",
                    build_string="py313h39782a4_0",
                    depends=[
                        "libarrow-acero 20.0.0.*",
                        "libarrow-dataset 20.0.0.*",
                        "libarrow-substrait 20.0.0.*",
                        "libparquet 20.0.0.*",
                        "pyarrow-core 20.0.0 *_0_*",
                        "python >=3.13,<3.14.0a0",
                        "python_abi 3.13.* *_cp313",
                    ],
                )
            ),
        ]
    )
