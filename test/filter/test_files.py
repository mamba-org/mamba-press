from pathlib import PurePath

import mamba_press


def test_glob_file_filter() -> None:
    """Files are excluded if they match any pattern."""
    filter = mamba_press.filter.UnixFilesFilter(["*/bar/*.txt", "*.hpp"])

    assert filter.filter_file(PurePath("bar.txt"))
    assert filter.filter_file(PurePath("bar/baz.txt"))
    assert filter.filter_file(PurePath("file.hpp.in"))

    assert not filter.filter_file(PurePath("foo/bar/baz.txt"))
    assert not filter.filter_file(PurePath("the/foo/bar/baz.txt"))
    assert not filter.filter_file(PurePath("the/foo/bar/baz.txt"))
    assert not filter.filter_file(PurePath("file.hpp"))
    assert not filter.filter_file(PurePath("folder/file.hpp"))


def test_glob_file_filter_include() -> None:
    """Files are included if they match any pattern."""
    filter = mamba_press.filter.UnixFilesFilter(["*/bar/*.txt", "*.hpp"], exclude=False)

    assert not filter.filter_file(PurePath("bar.txt"))
    assert not filter.filter_file(PurePath("bar/baz.txt"))
    assert not filter.filter_file(PurePath("file.hpp.in"))

    assert filter.filter_file(PurePath("foo/bar/baz.txt"))
    assert filter.filter_file(PurePath("the/foo/bar/baz.txt"))
    assert filter.filter_file(PurePath("the/foo/bar/baz.txt"))
    assert filter.filter_file(PurePath("file.hpp"))
    assert filter.filter_file(PurePath("folder/file.hpp"))
