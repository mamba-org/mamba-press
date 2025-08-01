import unittest.mock as mock
from pathlib import PurePath

import mamba_press


def test_unix_filter_from_config() -> None:
    """Can be created from a dictionary."""
    filter = mamba_press.filter.UnixFilesFilter.from_config(
        {"patterns": ["file.py", "dir/bar"]},
        source=mock.MagicMock(),
    )

    assert len(filter.patterns) == 2
    assert str(filter.patterns[1]) == "dir/bar"
    assert filter.exclude


def test_unix_file_filter() -> None:
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


def test_unix_file_filter_include() -> None:
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


def test_combined_filter() -> None:
    """Combined filter apply all filters."""
    filter1 = mamba_press.filter.UnixFilesFilter(["lib/*"], exclude=False)
    filter2 = mamba_press.filter.UnixFilesFilter(["lib/python/*"], exclude=False)

    combined_all = mamba_press.filter.CombinedFilesFilter([filter1, filter2], all=True)
    assert combined_all.filter_file(PurePath("lib/python/bar.py"))
    assert not combined_all.filter_file(PurePath("lib/bar.so"))
    assert not combined_all.filter_file(PurePath("baz.txt"))

    combined_any = mamba_press.filter.CombinedFilesFilter([filter1, filter2], all=False)
    assert combined_any.filter_file(PurePath("lib/python/bar.py"))
    assert combined_any.filter_file(PurePath("lib/bar.so"))
    assert not combined_any.filter_file(PurePath("baz.txt"))
