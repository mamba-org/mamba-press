import mamba_press


def test_glob_file_filter():
    """Files are excluded if they match any pattern."""
    filter = mamba_press.filter.UnixFilesFilter(["*/bar/*.txt", "*.hpp"])

    assert next(filter.filter_files(["bar.txt"]), None) is not None
    assert next(filter.filter_files(["bar/baz.txt"]), None) is not None
    assert next(filter.filter_files(["file.hpp.in"]), None) is not None

    assert next(filter.filter_files(["foo/bar/baz.txt"]), None) is None
    assert next(filter.filter_files(["the/foo/bar/baz.txt"]), None) is None
    assert next(filter.filter_files(["the/foo/bar/baz.txt"]), None) is None
    assert next(filter.filter_files(["file.hpp"]), None) is None
    assert next(filter.filter_files(["folder/file.hpp"]), None) is None


def test_glob_file_filter_include():
    """Files are included if they match any pattern."""
    filter = mamba_press.filter.UnixFilesFilter(["*/bar/*.txt", "*.hpp"], exclude=False)

    assert next(filter.filter_files(["bar.txt"]), None) is None
    assert next(filter.filter_files(["bar/baz.txt"]), None) is None
    assert next(filter.filter_files(["file.hpp.in"]), None) is None

    assert next(filter.filter_files(["foo/bar/baz.txt"]), None) is not None
    assert next(filter.filter_files(["the/foo/bar/baz.txt"]), None) is not None
    assert next(filter.filter_files(["the/foo/bar/baz.txt"]), None) is not None
    assert next(filter.filter_files(["file.hpp"]), None) is not None
    assert next(filter.filter_files(["folder/file.hpp"]), None) is not None
