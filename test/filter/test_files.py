import mamba_press


def test_glob_file_filter():
    """Files are excluded if they match any pattern."""
    filter = mamba_press.filter.UnixFilesFilter(["*/bar/*.txt", "*.hpp"])

    assert filter.filter_file("bar.txt")
    assert filter.filter_file("bar/baz.txt")
    assert filter.filter_file("file.hpp.in")

    assert not filter.filter_file("foo/bar/baz.txt")
    assert not filter.filter_file("the/foo/bar/baz.txt")
    assert not filter.filter_file("the/foo/bar/baz.txt")
    assert not filter.filter_file("file.hpp")
    assert not filter.filter_file("folder/file.hpp")


def test_glob_file_filter_include():
    """Files are included if they match any pattern."""
    filter = mamba_press.filter.UnixFilesFilter(["*/bar/*.txt", "*.hpp"], exclude=False)

    assert not filter.filter_file("bar.txt")
    assert not filter.filter_file("bar/baz.txt")
    assert not filter.filter_file("file.hpp.in")

    assert filter.filter_file("foo/bar/baz.txt")
    assert filter.filter_file("the/foo/bar/baz.txt")
    assert filter.filter_file("the/foo/bar/baz.txt")
    assert filter.filter_file("file.hpp")
    assert filter.filter_file("folder/file.hpp")
