import io

from mamba_press.wheel import Metadata, Wheel


def test_wheel_basic_construction() -> None:
    """Test basic dataclass construction."""
    wheel_meta = Wheel(
        wheel_version="1.0",
        generator="bdist_wheel (0.37.1)",
        root_is_purelib=True,
        tag=["py3-none-any"],
    )

    assert wheel_meta.wheel_version == "1.0"
    assert wheel_meta.generator == "bdist_wheel (0.37.1)"
    assert wheel_meta.root_is_purelib is True
    assert wheel_meta.tag == ["py3-none-any"]
    assert wheel_meta.build is None


def test_wheel_construction_with_build() -> None:
    """Test construction with optional build field."""
    wheel_meta = Wheel(
        wheel_version="1.0",
        generator="bdist_wheel (0.37.1)",
        root_is_purelib=False,
        tag=["cp39-cp39-linux_x86_64"],
        build="123",
    )

    assert wheel_meta.build == "123"


def test_wheel_from_wheel_file_basic() -> None:
    """Test parsing basic WHEEL file content."""
    content = "Wheel-Version: 1.0\nGenerator: bdist_wheel (0.37.1)\nRoot-Is-Purelib: true\nTag: py3-none-any"

    wheel_meta = Wheel.from_wheel_file(content)

    assert wheel_meta.wheel_version == "1.0"
    assert wheel_meta.generator == "bdist_wheel (0.37.1)"
    assert wheel_meta.root_is_purelib is True
    assert wheel_meta.tag == ["py3-none-any"]
    assert wheel_meta.build is None


def test_wheel_from_wheel_file_with_build() -> None:
    """Test parsing WHEEL file with build number."""
    content = (
        "Wheel-Version: 1.0\n"
        "Generator: bdist_wheel (0.37.1)\n"
        "Root-Is-Purelib: false\n"
        "Tag: cp39-cp39-linux_x86_64\n"
        "Build: 123"
    )

    wheel_meta = Wheel.from_wheel_file(content)

    assert wheel_meta.wheel_version == "1.0"
    assert wheel_meta.generator == "bdist_wheel (0.37.1)"
    assert wheel_meta.root_is_purelib is False
    assert wheel_meta.tag == ["cp39-cp39-linux_x86_64"]
    assert wheel_meta.build == "123"


def test_wheel_from_wheel_file_multiple_tags() -> None:
    """Test parsing WHEEL file with multiple tags."""
    content = (
        "Wheel-Version: 1.0\n"
        "Generator: bdist_wheel (0.37.1)\n"
        "Root-Is-Purelib: true\n"
        "Tag: py2-none-any\n"
        "Tag: py3-none-any\n"
        "Tag: cp39-none-any"
    )

    wheel_meta = Wheel.from_wheel_file(content)

    assert wheel_meta.tag == ["py2-none-any", "py3-none-any", "cp39-none-any"]


def test_wheel_from_wheel_file_case_insensitive() -> None:
    """Test that parsing is case insensitive for boolean values."""
    content = "Wheel-Version: 1.0\nGenerator: bdist_wheel (0.37.1)\nRoot-Is-Purelib: TRUE\nTag: py3-none-any"

    wheel_meta = Wheel.from_wheel_file(content)
    assert wheel_meta.root_is_purelib is True

    content_false = (
        "Wheel-Version: 1.0\nGenerator: bdist_wheel (0.37.1)\nRoot-Is-Purelib: FALSE\nTag: py3-none-any"
    )

    wheel_meta_false = Wheel.from_wheel_file(content_false)
    assert wheel_meta_false.root_is_purelib is False


def test_wheel_from_wheel_file_extra_whitespace() -> None:
    """Test parsing with extra whitespace around values."""
    content = (
        "Wheel-Version:   1.0   \n"
        "Generator:  bdist_wheel (0.37.1)  \n"
        "Root-Is-Purelib:  true  \n"
        "Tag:  py3-none-any  "
    )

    wheel_meta = Wheel.from_wheel_file(content)

    assert wheel_meta.wheel_version == "1.0"
    assert wheel_meta.generator == "bdist_wheel (0.37.1)"
    assert wheel_meta.root_is_purelib is True
    assert wheel_meta.tag == ["py3-none-any"]


def test_wheel_from_wheel_file_empty_lines() -> None:
    """Test parsing with empty lines."""
    content = (
        "Wheel-Version: 1.0\n"
        "\n"
        "Generator: bdist_wheel (0.37.1)\n"
        "\n"
        "Root-Is-Purelib: true\n"
        "Tag: py3-none-any\n"
        "\n"
    )

    wheel_meta = Wheel.from_wheel_file(content)

    assert wheel_meta.wheel_version == "1.0"
    assert wheel_meta.generator == "bdist_wheel (0.37.1)"
    assert wheel_meta.root_is_purelib is True
    assert wheel_meta.tag == ["py3-none-any"]


def test_wheel_read_from_io() -> None:
    """Test reading from a TextIO stream."""
    content = "Wheel-Version: 1.0\nGenerator: bdist_wheel (0.37.1)\nRoot-Is-Purelib: true\nTag: py3-none-any"

    with io.StringIO(content) as f:
        wheel_meta = Wheel.read(f)

    assert wheel_meta.wheel_version == "1.0"
    assert wheel_meta.generator == "bdist_wheel (0.37.1)"
    assert wheel_meta.root_is_purelib is True
    assert wheel_meta.tag == ["py3-none-any"]


def test_wheel_to_wheel_file_basic() -> None:
    """Test converting to WHEEL file format."""
    wheel_meta = Wheel(
        wheel_version="1.0",
        generator="bdist_wheel (0.37.1)",
        root_is_purelib=True,
        tag=["py3-none-any"],
    )

    result = wheel_meta.to_wheel_file()
    expected = (
        "Wheel-Version: 1.0\nGenerator: bdist_wheel (0.37.1)\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    )

    assert result == expected


def test_wheel_to_wheel_file_with_build() -> None:
    """Test converting to WHEEL file format with build."""
    wheel_meta = Wheel(
        wheel_version="1.0",
        generator="bdist_wheel (0.37.1)",
        root_is_purelib=False,
        tag=["cp39-cp39-linux_x86_64"],
        build="123",
    )

    result = wheel_meta.to_wheel_file()
    expected = (
        "Wheel-Version: 1.0\n"
        "Generator: bdist_wheel (0.37.1)\n"
        "Root-Is-Purelib: false\n"
        "Tag: cp39-cp39-linux_x86_64\n"
        "Build: 123\n"
    )

    assert result == expected


def test_wheel_to_wheel_file_multiple_tags() -> None:
    """Test converting to WHEEL file format with multiple tags."""
    wheel_meta = Wheel(
        wheel_version="1.0",
        generator="bdist_wheel (0.37.1)",
        root_is_purelib=True,
        tag=["py2-none-any", "py3-none-any", "cp39-none-any"],
    )

    result = wheel_meta.to_wheel_file()
    expected = (
        "Wheel-Version: 1.0\n"
        "Generator: bdist_wheel (0.37.1)\n"
        "Root-Is-Purelib: true\n"
        "Tag: py2-none-any\n"
        "Tag: py3-none-any\n"
        "Tag: cp39-none-any\n"
    )

    assert result == expected


def test_wheel_write_to_io() -> None:
    """Test writing to a TextIO stream."""
    wheel_meta = Wheel(
        wheel_version="1.0",
        generator="bdist_wheel (0.37.1)",
        root_is_purelib=True,
        tag=["py3-none-any"],
    )

    output = io.StringIO()
    wheel_meta.write(output)
    result = output.getvalue()

    expected = (
        "Wheel-Version: 1.0\nGenerator: bdist_wheel (0.37.1)\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    )

    assert result == expected


def test_wheel_roundtrip_conversion() -> None:
    """Test that parsing and converting back preserves data."""
    original_content = (
        "Wheel-Version: 1.0\n"
        "Generator: bdist_wheel (0.37.1)\n"
        "Root-Is-Purelib: false\n"
        "Tag: cp39-cp39-linux_x86_64\n"
        "Tag: cp39-cp39-win_amd64\n"
        "Build: 123\n"
    )

    # Parse and convert back
    wheel_meta = Wheel.from_wheel_file(original_content)
    result = wheel_meta.to_wheel_file()

    # Parse again to compare structure
    wheel_meta2 = Wheel.from_wheel_file(result)

    assert wheel_meta == wheel_meta2


def test_wheel_missing_fields_defaults() -> None:
    """Test behavior with missing fields."""
    content = "Wheel-Version: 1.0"

    wheel_meta = Wheel.from_wheel_file(content)

    assert wheel_meta.wheel_version == "1.0"
    assert wheel_meta.generator == ""
    assert wheel_meta.root_is_purelib is False  # Default for missing field
    assert wheel_meta.tag == []
    assert wheel_meta.build is None


def test_wheel_invalid_format_lines() -> None:
    """Test handling of lines without colons."""
    content = (
        "Wheel-Version: 1.0\n"
        "Generator: bdist_wheel (0.37.1)\n"
        "Invalid line without colon\n"
        "Root-Is-Purelib: true\n"
        "Tag: py3-none-any"
    )

    wheel_meta = Wheel.from_wheel_file(content)

    # Should parse successfully, ignoring invalid line
    assert wheel_meta.wheel_version == "1.0"
    assert wheel_meta.generator == "bdist_wheel (0.37.1)"
    assert wheel_meta.root_is_purelib is True
    assert wheel_meta.tag == ["py3-none-any"]


def test_wheel_empty_content() -> None:
    """Test parsing empty content."""
    wheel_meta = Wheel.from_wheel_file("")

    assert wheel_meta.wheel_version == ""
    assert wheel_meta.generator == ""
    assert wheel_meta.root_is_purelib is False
    assert wheel_meta.tag == []
    assert wheel_meta.build is None


def test_wheel_value_with_colons() -> None:
    """Test parsing values that contain colons."""
    content = (
        "Wheel-Version: 1.0\n"
        "Generator: bdist_wheel (0.37.1): special edition\n"
        "Root-Is-Purelib: true\n"
        "Tag: py3-none-any"
    )

    wheel_meta = Wheel.from_wheel_file(content)

    assert wheel_meta.generator == "bdist_wheel (0.37.1): special edition"


def test_metadata_basic_construction() -> None:
    """Test basic dataclass construction."""
    metadata = Metadata(
        metadata_version="2.1",
        name="example-package",
        version="1.0.0",
    )

    assert metadata.metadata_version == "2.1"
    assert metadata.name == "example-package"
    assert metadata.version == "1.0.0"
    assert metadata.summary is None
    assert metadata.classifier == []


def test_metadata_construction_with_optional_fields() -> None:
    """Test construction with optional fields."""
    metadata = Metadata(
        metadata_version="2.1",
        name="example-package",
        version="1.0.0",
        summary="A test package",
        author="Test Author",
        classifier=["Development Status :: 4 - Beta", "Programming Language :: Python :: 3"],
    )

    assert metadata.summary == "A test package"
    assert metadata.author == "Test Author"
    assert metadata.classifier == ["Development Status :: 4 - Beta", "Programming Language :: Python :: 3"]


def test_metadata_from_metadata_file_basic() -> None:
    """Test parsing basic METADATA file content."""
    content = (
        "Metadata-Version: 2.1\n"
        "Name: example-package\n"
        "Version: 1.0.0\n"
        "Summary: A simple test package\n"
        "Author: John Doe"
    )

    metadata = Metadata.from_metadata_file(content)

    assert metadata.metadata_version == "2.1"
    assert metadata.name == "example-package"
    assert metadata.version == "1.0.0"
    assert metadata.summary == "A simple test package"
    assert metadata.author == "John Doe"
    assert metadata.description is None


def test_metadata_from_metadata_file_with_empty_fields() -> None:
    """Test parsing METADATA file with explicitly empty fields."""
    content = "Metadata-Version: 2.1\nName: example-package\nVersion: 1.0.0\nSummary:\nAuthor: John Doe"

    metadata = Metadata.from_metadata_file(content)

    assert metadata.summary == ""  # Empty string, not None
    assert metadata.description is None  # Not provided


def test_metadata_from_metadata_file_with_classifiers() -> None:
    """Test parsing METADATA file with multiple classifiers."""
    content = (
        "Metadata-Version: 2.1\n"
        "Name: example-package\n"
        "Version: 1.0.0\n"
        "Classifier: Development Status :: 4 - Beta\n"
        "Classifier: Programming Language :: Python :: 3\n"
        "Classifier: License :: OSI Approved :: MIT License"
    )

    metadata = Metadata.from_metadata_file(content)

    assert metadata.classifier == [
        "Development Status :: 4 - Beta",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
    ]


def test_metadata_from_metadata_file_with_requires_dist() -> None:
    """Test parsing METADATA file with requirements."""
    content = (
        "Metadata-Version: 2.1\n"
        "Name: example-package\n"
        "Version: 1.0.0\n"
        "Requires-Dist: requests >= 2.20.0\n"
        "Requires-Dist: click >= 7.0\n"
        "Requires-Dist: pytest ; extra == 'test'"
    )

    metadata = Metadata.from_metadata_file(content)

    assert metadata.requires_dist == ["requests >= 2.20.0", "click >= 7.0", "pytest ; extra == 'test'"]


def test_metadata_from_metadata_file_with_multiline_description() -> None:
    """Test parsing METADATA file with multi-line description."""
    content = (
        "Metadata-Version: 2.1\n"
        "Name: example-package\n"
        "Version: 1.0.0\n"
        "Description:\n"
        "        This is a longer description\n"
        "        that spans multiple lines.\n"
        "\n"
        "        It can have empty lines too."
    )

    metadata = Metadata.from_metadata_file(content)

    expected_description = (
        "        This is a longer description\n"
        "        that spans multiple lines.\n"
        "\n"
        "        It can have empty lines too."
    )
    assert metadata.description == expected_description


def test_metadata_from_metadata_file_case_insensitive_fields() -> None:
    """Test that field names are case insensitive and handle dashes."""
    content = (
        "Metadata-Version: 2.1\n"
        "Name: example-package\n"
        "Version: 1.0.0\n"
        "Home-Page: https://example.com\n"
        "Author-Email: author@example.com\n"
        "Requires-Python: >=3.8"
    )

    metadata = Metadata.from_metadata_file(content)

    assert metadata.home_page == "https://example.com"
    assert metadata.author_email == "author@example.com"
    assert metadata.requires_python == ">=3.8"


def test_metadata_from_metadata_file_extra_whitespace() -> None:
    """Test parsing with extra whitespace around values."""
    content = (
        "Metadata-Version:   2.1   \n"
        "Name:  example-package  \n"
        "Version:  1.0.0  \n"
        "Summary:   A test package   "
    )

    metadata = Metadata.from_metadata_file(content)

    assert metadata.metadata_version == "2.1"
    assert metadata.name == "example-package"
    assert metadata.version == "1.0.0"
    assert metadata.summary == "A test package"


def test_metadata_from_metadata_file_empty_lines() -> None:
    """Test parsing with empty lines."""
    content = "Metadata-Version: 2.1\n\nName: example-package\n\nVersion: 1.0.0\n\n"

    metadata = Metadata.from_metadata_file(content)

    assert metadata.metadata_version == "2.1"
    assert metadata.name == "example-package"
    assert metadata.version == "1.0.0"


def test_metadata_read_from_io() -> None:
    """Test reading from a TextIO stream."""
    content = "Metadata-Version: 2.1\nName: example-package\nVersion: 1.0.0\nSummary: A test package"

    with io.StringIO(content) as f:
        metadata = Metadata.read(f)

    assert metadata.metadata_version == "2.1"
    assert metadata.name == "example-package"
    assert metadata.version == "1.0.0"
    assert metadata.summary == "A test package"


def test_metadata_to_metadata_file_basic() -> None:
    """Test converting to METADATA file format."""
    metadata = Metadata(
        metadata_version="2.1",
        name="example-package",
        version="1.0.0",
        summary="A test package",
        author="John Doe",
    )

    result = metadata.to_metadata_file()
    expected = (
        "Metadata-Version: 2.1\n"
        "Name: example-package\n"
        "Version: 1.0.0\n"
        "Summary: A test package\n"
        "Author: John Doe\n"
    )

    assert result == expected


def test_metadata_to_metadata_file_with_empty_string() -> None:
    """Test converting with explicitly empty fields."""
    metadata = Metadata(
        metadata_version="2.1",
        name="example-package",
        version="1.0.0",
        summary="",  # Empty string should be written
        author="John Doe",
    )

    result = metadata.to_metadata_file()
    expected = "Metadata-Version: 2.1\nName: example-package\nVersion: 1.0.0\nSummary:\nAuthor: John Doe\n"

    assert result == expected


def test_metadata_to_metadata_file_omits_none_fields() -> None:
    """Test that None fields are omitted from output."""
    metadata = Metadata(
        metadata_version="2.1",
        name="example-package",
        version="1.0.0",
        summary=None,  # None should be omitted
        author="John Doe",
    )

    result = metadata.to_metadata_file()
    expected = "Metadata-Version: 2.1\nName: example-package\nVersion: 1.0.0\nAuthor: John Doe\n"

    assert result == expected


def test_metadata_to_metadata_file_with_classifiers() -> None:
    """Test converting with multiple classifiers."""
    metadata = Metadata(
        metadata_version="2.1",
        name="example-package",
        version="1.0.0",
        classifier=[
            "Development Status :: 4 - Beta",
            "Programming Language :: Python :: 3",
            "License :: OSI Approved :: MIT License",
        ],
    )

    result = metadata.to_metadata_file()
    expected = (
        "Metadata-Version: 2.1\n"
        "Name: example-package\n"
        "Version: 1.0.0\n"
        "Classifier: Development Status :: 4 - Beta\n"
        "Classifier: Programming Language :: Python :: 3\n"
        "Classifier: License :: OSI Approved :: MIT License\n"
    )

    assert result == expected


def test_metadata_to_metadata_file_with_description() -> None:
    """Test converting with multi-line description."""
    description = "This is a longer description\nthat spans multiple lines.\n\nIt can have empty lines too."

    metadata = Metadata(
        metadata_version="2.1",
        name="example-package",
        version="1.0.0",
        description=description,
    )

    result = metadata.to_metadata_file()
    expected = (
        "Metadata-Version: 2.1\n"
        "Name: example-package\n"
        "Version: 1.0.0\n"
        "Description:\n"
        "        This is a longer description\n"
        "        that spans multiple lines.\n"
        "\n"
        "        It can have empty lines too.\n"
    )

    assert result == expected


def test_metadata_to_metadata_file_omits_empty_description() -> None:
    """Test that None description is omitted."""
    metadata = Metadata(
        metadata_version="2.1",
        name="example-package",
        version="1.0.0",
        description=None,
    )

    result = metadata.to_metadata_file()
    expected = "Metadata-Version: 2.1\nName: example-package\nVersion: 1.0.0\n"

    assert result == expected


def test_metadata_write_to_io() -> None:
    """Test writing to a TextIO stream."""
    metadata = Metadata(
        metadata_version="2.1",
        name="example-package",
        version="1.0.0",
        summary="A test package",
    )

    output = io.StringIO()
    metadata.write(output)
    result = output.getvalue()

    expected = "Metadata-Version: 2.1\nName: example-package\nVersion: 1.0.0\nSummary: A test package\n"

    assert result == expected


def test_metadata_missing_fields_defaults() -> None:
    """Test behavior with missing fields."""
    content = "Metadata-Version: 2.1\nName: example-package\nVersion: 1.0.0"

    metadata = Metadata.from_metadata_file(content)

    assert metadata.metadata_version == "2.1"
    assert metadata.name == "example-package"
    assert metadata.version == "1.0.0"
    assert metadata.summary is None  # Not provided
    assert metadata.author is None  # Not provided
    assert metadata.classifier == []  # Empty list
    assert metadata.requires_dist == []  # Empty list


def test_metadata_invalid_format_lines() -> None:
    """Test handling of lines without colons."""
    content = (
        "Metadata-Version: 2.1\n"
        "Name: example-package\n"
        "Invalid line without colon\n"
        "Version: 1.0.0\n"
        "Summary: A test package"
    )

    metadata = Metadata.from_metadata_file(content)

    # Should parse successfully, ignoring invalid line
    assert metadata.metadata_version == "2.1"
    assert metadata.name == "example-package"
    assert metadata.version == "1.0.0"
    assert metadata.summary == "A test package"


def test_metadata_empty_content() -> None:
    """Test parsing empty content."""
    metadata = Metadata.from_metadata_file("")

    assert metadata.metadata_version == ""
    assert metadata.name == ""
    assert metadata.version == ""
    assert metadata.summary is None
    assert metadata.classifier == []


def test_metadata_value_with_colons() -> None:
    """Test parsing values that contain colons."""
    content = (
        "Metadata-Version: 2.1\n"
        "Name: example-package\n"
        "Version: 1.0.0\n"
        "Home-Page: https://example.com:8080/path\n"
        "Summary: Package for URL: parsing"
    )

    metadata = Metadata.from_metadata_file(content)

    assert metadata.home_page == "https://example.com:8080/path"
    assert metadata.summary == "Package for URL: parsing"


def test_metadata_complex_real_world_example() -> None:
    """Test with a complex real-world-like METADATA file."""
    content = (
        "Metadata-Version: 2.1\n"
        "Name: requests\n"
        "Version: 2.28.1\n"
        "Summary: Python HTTP for Humans.\n"
        "Home-Page: https://requests.readthedocs.io\n"
        "Author: Kenneth Reitz\n"
        "Author-Email: me@kennethreitz.org\n"
        "License: Apache 2.0\n"
        "Project-URL: Documentation, https://requests.readthedocs.io\n"
        "Project-URL: Source, https://github.com/psf/requests\n"
        "Classifier: Development Status :: 5 - Production/Stable\n"
        "Classifier: Intended Audience :: Developers\n"
        "Classifier: Natural Language :: English\n"
        "Classifier: License :: OSI Approved :: Apache Software License\n"
        "Classifier: Programming Language :: Python\n"
        "Classifier: Programming Language :: Python :: 3\n"
        "Classifier: Programming Language :: Python :: 3.7\n"
        "Classifier: Programming Language :: Python :: 3.8\n"
        "Classifier: Programming Language :: Python :: 3.9\n"
        "Classifier: Programming Language :: Python :: 3.10\n"
        "Requires-Python: >=3.7, <4\n"
        "Requires-Dist: charset-normalizer (<3,>=2)\n"
        "Requires-Dist: idna (<4,>=2.5)\n"
        "Requires-Dist: urllib3 (<1.27,>=1.21.1)\n"
        "Requires-Dist: certifi (>=2017.4.17)\n"
        "Requires-Dist: PySocks (!=1.5.7,>=1.5.6) ; extra == 'socks'\n"
        "Provides-Extra: socks\n"
        "Provides-Extra: use-chardet-on-py3\n"
        "Description:\n"
        "        Requests: HTTP for Humans\n"
        "        =========================\n"
        "\n"
        "        Requests is an elegant and simple HTTP library for Python, built for human beings.\n"
    )

    metadata = Metadata.from_metadata_file(content)

    assert metadata.name == "requests"
    assert metadata.version == "2.28.1"
    assert metadata.author == "Kenneth Reitz"
    assert metadata.requires_python == ">=3.7, <4"
    assert len(metadata.classifier) == 10
    assert len(metadata.requires_dist) == 5
    assert len(metadata.provides_extra) == 2
    assert len(metadata.project_url) == 2
    assert metadata.description is not None
    assert "Requests: HTTP for Humans" in metadata.description
    assert "built for human beings." in metadata.description
