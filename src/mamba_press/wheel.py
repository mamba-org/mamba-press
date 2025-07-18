import dataclasses
import io
from typing import TextIO


@dataclasses.dataclass
class Wheel:
    """Represents the WHEEL metadata file found in .dist-info directories.

    Based on PEP 427 and PEP 491 specifications for the wheel binary package format.

    Attributes:
        wheel_version: Version number of the Wheel specification (e.g., "1.0")
        generator: Name and optionally version of software that produced the archive
        root_is_purelib: True if top level should be installed into purelib, False for platlib
        tag: Wheel's expanded compatibility tags
        build: Build number for this particular build (optional)

    """

    wheel_version: str = ""
    generator: str = ""
    root_is_purelib: bool = False
    tag: list[str] = dataclasses.field(default_factory=list)
    build: str | None = None

    @classmethod
    def from_wheel_file(cls, content: str) -> "Wheel":
        """Parse WHEEL metadata from file content string."""
        return cls.read(io.StringIO(content))

    @classmethod
    def read(cls, file: TextIO) -> "Wheel":
        """Read WHEEL metadata from a text IO stream."""
        data: dict[str, str] = {}
        tags: list[str] = []
        root_is_purelib: bool = False

        for line in file:
            line = line.strip()
            if ":" in line:
                key, value = line.split(":", 1)
                key = key.strip().lower().replace("-", "_")
                value = value.strip()

                # Handle multiple tags
                if key == "tag":
                    tags.append(value)
                elif key == "root_is_purelib":
                    root_is_purelib = value.lower() == "true"
                else:
                    data[key] = value

        return cls(
            root_is_purelib=root_is_purelib,
            tag=tags,
            **data,
        )

    def to_wheel_file(self) -> str:
        """Convert to WHEEL file format string."""
        output = io.StringIO()
        self.write(output)
        return output.getvalue()

    def write(self, file: TextIO) -> None:
        """Write WHEEL metadata to a text IO stream."""
        file.write(f"Wheel-Version: {self.wheel_version}\n")
        file.write(f"Generator: {self.generator}\n")
        file.write(f"Root-Is-Purelib: {'true' if self.root_is_purelib else 'false'}\n")

        for tag in self.tag:
            file.write(f"Tag: {tag}\n")

        # Build may be skipped in the file
        if self.build:
            file.write(f"Build: {self.build}\n")


@dataclasses.dataclass
class Metadata:
    """Represents the METADATA file found in .dist-info directories.

    Based on the Core Metadata specifications for Python packages.

    Attributes:
        metadata_version: Version of the metadata format (e.g., "2.1")
        name: Name of the package
        version: Version of the package
        summary: One-line summary of what the package does
        description: Longer description of the package
        description_content_type: Content type of the description (e.g., "text/markdown")
        home_page: URL for the package's home page
        download_url: URL from which this version can be downloaded
        author: Author name
        author_email: Author email address
        maintainer: Maintainer name
        maintainer_email: Maintainer email address
        license: License for the package
        license_file: Path to the license of the package
        keywords: List of package keywords
        classifier: List of trove classifiers
        platform: List of platforms supported by the package
        supported_platform: List of supported platforms with more detail
        requires_dist: List of requirements for this package
        provides_dist: List of packages provided by this distribution
        obsoletes_dist: List of packages made obsolete by this distribution
        requires_python: Python version requirements
        requires_external: List of external dependencies
        project_url: List of project URLs (name, url pairs)
        provides_extra: List of optional features provided
        dynamic: List of fields that are dynamic

    """

    metadata_version: str = ""
    name: str = ""
    version: str = ""
    summary: str | None = None
    description: str | None = None
    description_content_type: str | None = None
    home_page: str | None = None
    download_url: str | None = None
    author: str | None = None
    author_email: str | None = None
    maintainer: str | None = None
    maintainer_email: str | None = None
    license: str | None = None
    license_file: str | None = None
    requires_python: str | None = None
    keywords: list[str] = dataclasses.field(default_factory=list)
    classifier: list[str] = dataclasses.field(default_factory=list)
    platform: list[str] = dataclasses.field(default_factory=list)
    supported_platform: list[str] = dataclasses.field(default_factory=list)
    requires_dist: list[str] = dataclasses.field(default_factory=list)
    provides_dist: list[str] = dataclasses.field(default_factory=list)
    obsoletes_dist: list[str] = dataclasses.field(default_factory=list)
    requires_external: list[str] = dataclasses.field(default_factory=list)
    project_url: list[str] = dataclasses.field(default_factory=list)
    provides_extra: list[str] = dataclasses.field(default_factory=list)
    dynamic: list[str] = dataclasses.field(default_factory=list)

    @classmethod
    def from_metadata_file(cls, content: str) -> "Metadata":
        """Parse METADATA from file content string."""
        return cls.read(io.StringIO(content))

    @classmethod
    def read(cls, file: TextIO) -> "Metadata":
        """Read METADATA from a text IO stream."""
        data: dict[str, str] = {}
        list_data: dict[str, list[str]] = {}
        description_lines: list[str] = []
        in_description = False

        for line in file:
            # Handle description continuation
            if in_description:
                if line.startswith(" ") or line.startswith("\t") or line.strip() == "":
                    description_lines.append(line.rstrip())
                    continue
                else:
                    # End of description, process normally
                    in_description = False
                    data["description"] = "\n".join(description_lines)
                    description_lines = []

            line = line.strip()
            if ":" in line:
                key, value = line.split(":", 1)
                key = key.strip().lower().replace("-", "_")
                value = value.strip()

                # Multi-value fields
                if key in [
                    "classifier",
                    "keywords",
                    "platform",
                    "supported_platform",
                    "requires_dist",
                    "provides_dist",
                    "obsoletes_dist",
                    "requires_external",
                    "project_url",
                    "provides_extra",
                    "dynamic",
                ]:
                    list_data.setdefault(key, []).append(value)
                elif key == "description" and not value:
                    # Empty description value means multi-line description follows
                    in_description = True
                    description_lines = []
                else:
                    # Store the value even if it's empty string
                    data[key] = value

        # Handle description at end of file
        if in_description and description_lines:
            data["description"] = "\n".join(description_lines)

        return cls(**data, **list_data)  # type: ignore[arg-type]

    def to_metadata_file(self) -> str:
        """Convert to METADATA file format string."""
        output = io.StringIO()
        self.write(output)
        return output.getvalue()

    def write(self, file: TextIO) -> None:
        """Write METADATA to a text IO stream."""
        # Required fields first (always written)
        file.write(f"Metadata-Version: {self.metadata_version}\n")
        file.write(f"Name: {self.name}\n")
        file.write(f"Version: {self.version}\n")

        # Optional single-value fields (only write if not None)
        optional_fields = [
            ("summary", "Summary"),
            ("home_page", "Home-page"),
            ("download_url", "Download-URL"),
            ("author", "Author"),
            ("author_email", "Author-email"),
            ("maintainer", "Maintainer"),
            ("maintainer_email", "Maintainer-email"),
            ("license", "License"),
            ("license_file", "License-File"),
            ("requires_python", "Requires-Python"),
            ("description_content_type", "Description-Content-Type"),
        ]

        for attr_name, field_name in optional_fields:
            value = getattr(self, attr_name)
            if value is not None:
                # Handle empty string cases
                value_and_space = f" {value}".rstrip()
                file.write(f"{field_name}:{value_and_space}\n")

        # Multi-value fields (only write if list is not empty)
        multi_fields = [
            ("classifier", "Classifier"),
            ("keywords", "Keywords"),
            ("platform", "Platform"),
            ("supported_platform", "Supported-Platform"),
            ("requires_dist", "Requires-Dist"),
            ("provides_dist", "Provides-Dist"),
            ("obsoletes_dist", "Obsoletes-Dist"),
            ("requires_external", "Requires-External"),
            ("project_url", "Project-URL"),
            ("provides_extra", "Provides-Extra"),
            ("dynamic", "Dynamic"),
        ]

        for attr_name, field_name in multi_fields:
            values = getattr(self, attr_name)
            for value in values:
                file.write(f"{field_name}: {value}\n")

        # Description comes last and can be multi-line (only write if not None)
        if self.description is not None:
            file.write("Description:\n")
            for line in self.description.split("\n"):
                if line.strip():
                    file.write(f"        {line}\n")
                else:
                    file.write("\n")
