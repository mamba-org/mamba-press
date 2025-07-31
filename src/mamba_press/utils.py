import re
from collections.abc import Mapping
from typing import Final

KEBAB_CASE_PATTERN: Final[re.Pattern[str]] = re.compile(r"\b[a-z]+(?:-[a-z]+)*\b")


def kebab_to_pascal(text: str) -> str:
    """Transform kebab-case to PascalCase."""

    def replacer(match: re.Match[str]) -> str:
        parts = match.group().split("-")
        return "".join(part.capitalize() for part in parts)

    return KEBAB_CASE_PATTERN.sub(replacer, text)


INTERPOLATE_VAR_PATTERN: Final[re.Pattern[str]] = re.compile(r"\${{\s*(\w+)\s*}}")


def interpolate(template: str, context: Mapping[str, object]) -> str:
    """Replace variables with a simple JinJa-like syntax."""
    return INTERPOLATE_VAR_PATTERN.sub(lambda m: str(context[m.group(1)]), template)
