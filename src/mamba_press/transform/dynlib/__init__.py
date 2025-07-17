"""Relocate dynamic libraries."""

from .abc import DynamicLibRelocate
from .relocation import make_relocator

__all__ = [
    "DynamicLibRelocate",
    "make_relocator",
]
