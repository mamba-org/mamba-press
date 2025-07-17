"""Relocate dynamic libraries."""

from . import abc, elf, macho
from .abc import DynamicLibRelocate
from .elf import ElfDynamicLibRelocate
from .macho import MachODynamicLibRelocate

__all__ = [
    "DynamicLibRelocate",
    "ElfDynamicLibRelocate",
    "MachODynamicLibRelocate",
    "abc",
    "elf",
    "macho",
]
