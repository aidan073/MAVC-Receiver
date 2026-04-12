"""
Enums related to the wire layout
"""

__all__ = ["Endian"]

from enum import Enum


class Endian(Enum):
    """Byte order used when packing/unpacking the message on the wire."""
    BIG = ">"
    LITTLE = "<"
