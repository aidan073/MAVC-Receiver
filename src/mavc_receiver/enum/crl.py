"""
Enums related to the local CA's crl
"""

__all__ = ["CertStatus"]

from enum import Enum


class CertStatus(Enum):
    """Status of certificates"""
    Valid = "V"
    Revoked = "R"