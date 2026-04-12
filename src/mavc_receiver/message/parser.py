from abc import ABC, abstractmethod

from typing import Any


class IParser(ABC):
    """Interface for classes that deserialize messages."""

    @abstractmethod
    def decode(self, data: bytes) -> Any:
        """Parse wire-format bytes into a message instance."""
