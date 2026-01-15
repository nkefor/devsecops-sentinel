"""Abstract base class for security scanners."""
from abc import ABC, abstractmethod
from typing import List, Optional
from models.vulnerability import Vulnerability


class BaseScanner(ABC):
    """Abstract base class for infrastructure security scanners."""

    def __init__(self, target_path: str = "."):
        """
        Initialize the scanner.

        Args:
            target_path: Path to scan (default: current directory)
        """
        self.target_path = target_path
        self.name: str = "base"

    @abstractmethod
    def scan(self) -> List[Vulnerability]:
        """
        Execute the security scan and return vulnerabilities.

        Returns:
            List of Vulnerability objects found during scanning
        """
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """
        Check if the scanner tool is installed and available.

        Returns:
            True if scanner is available, False otherwise
        """
        pass

    def get_name(self) -> str:
        """Return the scanner name."""
        return self.name

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(target_path='{self.target_path}')"
