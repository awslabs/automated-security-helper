from abc import ABC, abstractmethod
from typing import Any, Dict, List
from .config import ScannerConfig, ParserConfig
from .core import Location


class IScanner(ABC):
    """Interface for security scanners."""

    @abstractmethod
    def configure(self, config: ScannerConfig) -> None:
        """Configure the scanner with provided configuration."""
        pass

    @abstractmethod
    def scan(self, target: str) -> List[Dict[str, Any]]:
        """Execute the security scan on the target."""
        pass

    @abstractmethod
    def validate(self) -> bool:
        """Validate scanner configuration and requirements."""
        pass


class IScannerParser(ABC):
    """Interface for parsing scanner results."""

    @abstractmethod
    def configure(self, config: ParserConfig) -> None:
        """Configure the parser with provided configuration."""
        pass

    @abstractmethod
    def parse(self, raw_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Parse raw scanner results into a standardized format."""
        pass

    @abstractmethod
    def get_finding_locations(self, finding: Dict[str, Any]) -> List[Location]:
        """Extract location information from a finding."""
        pass
