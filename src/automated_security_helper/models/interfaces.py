from abc import ABC, abstractmethod
from typing import Any, Dict, List

from automated_security_helper.models.asharp_model import ASHARPModel
from ..config.config import ScannerPluginConfig, ParserConfig
from .core import Location


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


class IScanner(ABC):
    """Interface for security scanners."""

    @abstractmethod
    def configure(self, config: ScannerPluginConfig) -> None:
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

    def _set_parser(self, parser: IScannerParser) -> None:
        """Set the parser for the scanner."""
        self.parser = parser

    def _parse_results(self, raw_results: Any):
        """Parse raw scanner output."""
        return self.parser.parse(raw_results)


class IOutputReporter(ABC):
    """Interface for output formatters."""

    @abstractmethod
    def format(self, model: ASHARPModel) -> str:
        """Format ASH model into output string."""
        pass
