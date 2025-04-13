"""Parser interface implementation for ASH scanners."""

from typing import Dict, List, Any, Optional

from automated_security_helper.base.scanner import ParserConfig
from .interfaces import IParser
from .core import Location
from .asharp_model import ASHARPModel


class ScannerParser(IParser):
    """Parser implementation for scanner results."""

    def __init__(self):
        """Initialize the parser."""
        self._config: Optional[ParserConfig] = None
        self._model: Optional[ASHARPModel] = None

    def configure(self, config: ParserConfig) -> None:
        """Configure the parser with scanner-specific settings."""
        self._config = config

    def parse(self, raw_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Parse raw scanner results into a standardized format."""
        parsed_results = []
        for result in raw_results:
            parsed_result = self._parse_result(result)
            if parsed_result:
                parsed_results.append(parsed_result)
        return parsed_results

    def get_finding_locations(self, finding: Dict[str, Any]) -> List[Location]:
        """Extract location information from a finding."""
        locations = []
        if "file" in finding:
            location = Location(
                file_path=finding["file"],
                line_number=finding.get("line_number", 0),
                column=finding.get("column", 0),
            )
            locations.append(location)
        return locations

    def _parse_result(self, result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse a single result into the standardized format."""
        if not result:
            return None

        parsed = {
            "type": result.get("type", "unknown"),
            "severity": result.get("severity", "INFO"),
            "description": result.get("description", ""),
            "locations": self.get_finding_locations(result),
        }
        return parsed
