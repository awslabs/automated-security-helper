"""Module containing the ScanResultsContainer class for wrapping scanner results."""

from typing import Any, Dict, List, Optional


class ScanResultsContainer:
    """Container for scanner results with metadata."""

    def __init__(self):
        """Initialize an empty container."""
        self._findings: List[Any] = []
        self._metadata: Dict[str, Any] = {}
        self._raw_results: Optional[Dict[str, Any]] = None

    def add_findings(self, findings: List[Any]) -> None:
        """Add findings to the container.

        Args:
            findings: List of findings to add
        """
        self._findings.extend(findings)

    def add_metadata(self, key: str, value: Any) -> None:
        """Add metadata to the container.

        Args:
            key: Metadata key
            value: Metadata value
        """
        self._metadata[key] = value

    def set_raw_results(self, results: Dict[str, Any]) -> None:
        """Set raw scanner results.

        Args:
            results: Raw scanner results
        """
        self._raw_results = results

    @property
    def findings(self) -> List[Any]:
        """Get findings.

        Returns:
            List of findings
        """
        return self._findings

    @property
    def metadata(self) -> Dict[str, Any]:
        """Get metadata.

        Returns:
            Metadata dictionary
        """
        return self._metadata

    @property
    def raw_results(self) -> Optional[Dict[str, Any]]:
        """Get raw results.

        Returns:
            Raw scanner results if set, None otherwise
        """
        return self._raw_results
