"""Result processor module for ASH.

This module contains the ResultProcessor class which is responsible for:
1. Resolving appropriate parsers for scanner results
2. Implementing the parsing pipeline
3. Building ASH models from parsed results
"""

from pathlib import Path
from typing import Any, Dict, List, Type, Union
from abc import ABC, abstractmethod
from automated_security_helper.models.asharp_model import ASHARPModel
from automated_security_helper.utils.log import ASH_LOGGER


class IResultParser(ABC):
    """Interface for result parsers."""

    @abstractmethod
    def parse(
        self, raw_results: str
    ) -> Dict[str, Union[List[Dict[str, Any]], Dict[str, str]]]:
        """Parse raw scanner results into a structured format."""
        pass


class ResultProcessor:
    """Processes scanner results through parsing pipeline."""

    def __init__(
        self,
    ):
        ASH_LOGGER.info("Initializing ResultProcessor")
        self._parsers: Dict[str, Type[IResultParser]] = {}

    def register_parser(self, scanner_type: str, parser_class: Type[IResultParser]):
        """Register a parser for a specific scanner type."""
        self._parsers[scanner_type] = parser_class

    def get_parser(self, scanner_type: str) -> IResultParser:
        """Get the appropriate parser for a scanner type."""
        if scanner_type not in self._parsers:
            raise ValueError(f"No parser registered for scanner type: {scanner_type}")
        return self._parsers[scanner_type]()

    def process_results(
        self, scanner_type: str, raw_results: Union[str, Dict[str, Any]]
    ) -> ASHARPModel:
        """Process raw scanner results through the parsing pipeline.

        Args:
            scanner_type: Type of scanner that produced the results
            raw_results: Raw results from scanner execution or path to JSON model

        Returns:
            ASHARPModel: Processed security findings model

        Raises:
            ValueError: If scanner type not provided when processing raw results
        """
        if isinstance(raw_results, str) and raw_results.endswith(".json"):
            # Load existing ASHARPModel from JSON
            from automated_security_helper.models.json_serializer import (
                ASHARPModelSerializer,
            )

            return ASHARPModelSerializer.load_model(Path(raw_results))

        if not scanner_type:
            raise ValueError("Scanner type required when processing raw results")

        parser = self.get_parser(scanner_type)
        parsed_results = parser.parse(raw_results)
        model = self._build_ash_model(parsed_results)
        return model

    def _build_ash_model(
        self, parsed_results: Dict[str, Union[List[Dict[str, Any]], Dict[str, str]]]
    ) -> ASHARPModel:
        """Build an ASH model from parsed results."""
        model = ASHARPModel()
        if "findings" in parsed_results:
            findings: List[Dict[str, Any]] = parsed_results["findings"]
            model.findings = findings
        if "metadata" in parsed_results:
            model.metadata = parsed_results["metadata"]
        return model
