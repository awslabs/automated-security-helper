"""Output formatter module for ASH.

This module contains the OutputFormatter class and related formatters for:
- JSON output
- HTML output
- CSV output
"""

from automated_security_helper.models.asharp_model import ASHARPModel
from automated_security_helper.models.core import ExportFormat
from automated_security_helper.reporters import (
    ASFFReporter,
    CSVReporter,
    CycloneDXReporter,
    HTMLReporter,
    JSONReporter,
    JUnitXMLReporter,
    SARIFReporter,
    SPDXReporter,
    TextReporter,
    YAMLReporter,
)
from automated_security_helper.utils.log import ASH_LOGGER


class OutputFormatter:
    """Main formatter class that manages different output formats."""

    def __init__(
        self,
    ):
        ASH_LOGGER.info("Initializing OutputFormatter")

        self._formatters = {
            "asff": ASFFReporter(),
            "csv": CSVReporter(),
            "cyclonedx": CycloneDXReporter(),
            "dict": JSONReporter(),
            "html": HTMLReporter(),
            "json": JSONReporter(),
            "junitxml": JUnitXMLReporter(),
            "sarif": SARIFReporter(),
            "spdx": SPDXReporter(),
            "text": TextReporter(),
            "yaml": YAMLReporter(),
        }

    def format(self, model: ASHARPModel, output_format: ExportFormat) -> str:
        """Format ASH model using specified formatter."""
        if f"{output_format}" not in self._formatters:
            raise ValueError(f"Unsupported output format: {output_format}")

        return self._formatters[f"{output_format}"].format(model)
