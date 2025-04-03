"""Output formatter module for ASH.

This module contains the OutputFormatter class and related formatters for:
- JSON output
- HTML output
- CSV output
"""

from automated_security_helper.models.asharp_model import ASHARPModel
from automated_security_helper.models.data_interchange import ExportFormat
from automated_security_helper.outputs import (
    ASFFFormatter,
    CSVFormatter,
    CycloneDXFormatter,
    HTMLFormatter,
    JSONFormatter,
    JUnitXMLFormatter,
    SARIFFormatter,
    SPDXFormatter,
    TextFormatter,
    YAMLFormatter,
)


class OutputFormatter:
    """Main formatter class that manages different output formats."""

    def __init__(self):
        self._formatters = {
            "asff": ASFFFormatter(),
            "csv": CSVFormatter(),
            "cyclonedx": CycloneDXFormatter(),
            "dict": JSONFormatter(),
            "html": HTMLFormatter(),
            "json": JSONFormatter(),
            "junitxml": JUnitXMLFormatter(),
            "sarif": SARIFFormatter(),
            "spdx": SPDXFormatter(),
            "text": TextFormatter(),
            "yaml": YAMLFormatter(),
        }

    def format(self, model: ASHARPModel, output_format: ExportFormat) -> str:
        """Format ASH model using specified formatter."""
        if f"{output_format}" not in self._formatters:
            raise ValueError(f"Unsupported output format: {output_format}")

        return self._formatters[f"{output_format}"].format(model)
