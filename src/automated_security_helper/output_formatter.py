"""Output formatter module for ASH.

This module contains the OutputFormatter class and related formatters for:
- JSON output
- HTML output
- CSV output
"""

from abc import ABC, abstractmethod
import json
import csv
from io import StringIO
import html

from .result_processor import ASHModel


class IOutputFormatter(ABC):
    """Interface for output formatters."""

    @abstractmethod
    def format(self, model: ASHModel) -> str:
        """Format ASH model into output string."""
        pass


class JSONFormatter(IOutputFormatter):
    """Formats results as JSON."""

    def format(self, model: ASHModel) -> str:
        """Format ASH model as JSON string."""
        data = {"findings": model.findings, "metadata": model.metadata}
        return json.dumps(data, indent=2)


class HTMLFormatter(IOutputFormatter):
    """Formats results as HTML."""

    def format(self, model: ASHModel) -> str:
        """Format ASH model as HTML string."""
        # Basic HTML template
        template = """
        <!DOCTYPE html>
        <html>
        <head><title>ASH Results</title></head>
        <body>
            <h1>Security Scan Results</h1>
            <h2>Findings</h2>
            {findings}
            <h2>Metadata</h2>
            {metadata}
        </body>
        </html>
        """

        # TODO: Implement detailed HTML formatting
        return template.format(
            findings=html.escape(str(model.findings)),
            metadata=html.escape(str(model.metadata)),
        )


class CSVFormatter(IOutputFormatter):
    """Formats results as CSV."""

    def format(self, model: ASHModel) -> str:
        """Format ASH model as CSV string."""
        output = StringIO()
        writer = csv.writer(output)

        # Write headers
        writer.writerow(["Finding ID", "Severity", "Description", "Location"])

        # TODO: Implement CSV row writing based on findings

        return output.getvalue()


class OutputFormatter:
    """Main formatter class that manages different output formats."""

    def __init__(self):
        self._formatters = {
            "json": JSONFormatter(),
            "html": HTMLFormatter(),
            "csv": CSVFormatter(),
        }

    def format(self, model: ASHModel, output_format: str) -> str:
        """Format ASH model using specified formatter."""
        if output_format not in self._formatters:
            raise ValueError(f"Unsupported output format: {output_format}")

        return self._formatters[output_format].format(model)
