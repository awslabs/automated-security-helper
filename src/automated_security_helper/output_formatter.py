"""Output formatter module for ASH.

This module contains the OutputFormatter class and related formatters for:
- JSON output
- HTML output
- CSV output
"""

from abc import ABC, abstractmethod
import csv
from io import StringIO
import html

import yaml

from .models.asharp_model import ASHARPModel


class IOutputFormatter(ABC):
    """Interface for output formatters."""

    @abstractmethod
    def format(self, model: ASHARPModel) -> str:
        """Format ASH model into output string."""
        pass


class JSONFormatter(IOutputFormatter):
    """Formats results as JSON."""

    def format(self, model: ASHARPModel) -> str:
        """Format ASH model as JSON string."""
        return model.model_dump_json(indent=2, serialize_as_any=True)


class YAMLFormatter(IOutputFormatter):
    """Formats results as YAML."""

    def format(self, model: ASHARPModel) -> str:
        """Format ASH model as YAML string."""
        return yaml.dump(model.model_dump(), indent=2)


class HTMLFormatter(IOutputFormatter):
    """Formats results as HTML."""

    def format(self, model: ASHARPModel) -> str:
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

    def format(self, model: ASHARPModel) -> str:
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
            "yaml": YAMLFormatter(),
            "yml": YAMLFormatter(),
            "html": HTMLFormatter(),
            "csv": CSVFormatter(),
        }

    def format(self, model: ASHARPModel, output_format: str) -> str:
        """Format ASH model using specified formatter."""
        if output_format not in self._formatters:
            raise ValueError(f"Unsupported output format: {output_format}")

        return self._formatters[output_format].format(model)
