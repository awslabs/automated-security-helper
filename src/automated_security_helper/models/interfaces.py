# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from abc import ABC, abstractmethod
from pathlib import Path
import re
from typing import Any, Dict, List

from automated_security_helper.models.asharp_model import ASHARPModel
from automated_security_helper.models.core import (
    ConverterPluginConfig,
    Location,
    ParserConfig,
    ScannerPluginConfig,
)
from automated_security_helper.models.data_interchange import SecurityReport


class Normalizer:
    @staticmethod
    def get_normalized_filename(str_to_normalize: str) -> str:
        """Returns a normalized filename for the given string.

        Args:
            str_to_normalize (str): The string to normalize.

        Returns:
            str: The normalized filename.
        """
        normalized = re.sub(
            pattern=r"\W+",
            repl="-",
            string=str_to_normalize.replace("/", "--").replace(".", "_"),
            flags=re.IGNORECASE,
        )
        return normalized


class IParser(ABC, Normalizer):
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


class IScanner(ABC, Normalizer):
    """Interface for security scanners."""

    @abstractmethod
    def configure(self, config: ScannerPluginConfig) -> None:
        """Configure the scanner with provided configuration."""
        pass

    @abstractmethod
    def scan(self, target: Path | str) -> SecurityReport:
        """Execute the security scan on the target."""
        pass

    @abstractmethod
    def validate(self) -> bool:
        """Validate scanner configuration and requirements."""
        pass

    def _set_parser(self, parser: IParser) -> None:
        """Set the parser for the scanner."""
        self.parser = parser

    def _parse_results(self, raw_results: Any):
        """Parse raw scanner output."""
        return self.parser.parse(raw_results)


class IConverter(ABC, Normalizer):
    """Interface for file converters.

    Converters are responsible for converting an unscannable file type (e.g.
    ZIP archives or Jupyter Notebook/`.ipynb` files) into a scannable format within the
    provided structured path: `f"{work_dir}/converters/{normalized_file_name}"`.
    """

    @abstractmethod
    def configure(
        self,
        config: ConverterPluginConfig | None = None,
        options: Any = None,
    ) -> None:
        """Configure the converter with provided configuration."""
        pass

    @abstractmethod
    def validate(self) -> bool:
        """Validate converter configuration and requirements."""
        pass

    @abstractmethod
    def convert(self, target: Path | str) -> List[Path]:
        """Execute the converter on the target prior to scans.

        Returns the list of Path objects emitted by the `convert()` operation.
        """
        pass


class IOutputReporter(ABC, Normalizer):
    """Interface for output reporters/formatters."""

    @abstractmethod
    def format(
        self,
        model: ASHARPModel,
        output_path: Path | None = None,
    ) -> str | Path:
        """Format ASH model into output string.

        If output_path is not None, save the formatted content to the provided Path and
        return the Path back to the caller.

        If output_path is None (default), return the formatted string content back to
        the caller.
        """
        pass
