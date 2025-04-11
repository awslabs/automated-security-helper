"""Module containing the ParserPlugin base class."""

import logging
import shutil
from abc import abstractmethod
from pathlib import Path
from typing import Any, Dict, List
from typing_extensions import Self

from pydantic import BaseModel, model_validator

from automated_security_helper.models.core import BaseParserOptions
from automated_security_helper.models.interfaces import IParser


class ParserPluginConfig(BaseModel):
    """Base configuration class for parser plugins."""

    name: str = "base-parser"
    description: str = "Base parser configuration."
    enabled: bool = True
    options: Dict[str, Any] = {}
    check_for_updates: bool = False


class ParserPlugin(IParser, BaseModel):
    """Base parser plugin with some methods of the IParser abstract class
    implemented for convenience.
    """

    _default_config: ParserPluginConfig | None = None
    _config: ParserPluginConfig | None = None
    _output: List[str] = []
    _errors: List[str] = []
    _work_path: Path | None = None
    _args: List[str] = []

    # Required fields that should be set in child classes
    enabled: bool = True
    source_dir: Path | None = None
    output_dir: Path | None = None
    work_dir: Path | None = None
    options: BaseParserOptions = BaseParserOptions()

    @model_validator(mode="after")
    def setup_paths(self) -> Self:
        """Set up default paths and initialize plugin configuration."""
        # Use default paths if none provided
        if self.source_dir is None:
            self.source_dir = Path(".")
        if self.output_dir is None:
            self.output_dir = Path("output")

        # Ensure paths are Path objects
        self.source_dir = Path(str(self.source_dir))
        self.output_dir = Path(str(self.output_dir))
        self.work_dir = self.output_dir.joinpath("work")

        # Set up scanner name
        if self._config is None:
            self._config = self._default_config
        scanner_name = (
            getattr(self._config, "name", "unknown") if self._config else "unknown"
        )
        self.logger = logging.getLogger(f"ash.scanners.{scanner_name}")

        self.results_dir = self.output_dir.joinpath("scanners").joinpath(scanner_name)
        if self.results_dir.exists():
            shutil.rmtree(self.results_dir)
        self.results_dir.mkdir(parents=True, exist_ok=True)

        return self

    def configure(
        self,
        config: ParserPluginConfig | None = None,
        options: BaseParserOptions | None = None,
    ) -> None:
        """Configure the parser with provided configuration."""
        if config:
            self._config = config
        if options:
            self.options = options

    @abstractmethod
    def validate(self) -> bool:
        """Validate parser configuration and requirements."""
        pass

    @abstractmethod
    def convert(self, target: Path | str) -> List[Path]:
        """Execute the parser on the target prior to scans.

        Returns the list of Path objects emitted by the `convert()` operation.
        """
        pass
