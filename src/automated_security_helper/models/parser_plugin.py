"""Module containing the ParserPlugin base class."""

from pathlib import Path
from typing import List

from pydantic import BaseModel, ConfigDict

from automated_security_helper.base.options import BaseParserOptions
from automated_security_helper.utils.log import ASH_LOGGER


class ParserPluginConfig(BaseModel):
    """Base configuration class for parser plugins."""

    model_config = ConfigDict(extra="allow")

    enabled: bool = True
    options: BaseParserOptions = BaseParserOptions()


class ParserPlugin(BaseModel):
    """Base parser plugin with some methods of the abstract class
    implemented for convenience.
    """

    name: str = "base-parser"
    description: str = "Base parser configuration."
    config: ParserPluginConfig = ParserPluginConfig()

    source_dir: Path | None = None
    output_dir: Path | None = None

    output: List[str] = []
    errors: List[str] = []

    def parse(self, results_str_or_path: str | Path):
        """Parse raw scanner results into a standardized format."""
        # Collect results as string if Path is provided
        if isinstance(results_str_or_path, Path):
            with open(results_str_or_path, "r") as f:
                results_str = f.read()
        else:
            results_str = results_str_or_path
        ASH_LOGGER.debug(f"ParserPlugin.parse: {results_str}")

        pass
