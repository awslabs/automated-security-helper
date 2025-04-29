"""Module containing the ReporterPlugin base class."""

from abc import abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Generic, List, TypeVar
from typing_extensions import Self

from pydantic import BaseModel, ConfigDict, model_validator

from automated_security_helper.base.plugin_config import PluginConfigBase
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.asharp_model import ASHARPModel
from automated_security_helper.utils.log import ASH_LOGGER


class ReporterPluginConfigBase(PluginConfigBase):
    extension: str | None = None


T = TypeVar("T", bound=ReporterPluginConfigBase)


class ReporterPluginBase(BaseModel, Generic[T]):
    """Base reporter plugin with some methods of the IReporter abstract class
    implemented for convenience.
    """

    model_config = ConfigDict(extra="allow")

    # Required fields that should be set in child classes
    config: T | ReporterPluginConfigBase | None = None
    context: PluginContext | None = None

    output: List[str] = []
    errors: List[str] = []

    # These will be initialized during `self.model_post_init()`
    # in paths relative to the `output_dir` provided
    results_dir: Path | None = None
    start_time: datetime | None = None
    end_time: datetime | None = None
    exit_code: int = 0

    @model_validator(mode="after")
    def setup_paths(self) -> Self:
        """Set up default paths and initialize plugin configuration."""
        # Use context if provided, otherwise fall back to instance attributes
        if self.context is None:
            raise ScannerError(f"No context provided for {self.__class__.__name__}!")
        ASH_LOGGER.trace(f"Using provided context for {self.__class__.__name__}")
        return self

    def configure(
        self,
        config: ReporterPluginConfigBase | None = None,
    ) -> None:
        """Configure the reporter with provided configuration."""
        if config:
            self._config = config

    def _pre_report(self) -> None:
        self.start_time = datetime.now(timezone.utc)

    def _post_report(self) -> None:
        self.end_time = datetime.now(timezone.utc)

    def sarif_field_mappings(self) -> dict[str, str] | None:
        """
        Get mappings from SARIF fields to this reporter's output format.

        This method should be implemented by reporter classes to provide
        information about how SARIF fields map to their specific output format.

        Returns:
            Optional[Dict[str, str]]: Dictionary mapping SARIF field paths to
                                     reporter-specific field paths, or None if
                                     no mappings are available.
        """
        return None

    ### Methods that require implementation by plugins.
    @abstractmethod
    def report(self, model: ASHARPModel) -> str | None:
        """Execute the reporter against the aggregated ASHARPModel.

        Returns a string containing the report or the response from the remote
        receiving the report.
        """
        pass
