"""Module containing the ReporterPlugin base class."""

from datetime import datetime, timezone
from pathlib import Path
from typing import Generic, List, TypeVar
from typing_extensions import Self

from pydantic import BaseModel, ConfigDict, model_validator

from automated_security_helper.base.plugin_config import PluginConfigBase
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
    config: T | PluginConfigBase | None = None

    source_dir: Path | None = None
    output_dir: Path | None = None

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
        # Use default paths if none provided
        if self.source_dir is None:
            self.source_dir = Path(".")
        if self.output_dir is None:
            self.output_dir = self.source_dir.joinpath("ash_output")
        return self

    def configure(
        self,
        config: ReporterPluginConfigBase | None = None,
    ) -> None:
        """Configure the reporter with provided configuration."""
        if config:
            self._config = config

    def validate(self) -> bool:
        """Validate reporter configuration and requirements."""
        return True

    def _pre_convert(self, target: Path | str) -> None:
        self.start_time = datetime.now(timezone.utc)
        if not Path(target).exists():
            ASH_LOGGER.error(f"Target {target} does not exist.")
            raise

    def _post_convert(self, target: Path | str) -> None:
        if not Path(target).exists():
            ASH_LOGGER.error(f"Target {target} does not exist.")
            raise
        self.end_time = datetime.now(timezone.utc)

    def convert(self, target: Path | str) -> List[Path]:
        """Execute the reporter on the target prior to scans.

        Returns the list of Path objects emitted by the `convert()` operation.
        """
        self._pre_convert(target)

        self._post_convert(target)
