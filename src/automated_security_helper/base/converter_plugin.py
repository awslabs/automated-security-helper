"""Module containing the ConverterPlugin base class."""

from abc import abstractmethod
from pathlib import Path
from typing import Generic, List, TypeVar
from typing_extensions import Self

from pydantic import BaseModel, ConfigDict, model_validator

from automated_security_helper.base.plugin_config import PluginConfigBase
from automated_security_helper.utils.log import ASH_LOGGER


class ConverterPluginConfigBase(PluginConfigBase):
    pass


T = TypeVar("T", bound=ConverterPluginConfigBase)


class ConverterPluginBase(BaseModel, Generic[T]):
    """Base converter plugin with some methods of the IConverter abstract class
    implemented for convenience.
    """

    model_config = ConfigDict(
        extra="allow", arbitrary_types_allowed=True, use_enum_values=True
    )

    config: T | PluginConfigBase | None = None

    source_dir: Path | None = None
    output_dir: Path | None = None
    work_dir: Path | None = None

    @model_validator(mode="after")
    def setup_paths(self) -> Self:
        """Set up default paths and initialize plugin configuration."""
        # Use default paths if none provided
        if self.source_dir is None:
            self.source_dir = Path(".")
            ASH_LOGGER.verbose(
                f"({self.config.name or self.__class__.__name__}) Source directory was not provided! Defaulting to the current directory"
            )
        if self.output_dir is None:
            ASH_LOGGER.verbose(
                f"({self.config.name or self.__class__.__name__}) Output directory was not provided! Defaulting to ash_output directory relative to the source directory."
            )
            self.output_dir = self.source_dir.joinpath("ash_output")

        # Ensure paths are Path objects
        self.source_dir = Path(str(self.source_dir))
        self.output_dir = Path(str(self.output_dir))
        self.work_dir = self.output_dir.joinpath("converted")

        return self

    def configure(
        self,
        config: ConverterPluginConfigBase | None = None,
    ) -> None:
        """Configure the converter with provided configuration."""
        if config:
            self.config = config

    ### Methods that require implementation by plugins.
    @abstractmethod
    def validate(self) -> bool:
        """Validate converter configuration and requirements."""
        pass

    @abstractmethod
    def convert(self, target: Path | str) -> List[Path]:
        """Execute the converter on the target prior to scans.

        Returns the list of Path objects emitted by the `convert()` operation that
        correspond to scannable files emitted to the work_dir.
        """
        pass
