"""Module containing the ConverterPlugin base class."""

from abc import abstractmethod
from pathlib import Path
from typing import Generic, List, TypeVar
from typing_extensions import Self

from pydantic import model_validator

from automated_security_helper.base.plugin_base import PluginBase
from automated_security_helper.base.plugin_config import PluginConfigBase
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.utils.log import ASH_LOGGER


class ConverterPluginConfigBase(PluginConfigBase):
    pass


T = TypeVar("T", bound=ConverterPluginConfigBase)


class ConverterPluginBase(PluginBase, Generic[T]):
    """Base converter plugin with some methods of the IConverter abstract class
    implemented for convenience.
    """

    config: T | ConverterPluginConfigBase | None = None
    dependencies_satisfied: bool = True

    @model_validator(mode="after")
    def setup_paths(self) -> Self:
        """Set up default paths and initialize plugin configuration."""
        # Use context if provided, otherwise fall back to instance attributes
        if self.context is None:
            raise ScannerError(f"No context provided for {self.__class__.__name__}!")
        ASH_LOGGER.trace(f"Using provided context for {self.__class__.__name__}")

        ASH_LOGGER.trace(
            f"Converter {self.config.name if self.config else self.__class__.__name__} initialized with source_dir={self.context.source_dir}, output_dir={self.context.output_dir}"
        )
        return self

    def model_post_init(self, context):
        if self.config is None:
            self.config = ConverterPluginConfigBase()
        self.results_dir = self.context.work_dir.joinpath(
            self.config.name or self.__class__.__name__
        )
        return super().model_post_init(context)

    def configure(
        self,
        config: ConverterPluginConfigBase | None = None,
    ) -> None:
        """Configure the converter with provided configuration."""
        if config:
            self.config = config

    def validate(self) -> bool:
        """Validate converter configuration and requirements.

        Defaults to returning True as most converter plugins are entirely Python based."""
        return True

    @abstractmethod
    def convert(self, target: Path | str) -> List[Path]:
        """Execute the converter on the target prior to scans.

        Returns the list of Path objects emitted by the `convert()` operation that
        correspond to scannable files emitted to the work_dir.
        """
        pass
