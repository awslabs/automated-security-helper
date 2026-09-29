"""Module containing the ConverterPlugin base class."""

from abc import abstractmethod
from pathlib import Path
from typing import Annotated, Generic, List, TypeVar
from typing_extensions import Self

from pydantic import Field, model_validator

from automated_security_helper.base.options import ConverterOptionsBase
from automated_security_helper.base.plugin_base import PluginBase
from automated_security_helper.base.plugin_config import PluginConfigBase
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.utils.log import ASH_LOGGER


class ConverterPluginConfigBase(PluginConfigBase):
    options: Annotated[ConverterOptionsBase, Field(description="Converter options")] = (
        ConverterOptionsBase()
    )


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

    def validate_plugin_dependencies(self) -> bool:
        """Validate converter configuration and requirements.

        Defaults to returning True as most converter plugins are entirely Python based."""
        return True

    def candidate_input_count(self) -> int | None:
        """How many files this converter WOULD convert, or None if it cannot say.

        Answered WITHOUT the converter's tool, which is the whole point. A converter
        whose tool is unavailable is dropped by ``filter_enabled_plugins`` before it can
        run, so by the time anything asks "did conversion lose coverage?" the converter
        has never looked at the tree. That question has two very different answers --
        "there were notebooks and none were converted" is lost coverage, "there were no
        notebooks at all" is nothing -- and without this they were indistinguishable.

        WHY THE DEFAULT IS None AND NOT 0
        ---------------------------------
        ``None`` means "this converter does not report a count", and the completeness
        gate treats that as strictly as it did before: an unavailable converter with no
        count still reports incomplete conversion. Defaulting to 0 would silently exempt
        every converter that has not implemented this, turning a gate into a no-op for
        all of them at once -- the opposite of the intended direction. Each converter
        opts in by overriding, and until it does nothing about its behaviour changes.

        Counting rather than returning a bool, so a caller can report the number. The
        count is of CANDIDATES, not of conversions: it says what the converter was asked
        to do, which is what makes it the right denominator for a coverage claim.
        """
        return None

    @abstractmethod
    def convert(self, target: Path | str) -> List[Path]:
        """Execute the converter on the target prior to scans.

        Returns the list of Path objects emitted by the `convert()` operation that
        correspond to scannable files emitted to the work_dir.
        """
