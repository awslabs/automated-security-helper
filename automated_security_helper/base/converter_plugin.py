"""Module containing the ConverterPlugin base class."""

from abc import abstractmethod
from pathlib import Path
from typing import Annotated, BinaryIO, Generic, List, TypeVar
from typing_extensions import Self

from pydantic import Field, model_validator

from automated_security_helper.base.options import ConverterOptionsBase
from automated_security_helper.base.plugin_base import PluginBase
from automated_security_helper.base.plugin_config import PluginConfigBase
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.asharp_model import RefusedInputInfo
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.scanned_tree import (
    TreeInputRefused,
    open_in_scanned_tree,
)


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
    # Inputs this converter declined to read during convert(). ConvertPhase copies them
    # into the converter's results row, which is what keeps a refused input visible in
    # the scan result rather than only in the log.
    refused_inputs: List[RefusedInputInfo] = Field(default_factory=list)

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

    def open_source_file(self, path: Path | str) -> BinaryIO:
        """Open a file from the scan set for reading, under the scanned-tree rule.

        Converters read their inputs through this rather than ``open()``, so a symlink
        or a path outside ``context.source_dir`` is refused before anything is read.
        See ``utils/scanned_tree.py`` for the rule. Read from the returned object; do
        not reopen ``path`` by name.

        Raises:
            TreeInputRefused: The input breaks the rule. Pass it to
                :meth:`record_refused_input`.
        """
        if self.context is None:
            raise ScannerError(f"No context provided for {self.__class__.__name__}!")
        return open_in_scanned_tree(path, self.context.source_dir)

    def record_refused_input(
        self, refusal: TreeInputRefused, member: str | None = None
    ) -> None:
        """Warn once about a refused input and keep it for the results row.

        Args:
            refusal: What :meth:`open_source_file` raised, or an equivalent built for
                an archive member.
            member: The archive member's name, when the refusal is of a member.
        """
        if member is None:
            ASH_LOGGER.warning(
                f"Skipped converter input '{refusal.path}': {refusal.reason}"
            )
        else:
            ASH_LOGGER.warning(
                f"Skipped member '{member}' of archive '{refusal.path}': "
                f"{refusal.reason}"
            )
        self.refused_inputs.append(
            RefusedInputInfo(path=refusal.path, member=member, reason=refusal.reason)
        )

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
