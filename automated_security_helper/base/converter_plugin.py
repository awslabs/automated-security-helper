"""Module containing the ConverterPlugin base class."""

from abc import abstractmethod
from pathlib import Path
from typing import (
    Annotated,
    Any,
    BinaryIO,
    ClassVar,
    Generic,
    List,
    Literal,
    TypeVar,
)
from typing_extensions import Self

from pydantic import (
    Field,
    PrivateAttr,
    ValidationError,
    ValidationInfo,
    ValidatorFunctionWrapHandler,
    field_validator,
    model_validator,
)

from automated_security_helper.base.options import ConverterOptionsBase
from automated_security_helper.base.plugin_base import PluginBase
from automated_security_helper.base.plugin_config import (
    PluginConfigBase,
    config_validated_by_declared_model,
    declared_config_model,
)
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.asharp_model import (
    FailedInputInfo,
    RefusedInputInfo,
)
from automated_security_helper.utils.log import ASH_LOGGER, NO_MARKUP
from automated_security_helper.utils.scanned_tree import (
    TreeInputRefused,
    open_in_scanned_tree,
    relative_display,
)
from automated_security_helper.utils.terminal_text import shown_on_one_line
from automated_security_helper.utils.undecodable_text import text_of_undecodable


class ConverterPluginConfigBase(PluginConfigBase):
    SECTION_SEGMENT: ClassVar[str] = "converters"
    GENERIC_SECTION: ClassVar[bool] = True

    options: Annotated[ConverterOptionsBase, Field(description="Converter options")] = (
        ConverterOptionsBase()
    )


T = TypeVar("T", bound=ConverterPluginConfigBase)

#: What an accepted input's record and log line carry as the suppression's
#: reason when the config's environment record cannot be read: a reason the
#: config file read from the environment is quoted by its reference, never its
#: value, and without the record the two cannot be told apart.
REASON_NOT_RENDERED = "the suppression's reason could not be rendered as written"


class ConverterPluginBase(PluginBase, Generic[T]):
    """Base converter plugin with some methods of the IConverter abstract class
    implemented for convenience.
    """

    config: T | ConverterPluginConfigBase | None = None
    dependencies_satisfied: bool = True
    # Why the dependency check failed, when the converter knows more than that its tool
    # is absent: for example, that the copy on PATH does not satisfy its tool_version.
    dependency_unavailable_reason: str | None = None
    # Inputs this converter declined to read during convert(). ConvertPhase copies them
    # into the converter's results row, which is what keeps a refused input visible in
    # the scan result rather than only in the log.
    refused_inputs: List[RefusedInputInfo] = Field(default_factory=list)
    # Inputs convert() set out to convert and could not. Copied into the row the same
    # way; the completeness gate counts them as lost coverage.
    failed_inputs: List[FailedInputInfo] = Field(default_factory=list)
    #: The written-form ids of the suppressions that accepted this run's failed
    #: inputs, recorded by record_failed_input as each acceptance is granted;
    #: ConvertPhase unions them into used_suppressions. Each id is recorded at
    #: the match, on the record itself (``accepted_by``) and in this list,
    #: because a re-match of the record later could answer differently: an
    #: expiring entry no longer matches the second time, and the next entry
    #: that matches the path is not the one that granted. ConvertPhase
    #: re-derives the entry from the record's path only for a record that
    #: carries no id.
    _accepted_suppression_ids: List[str] = PrivateAttr(default_factory=list)

    @field_validator("config", mode="wrap")
    @classmethod
    def _config_is_validated_by_the_declared_model(
        cls, value: Any, handler: ValidatorFunctionWrapHandler, info: ValidationInfo
    ) -> Any:
        """A converter that declares a config model is configured by that model.

        A section it refuses is a ValidationError, which ``ConvertPhase`` records
        as that converter's failure, naming the option, before it goes on with
        the others. The model validates under this field's own validation context
        (``info``), so what the converter was validated with (the stored-config
        tolerance's notes, say) reaches the model's validators as it would have
        through the union. See ``plugin_config.config_validated_by_declared_model``.
        """
        return config_validated_by_declared_model(
            cls, ConverterPluginConfigBase, value, handler, info
        )

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
        # pydantic runs model_post_init inside the model's own schema, before an
        # after-validator such as setup_paths, so the context is checked here too:
        # without it a converter built with none raised AttributeError on the
        # work directory below, and the ScannerError the validator names was
        # never reached.
        if self.context is None:
            raise ScannerError(f"No context provided for {self.__class__.__name__}!")
        if self.config is None:
            self.config = self._default_config()
        self.results_dir = self.context.work_dir.joinpath(
            self.config.name or self.__class__.__name__
        )
        return super().model_post_init(context)

    @classmethod
    def _declared_config_model(cls) -> type[ConverterPluginConfigBase] | None:
        """The config model this converter class declares, or None.

        Read from the class itself: a class taken from a value (``type(self)``)
        handed to a call is what the shown-text guard refuses in the package.
        """
        return declared_config_model(cls, ConverterPluginConfigBase)

    def _default_config(self) -> ConverterPluginConfigBase:
        """The config a converter runs with when it is given none.

        An instance of the model the converter declares
        (``ConverterPluginBase[XConfig]``), so its name, its declared ``enabled``
        default and its options' defaults apply, as they do for a configured
        run: a converter declared disabled by default stays disabled, and its
        work directory is named for the converter. The generic base only for a
        converter that declares no model, or one whose model needs a section to
        be built.
        """
        declared = self._declared_config_model()
        if declared is None:
            return ConverterPluginConfigBase()
        try:
            return declared()
        except Exception as error:
            # A model that needs a section raises ValidationError, the expected
            # shape, told at DEBUG; one whose defaults are computed can raise
            # anything, which is a defect in that default and is told at
            # WARNING so it is seen. A converter given no config must still run
            # with the generic one either way.
            if isinstance(error, ValidationError):
                detail = f"{error.error_count()} error(s)"
                log = ASH_LOGGER.debug
            else:
                detail = type(error).__name__
                log = ASH_LOGGER.warning
            log(
                f"{self.__class__.__name__}: its config model "
                f"{declared.__name__} cannot be built without a section "
                f"({detail}); using the generic one"
            )
            return ConverterPluginConfigBase()

    def configure(
        self,
        config: ConverterPluginConfigBase | None = None,
    ) -> None:
        """Configure the converter with provided configuration."""
        if config:
            self.config = config

    def validate_plugin_dependencies(self) -> bool:
        """Validate converter configuration and requirements.

        Most converter plugins are entirely Python based, so the default answers
        from the converter's own ``dependencies_satisfied``: True unless the
        converter declared otherwise. ``ConvertPhase`` assigns the answer back to
        that field, so a fixed True here overwrote a converter's own False, and
        its ``dependency_unavailable_reason`` named a missing tool the phase
        then ran the converter without.
        """
        if not self.dependencies_satisfied:
            ASH_LOGGER.debug(
                f"{self.__class__.__name__}: its dependencies are recorded as "
                "not satisfied"
                + (
                    f": {self.dependency_unavailable_reason}"
                    if self.dependency_unavailable_reason
                    else ""
                ),
                extra=NO_MARKUP,
            )
        return bool(self.dependencies_satisfied)

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
        self,
        refusal: TreeInputRefused,
        member: str | None = None,
        limit: str | None = None,
        unlisted_members: int | None = None,
    ) -> None:
        """Warn once about a refused input and keep it for the results row.

        A name read from the tree or an archive can hold bytes that are not UTF-8,
        which os.listdir and tarfile read as lone surrogates: no text a log or a
        model can hold. So the warning is shown here, once, with
        utils/terminal_text.py's shown_on_one_line, which writes a surrogate as its
        escape (``\\udce9``). Each field of the record is the text as given, with
        only its lone surrogates written as escapes (utils/undecodable_text.py);
        ``RefusedInputInfo`` and ``FailedInputInfo`` keep every string field as
        given, whitespace included, so a name that ends in a space is recorded
        with it, as the warning shown here shows it. Whatever prints the record
        shows it for its own sink.

        Args:
            refusal: What :meth:`open_source_file` raised, or an equivalent built for
                an archive member.
            member: The archive member's name, when the refusal is of a member, as
                read from the archive.
            limit: The name of the extraction-limit option the input exceeded, when
                that is why it was refused. Such a refusal leaves the scan
                incomplete; see ``RefusedInputInfo.limit``.
            unlisted_members: The record stands for this many more members of the
                archive, refused for the same reason and not listed one by one.
        """
        # NO_MARKUP: the name is the tree's, and a "[/x]" in it read as markup
        # raises inside the handler, losing the line.
        if unlisted_members is not None:
            ASH_LOGGER.warning(
                shown_on_one_line(
                    f"Skipped {unlisted_members} more members of archive "
                    f"'{refusal.path}', not listed one by one: {refusal.reason}"
                ),
                extra=NO_MARKUP,
            )
        elif member is None:
            ASH_LOGGER.warning(
                shown_on_one_line(
                    f"Skipped converter input '{refusal.path}': {refusal.reason}"
                ),
                extra=NO_MARKUP,
            )
        else:
            ASH_LOGGER.warning(
                shown_on_one_line(
                    f"Skipped member '{member}' of archive '{refusal.path}': "
                    f"{refusal.reason}"
                ),
                extra=NO_MARKUP,
            )
        self.refused_inputs.append(
            RefusedInputInfo(
                path=text_of_undecodable(refusal.path),
                member=None if member is None else text_of_undecodable(member),
                reason=text_of_undecodable(refusal.reason),
                limit=limit,
                unlisted_members=unlisted_members,
            )
        )

    def record_failed_input(
        self, path: Path | str, reason: str, kind: Literal["input", "tool"] = "tool"
    ) -> None:
        """Log an input that could not be converted and keep it for the results row.

        The path is recorded relative to the scanned tree, as a refused input's
        is, and the error is shown once here, on one line, as
        :meth:`record_refused_input` shows its warning.

        ``kind`` is "input" when the file is not one this converter could hand
        to its tool, decided before the tool runs, and "tool" for everything
        after that. An input error is accepted by a
        ``global_settings.suppressions`` entry with rule_id
        "ash-unconverted-input" whose path matches
        (utils/suppression_matcher.accepting_unconverted_input): the record
        keeps ``accepted`` True and the suppression's reason, and the
        completeness gate leaves it out. A tool failure never consults the
        suppressions.

        Args:
            path: The input, as the scan set gave it.
            reason: Why conversion failed, without the input's content.
            kind: "input" or "tool", as above.
        """
        from automated_security_helper.utils.suppression_matcher import (
            accepting_unconverted_input,
            written_suppression_reasons,
        )

        # Recording a failure must not itself fail: with no context, the path as
        # given is the best name there is.
        display = (
            relative_display(path, self.context.source_dir)
            if self.context is not None
            else Path(path).as_posix()
        )
        config = getattr(self.context, "config", None)
        global_settings = getattr(config, "global_settings", None)
        # --ignore-suppressions runs the scan as if no suppression existed, and
        # this acceptance is a suppression (scan_result_processor reads the same
        # flag for finding suppressions). Guarded as the bookkeeping below is:
        # the match reads the configured suppressions (their paths, expirations
        # and client_supplied flags), and an error there lost the input's record
        # before it was appended, the loss this method exists to prevent. On an
        # error the input is not accepted, the side that keeps the gate strict,
        # and the error's type is logged.
        accepting = None
        if kind == "input" and not getattr(self.context, "ignore_suppressions", False):
            try:
                accepting = accepting_unconverted_input(
                    display, getattr(global_settings, "suppressions", None)
                )
            except Exception as error:
                accepting = None
                ASH_LOGGER.debug(
                    "could not read the suppressions for an unconverted input, so "
                    f"it is recorded as not accepted: {type(error).__name__}"
                )
        # A reason read from the environment is quoted by its reference, as
        # every quote of a suppression's reason is (written_suppression_reasons):
        # the log line and the record both reach the results and the reports.
        # Guarded as the id bookkeeping below is: recording a failure must not
        # itself fail, and this reads the same environment record. Without the
        # guard an error here lost the accepted input's record. With the record
        # unreadable nothing says whether the reason was read from the
        # environment, so the expanded value never stands in for the written
        # one: a fixed text does.
        accepted_reason = None
        if accepting is not None:
            try:
                accepted_reason = written_suppression_reasons(config).get(
                    id(accepting), accepting.reason
                )
            except Exception as error:
                accepted_reason = REASON_NOT_RENDERED
                ASH_LOGGER.debug(
                    "could not read an accepted input's suppression reason as "
                    f"written: {type(error).__name__}"
                )
        accepted_id = None
        if accepting is not None:
            from automated_security_helper.utils.suppression_matcher import (
                recorded_suppressions,
                written_suppression_id,
            )

            # The acceptance is registered from here (see the private list's
            # comment): the entry marked used is exactly the entry that
            # matched, by its written form's id, kept on the record itself
            # (``accepted_by``) and in the private list. Registering is
            # bookkeeping, and recording a failure must not itself fail: a
            # failure here is logged and the id left unregistered, and the
            # record below lands either way, with no id, so the phase
            # re-derives its entry from its path. The cost is one entry the
            # unused-suppressions report may offer for this run; without the
            # guard the record was lost, and the jupyter loop re-recorded the
            # input as a gating tool failure.
            try:
                accepted_id = written_suppression_id(
                    accepting, recorded_suppressions(config)
                )
                self._accepted_suppression_ids.append(accepted_id)
            except Exception as error:
                accepted_id = None
                ASH_LOGGER.debug(
                    "could not register an accepted input's suppression as "
                    f"used: {type(error).__name__}"
                )
        # NO_MARKUP, as for a refused input: the name is the tree's. An accepted
        # input does not gate, so its line is informational.
        if accepting is None:
            ASH_LOGGER.error(
                shown_on_one_line(f"Could not convert '{display}': {reason}"),
                extra=NO_MARKUP,
            )
        else:
            ASH_LOGGER.info(
                shown_on_one_line(
                    f"Could not convert '{display}': {reason} (accepted by a "
                    f"suppression: {accepted_reason})"
                ),
                extra=NO_MARKUP,
            )
        self.failed_inputs.append(
            FailedInputInfo(
                path=text_of_undecodable(display),
                reason=text_of_undecodable(reason),
                kind=kind,
                accepted=accepting is not None,
                accepted_reason=(
                    None
                    if accepted_reason is None
                    else text_of_undecodable(accepted_reason)
                ),
                # Omitted rather than passed as None, so a record without an
                # id dumps as it did before the field existed
                # (``to_simple_dict`` dumps with ``exclude_unset``).
                **(
                    {}
                    if accepted_id is None
                    else {"accepted_by": text_of_undecodable(accepted_id)}
                ),
            )
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
    def convert(self) -> List[Path]:
        """Convert this converter's inputs before the scanners run.

        ``ConvertPhase`` calls this once per scan with no arguments, and always has.
        The converter finds its own inputs under ``self.context.source_dir``: the
        built-ins take the scan set (``utils.get_scan_set.scan_set``, which applies
        ``.gitignore`` and ``.ignore`` files) and skip the config's
        ``global_settings.ignore_paths``. It reads each input through
        :meth:`open_source_file` and writes its output under ``self.results_dir``.

        Returns the paths written, which the scanners receive as the ``converted``
        target. Return an empty list when there was nothing to convert.

        This declared ``convert(self, target)`` until the declaration was made to
        match the call. A converter written to that form, or any ``convert()`` that
        requires an argument, is refused: its row records a failure that names it
        and says to declare ``convert(self)``.
        """
