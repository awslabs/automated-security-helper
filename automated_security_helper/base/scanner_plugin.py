from datetime import datetime, timezone
import json
import logging
import os
import re
import shlex
from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.plugin_base import (
    PluginBase,
    read_log_bounded,
    shown_excerpt,
    worse_exit_code,
)
from automated_security_helper.base.plugin_config import (
    PluginConfigBase,
    config_validated_by_declared_model,
)
from automated_security_helper.base.uv_tool_mixin import (
    guarded_values,
    guarded_values_read,
)
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason, ToolArgs
from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import CycloneDXReport
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Invocation,
    SarifReport,
)
from automated_security_helper.utils.get_shortest_name import get_shortest_name
from automated_security_helper.utils.error_text import (
    error_text,
    shown_tool_stderr,
    text_without_values,
    timeout_limit_token,
    traceback_text,
)
from automated_security_helper.utils.log import ASH_LOGGER, NO_MARKUP, delivers
from automated_security_helper.utils.subprocess_utils import (
    COULD_NOT_STOP_ENDING,
    SPAWN_FAILURE_RETURNCODE,
    WAS_KILLED_ENDING,
    exit_status,
    find_executable,
    flagged_returncode,
    in_tree_refusal,
    is_exit_code,
    path_independent_dirs,
)

from pydantic import (
    Field,
    PrivateAttr,
    ValidationInfo,
    ValidatorFunctionWrapHandler,
    field_validator,
)
from typing import (
    Annotated,
    Any,
    ClassVar,
    Dict,
    Generic,
    Iterable,
    List,
    Literal,
    Optional,
    Sequence,
    Set,
    Tuple,
    TypeVar,
)
from abc import abstractmethod

# Pattern for valid CLI flag keys: one or two leading dashes followed by
# a letter, then alphanumerics/underscores/hyphens. Optionally followed by
# '=' and a value (e.g., --exclude="path1,path2" or --skip-path=".venv/").
# Anchored with \Z: "$" also matches just before a trailing newline, which
# would let a key ending in one through to the tool's command line.
_VALID_FLAG_KEY_PATTERN = re.compile(r"^-{1,2}[A-Za-z][A-Za-z0-9_\-]*(=.*)?\Z")
from pathlib import Path
from automated_security_helper.utils.output_excerpt import head_and_tail

# How much of a tool's stderr goes into the failure message. The full text stays
# in the stderr log file, whose path the message names, so this bounds the
# exception without losing anything.
_STDERR_EXCERPT_LIMIT = 2000
#: The largest results file a rejected run's notifications are read from.
_NOTIFICATIONS_READ_LIMIT = 5 * 1024 * 1024
#: The most of a tool's results file the template scan reads (``_read_results_file``);
#: a larger one is refused with its size rather than read without bound.
_RESULTS_FILE_READ_LIMIT = 1 << 30


def _error_notifications(results_file: Path, values: Iterable[str] = ()) -> str:
    """The text of the error-level toolExecutionNotifications in a SARIF file.

    For a rejected run, to say why it failed; nothing read here is graded. Best
    effort: a file that is missing, not a regular file, larger than
    _NOTIFICATIONS_READ_LIMIT or not SARIF gives "". Read under fs_guard's
    reader semantics (``read_bytes_at_most``): no link is followed at the name,
    a FIFO left there cannot block the open, anything but a regular file is
    refused, and the read stops one byte past the limit however the file grows.
    JSON nested deeper than the interpreter allows is not SARIF either. The
    text is the tool's own, so a configured value it
    echoes (a path it could not read, say) is redacted with *values*, the same
    values the stderr excerpt is redacted with, BEFORE the cut to
    _STDERR_EXCERPT_LIMIT: a cut first could leave half a value in the clear.
    """
    from automated_security_helper.utils.sandbox.fs_guard import read_bytes_at_most

    try:
        raw = read_bytes_at_most(results_file, _NOTIFICATIONS_READ_LIMIT + 1)
        if len(raw) > _NOTIFICATIONS_READ_LIMIT:
            return ""
        data = json.loads(raw.decode("utf-8", errors="replace"))
    except (OSError, ValueError, RecursionError):
        return ""

    def items(value):
        return value if isinstance(value, list) else []

    texts = []
    runs = data.get("runs") if isinstance(data, dict) else None
    for run in items(runs):
        invocations = run.get("invocations") if isinstance(run, dict) else None
        for invocation in items(invocations):
            notes = (
                invocation.get("toolExecutionNotifications")
                if isinstance(invocation, dict)
                else None
            )
            for note in items(notes):
                if not isinstance(note, dict) or note.get("level") != "error":
                    continue
                message = note.get("message")
                text = message.get("text") if isinstance(message, dict) else None
                if isinstance(text, str) and text.strip():
                    texts.append(text.strip())
    joined = text_without_values(" | ".join(texts), values)
    if len(joined) > _STDERR_EXCERPT_LIMIT:
        joined = joined[:_STDERR_EXCERPT_LIMIT] + " ...[truncated]"
    return joined


# The per-flag codes a codeless flagged response judges by live beside the
# flags themselves: subprocess_utils.flagged_returncode, shared with
# plugin_base's two response-dict readers so the three cannot drift.


class _RejectedResultError(ScannerError):
    """The error ``_refuse_rejected_exit_code`` raises for a rejected result.

    The failure description tells a rejected result from any other failure by
    this type: its exit code is outside the scanner's accepted set, so its
    outputs, the stderr log among them, are not read for the message.
    """


def _changed_window(joined: str, redacted: str, margin: int) -> Tuple[int, int]:
    """The offsets in *joined* between which *redacted* differs from it.

    The common prefix and the common suffix of the two lines lie outside every
    redacted span, except that a span's replacement can share its first or
    last characters with the text it replaced, so the window is widened by
    *margin* (the replacement's length) on each side.
    """
    shortest = min(len(joined), len(redacted))
    prefix = 0
    while prefix < shortest and joined[prefix] == redacted[prefix]:
        prefix += 1
    suffix = 0
    while suffix < shortest - prefix and joined[-1 - suffix] == redacted[-1 - suffix]:
        suffix += 1
    return max(prefix - margin, 0), min(len(joined) - suffix + margin, len(joined))


def _arguments_in_joined_redactions(
    arguments: List[str],
    values: Iterable[str],
    redacted: Optional[str] = None,
) -> List[bool]:
    """Which of *arguments* take part in a redaction only their joined text makes.

    *arguments* are already redacted one at a time. Redacting the joined
    command line again hides a value that spans two entries, or that matches
    only in the quoting ``shlex.join`` adds.

    An entry takes part when it lies inside a redacted span. That is tested
    on the line itself: the entry's quoted text is swapped for a filler no
    value can match, the line is redacted again, and the filler is swapped
    back. An entry inside a span is always reported; one beside a cut marker
    that starts a span may be reported too. Spans that overlap are merged
    into one marker, so counting markers would miss the entries at the two
    ends of a chain; this test does not. When the second pass changed the
    line but no entry can be named, every entry is reported, so nothing the
    pass hid stays bare.

    *redacted* is the joined line already redacted, for a caller that has
    computed it (``shlex.join`` of *arguments* through ``text_without_values``);
    without it the line is redacted here. Only the entries that overlap the
    part of the line the redaction changed are probed: an entry wholly before
    the first changed character or after the last cannot be inside a span.
    """
    from automated_security_helper.config.config_validator import REDACTED

    values = list(values)
    pieces = [shlex.quote(argument) for argument in arguments]
    joined = " ".join(pieces)
    if redacted is None:
        redacted = text_without_values(joined, values)
    if redacted == joined:
        return [False] * len(arguments)
    window_start, window_end = _changed_window(joined, redacted, len(REDACTED))
    covered = []
    start = 0
    for index, piece in enumerate(pieces):
        end = start + len(piece)
        overlaps = end > window_start and start < window_end
        start = end + 1
        if not overlaps:
            covered.append(False)
            continue
        filler = "\x01" * max(len(piece), 1)
        probe = " ".join(filler if i == index else p for i, p in enumerate(pieces))
        restored = text_without_values(probe, values).replace(filler, piece, 1)
        covered.append(restored != redacted)
    return covered if any(covered) else [True] * len(arguments)


def redacted_command_record(
    final_args: Sequence[str], values: Iterable[str]
) -> Tuple[str, List[str]]:
    """The recorded ``(command_line, arguments)`` for a command and its values.

    Each argument is redacted before the join: ``shlex.join`` respells an
    argument that holds a single quote, and a value would then no longer match
    in the joined text. The joined text is redacted again, so a value a scanner
    split across two arguments, which no single argument holds, is hidden as
    well. An argument that takes part in a redaction the joined text made is
    hidden in the argument list too: the list would otherwise hold the bare
    halves of a split value. The list leaves out the command itself.
    """
    from automated_security_helper.config.config_validator import REDACTED

    values = list(values)
    per_argument = [text_without_values(str(a), values) for a in final_args]
    command_line = text_without_values(shlex.join(per_argument), values)
    crossing = _arguments_in_joined_redactions(
        per_argument, values, redacted=command_line
    )
    arguments = [
        REDACTED if hidden else text
        for text, hidden in zip(per_argument[1:], crossing[1:])
    ]
    return command_line, arguments


def values_hook_failure_line(class_name: str, failure: str, argument_count: int) -> str:
    """The warning for a scan whose values hook gave no usable answer.

    Nothing can be redacted then, so the records hold only the command's name;
    the line says so without naming any argument.
    """
    return (
        f"{class_name}: the values hook {failure}, so the recorded command "
        f"line holds only the command name and {max(argument_count, 0)} "
        "argument(s) were not recorded."
    )


def plugin_missing_dependency_reason(
    plugin_instance: Any,
    values: Iterable[str] = (),
    *,
    when_it_raises: str = "recording the generic reason",
) -> Optional[str]:
    """What the plugin's own ``missing_dependency_reason()`` says, or None.

    The one reader of that hook: the scan's MISSING row
    (``scan_phase._missing_dependency_reason``), the executor's reason for a
    scan that found its dependencies unavailable
    (``scanner_executor._missing_reason_after_scan``) and ``ash dependencies
    install``'s check-refused line all ask it, so they quote the same text. A
    scanner plugin is not required to inherit ``ScannerPluginBase``, and a test
    double answers every method with a Mock, so only a non-empty string is a
    reason; a hook that raises gives none, and its exception is logged at
    DEBUG, with ``when_it_raises`` saying what the caller does instead.

    Returned as the plugin gave it: each caller redacts it with ``values`` and
    writes the home directory as ``~`` where the text leaves ash.log.
    """
    explain = getattr(plugin_instance, "missing_dependency_reason", None)
    if not callable(explain):
        return None
    try:
        reason = explain()
    except Exception as e:
        # error_text with the caller's environment values: the hook's
        # exception can name a configured value.
        ASH_LOGGER.debug(
            f"{type(plugin_instance).__name__}.missing_dependency_reason() "
            f"raised {type(e).__name__}: {error_text(e, values)}; "
            f"{when_it_raises}",
            extra=NO_MARKUP,
        )
        return None
    return reason if isinstance(reason, str) and reason else None


def plugin_explains_its_own_refusal(plugin_instance: Any, reason: str) -> bool:
    """Whether *reason*, the text ``missing_dependency_reason()`` gave, is the
    plugin's own words: its check recorded one (``dependency_unavailable_reason``,
    which a sandbox refusal also fills), or its hook gave text other than the
    base hook's generic answer.

    False for that generic answer (its command not found on PATH, or a check
    that failed without saying why), whether the plugin keeps
    ``ScannerPluginBase``'s hook or an override of it falls back to
    ``super()``: the text says whose words it is, not the class the method is
    defined on. A plugin that does not inherit ``ScannerPluginBase`` has no
    generic answer, so its hook's text is its own.
    """
    recorded = getattr(plugin_instance, "dependency_unavailable_reason", None)
    if isinstance(recorded, str) and recorded:
        return True
    if not isinstance(plugin_instance, ScannerPluginBase):
        return True
    try:
        generic = _generic_missing_dependency_reason(plugin_instance)
    except Exception:  # noqa: BLE001 -- the base hook's own answer raised too
        return True
    return reason != generic


def _generic_missing_dependency_reason(plugin: "ScannerPluginBase") -> str:
    """The base ``missing_dependency_reason()``'s answer for a scanner that
    recorded no reason: its command not found on PATH, or a check that failed
    without saying why. Generic: it names no cause the plugin knows, and
    :func:`plugin_explains_its_own_refusal` tells it apart by this text."""
    name = getattr(plugin.config, "name", None) or plugin.__class__.__name__
    if (
        isinstance(plugin.command, str)
        and plugin.command
        and find_executable(plugin.command) is None
    ):
        if getattr(plugin, "use_uv_tool", False):
            from automated_security_helper.utils.uv_tool_runner import find_uv_or_none

            if find_uv_or_none() is None:
                # The tool runs through uv, so its absence from PATH is not
                # the cause: uv itself is what is missing.
                return (
                    f"its tool {plugin.command} runs through uv, and uv was "
                    "not found; install uv or exclude "
                    f"{name} with --exclude-scanners"
                )
        searched = ", ".join(
            directory.as_posix() for directory in path_independent_dirs()
        )
        return (
            f"its tool {plugin.command} was not found on PATH"
            + (f" or in {searched}" if searched else "")
            + "; install it with `ash dependencies install` or exclude "
            f"{name} with --exclude-scanners"
        )
    return (
        f"its dependency check failed ({type(plugin).__name__}."
        "validate_plugin_dependencies() returned False); ash.log has the "
        "scanner's own message"
    )


class ScannerPluginConfigBase(PluginConfigBase):
    SECTION_SEGMENT: ClassVar[str] = "scanners"
    GENERIC_SECTION: ClassVar[bool] = True

    options: Annotated[ScannerOptionsBase, Field(description="Scanner options")] = (
        ScannerOptionsBase()
    )


T = TypeVar("T", bound=ScannerPluginConfigBase)


class ScannerPluginBase(PluginBase, Generic[T]):
    """Base class for all scanner plugins.

    Plugin implementations
    """

    config: T | ScannerPluginConfigBase | None = None
    dependencies_satisfied: bool = False

    # The content database cache this scanner's scan was pointed at, set by the
    # scanner when it resolves one (grype, trivy-repo), and handed to the staleness
    # check by content_database_probe_context so the check reads what the scan read.
    _content_db_cache_dir: Optional[Path] = PrivateAttr(default=None)

    dependency_unavailable_reason: Annotated[
        str | None,
        Field(
            description=(
                "Why this scanner cannot run, recorded during construction rather "
                "than raised from it. None when nothing blocks it."
            )
        ),
    ] = None
    """Why this scanner cannot run, discovered while it was being constructed.

    A FIELD RATHER THAN AN EXCEPTION, AND THAT IS THE WHOLE POINT. Construction
    runs ``_process_config_options`` from ``model_post_init``, so a subclass that
    raised there destroyed its own instance. ``ScanPhase`` creates every scanner
    inside a ``try/except Exception`` that logs one line and does not append to
    ``scanner_instances`` -- and both hooks the repository built for "cannot run
    here", ``validate_plugin_dependencies`` and ``unsupported_platform_reason``,
    are consulted only on entries in that list. So a scanner that refused at
    construction did not land as MISSING or SKIPPED; it left the run entirely,
    with the five status counters summing correctly over the scanners that
    remained. A consumer could not tell that scan from a complete one.

    Recording the reason instead keeps the instance, which is what lets the
    existing MISSING path do its job. It carries the remediation text, so the
    operator still gets the guidance the exception used to carry -- see
    ``GrepScannerBase._configure_offline_mode``, where the offline-cache verdict
    now lands.

    DISTINCT FROM ``unsupported_platform_reason``, which is a statement about the
    platform and resolves to SKIPPED because no install would help. This is
    "something this run needs is absent", which is MISSING: the operator is being
    told to fix something, and the completeness gate should fail until they do.
    """

    tool_type: ScannerToolType = ScannerToolType.UNKNOWN
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.UNKNOWN

    #: Whether this scanner needs nothing but Python: its tool is a Python package
    #: ASH runs through uv or imports. ``--python-only`` runs exactly the scanners for
    #: which ``is_python_only()`` is True. None, the default, derives the answer; see
    #: ``is_python_only``. Every scanner ASH ships states it.
    python_only: ClassVar[Optional[bool]] = None
    #: The ``skipped_reason`` for a target this scanner's ``scan()`` attempted none of.
    #: None, the default, asks ``nothing_to_scan_reason()``. A scanner whose hook is
    #: expensive (cfn-nag and cdk-nag parse every candidate in both trees) states the
    #: reason here instead: scan() has just looked at every candidate of that target.
    nothing_scanned_reason: ClassVar[Optional[str]] = None
    #: Whether this scanner's ``validate_plugin_dependencies`` can start its tool
    #: where a PATH lookup does not find it: the check runs a library in-process,
    #: or resolves the tool its own way. ``ash dependencies install`` asks the check
    #: only for a scanner that sets this True, and judges every other one by the
    #: PATH lookup (and a scanner run through ``uv tool run`` by uv's tool list).
    #: Leave it False when the check is the base class's PATH lookup: asking it
    #: again could only agree, or report a tool present that nothing can start.
    resolves_tool_off_path: ClassVar[bool] = False
    #: The same reason for the target scan() just looked at, when it differs from the
    #: class's: cfn-nag and cdk-nag set it when they passed over a candidate they could
    #: not parse, and reset it at the top of each scan(). Read before the class value.
    _nothing_scanned_reason: Optional[str] = PrivateAttr(default=None)
    #: Files this scanner asked ASH to own (``_neutral_tool_file``), by path, with
    #: the text each holds. Written when the arguments are resolved.
    _neutral_files: Dict[str, str] = PrivateAttr(default_factory=dict)

    command: Annotated[
        str | None,
        Field(
            description="The command to invoke the scanner, typically the binary or path to a script"
        ),
    ] = None
    subcommands: Annotated[
        List[str],
        Field(
            description="Subcommands to include when invoking the scanner, e.g. ['scan'] is needed as the subcommand for 'semgrep' as Semgrep supports multiple subcommands, but we are specifically interested in running a scan."
        ),
    ] = []
    args: Annotated[
        ToolArgs,
        Field(
            description="Specialized arguments to pass to the scanner command. Includes an `extra_args` field which accepts a dictionary of arbitrary arguments to pass to the scanner. These are not configurable at scan time."
        ),
    ] = ToolArgs()

    results_file: Annotated[
        Path | None,
        Field(
            description="The path to the results file, if any. This is set by the scanner plugin after the scan is complete."
        ),
    ] = None

    use_uv_tool: Annotated[
        bool,
        Field(
            description="Flag to indicate whether this scanner should use UV tool execution instead of direct command execution"
        ),
    ] = False

    uv_tool_install_commands: Annotated[
        List[str],
        Field(
            description="List of UV tool install commands to execute for this scanner"
        ),
    ] = []

    @field_validator("config", mode="wrap")
    @classmethod
    def _config_is_validated_by_the_declared_model(
        cls, value: Any, handler: ValidatorFunctionWrapHandler, info: ValidationInfo
    ) -> Any:
        """A scanner that declares a config model is configured by that model.

        A section it refuses, such as an opengrep ``sha256`` that is not a
        digest, is a ValidationError, which ``ScanPhase`` records as that
        scanner's ERROR, naming the option, before it goes on with the others.
        The declared model validates under the validation context the field was
        given. See ``plugin_config.config_validated_by_declared_model``.
        """
        return config_validated_by_declared_model(
            cls, ScannerPluginConfigBase, value, handler, info
        )

    def model_post_init(self, context):
        if self.config is None:
            raise ScannerError(
                f"Unable to initialize {self.__class__.__name__}! Configuration is empty."
            )

        # Use context if provided, otherwise fall back to instance attributes
        if self.context is None:
            raise ScannerError(f"No context provided for {self.__class__.__name__}!")
        ASH_LOGGER.trace(f"Using provided context for {self.__class__.__name__}")

        # Set up results directory based on output directory
        self.results_dir = self.context.output_dir.joinpath("scanners").joinpath(
            self.config.name
        )

        self._process_config_options()

        ASH_LOGGER.trace(
            f"Scanner {self.config.name} initialized with source_dir={self.context.source_dir}, output_dir={self.context.output_dir}"
        )
        return super().model_post_init(context)

    def _scanner_offline(self) -> bool:
        """Whether this scanner runs offline, resolved at the moment it is asked.

        Precedence, highest first:

        1. ASH's offline mode -- ``--offline`` (which sets ``ASH_OFFLINE`` before any
           scanner is built), ``ASH_OFFLINE`` in the environment, or an image built
           with ``--offline``. It applies to every scanner and cannot be switched off
           for one of them.
        2. The scanner's own ``options.offline: true``, which forces that scanner
           offline while the rest of the run stays online.

        ``options.offline: false``, the default, means "follow ASH". It does not
        re-enable the network under ``--offline``: ``ash config init`` and the
        documented examples write ``offline: false`` for every scanner that has the
        option, so letting it win would put those configurations online during an
        air-gapped run.

        Why the global mode is read here and not baked into the option: the option
        used to default to ``is_offline_mode()``, evaluated when the config object
        was built. ``ScannerConfigSegment`` builds its default scanner configs when
        ``ash_config`` is imported, which in local mode is before ``--offline`` sets
        ``ASH_OFFLINE``, so ``ash scan --offline`` left checkov, grype, syft and the
        rest with ``offline=False`` and they went to the network. Config round-trips
        through ``model_dump`` and ``model_validate`` carry that stale value forward,
        so the only reliable reading is one taken when the scanner uses it.
        """
        from automated_security_helper.core.constants import is_offline_mode

        if is_offline_mode():
            return True
        options = getattr(self.config, "options", None)
        return getattr(options, "offline", False) is True

    def unsupported_platform_reason(self) -> str | None:
        """Why this scanner cannot run on the current platform, or None if it can.

        A DIFFERENT QUESTION FROM ``validate_plugin_dependencies``, AND THE WHOLE POINT
        OF SEPARATING THEM. That method answers "is the tool available here", and it
        answers it with one boolean -- so a scanner that returned False because its
        platform is not supported was indistinguishable from one whose dependencies were
        genuinely absent. ScanPhase classified both as MISSING, and MISSING means "this
        scanner was supposed to run and did not", which fails the completeness gate.

        The measured case is semgrep on Windows. It publishes no Windows build, said so
        in its own log line ("Semgrep is not supported on Windows and will be skipped"),
        and was then recorded MISSING -- while its installer status was INSTALLED with a
        real path, so nothing was actually unprovisioned. Every Windows leg would have
        failed the completeness gate for a scanner that is permanently and deliberately
        absent there.

        A scanner overriding this is stating a fact about the PLATFORM, not about this
        host's installation. Return a reason only when no amount of installing would
        help; a tool that is merely not installed yet belongs in
        ``validate_plugin_dependencies``, where MISSING is the correct verdict and the
        remediation is to install it.

        The return is a plain string so the reason reaches the report and the log rather
        than being reconstructed from a boolean at the call site.
        """
        return None

    def _setting_names(self, config: Any) -> str:
        """Which settings ``config``, this scanner's section, holds, never their
        values, for the debug lines: a value can be one the config file read from
        the environment, or a credential (``config/environment_record.py``)."""
        from automated_security_helper.config.environment_record import (
            setting_names,
        )

        ash_config = getattr(self.context, "config", None)
        return setting_names(
            config,
            getattr(ash_config, "_environment_references", ()) or (),
            at=("scanners", str(getattr(self.config, "name", "") or "")),
        )

    def validate_plugin_dependencies(self) -> bool:
        """Check whether the scanner's command is available on PATH.

        Subclasses with more complex requirements (UV tool management,
        version checks, non-standard binaries) should override this.

        ``dependency_unavailable_reason`` is consulted first so a construction-time
        verdict is not silently outvoted by a PATH probe: a grep-family scanner in
        offline mode with no rule cache has its binary on PATH and would otherwise
        answer True, run, and report an offline scan against online defaults.

        A subclass that chains to this method gets that check for free. One that
        overrides without chaining does NOT, and nothing outside the scanner plugins
        restores it: the field is read only here and in the plugin modules, never by
        the phases. ``ScanPhase`` reads the sibling ``unsupported_platform_reason``,
        which is a different question, so this method's return value is the only
        route a recorded reason has to the decision. ``missing_dependency_reason``
        reads the field too, but only to word the MISSING row once this method has
        returned False; it never makes a scanner MISSING.

        For the grep family the gap is closed at the other end instead.
        ``GrepScannerBase`` declares this method final and pushes customisation into
        ``_validate_tool_dependencies``, and ``_execute_scan`` raises
        ``ScannerError`` on a recorded reason -- so a scanner of that family which
        reached execution anyway fails closed rather than reporting an offline scan
        against online defaults. A scanner outside that family which overrides this
        method without chaining has neither guard.
        """
        if self.dependency_unavailable_reason:
            return False
        found = find_executable(self.command)
        if found is None and self.command:
            # A copy inside the scanned tree was refused: say so in the MISSING row,
            # with the path and how to allow it, rather than "not installed".
            refusal = in_tree_refusal(self.command)
            if refusal is not None:
                self.dependency_unavailable_reason = refusal
        return found is not None

    def is_python_only(self) -> bool:
        """Whether this scanner needs nothing but Python; see ``python_only``.

        The class's ``python_only`` when it states one. Otherwise True only when the
        scanner runs its tool through uv and the install-based check of
        ``PluginBase.is_python_only`` holds. That base check alone answered True for
        any scanner that declared no dependencies, so a scanner that runs a native
        tool and said nothing about it counted as Python-only: snyk-code, ferret-scan
        and cdk-nag (which needs Node.js) all ran under ``--python-only``. A scanner
        whose tool is not run through uv has to say it is Python-only.
        """
        declared = type(self).python_only
        if declared is not None:
            return declared
        return bool(self.use_uv_tool) and super().is_python_only()

    def nothing_to_scan_reason(self) -> str | None:
        """Why this scanner has nothing to scan in this run, or None.

        For a scanner that picks its own input out of the scan set -- cdk-nag and
        cfn-nag their CloudFormation templates, npm-audit its lockfiles -- and can
        do that without its tool. ``ScanPhase`` asks this when the dependency check
        has failed: a reason makes the scanner SKIPPED instead of MISSING, because
        an absent tool cost this scan nothing. The executor also asks it for the
        reason of a scanner that ran and evaluated no target.

        Return a reason only from the same selection ``scan()`` makes, over both
        the source tree and the converted tree, and only when it selects nothing.
        A reason returned for a tree that does hold input would hide a MISSING
        scanner from the completeness gate. None, the default, means "cannot tell",
        and keeps MISSING.
        """
        return None

    def missing_dependency_reason(self) -> str:
        """Why ``validate_plugin_dependencies`` said no, for the MISSING row.

        Asked only after the check returned False, and only to explain it: what this
        returns never decides whether the scanner runs. A scanner whose check fails
        for a reason other than its command being absent (cdk-nag needs node and the
        CDK packages, not its ``python`` command) overrides this to name it.

        In order: the reason the scanner recorded in
        ``dependency_unavailable_reason``, then its command not being found, then a
        message that the check failed without saying why.
        """
        if (
            isinstance(self.dependency_unavailable_reason, str)
            and self.dependency_unavailable_reason
        ):
            return self.dependency_unavailable_reason
        return _generic_missing_dependency_reason(self)

    def content_databases_in_use(self) -> list:
        """The declared content databases this scanner's last scan read.

        Defaults to every entry in ``utils/content_databases.py`` that this scanner's config
        name reads: the entry's ``scanner``, or one of its ``also_read_by``. A scanner that reads its database only in some modes -- the
        semgrep and opengrep offline rulesets -- overrides this to say so. The executor
        holds each one to its declared age bound after the scan; see
        ``utils/content_db_staleness.py``.
        """
        from automated_security_helper.utils.content_databases import CONTENT_DATABASES

        name = str(getattr(self.config, "name", "") or "")
        return [entry for entry in CONTENT_DATABASES if name in entry.readers]

    def content_database_probe_context(self):
        """How to read this scanner's database, as its scan did.

        Its binary; the env its scan ran with (the scanner's own ``extra_env`` over
        the process environment); the cache directory its scan was pointed at, when
        it recorded one; and a working directory outside the scanned tree
        (``path_trust.cwd_outside_scanned_tree``), so the probe reads no config file
        the scanned repository wrote. See "What the probes read" in
        ``utils/content_db_staleness.py``.
        """
        from automated_security_helper.config.path_trust import (
            cwd_outside_scanned_tree,
        )
        from automated_security_helper.utils.content_db_staleness import (
            ProbeContext,
            probe_env,
        )

        # _values_to_redact is an overridable hook that can raise, and this
        # builder deliberately lets it: the one caller (content_db_staleness
        # .assess_scanner, which never raises) catches anything raised
        # here and records an unmeasurable verdict for each declared
        # database, so no probe runs and no probe text is shown. Guarding
        # here with ``values=()`` would be worse -- the probe would run and
        # its excerpts would print unredacted. A hook that gave no usable
        # answer is refused the same way as one that raised.
        read = guarded_values_read(self)
        if read.values is None:
            raise RuntimeError(f"the plugin's values hook {read.failure()}")
        cache = self._content_db_cache_dir
        cwd = cwd_outside_scanned_tree(
            self.context.source_dir,
            results_dir=self.results_dir or self.context.output_dir,
            source_dir=self.context.source_dir,
            config=getattr(self.context, "config", None),
        )
        return ProbeContext(
            env=probe_env(getattr(self, "extra_env", None)),
            executable=find_executable(self.command) if self.command else None,
            cache_dir=cache.as_posix() if cache is not None else None,
            cwd=cwd.as_posix(),
            values=read.values,
        )

    def _process_config_options(self) -> None:
        """By default, returns False to indicate that the scanner did not perform any
        configuration option processing.

        Override this method if you need to process custom options before
        arguments are resolved!

        This method is called at the start of `self._resolve_arguments(target)` before
        `self.args.extra_args` is processed. Use this method to populate additional
        argument key/value pairs where needed.
        """

    def _neutral_tool_file(self, name: str, content: str) -> str:
        """The path of a file ASH owns, to hand a tool in place of one it would
        discover from the scanned tree.

        A tool run from the source directory reads its own config file by name
        from there when it is given none (``.syft.yaml``, ``.grype.yaml``,
        ``.bandit``), so a scan that refuses the configured file and passes
        nothing leaves the choice to the repository. The file lives in the
        results directory and sets nothing. The path is returned now and the
        file is written when the arguments are resolved, so building a scanner
        writes nothing.
        """
        if self.results_dir is None:
            raise ScannerError(f"{self.__class__.__name__} has no results directory")
        path = (Path(self.results_dir).absolute() / name).as_posix()
        self._neutral_files[path] = content
        return path

    def _write_neutral_files(self) -> None:
        """Write the files ``_neutral_tool_file`` named."""
        from automated_security_helper.utils.sandbox.fs_guard import open_for_write

        for path, content in self._neutral_files.items():
            written = Path(path)
            written.parent.mkdir(parents=True, exist_ok=True)
            with open_for_write(written) as handle:
                handle.write(content)

    def _resolve_arguments(
        self, target: str | Path, results_file: str | Path | None = None
    ) -> List[str]:
        """Resolve any configured options into command line arguments.

        Args:
            target: Target to scan

        Returns:
            List[str]: Arguments to pass to scanner
        """

        # # Process configuration options to populate extra_args
        # self._process_config_options()
        self._write_neutral_files()

        args = [
            self.command,
            *self.subcommands,
            self.args.format_arg,
            self.args.format_arg_value,
        ]

        for tool_extra_arg in self.args.extra_args:
            if not _VALID_FLAG_KEY_PATTERN.match(tool_extra_arg.key):
                ASH_LOGGER.warning(
                    f"Skipping extra arg with invalid key: {tool_extra_arg.key!r}. "
                    "Keys must match pattern: -<letter> or --<letter>[alphanumeric_-]*"
                )
                continue
            # An extra arg's value may be a number or a bool (ToolExtraArg),
            # and a spawn takes text only: handed over as it was, the tool
            # "could not start". A number is spelled as text. A bool is the
            # switch's own state, not a word: True is the flag alone and False
            # leaves it out. Spelled as a word after the key, a store_true flag
            # would run ON for "false" and leave the word behind as a stray
            # positional, which bandit reads as a target. A tool whose flag
            # takes the word "true" or "false" is given that word as text.
            value = tool_extra_arg.value
            if value is False:
                continue
            args.append(tool_extra_arg.key)
            if value is True:
                value = None
            elif value is not None and not isinstance(value, str):
                value = str(value)
            args.append(value)

        args.extend(
            [
                self.args.scan_path_arg,
                Path(target).as_posix(),
                self.args.output_arg,
                (
                    Path(results_file).as_posix()
                    if results_file is not None
                    else (
                        Path(self.results_file).as_posix()
                        if self.results_file is not None
                        else None
                    )
                ),
            ]
        )
        return [item for item in args if item is not None and str(item).strip() != ""]

    def _pre_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        config: Optional[ScannerPluginConfigBase] = None,
        *args,
        **kwargs,
    ) -> bool:
        """Perform pre-scan setup.

        Args:
            target: Target to scan
            options: Optional scanner-specific options
        """
        self.start_time = datetime.now(timezone.utc)
        self.results_dir.mkdir(parents=True, exist_ok=True)

        self.dependencies_satisfied = self.validate_plugin_dependencies()

        if not self.dependencies_satisfied:
            self._plugin_log(
                "Scanner is missing dependencies and will be skipped.",
                target_type=target_type,
                level=logging.WARNING,
                append_to_stream="stderr",
            )
            return False

        self._plugin_log(
            "Starting scan",
            target_type=target_type,
            level=logging.INFO,
        )
        self._plugin_log(
            f"self.config setting: {self._setting_names(self.config)}",
            target_type=target_type,
            level=logging.DEBUG,
        )
        # Redacted: the whole config is dumped, a configured option can come
        # from the environment, and under --debug the console shows DEBUG
        # lines (file logs stay at INFO; the console level is what rises).
        # Dumped as written first: a short number prints bare in a dump
        # (scan_timeout=67), which redaction leaves. The dumps and the work
        # behind them (model_dump, the as-written rewrite, the redaction) run
        # only when a DEBUG line would reach a handler (utils.log.delivers):
        # _pre_scan runs on every scan of every scanner. _plugin_log logs
        # through _log, which skips the logger's own level, so the question is
        # the handlers' levels -- the CLI's logger sits at TRACE with its file
        # handlers at INFO, and a DEBUG handler under an INFO logger still gets
        # the dumps.
        dumps_enabled = delivers(ASH_LOGGER, logging.DEBUG)
        dump_values: tuple = ()
        if dumps_enabled:
            # The ONE guarded read of the overridable values hook for the two
            # dumps (_values_to_redact's guarding rule): they are best-effort
            # DEBUG records, so a raising hook skips them -- never an empty
            # value set, which would print what the values would have hidden
            # -- and the scan itself goes on. An override that answers None,
            # or anything that is not a value set at all, is the same broken
            # answer as a raise: the normalizer reads such an answer as no
            # values, which is right for the redaction READS elsewhere but
            # here would be the license to print the dumps in clear, so the
            # gate takes the conservative arm instead. The read is
            # guarded_values: an empty value set means no values, a bare
            # string is one value, never its characters, and an iterable
            # that raises mid-iteration skips the dumps.
            guarded = guarded_values(self)
            if guarded is None:
                dumps_enabled = False
            else:
                dump_values = guarded
        if dumps_enabled:
            self._plugin_log(
                text_without_values(
                    f"self.config: {self._config_as_written(self.config.model_dump(by_alias=True))}",
                    dump_values,
                ),
                target_type=target_type,
                level=logging.DEBUG,
            )
        if config is not None:
            if hasattr(config, "model_dump") and callable(config.model_dump):
                config = config.model_dump(by_alias=True)
            self.config = self.config.__class__.model_validate(config)
        self._plugin_log(
            f"config setting: {self._setting_names(config)}",
            target_type=target_type,
            level=logging.DEBUG,
        )
        if dumps_enabled:
            self._plugin_log(
                text_without_values(
                    f"config: {self._config_as_written(config)}",
                    dump_values,
                ),
                target_type=target_type,
                level=logging.DEBUG,
            )

        if not Path(target).exists():
            # Text, not markup: the executor logs this and the scan prints it.
            raise ScannerError(
                f"({self.config.name or self.__class__.__name__} @ {target_type}) "
                f"Target {target} does not exist!"
            )

        # Ensure all required directories exist
        self.context.work_dir.mkdir(parents=True, exist_ok=True)
        if self.results_dir:
            self.results_dir.mkdir(parents=True, exist_ok=True)

        # Log the paths being used
        self._plugin_log(
            f"Using source_dir: {self.context.source_dir}",
            f"Using output_dir: {self.context.output_dir}",
            f"Using work_dir: {self.context.work_dir}",
            f"Using results_dir: {self.results_dir}",
            target_type=target_type,
            level=logging.DEBUG,
        )

        return True

    def _post_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
    ) -> None:
        """Perform pre-scan setup.

        Args:
            target: Target to scan
            options: Optional scanner-specific options
        """
        self.end_time = datetime.now(timezone.utc)
        if not self.start_time:
            self.start_time = self.end_time

        # ec_color = "bold green" if self.exit_code == 0 else "bold red"
        self._plugin_log(
            f"Scan completed in {(self.end_time - self.start_time).total_seconds()} seconds",
            # f"Scan completed in {(self.end_time - self.start_time).total_seconds()} seconds with an exit code of [{ec_color}]{self.exit_code}[/{ec_color}]",
            target_type=target_type,
            level=logging.INFO,
        )

    # Exit codes considered "successful". Grype uses {0, 2}; the default set
    # works for bandit/checkov/etc. Override on subclasses where the scanner
    # has a different convention.
    success_exit_codes: ClassVar[Set[int]] = {0, 1}

    def _exit_code_accepted(self, success_codes: Optional[Set[int]] = None) -> bool:
        """Whether ``self.exit_code`` says the tool ran to completion.

        ``SPAWN_FAILURE_RETURNCODE`` (127) never does, even for a scanner that
        lists it: it is what ASH reports for a command the OS could not start,
        and a tool that never ran found nothing.

        The rule is :meth:`_code_is_accepted`'s, the one the fold of several
        runs' codes ranks by too, so a scanner that changes it changes both.
        """
        return self._code_is_accepted(self.exit_code, success_codes)

    def _worse_exit_code(self, current: int | None, new: int) -> int:
        """The worse of two runs' exit codes, by this scanner's accepted set.

        The base keeps the larger code, which is right only while the accepted
        codes are the small ones: for a set such as grype's ``{0, 2}`` an error
        code of 1 from one run was hidden behind an accepted 2 from another,
        and the accumulated code then read as a completed scan. A code outside
        ``success_exit_codes`` (``SPAWN_FAILURE_RETURNCODE`` always is) ranks
        above an accepted one. Between two codes of the same rank, and for a
        signal death (a negative code), a missing code or a 0, the larger code
        is kept as ``worse_exit_code`` keeps it.
        """
        if current is None or current <= 0 or new <= 0:
            return worse_exit_code(current, new)
        accepted_now = self._code_is_accepted(current)
        accepted_new = self._code_is_accepted(new)
        if accepted_now == accepted_new:
            return worse_exit_code(current, new)
        return current if accepted_new else new

    def _code_is_accepted(
        self, code: Optional[int], success_codes: Optional[Set[int]] = None
    ) -> bool:
        """Whether *code* is one this scanner accepts: in *success_codes* (the
        class's ``success_exit_codes`` when none are given), and never the
        spawn-failure code. The one rule behind :meth:`_exit_code_accepted`, which
        applies it to the current code, and :meth:`_worse_exit_code`, which
        applies it to two."""
        if success_codes is None:
            success_codes = self.success_exit_codes
        if code == SPAWN_FAILURE_RETURNCODE:
            return False
        return code in success_codes

    def _sarif_execution_successful(self) -> bool:
        """SARIF ``executionSuccessful`` under the graded rule: the counter rule
        ``ScanResultsContainer.scan_succeeded`` states, with the recorded stop
        causes and the exit code added on top (the container holds counters
        only, so it reads neither; whenever it is False this is False too).
        A recorded failure or a
        recorded stop cause (``scan_kept_flag`` or ``scan_post_run_error``)
        means False whatever the attempt count; a run that attempted nothing
        and recorded no stop cause reports True whatever it skipped; one that
        attempted any is successful only when every attempted target was
        evaluated, so the flag cannot say success while the rendered status
        says ERROR about the same run. A run that recorded a code none of the
        scanner's accepted ones is unsuccessful too; one that recorded no
        aggregate code at all (per-target runs record theirs elsewhere) is
        judged by its counters alone -- and a run where nothing accepted ever
        ran shows up in those counters as failed targets.

        The counters are the per-scanner ``targets_attempted`` and
        ``targets_failed`` the status derivation reads; a scanner without
        them has made no claim, which reads as attempted-nothing here.

        The recorded causes are read before the exit-code band. A run a flag
        judged (``scan_kept_flag``: timed out, cancelled, rejected, signaled;
        ``scan_post_run_error``: output ASH could not record) carries the
        flag's own conventional code on ``exit_code`` -- recorded so the 0
        default cannot read as an accepted run -- and a scanner whose
        accepted band is wide would read that judged code back as the tool's
        own verdict: cfn_nag accepts any non-negative violation count, which
        admits every judged code. The flag is the judgment, so no band is
        consulted for it. A never-started run (``spawn_failed``) is covered
        by its code where the band refuses 127 (the base's accepted set,
        npm_audit's 0-31), and by the recorded spawn failure
        (``scan_spawn_failure``) where the band admits it: cfn_nag's count
        can be 127, so its override reads that marker before the code.
        """
        failed = getattr(self, "targets_failed", 0) or 0
        if failed:
            # Read first, as the container does: a recorded failure is
            # failure whatever the attempt count holds (None, 0 or more).
            return False
        if self.scan_kept_flag is not None or self.scan_post_run_error is not None:
            # Read before the attempt count: a scan stopped before it counted
            # a target has None or 0 attempted, and its recorded cause is
            # still the judgment (the status derivation reads the same flag).
            return False
        attempted = getattr(self, "targets_attempted", None)
        if not attempted:
            return True
        if attempted < 0:
            return False
        return self.exit_code is None or self._sarif_exit_code_accepted()

    def _sarif_exit_code_accepted(self) -> bool:
        """Whether the aggregate code says the tool ran to completion, for
        the SARIF flag above. The base reads the scanner's accepted set
        (``_exit_code_accepted``). A scanner whose tool encodes its FINDINGS
        in the exit status -- cfn_nag's violation count, yarn audit's
        severity bitmask -- overrides this with the band its own exit-code
        judgment accepts, because such a code says nothing about completion
        that the target counters have not already graded, and reading it
        against a fixed set marked clean runs with findings unsuccessful.

        The band is only ever consulted for a code the tool returned: a run
        whose code is a flag's judgment never reaches it, because the caller
        reads the recorded cause first. A wide band can therefore stay wide
        without re-accepting a judged 124, 130 or 125 as the tool's own."""
        return self._exit_code_accepted()

    def _record_target_exit_code(self, response: Any) -> None:
        """Make ``exit_code`` the code of the run that scanned this target.

        ``_process_command_response`` keeps the largest code any run of this plugin
        returned, and the sets are not ordered: with grype's ``{0, 2}`` a 2 from one
        target would accept a 1 from the next. A response without a code (a test
        double, the runner's own failure) leaves the value as it is. A negative
        code, a signal death, is recorded as the shell reports it
        (``exit_status``: 128 + N), which no accepted set admits.

        A flagged response without a code -- a timed-out run whose stop
        failed carries ``returncode: None`` because the tool never finished
        and may still be running, and a cancelled, rejected, post-run-failed
        or never-spawned run can carry none either -- keeps that ``None`` on
        the response: no printer may invent a code the tool never returned.
        The attribute, which is what judging code reads, records the flag's
        own conventional code so the 0 default cannot read as an accepted
        run. The flags are checked in the runner's own precedence order.
        """
        code = response.get("returncode") if isinstance(response, dict) else None
        if not is_exit_code(code):
            # None, a bool or any other non-int is no code of the run's: a
            # flagged response still grades by its flag's own code, and an
            # unflagged one leaves the value as it is (a test double).
            code = flagged_returncode(response)
        if is_exit_code(code):
            self.exit_code = exit_status(code)

    def _refuse_rejected_exit_code(self, results_file: Optional["Path"] = None) -> None:
        """Raise ScannerError when the tool's exit code is outside its success set.

        For the template and for a scanner that overrides ``scan()`` and runs one tool
        per target: call it after the run and before reading the results file. A
        tool that failed can still leave a results file -- semgrep writes SARIF that
        holds only error notifications when it cannot read its rules, and grype a
        zero-byte report when it cannot load its database -- and "found nothing"
        and "never scanned" read the same in it.

        The message names the code. With ``results_file``, for an override whose own
        handler does not describe the failure, it also carries the accepted set and
        the tool's stderr (``_describe_scan_failure``); the template's handler adds
        those itself.
        """
        if self._exit_code_accepted():
            return
        # A cancelled run or a rejected result carries a code ASH chose for it
        # (130, 125), not one the tool returned: saying the tool exited with it
        # would name a code the tool never produced.
        kept = self.scan_kept_flag
        ash_judged = {
            "cancelled": "was cancelled while its tool ran",
            "result_rejected": "returned a result ASH rejected",
        }.get(kept[0] if kept is not None else "")
        if ash_judged is not None:
            origin = f"its run {ash_judged}, so ASH recorded exit code {self.exit_code}"
        else:
            origin = f"its tool exited with code {self.exit_code}"
        rejected = _RejectedResultError(
            f"{origin}, which this scanner "
            "does not accept as a completed run, so its results file is not graded"
        )
        if results_file is None:
            raise rejected
        raise ScannerError(self._describe_scan_failure(rejected, results_file))

    # Log level used for the empty-target preamble message. Defaults to INFO;
    # bandit overrides to VERBOSE since python-only repos commonly trip it.
    empty_target_log_level: ClassVar[int] = logging.INFO

    def _invocation_extras(
        self,
        sarif_report: SarifReport,
        final_args: List[str],
        target: "Path",
    ) -> dict:
        """Return additional Invocation kwargs (e.g. ``properties``).

        Default returns an empty dict. Override to attach scanner-specific
        Invocation fields like a PropertyBag. Called from ``_inject_invocation``.
        """
        return {}

    def _inject_invocation(
        self,
        sarif_report: SarifReport,
        final_args: List[str],
        target: "Path",
        success_codes: Optional[Set[int]] = None,
    ) -> None:
        """Populate runs[0].invocations with timing, exit-code, and command info.

        Also attaches per-result and tool-driver ``scanner_details`` via
        :func:`attach_scanner_details` so consumers that read
        ``result.properties.scanner_details.tool_invocation`` continue to
        see the command line, arguments, working directory, and exit code
        for migrated scanners. Without this, the un-migrated scanners
        (ferret/snyk/trivy) populate per-result details inside their own
        ``scan()`` while migrated scanners would only have the run-level
        ``invocations[0]``, which an earlier review flagged.

        No-op when sarif_report.runs is empty (avoids IndexError on empty reports).
        """
        if success_codes is None:
            success_codes = self.success_exit_codes
        if not sarif_report.runs:
            return
        working_dir = ArtifactLocation(uri=get_shortest_name(input=target))  # type: ignore[call-arg]
        extras = self._invocation_extras(sarif_report, final_args, target)
        # The values hook is overridable and is read once, guarded, for both
        # records. When it raised or gave no usable answer nothing can be
        # redacted, so the records carry only the command's name.
        values_read = guarded_values_read(self)
        redact_values = values_read.values
        if redact_values is None:
            command_line = str(self.command or "")
            recorded_arguments: List[str] = []
            # The arguments are left out of the records; say so, without
            # naming any of them.
            ASH_LOGGER.warning(
                values_hook_failure_line(
                    self.__class__.__name__,
                    values_read.failure(),
                    len(final_args) - 1,
                )
            )
        else:
            command_line, recorded_arguments = redacted_command_record(
                final_args, redact_values
            )
        # What the tool's own invocations said is carried into ASH's: the
        # toolExecutionNotifications (semgrep reports a rule file it cannot read
        # there, and run_ash_scan's unevaluated-rules gate reads them) and an
        # executionSuccessful the tool set to false. Replacing the list outright
        # discarded both, so a run the tool itself called unsuccessful read as a
        # complete one with no notifications.
        tool_notifications: List[Any] = []
        tool_said_unsuccessful = False
        for own in sarif_report.runs[0].invocations or []:
            notes = getattr(own, "toolExecutionNotifications", None)
            if notes:
                tool_notifications.extend(notes)
            if getattr(own, "executionSuccessful", None) is False:
                tool_said_unsuccessful = True
        if tool_notifications and "toolExecutionNotifications" not in extras:
            extras = {**extras, "toolExecutionNotifications": tool_notifications}
        sarif_report.runs[0].invocations = [
            Invocation(  # type: ignore[call-arg]
                commandLine=command_line,
                arguments=recorded_arguments,
                startTimeUtc=self.start_time,
                endTimeUtc=self.end_time,
                # The graded rule, not the exit code alone: a scanner that
                # counted a failed target, or whose run was stopped or whose
                # output ASH could not record, reported executionSuccessful
                # true whenever its tool's code was an accepted one, and the
                # unevaluated-rules gate read that as a complete run.
                executionSuccessful=(
                    self._exit_code_accepted(success_codes)
                    and self._sarif_execution_successful()
                    and not tool_said_unsuccessful
                ),
                exitCode=self.exit_code,
                exitCodeDescription="\n".join(self.errors) if self.errors else "",
                workingDirectory=working_dir,
                **extras,
            )
        ]
        # Mirror the un-migrated scanner pattern: attach per-result and
        # tool-driver scanner_details so downstream consumers (and the
        # ScanResultProcessor's own attach pass) see the same shape they
        # saw before the template-method refactor (an earlier review finding).
        from automated_security_helper.utils.sarif_utils import (
            attach_scanner_details as _attach_scanner_details,
        )

        scanner_name = (
            str(self.config.name)
            if self.config is not None and getattr(self.config, "name", None)
            else self.__class__.__name__
        )
        # Normally already run by the dependency check; a no-op then.
        self.resolve_deferred_tool_version()
        _attach_scanner_details(
            sarif_report=sarif_report,
            scanner_name=scanner_name,
            scanner_version=getattr(self, "tool_version", None),
            invocation_details={
                "command_line": command_line,
                "arguments": recorded_arguments,
                "working_directory": get_shortest_name(input=target),
                "exit_code": self.exit_code,
                "start_time": self.start_time.isoformat()
                if self.start_time is not None
                else None,
                "end_time": self.end_time.isoformat()
                if self.end_time is not None
                else None,
            },
        )

    def _read_results_file(self, results_file: "Path") -> Optional[dict]:
        """Read and parse the scanner results file as JSON.

        Returns ``None`` for a file that exists and is EMPTY (or holds JSON
        ``null``), which ``scan()`` hands to ``_handle_empty_results``.

        A **missing** file must raise, and that is a constraint rather than an
        accident of this implementation. Returning ``None`` for it would route a
        scanner that produced no output at all into ``_handle_empty_results()``,
        which a scanner may override to return a report and let the scan
        **succeed** -- reporting a clean result for a tool that died. That is a false negative in a security
        scanner, so the missing case must stay an exception. ``scan()``'s handler
        enriches it with the exit code and the tool's stderr; see
        ``_describe_scan_failure``.

        An earlier version of this docstring said ``None`` signalled an
        "empty/missing" result, which the code has never done for missing. The
        wording is corrected here rather than the behaviour.

        Subclasses may override to add their own empty-file detection or
        alternative parsing, but must preserve the missing-file raise.
        """
        # Under fs_guard's reader semantics (``read_bytes_at_most``): no link is
        # followed at the name, a FIFO left there cannot block the open or the
        # read, anything but a regular file is refused with OSError, and the read
        # is bounded. A plain open followed a link to any file on the host and
        # blocked ASH for good on a FIFO a scanner's process left at the name.
        from automated_security_helper.utils.sandbox.fs_guard import (
            read_bytes_at_most,
        )

        data = read_bytes_at_most(results_file, _RESULTS_FILE_READ_LIMIT + 1)
        if len(data) > _RESULTS_FILE_READ_LIMIT:
            raise ScannerError(
                f"its results file is larger than {_RESULTS_FILE_READ_LIMIT} bytes, "
                "the most this scanner reads, so it is not graded"
            )
        content = data.decode("utf-8")
        if not content or content.strip() == "":
            return None
        return json.loads(content)

    def _handle_empty_results(self) -> SarifReport:
        """Decide what an empty results file means, after an accepted exit code.

        The default raises ``ScannerError``: there is nothing to grade. bandit,
        checkov and semgrep write SARIF with one run even when there is nothing for
        them to scan (measured), and grype's and opengrep's SARIF writers always add
        one, so an empty file is not a clean scan. A scanner whose tool really does
        write an empty file for a clean scan overrides this to return a report.

        A report an override returns has to hold at least one SARIF run, as a
        report the tool wrote does: one with none is refused with the same
        "no SARIF run" error, since it grades nothing. A clean scan is a run
        with no results.
        """
        raise ScannerError("its results file is empty, so there is nothing to grade")

    def _post_process_sarif(
        self,
        sarif_report: SarifReport,
        final_args: List[str],
        target: "Path",
    ) -> SarifReport:
        """Apply scanner-specific tweaks to a SARIF report after invocation injection.

        Default returns the report unchanged. Override to normalize URIs,
        mask secrets, attach scanner details, etc.
        """
        return sarif_report

    @abstractmethod
    def _execute_scan(
        self,
        target: "Path",
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> Tuple[List[str], "Path", Optional[dict]]:
        """Run the scanner tool and return (final_args, results_file, subprocess_env).

        Abstract template-method hook. Subclasses that use the default
        `scan()` template MUST implement this with real tool-invocation
        logic. Subclasses that override `scan()` directly (e.g. Python-API
        scanners, file-iterating scanners) must still satisfy the abstract
        contract — provide a one-line stub that raises NotImplementedError
        so ABC can verify the interface at class-definition time and the
        stub is never reached at runtime.

        Returns:
            (final_args, results_file, subprocess_env) where subprocess_env is
            a dict merged with os.environ (or None to inherit the parent env).
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} must implement _execute_scan() "
            "or override scan() directly."
        )

    def _output_dir_inside(self, target: "Path") -> Optional["Path"]:
        """ASH's output directory relative to ``target``, when it sits inside it.

        ASH writes its output under the source tree by default, so a scanner that
        walks the whole target reads ASH's previous reports back in.
        ``scan_set`` and detect-secrets drop those files by testing each one
        against the output directory; a scanner that hands a directory to its
        tool cannot do that and has to tell the tool to skip it instead, which
        needs this path.

        None when the output directory is the target, outside it, or contains it.
        The last is the converted target, ``work_dir``, which lives under
        ``output_dir``: excluding the output directory there would exclude
        everything the converters produced.

        ``os.path.abspath`` on both sides and not ``resolve()``: the tool sees the
        target path as given, symlinked prefix and all, and a containment test that
        resolves only one side answers a different question. ``abspath`` also
        removes ``.`` and ``..`` without following a link, which ``absolute()``
        does not: ``<source>/../out`` is outside ``<source>``, and compared as
        written it read as inside it. It removes ``..`` by text, so
        ``<source>/link/../x`` reads as ``<source>/x`` even when ``link`` is a
        symlink, where the filesystem would resolve it elsewhere.
        """
        import os

        output_dir = getattr(self.context, "output_dir", None)
        if output_dir is None:
            return None
        output_abs = Path(os.path.abspath(output_dir))
        target_abs = Path(os.path.abspath(target))
        if output_abs == target_abs or not output_abs.is_relative_to(target_abs):
            return None
        return output_abs.relative_to(target_abs)

    def _ash_output_dirs_inside(self, target: "Path") -> List["Path"]:
        """Every ASH output directory inside ``target``, relative to it.

        ASH writes its output under the source tree by default, so a scanner that
        walks the whole target reads ASH's previous reports back in. ``scan_set``
        and detect-secrets drop those files by testing each one; a scanner that
        hands a directory to its tool cannot, and tells the tool to skip each of
        these with the tool's own option instead. They are the directories
        ``utils/scan_output_dirs.py`` names: this run's output directory, and the
        default ``.ash/ash_output`` an earlier run can have left in the tree; for
        one holding committed files the scan set includes, ASH's own directories
        in it instead (``output_dirs_to_exclude``). What reaches the tool anyway is
        dropped from its SARIF after the scan, and stays in output that is not
        SARIF, such as syft's SBOM.

        Empty for the converted target, ``work_dir``, which lives under
        ``output_dir``: excluding the output directory there would exclude
        everything the converters produced.
        """
        from automated_security_helper.utils.scan_output_dirs import (
            output_dirs_inside,
            output_dirs_to_exclude,
            scan_set_of,
        )

        context = getattr(self, "context", None)
        if context is None:
            return []
        try:
            dirs = output_dirs_to_exclude(
                context.source_dir,
                getattr(context, "output_dir", None),
                scanned_files=scan_set_of(context),
                workspace_output_dir=getattr(context, "workspace_output_dir", None),
            )
        except (OSError, TypeError, ValueError) as unreadable:
            # Best effort, so the scan goes on without the exclusions -- but not
            # silently: a TypeError here is a programming error, and an empty
            # answer would let the tool read ASH's own output back in with
            # nothing in the log to say so. Only the error's type is logged; its
            # text can quote a path.
            self._plugin_log(
                "ASH's output directories could not be worked out for this scan "
                f"({type(unreadable).__name__}); the tool is not told to skip them.",
                level=logging.WARNING,
            )
            return []
        return output_dirs_inside(dirs, target)

    def _subprocess_cwd(self, results_dir: Path) -> Path | None:
        """The working directory for the tool's scan subprocess.

        None runs it in the source directory (``PluginBase._run_subprocess``).
        A scanner whose tool reads its own config file from its working directory
        returns a directory outside the scanned tree instead.
        """
        return None

    def _effective_scan_timeout(self) -> float | None:
        """Seconds to allow this scanner's tool, or None to leave it unbounded.

        Read defensively rather than as self.config.options.scan_timeout. A
        third-party scanner may define options that predate this field, or set
        config to None entirely, and a scan must not fail with AttributeError
        because of a timeout lookup. An absent option means unbounded, which is
        the behaviour those scanners already had.
        """
        options = getattr(self.config, "options", None)
        timeout = getattr(options, "scan_timeout", None)
        if timeout is None:
            return None
        try:
            timeout = float(timeout)
        except (TypeError, ValueError):
            return None
        return timeout if timeout > 0 else None

    def scan(
        self,
        target: "Path",
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
        config: "T | ScannerPluginConfigBase | None" = None,
        *args,
        **kwargs,
    ) -> Any | SarifReport | CycloneDXReport:
        """Template scan: preamble → _execute_scan → read result → inject invocation → postamble.

        Subclasses with bespoke logic (file-iteration, Python-API scanners) should
        override this method directly and leave _execute_scan unimplemented, and
        start it with the same ``exit_code`` reset as this one, and with
        ``_reset_errors()`` where this one clears the error lines: the record of
        which of them are ASH's own notes is cleared with them.
        """
        if global_ignore_paths is None:
            global_ignore_paths = []

        # Per target. One plugin instance scans source and then converted, and
        # _process_command_response keeps the largest code any run of the instance
        # returned, so without this a target that returns before its tool runs (an
        # empty tree, missing dependencies) reports the previous target's code.
        self.exit_code = 0
        # The timing too: the instance's times belong to the last target it
        # scanned. An empty tree is timed from its own _post_scan, and a
        # failure before the tool ran must not read as ending when the previous
        # target did (a negative duration).
        self.start_time = None
        self.end_time = None
        # The tool lines too: _process_command_response appends every run's
        # stdout and stderr to these, and the executor records them, and the
        # failure message quotes them, as THIS target's. Carried over, a failed
        # converted-target run's record led with the source target's lines, and
        # the quoted stderr described the wrong run.
        self.output = []
        # The record of which of the error lines are ASH's own goes with them.
        self._reset_errors()

        # Only a directory can be empty: listing a file target raised
        # NotADirectoryError out of scan(), and a file is something to scan.
        if not target.exists() or (target.is_dir() and not any(target.iterdir())):
            self._plugin_log(
                f"Target directory {target} is empty or doesn't exist. Skipping scan.",
                target_type=target_type,
                level=self.empty_target_log_level,
                append_to_stream="stderr",
            )
            self._post_scan(target=target, target_type=target_type)
            return True

        try:
            validated = self._pre_scan(
                target=target,
                target_type=target_type,
                config=config,
            )
        except BaseException:
            # _pre_scan starts the timing and then does the work that can
            # raise (the results directory, the dependency check). The raise
            # leaves this method before the try below, so the end is set here:
            # left None, the executor would pair this target's start with no
            # end, or with the previous target's.
            if self.end_time is None:
                self.end_time = datetime.now(timezone.utc)
            raise
        if not validated:
            self._post_scan(target=target, target_type=target_type)
            return False

        if not self.dependencies_satisfied:
            self._post_scan(target=target, target_type=target_type)
            return False

        # Bound before the try so the failure handler can name the stderr log
        # even when _execute_scan itself is what raised.
        results_file = None
        # Whether the tool was started, so a failure before it (a refusal while
        # resolving the arguments) is not described with an exit code it never had.
        tool_started = False

        # The reset the attribute's declaration promises: a scan that never
        # reaches its tool reports no exit code, not the 0 the field starts
        # at or the previous target's code. Here and not at the top: the early
        # returns above (an empty tree, missing dependencies) are a clean skip
        # that keeps the 0 set at the top, which the invocation record reads
        # through _exit_code_accepted.
        self.exit_code = None

        try:
            final_args, results_file, subprocess_env = self._execute_scan(
                target=target,
                target_type=target_type,
                global_ignore_paths=global_ignore_paths,
            )

            # Bound the tool invocation. Without this every template-based
            # scanner could run indefinitely: bandit was reported running past 50
            # minutes on a project the CLI scanned in 20 seconds. detect-secrets
            # was the only scanner that timed out cleanly, because it carried its
            # own copy of this option and enforced it in its own scan override.
            effective_timeout = self._effective_scan_timeout()
            # Everything the call needs is worked out before the tool counts as
            # started: a raise from the results path or the overridable cwd
            # hook is a failure before the tool, not a run that ended.
            results_dir = results_file.parent
            tool_cwd = self._subprocess_cwd(results_dir)
            tool_started = True
            response = self._run_subprocess(
                command=final_args,
                results_dir=results_dir,
                cwd=tool_cwd,
                env=subprocess_env,
                timeout=effective_timeout,
            )

            self._post_scan(target=target, target_type=target_type)

            # Say "timed out" rather than "No such file or directory".
            #
            # A killed tool never writes its results file, so _read_results_file
            # below raises FileNotFoundError, which the except clause turns into
            # "<Scanner> scan failed: [Errno 2] No such file or directory". That
            # reads as a path bug and sends the reader looking in the wrong place.
            # The cause is a timeout and the message should say so, along with the
            # knob to change it.
            if isinstance(response, dict) and response.get("timed_out"):
                # The limit through the shared token (_timeout_limit_token),
                # redacted here: this error's text is recorded as it is
                # raised, and the token is what keeps an environment-derived
                # number out of it. "Was killed" only when the stop worked:
                # _run_subprocess recorded a stop that failed on
                # scan_could_not_stop, and a message saying the tool is gone
                # would be the one wrong thing to tell the operator then.
                if self.scan_could_not_stop is not None:
                    ending = f"{COULD_NOT_STOP_ENDING}. It produced no"
                else:
                    ending = f"{WAS_KILLED_ENDING}, so it produced no"
                # The ONE guarded read of the values hook for this message (the
                # rule of _values_to_redact): a hook that raised or gave no
                # usable answer must not replace the timeout as the scan's
                # error, and cannot be trusted to hide the limit or the
                # option's name, so a value-free note takes their place.
                read = guarded_values_read(self)
                if read.values is None:
                    raise ScannerError(
                        f"{self.__class__.__name__} timed out{ending} results "
                        "file. The limit is not shown: the plugin's values hook "
                        f"{read.failure()}. Raise the scanner's scan_timeout "
                        "option if this target legitimately needs longer."
                    )
                limit = timeout_limit_token(effective_timeout, read.values)
                raise ScannerError(
                    text_without_values(
                        f"{self.__class__.__name__} timed out after "
                        f"{limit}{ending} "
                        f"results file. Raise scanners.{getattr(self.config, 'name', '<scanner>')}"
                        ".options.scan_timeout if this target legitimately needs "
                        "longer, or set it to null to leave this scanner unbounded.",
                        read.values,
                    )
                )

            # Likewise "could not start" rather than the missing results file. The
            # exit code is 127, which no scanner accepts, so this is reported as
            # an error either way; this check only makes the message name it.
            # The headline carries none of the run's text. Each spawn-failure
            # path in _run_subprocess (the uv refusal, the OS refusal, the
            # handler's own response) goes through _process_command_response
            # before it reaches this check, which stores the stderr in
            # self.errors redacted, with the full uv layer for a uv run, and
            # _describe_scan_failure's Stderr part shows that copy (or reads the
            # stderr log under the same redaction). Quoting the stderr here as
            # well showed the same text a second time: as written by this
            # method, and where the executor redacts the whole message only
            # through the plain-value layer, which matches a value as written
            # and so misses what uv respells and the plugin-built --from and
            # --with inputs that hold one. A scanner that keeps its stderr out of
            # its errors on purpose (gitleaks) names its log in the message
            # instead of quoting it.
            if isinstance(response, dict) and response.get("spawn_failed"):
                raise ScannerError(
                    f"{self.__class__.__name__} could not start its tool, so it "
                    "produced no results file."
                )

            # And for a tool that ran when ASH could not record its output: its
            # results file may be complete, but the run is not graded on it.
            if isinstance(response, dict) and response.get("post_run_error"):
                raise ScannerError(
                    self._text_without_hooked_values(
                        f"{self.__class__.__name__} ran, but ASH could not record "
                        f"the scanner's output: {response.get('error')}",
                        f"{self.__class__.__name__} ran, but ASH could not record "
                        "the scanner's output",
                    )
                )

            # And for a tool a signal ASH did not send ended: it never finished, so
            # whatever results file it left is not the whole scan.
            if isinstance(response, dict) and response.get("signaled"):
                raise ScannerError(
                    self._text_without_hooked_values(
                        f"{self.__class__.__name__} did not finish: "
                        f"{response.get('error')}",
                        f"{self.__class__.__name__} did not finish",
                    )
                )

            # Before the results file is read: a failed tool's file decides nothing.
            self._record_target_exit_code(response)
            self._refuse_rejected_exit_code()

            raw = self._read_results_file(results_file)
            if raw is None:
                # Empty result file: defer to _handle_empty_results, which raises
                # unless the scanner says an empty file is a clean scan.
                error_msg = (
                    f"{self.__class__.__name__} results file is empty "
                    f"(exit code: {self.exit_code}). "
                )
                if self.errors:
                    error_msg += f"Stderr: {' '.join(self.errors)}"
                else:
                    error_msg += "No stderr output captured."
                # Redacted: the tool's stderr can name a path or option the
                # config read from the environment, and ash.log keeps this line.
                ASH_LOGGER.warning(
                    self._text_without_hooked_values(
                        error_msg,
                        f"{self.__class__.__name__} results file is empty "
                        f"(exit code: {self.exit_code})",
                    )
                )
                report = self._handle_empty_results()
                if not isinstance(report, SarifReport):
                    return report
                # A report the scanner's hook answers for an empty file is
                # finished as a tool-written one is: it is checked for a run,
                # gets the invocation record (timing, exit code, command) and
                # the scanner's own adjustments.
                if not report.runs:
                    raise ScannerError(
                        "its results file holds no SARIF run, so there is "
                        "nothing to grade"
                    )
                self._inject_invocation(report, final_args, target)
                return self._post_process_sarif(report, final_args, target)

            try:
                sarif_report: SarifReport = SarifReport.model_validate(raw)
            except Exception as e:
                # Not returned as it is: the executor would grade a dict without a
                # verdict on its zero findings, which is how a clean scan reads.
                raise ScannerError(
                    f"its results file is not SARIF ASH can read, so its findings "
                    f"could not be graded: {error_text(e)}"
                )
            if not sarif_report.runs:
                # Every field of a SARIF log is optional, so `{}` validates. No run
                # is no scan; see _handle_empty_results. Checked on the report as
                # the tool wrote it, before any scanner adjusts it.
                raise ScannerError(
                    "its results file holds no SARIF run, so there is nothing to grade"
                )
            # Failures from here on are ASH's or the scanner's own code, and the
            # outer handler reports them as what they are.
            self._inject_invocation(sarif_report, final_args, target)
            return self._post_process_sarif(sarif_report, final_args, target)

        except Exception as e:
            # A failure before _post_scan ran (the arguments, the spawn) ends
            # this target's timing here; left unset, the executor would pair
            # this target's start with no end, or with the previous one's.
            if self.end_time is None:
                self.end_time = datetime.now(timezone.utc)
            raise ScannerError(
                self._describe_scan_failure(e, results_file, tool_started=tool_started)
            )

    def _text_without_hooked_values(self, text: str, withheld: str) -> str:
        """*text* with the plugin's values hidden, read through the one guarded
        read of the overridable values hook (``_values_to_redact``'s rule).

        A hook that raised or gave no usable answer leaves nothing to hide the
        values with, and an empty value set would print them: *withheld*, the
        part of the message that carries none of the run's text, is returned
        with a note saying why instead, and the hook's own failure never
        replaces the error being reported.

        A uv run's text goes through the full uv layer
        (``shown_uv_output``, with the run's plugin-built inputs, unbounded):
        uv respells what it quotes ("9.9.9-RC777" prints as "9.9.9rc777") and
        the plain layer matches a value only as written. A raise from that
        layer (its setup or the shower) leaves the text out, as a failing
        values hook does, and does not fall back to the plain layer, which
        would print what uv respelled; *withheld* still says what happened,
        and the raise does not replace the error being reported either.
        """
        read = guarded_values_read(self)
        if read.values is None:
            return (
                f"{withheld} (text not shown: the plugin's values hook "
                f"{read.failure()})"
            )
        if getattr(self, "use_uv_tool", False):
            try:
                from automated_security_helper.utils.uv_tool_runner import (
                    shown_uv_output,
                )

                return shown_uv_output(
                    text,
                    read.values,
                    plugin_inputs=self._uv_run_inputs_for_records(),
                    tool_name=self.command,
                    limit=None,
                )
            except Exception:  # noqa: BLE001 -- the error being reported outranks it
                return f"{withheld} (text not shown: the uv redaction layer failed)"
        return text_without_values(text, read.values)

    def _config_as_written(self, dumped: Any) -> Any:
        """``dumped``, a dump of this scanner's config, as its section was written.

        Each value the scan config read from the environment is shown as the
        reference its file wrote, as a results file records the config
        (config_validator.record_of_config), the plugin's own model having
        typed it or not. Anything else, and a dump that is not a mapping, is
        returned as it is.
        """
        # Imported here: the config package imports base at start-up.
        from automated_security_helper.config.config_validator import (
            record_of_config,
        )

        scan_config = getattr(getattr(self, "context", None), "config", None)
        name = getattr(self.config, "name", None)
        if scan_config is None or not isinstance(name, str):
            return dumped
        if not isinstance(dumped, dict):
            return dumped
        record = record_of_config(scan_config, {"scanners": {name: dumped}})
        sections = record.get("scanners") if isinstance(record, dict) else None
        if not isinstance(sections, dict) or len(sections) != 1:
            return dumped
        # One section; its key is the record's, which a key the file read from
        # the environment renames.
        return next(iter(sections.values()))

    def _describe_scan_failure(
        self,
        exc: Exception,
        results_file: Optional["Path"],
        tool_started: bool = True,
    ) -> str:
        """Build the failure message, naming the cause rather than the symptom.

        Why this exists
        ---------------
        A tool that exits non-zero raises nothing:
        ``run_command_with_output_handling`` passes ``check=False``, so
        ``_run_subprocess`` returns ``{"returncode": 7}`` normally. ``scan()``
        then reads a results file the tool never wrote, and the FileNotFoundError
        from THAT is what surfaced -- two steps from the cause, in a different
        function, as a different exception type. Two opengrep runs failed in CI
        this way and the reported error was ``[Errno 2] No such file or
        directory``, which says nothing about why.

        The stderr was not lost. ``_run_subprocess`` defaults to
        ``stderr_preference="write"``, so it went to
        ``<results_dir>/<ClassName>.stderr.log`` and never into ``self.errors``
        -- ``_process_command_response`` only populates that from a RETURNED
        stderr, and only 3 of the 8 call sites ask for one. So this reads the log
        file when ``self.errors`` is empty, which is the common case rather than
        the exotic one. It reads it too when ``self.errors`` holds nothing but
        ASH's own notes (``_plugin_log``: a timeout notice): those say what ASH
        did, not what the tool wrote, and are kept in the message ahead of the
        log's text. The offline explainer is not one of them: it quotes the log
        itself ("uv said: ..."), so it stands in for the log and the log is not
        read beside it.

        Why the exit code needs a verdict, not just a value
        --------------------------------------------------
        ``success_exit_codes`` is ``{0, 1}`` and bandit deliberately exits 1 when
        it finds issues, so "non-zero" does not mean "failed". The message states
        the code AND whether this scanner accepts it, because that pair is what
        separates "the tool ran and signalled findings" from "the tool died". It
        is also why nothing here branches on ``exit_code != 0``: this method only
        describes a failure that has already happened and changes no control
        flow.

        Failure modes
        -------------
        * Reading the log is best-effort. If it cannot be read the message says
          where it looked, so the reader can tell "stderr was empty" from
          "stderr was not where we checked".
        * stderr is shortened to keep a scanner that wrote megabytes from
          swamping the error. The start and the end are kept
          (``utils/output_excerpt.head_and_tail``): a tool usually says why it
          failed last, after any progress output. The full text stays in the log
          file, which is named.
        * With ``tool_started`` False the failure came before the tool was
          started, such as a target the scanner refuses while resolving its
          arguments. There is no exit code or stderr to describe, so the message
          is the failure and that the tool was not started.
        """
        detail = f"{self.__class__.__name__} scan failed: {error_text(exc)}"
        # A result ``_refuse_rejected_exit_code`` rejected is not read: the
        # decision is the error's type, so it holds however the refusal text
        # was recorded.
        rejected = isinstance(exc, _RejectedResultError)
        if not tool_started:
            tool = getattr(getattr(self, "config", None), "name", None)
            return f"{detail} ({tool or 'its tool'} was not started)"

        if self.scan_could_not_stop is not None:
            # The attribute holds the timeout's judging code, but the tool
            # never returned one: it may still be running. Printing a number
            # here would claim an exit that never happened.
            detail += " (no exit code: ASH could not stop the tool)"
            # No code was returned, so none was accepted.
            accepted = False
        elif self.exit_code is None:
            detail += " (the scan reported no exit code: its tool never ran)"
            # The same reading _exit_code_accepted gives a missing code.
            accepted = False
        else:
            accepted = self._exit_code_accepted()
            verdict = (
                "an accepted exit code for this scanner"
                if accepted
                else f"not an accepted exit code; success_exit_codes="
                f"{sorted(self.success_exit_codes)}"
            )
            detail += f" (exit code {self.exit_code}: {verdict})"

        # Cut once, at the end, by head_and_tail: the tool says why it failed
        # in its LAST lines, and a cut to the first 2000 characters here
        # dropped them before the head-and-tail excerpt ran, so the excerpt's
        # tail was this cut's marker and its omitted count was wrong. The
        # errors lines are redacted again here, before the cut: the run's own
        # lines were redacted at insertion, but a line _plugin_log stored
        # (stored as written) was not, and the executor's later redaction
        # cannot match a value this cut split. The log-excerpt branch below
        # does its own bounded cut inside the shared helper.
        stderr_text = "\n".join(self.errors).strip()
        # ``errors`` also holds the notes ASH's own ``_plugin_log`` put there
        # (a timeout notice, the offline explainer), which are not what the
        # tool wrote: when they are all it holds, the tool's stderr log is
        # still unread, and is read below beside them.
        tool_said_nothing = not "\n".join(self._tool_error_lines()).strip()
        values_were_read = False
        read_values: Optional[Tuple[str, ...]] = None
        stderr_withheld = False
        if stderr_text:
            values_were_read, read_values = True, guarded_values(self)
            if read_values is not None:
                stderr_text = text_without_values(stderr_text, read_values)
            else:
                # The hook raised or gave no usable answer, so nothing here can
                # hide the values the lines hold. They are not shown: the log
                # branch below names the stderr log, as it does when it meets
                # the same hook, and the closing branches say so when it cannot.
                stderr_text = ""
                stderr_withheld = True
        # ASH's notes, kept in the message whatever the log read does.
        notes_text = stderr_text if tool_said_nothing else ""
        notes_part = (
            f". Stderr: {head_and_tail(notes_text, _STDERR_EXCERPT_LIMIT)}"
            if notes_text
            else ""
        )
        log_path = None
        if results_file is not None:
            log_path = (
                Path(results_file).parent / f"{self.__class__.__name__}.stderr.log"
            )

        # _values_to_redact is read at most ONCE per failure: the stderr block
        # reads it when it quotes the log, and the notification block below
        # reuses that read instead of asking the hook a second time.
        log_unreadable = False
        if (not stderr_text or notes_text) and log_path is not None and not rejected:
            # The log keeps the tool's text verbatim, so a quoted env-read
            # value sits in it in clear. The whole pipeline -- the bounded
            # read with its edge trim, redaction BEFORE the cut, the cut,
            # and the continuation marker when the read stopped before the
            # log's end -- is the shared helpers' (plugin_base
            # read_log_bounded and shown_excerpt): a site cutting on its own
            # re-created the split-value leak one bound at a time. Under the
            # default stderr_preference="write" this read is the ONLY route
            # a uv run's resolver text reaches the failure message, so a uv
            # run's log gets the full uv layer with the run's own inputs
            # (through _uv_run_inputs_for_records: it reads a raising inputs
            # hook as no inputs, so the excerpt stays and gets the plain
            # value layer, the one policy every record site applies; a raise
            # from the rest of this setup drops the excerpt, see the except
            # below) while any other tool's log gets the neutral layer, since
            # the respelling premise is uv's.
            # _values_to_redact is still an overridable hook that can raise,
            # and a raise must not replace the scan's real error with its
            # own: then the excerpt is DROPPED and the message names the log
            # path -- never the raw log, which would print the env-read
            # values the redaction hides.
            trim_inputs: Tuple[str, ...] = ()
            # Not asked a second time when ASH's notes were redacted above.
            guarded = read_values if values_were_read else guarded_values(self)
            values_were_read, read_values = True, guarded
            if guarded is None:
                # The hook raised or gave no usable answer BEFORE the log was
                # read, so nothing here knows whether stderr was captured:
                # the text claims only what it can.
                detail += (
                    f"{notes_part}. Stderr could not be shown; see "
                    f"{log_path.as_posix()}"
                )
                return detail
            values: Tuple[str, ...] = guarded
            try:
                if getattr(self, "use_uv_tool", False):
                    from automated_security_helper.utils.uv_tool_runner import (
                        shown_uv_output,
                    )

                    inputs = self._uv_run_inputs_for_records()
                    # The read-edge trim also drops a tail that is a proper
                    # prefix of an input's spelling: the shower hides a uv
                    # run's inputs WHOLE, so a cut just after a glued
                    # extra's value ("bandit[sarifqz4b") is the same edge
                    # piece a value split leaves.
                    trim_inputs = inputs

                    def _show(raw: str) -> str:
                        return shown_uv_output(
                            raw,
                            values,
                            plugin_inputs=inputs,
                            tool_name=self.command,
                            limit=None,
                        )
                else:

                    def _show(raw: str) -> str:
                        return shown_tool_stderr(raw, values)

            except Exception:  # noqa: BLE001 -- a raise in this setup drops the excerpt
                # Raised BEFORE the log was read, so nothing here knows
                # whether stderr was captured: the text claims only what it
                # can.
                detail += (
                    f"{notes_part}. Stderr could not be shown; see "
                    f"{log_path.as_posix()}"
                )
                return detail
            # The excerpt helper keeps the first `keep` characters, so a keep of
            # the excerpt limit here was a head-only cut BEFORE the head-and-tail
            # cut below, and the tool's last lines were gone before the cut that
            # was meant to keep them. The helper is given the whole bounded read
            # to redact and mark; head_and_tail makes the one cut, at the end.
            read_bound = _STDERR_EXCERPT_LIMIT * 32
            try:
                raw_log, read_cut = read_log_bounded(
                    log_path, read_bound, values, trim_inputs
                )
            except Exception:  # noqa: BLE001 -- reading the log is best-effort
                raw_log, read_cut = "", False
                # A log that is there and could not be read (a link or a
                # FIFO at the name, a permission) is not a log with nothing in
                # it; one the tool never wrote is told apart below.
                log_unreadable = os.path.lexists(log_path)
            if raw_log or read_cut:
                try:
                    excerpt = shown_excerpt(
                        raw_log, read_cut, log_path, read_bound, _show
                    )
                except Exception:  # noqa: BLE001 -- see the comment above
                    detail += (
                        f"{notes_part}. Stderr was captured but could not be "
                        f"shown; see {log_path.as_posix()}"
                    )
                    return detail
                # ASH's notes first, then the tool's text from the log.
                stderr_text = "\n".join(part for part in (notes_text, excerpt) if part)

        if stderr_text:
            stderr_text = head_and_tail(stderr_text, _STDERR_EXCERPT_LIMIT)
            detail += f". Stderr: {stderr_text}"
            if log_unreadable and log_path is not None:
                # Only ASH's notes are shown, and the log that holds the tool's
                # text is there but could not be read: say so after them.
                detail += (
                    ". The tool's stderr log could not be read; see "
                    f"{log_path.as_posix()}"
                )
        elif stderr_withheld:
            detail += ". Stderr could not be shown"
            if log_path is not None:
                detail += f"; see {log_path.as_posix()}"
        elif rejected and log_path is not None:
            # Names the log rather than quoting it: the result was refused, so
            # its outputs were not opened.
            detail += (
                ". Stderr not read: ASH refused this result, so its outputs "
                f"(the stderr log at {log_path.as_posix()}) were not read"
            )
        elif log_unreadable and log_path is not None:
            detail += f". Stderr could not be read; see {log_path.as_posix()}"
        elif log_path is not None:
            detail += f". No stderr captured; checked {log_path.as_posix()}"
            if not log_path.exists():
                detail += ", which the tool did not write"
        else:
            detail += ". No stderr captured."

        # A rejected run's results file is not graded, but a tool can say there
        # why it failed: semgrep reports a rule file it cannot read as an
        # error-level SARIF notification and writes nothing on stderr.
        if not accepted and results_file is not None:
            results_path = Path(results_file)
            # The notifications are quoted only with the values to hide in
            # hand: a hook that raised or gave no usable answer leaves the
            # text unquoted and the file named below. (On the non-rejected
            # path such a hook already returned above with the stderr log
            # named; this read is the rejected path's, and the one read for
            # a failure whose stderr block did not need the hook.)
            if not values_were_read:
                read_values = guarded_values(self)
            reported = (
                _error_notifications(results_path, read_values)
                if read_values is not None
                else ""
            )
            if reported:
                detail += f". {results_path.as_posix()} reports: {reported}"
            elif not stderr_text:
                stdout_log = (
                    results_path.parent / f"{self.__class__.__name__}.stdout.log"
                )
                outputs = [
                    p.as_posix() for p in (results_path, stdout_log) if p.exists()
                ]
                if outputs:
                    detail += f". The tool's output is in {' and '.join(outputs)}"

        return detail

    ### Methods that require implementation by plugins.
    def validate_plugin(self) -> bool:
        """Validate scanner configuration and requirements."""
        # A reason recorded while the scanner was built outranks any probe of
        # the tool, as in validate_plugin_dependencies: a tool that is present
        # does not make a scanner that refused to run satisfied.
        if self.dependency_unavailable_reason:
            # Redacted like every other place the reason is shown: it can name a
            # path or option the config read from the environment, and the line
            # is logged and kept in ``errors``, which the failure message and the
            # results file quote.
            self._plugin_log(
                self._text_without_hooked_values(
                    self.dependency_unavailable_reason,
                    f"{self.__class__.__name__} is unavailable",
                ),
                level=logging.ERROR,
            )
            self.dependencies_satisfied = False
            return False
        # Use enhanced validation that includes pre-installed tool detection
        validation_result = self._validate_tool_availability_with_pre_installed()

        # Log validation details
        if validation_result["available"]:
            self._plugin_log(
                f"Tool validation successful via {validation_result['validation_method']}",
                level=logging.INFO,
            )

            # Log any warnings
            for warning in validation_result.get("warnings", []):
                self._plugin_log(warning, level=logging.WARNING)

            self.dependencies_satisfied = True
            return True
        else:
            # Log validation errors
            for error in validation_result.get("errors", []):
                self._plugin_log(error, level=logging.ERROR)

            # Provide helpful offline mode message if applicable
            if self._is_offline_mode() and self.use_uv_tool:
                self._plugin_log(
                    f"Offline mode is enabled (ASH_OFFLINE, or this scanner's own options.offline) but tool '{self.command}' is not available. "
                    f"In offline mode, tools must be pre-installed. Please install '{self.command}' manually or disable offline mode.",
                    level=logging.ERROR,
                )

            self.dependencies_satisfied = False
            return False

    def safe_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
        config: T | ScannerPluginConfigBase | None = None,
        *args,
        **kwargs,
    ) -> Any | SarifReport | CycloneDXReport:
        """
        Safely execute scanner against a target with comprehensive error handling.

        This is a wrapper around the scan method that catches exceptions and returns
        a structured error response instead of propagating exceptions.

        Args:
            target: Target to scan
            target_type: Type of target (source or converted)
            global_ignore_paths: List of paths to ignore globally
            config: Scanner configuration
            *args: Variable length argument list
            **kwargs: Arbitrary keyword arguments

        Returns:
            Dict containing scan results or error information
        """
        if global_ignore_paths is None:
            global_ignore_paths = []
        try:
            return self.scan(
                target=target,
                target_type=target_type,
                global_ignore_paths=global_ignore_paths,
                config=config,
                *args,
                **kwargs,
            )
        except Exception as e:
            # The ONE guarded read of the values hook for this handler (the
            # rule of _values_to_redact), as _run_subprocess's handler reads it:
            # the exception can quote a value the config read from the
            # environment (a ScannerError carries the runner's text), and the
            # log, the stack trace and the response are all sinks. Without the
            # values only the exception's class is shown.
            read = guarded_values_read(self)
            if read.values is None:
                shown_error = (
                    f"{type(e).__name__} (text not shown: the plugin's values "
                    f"hook {read.failure()})"
                )
                stack_trace = "(stack trace not shown: the plugin's values hook failed)"
            else:
                shown_error = error_text(e, read.values)
                stack_trace = traceback_text(e, values=read.values)

            error_msg = f"{self.__class__.__name__} scanner failed: {shown_error}"
            ASH_LOGGER.error(error_msg)
            ASH_LOGGER.debug(f"Stack trace for scanner failure:\n{stack_trace}")

            # The response lists this failure once, ahead of the lines the run
            # recorded; the failure is then added to the scanner's error list.
            errors = [error_msg, *self.errors]
            self.errors.append(error_msg)

            # Return structured error response
            return {
                "scanner": self.__class__.__name__,
                "error": shown_error,
                "status": "failed",
                "findings": [],
                "errors": errors,
                "output": self.output,
                "stack_trace": stack_trace,
            }
