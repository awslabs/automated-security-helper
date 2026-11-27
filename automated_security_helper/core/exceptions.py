from dataclasses import dataclass
import logging
from pathlib import Path
import re
from typing import Any, Iterable, Optional

from automated_security_helper.utils.short_reason import is_short_reason

#: The ASH logger by name: this module imports no third-party package, and the
#: logger module that defines ``ASH_LOGGER`` imports several.
_LOGGER = logging.getLogger("ash")

#: What a reason code looks like: lower-case words joined by underscores.
_REASON_CODE = re.compile(r"\A[a-z][a-z0-9_]{1,47}\Z")


class ReasonCode:
    """The codes a :class:`FailureReason` carries, as plain strings.

    Not an ``Enum``: a ``(str, Enum)`` member formats as ``ReasonCode.NAME`` in an
    f-string and in ``str()`` on newer Pythons, and a code is written into the
    results file and compared as the string it is. A code names a kind of failure,
    in lower case, and each has a default sentence in :data:`DEFAULT_SENTENCES`.
    """

    # What the scan phase reads from the run the scanner's base class recorded.
    TIMED_OUT = "timed_out"
    COULD_NOT_STOP = "could_not_stop"
    COULD_NOT_START = "could_not_start"
    OUTPUT_NOT_RECORDED = "output_not_recorded"
    CANCELLED = "cancelled"
    RESULT_REJECTED = "result_rejected"
    DID_NOT_FINISH = "did_not_finish"
    EXIT_CODE_REJECTED = "exit_code_rejected"
    SCANNER_EXITED = "scanner_exited"
    # What the scan phase finds in the result a scanner handed back.
    NO_RESULT = "no_result"
    RESULT_UNGRADABLE = "result_ungradable"
    RESULTS_UNREADABLE = "results_unreadable"
    RESULTS_NOT_MERGED = "results_not_merged"
    NOT_EVALUATED = "not_evaluated"
    CONTENT_DATABASE_ABSENT = "content_database_absent"
    CONTENT_DATABASE_STALE = "content_database_stale"
    # What stops a scanner before its tool runs.
    SANDBOX_UNAVAILABLE = "sandbox_unavailable"
    SANDBOX_REFUSED = "sandbox_refused"
    NO_IMAGE_ASSET = "no_image_asset"
    CONSTRUCTION_FAILED = "construction_failed"
    NAME_REFUSED = "name_refused"
    NAME_TAKEN = "name_taken"
    CHECK_RAISED = "check_raised"
    MODULE_IMPORT_FAILED = "module_import_failed"
    NO_PLUGIN_CONTEXT = "no_plugin_context"
    NO_RESULTS_DIRECTORY = "no_results_directory"
    # What the statistics decide about a row no scanner reported on.
    TARGETS_FAILED = "targets_failed"
    COUNTERS_UNUSABLE = "counters_unusable"
    STATUS_UNKNOWN = "status_unknown"
    NO_STATUS = "no_status"
    QUEUED_NOT_COMPLETED = "queued_not_completed"
    #: The code a reason with no usable code of its own is recorded under.
    RUN_FAILED = "run_failed"


#: The sentence shown when a reason's own is not fit to show, and for a code that
#: has no sentence of its own. Each one is a clause the failure's message already
#: opens with, written without a path or a value, so a report reads the same
#: whether the scanner recorded the sentence itself or only its code.
FALLBACK_SENTENCE = "its run failed"

DEFAULT_SENTENCES: dict[str, str] = {
    ReasonCode.TIMED_OUT: "it timed out and was killed",
    ReasonCode.COULD_NOT_STOP: "it timed out and its tool could not be stopped",
    ReasonCode.COULD_NOT_START: "it could not start its tool",
    ReasonCode.OUTPUT_NOT_RECORDED: "ASH could not record its output",
    ReasonCode.CANCELLED: "its run was cancelled while its tool ran",
    ReasonCode.RESULT_REJECTED: "it returned a result ASH rejected",
    ReasonCode.DID_NOT_FINISH: "its tool did not finish",
    ReasonCode.EXIT_CODE_REJECTED: (
        "its tool exited with a code this scanner does not accept as a completed "
        "run, so its results file is not graded"
    ),
    ReasonCode.SCANNER_EXITED: "it ended the scan process before it finished",
    ReasonCode.NO_RESULT: "it returned no result",
    ReasonCode.RESULT_UNGRADABLE: "its result could not be graded",
    ReasonCode.RESULTS_UNREADABLE: (
        "its results file is not SARIF ASH can read, so its findings could not be "
        "graded"
    ),
    ReasonCode.RESULTS_NOT_MERGED: "its results could not be merged",
    ReasonCode.NOT_EVALUATED: "no rule was evaluated against some of its targets",
    ReasonCode.CONTENT_DATABASE_ABSENT: "its content database is absent",
    ReasonCode.CONTENT_DATABASE_STALE: (
        "its content database is older than the configured policy allows"
    ),
    ReasonCode.SANDBOX_UNAVAILABLE: "its sandbox backend is not available",
    ReasonCode.SANDBOX_REFUSED: "its scanner sandbox was refused",
    ReasonCode.NO_IMAGE_ASSET: "an image scan was queued for it with no image to scan",
    ReasonCode.CONSTRUCTION_FAILED: "it could not be constructed",
    ReasonCode.NAME_REFUSED: "its configured name is refused",
    ReasonCode.NAME_TAKEN: "another scanner already uses its name",
    ReasonCode.CHECK_RAISED: "its enabled or Python-only check raised",
    ReasonCode.MODULE_IMPORT_FAILED: "its plugin module failed to import",
    ReasonCode.NO_PLUGIN_CONTEXT: "it has no plugin context",
    ReasonCode.NO_RESULTS_DIRECTORY: "it has no results directory",
    ReasonCode.TARGETS_FAILED: "it failed on some of its targets",
    ReasonCode.COUNTERS_UNUSABLE: "its recorded target counts cannot be read",
    ReasonCode.STATUS_UNKNOWN: "its recorded status is not one ASH knows",
    ReasonCode.NO_STATUS: "no result was recorded for it",
    ReasonCode.QUEUED_NOT_COMPLETED: (
        "it was queued for execution but did not complete"
    ),
    ReasonCode.RUN_FAILED: FALLBACK_SENTENCE,
}


def is_reason_code(code: object) -> bool:
    """Whether ``code`` is written the way a reason code is."""
    return isinstance(code, str) and _REASON_CODE.fullmatch(code) is not None


@dataclass(frozen=True)
class FailureReason:
    """Why a scanner failed, as a code and one sentence a report can show.

    ``code`` names the kind of failure (see :class:`ReasonCode`). ``sentence`` is
    one line of at most ``SHORT_REASON_LIMIT`` characters with no path in it, as
    ``utils/short_reason.is_short_reason`` reads it, written so that
    ``<scanner> (ERROR): <sentence>`` reads as a sentence. Leave it out to get the
    code's default sentence.

    Building one never raises: it is built inside the handlers that report a
    failure, and an error raised there would hide the failure it was reporting. A
    sentence that is not fit to show (empty, longer than a line, a control
    character, or something that looks like a path) is replaced by the code's
    default sentence, ``its run failed`` for a code with none, and a code that is
    not written as a code is recorded as :attr:`ReasonCode.RUN_FAILED`. A DEBUG
    line says that a replacement was made, and never quotes what was replaced.
    """

    code: str
    sentence: str = ""

    def __post_init__(self) -> None:
        code = self.code
        if not is_reason_code(code):
            _LOGGER.debug("a failure reason's code is not a reason code; replaced")
            code = ReasonCode.RUN_FAILED
        elif code not in DEFAULT_SENTENCES:
            # A plugin may define a code of its own, so this is a note and not an
            # error; it makes a misspelled code at a raise site visible. The code
            # passed is_reason_code, so it holds no path and is safe to quote.
            _LOGGER.debug("a failure reason's code %r is not one ASH defines", code)
        sentence = self.sentence
        if is_short_reason(sentence):
            sentence = sentence.strip()
        else:
            if sentence:
                _LOGGER.debug(
                    "a failure reason's sentence is not a short sentence without "
                    "a path; its code's default is shown instead"
                )
            sentence = DEFAULT_SENTENCES.get(code, FALLBACK_SENTENCE)
        object.__setattr__(self, "code", code)
        object.__setattr__(self, "sentence", sentence)


class ScannerError(Exception):
    """Exception raised when scanner execution fails.

    ``reason`` is why, as a :class:`FailureReason`, when the code that raises it
    says. The text of the exception is unchanged and is for the log; the reason is
    what the reports show for the scanner, so it holds no path. An error raised
    with no reason is shown by the first sentence of its text where it has one.
    """

    #: None unless a raise site gave one. A class-level default, so a subclass
    #: whose own ``__init__`` never chains up still has the attribute.
    reason: Optional[FailureReason] = None

    def __init__(self, *args: object, reason: Optional[FailureReason] = None) -> None:
        super().__init__(*args)
        if reason is not None and not isinstance(reason, FailureReason):
            _LOGGER.debug("a scanner error was given a reason that is not a reason")
            reason = None
        self.reason = reason


def reason_of(error: Optional[BaseException]) -> Optional[FailureReason]:
    """The first reason recorded on ``error`` or on what it was raised from.

    The error itself first, then its ``__cause__``, then its ``__context__``, each
    followed through the same way before the next, and each error looked at once.
    A scanner's own raise sites record a reason, and the wrapper that re-raises
    them inside its ``except`` block (``scanner_plugin``) keeps the error it
    caught as ``__context__``, so the reason is found there without the wrapper
    copying it. A context that ``raise ... from None`` suppressed is not followed.
    """
    seen: set[int] = set()
    pending: list[Optional[BaseException]] = [error]
    while pending:
        current = pending.pop()
        if current is None or id(current) in seen:
            continue
        seen.add(id(current))
        reason = getattr(current, "reason", None)
        if isinstance(reason, FailureReason):
            return reason
        # The stack pops the cause before the context pushed under it.
        if not current.__suppress_context__:
            pending.append(current.__context__)
        pending.append(current.__cause__)
    return None


class ASHValidationError(Exception):
    """Exception raised when an ASH component fails to validate."""


class OrchestratorAlreadyUsedError(ASHValidationError):
    """A second execute_scan was called on one ASHScanOrchestrator.

    The orchestrator is single-scan: its run id is per instance and never
    refreshed, the scan set is recorded under that id, and reading the scan
    set with the same id returns the recorded list instead of walking again
    (by design, so plugins reread their own scan's list). A second scan on
    the same instance would therefore silently reuse the first scan's file
    list. Build a new ASHScanOrchestrator for a new scan.
    """


class ASHConfigValidationError(ASHValidationError, ValueError):
    """Exception raised when an AshConfig is invalid.

    A ValueError, as pydantic's ValidationError is, so code that catches either
    with ``except ValueError`` catches this too. A pydantic validator that raises
    it has it reported as a validation error.

    ``validation_error`` is the pydantic ValidationError a model refusal was
    described from, when there is one, for code that reads its fields. It is
    kept here and not chained as ``__cause__``: the message is redacted, and a
    traceback (or ``logger.exception``) prints a chained cause in full, and
    pydantic's text quotes every input, values read from the environment
    included. The sites that describe a ValidationError raise ``from None``.
    """

    #: The file ASH_CONFIG names, when this is that file's refusal: set by
    #: get_default_config, which every load of it goes through, so a command can
    #: say which file was refused without loading it again.
    ash_config_file: Optional[Path] = None

    #: True when the message ends with a parser's own message, which spans lines
    #: of its own that a printer keeps (cli/config.py _print_invalid_config).
    parser_message: bool = False

    def __init__(self, *args: object, validation_error: object = None) -> None:
        super().__init__(*args)
        self.validation_error = validation_error


class CommittedOutputFilesError(ASHConfigValidationError):
    """The output directory holds files git tracks where a scan writes its own.

    A scan deletes the previous run's results there and writes this run's, so
    running it would delete or overwrite the committed files. A subclass of
    ``ASHConfigValidationError`` so that the scan exits 3, as for any other setting
    it cannot run with: here the output directory.
    """


class ASHRespelledOverrideError(ASHConfigValidationError):
    """An override's key is a non-exact spelling of a section that exists.

    Raised by ``config_sources.resolve_override_segment``, the one resolver
    every override walker uses. Its own class so a caller that deliberately
    tolerates overrides that do not apply to a given base (the scan's replay
    of ``reporters`` overrides onto the operator's own configuration) can
    still re-raise this refusal: applying the respelling as a new extra key
    would be a silent no-op against the section the plugin reads.
    """


class ASHConfigSourceError(ASHConfigValidationError):
    """A config source could not be read or its ``extends`` chain resolved.

    Covers a missing or unreadable base, a cycle, a chain past its bounds, a base
    path outside the confinement root, a malformed ``patch``, and a
    ``pyproject.toml`` whose ``[tool.ash]`` table cannot be read. A subclass of
    ``ASHConfigValidationError`` so that ``resolve_config`` re-raises it rather
    than falling back to the default config: a config whose bases did not load is
    not the config the operator wrote, and scanning with the defaults instead
    would drop its suppressions and settings without failing.
    """


class ASHConfigUnparsedError(ASHConfigSourceError):
    """A config file's text did not parse, said in the shared refusal's words.

    The message is the complete refusal (``<path> could not be parsed (...)``,
    from ``unparsed_config_reason`` or built around ``parse_error_kind``): it
    names the file and says what failed, so a printer that frames other source
    errors ("Failed to parse config file:", "--profile 'x' failed to load
    <path>:") shows this one as it is, or the frame restates the reason and
    names the path twice.
    """


class ASHConfigFileNotFoundError(ASHConfigSourceError):
    """A config file that was named or discovered does not exist.

    Raised for a missing path, a symbolic link to nothing, and an ``ASH_CONFIG``
    naming a missing file. A subclass of ``ASHConfigSourceError`` so it refuses
    the same way; distinct so that a caller reporting it (the MCP tools) can say
    "not found" rather than "cannot be parsed".
    """


class ASHConfigInputNotPermittedError(ASHConfigSourceError):
    """A config file is outside what the caller may read.

    A file an ``extends`` chain names, or the one discovery selects in a
    directory (``resolve_config.find_config_file``). Raised only when the caller
    passed a ``permit_base`` gate, which the MCP server does with the session's
    allowed config roots. A subclass of ``ASHConfigSourceError`` so every path
    that already refuses a broken chain refuses this one, and distinct so the
    MCP tools can report it as a refusal rather than as a malformed config. The
    message names the ``extends`` entry as written, or the discovered file by
    its name, and never the resolved target, so it reads the same whether or not
    that target exists.
    """


class ASHConfigFieldDeniedError(ASHConfigValidationError):
    """A config file an MCP client delivered sets a field the session's policy denies.

    The policy is ``global_settings.mcp.runtime_overrides``' ``denied_paths`` and
    ``denied_value_patterns``, the rules a client's ``patch_ops`` and
    ``config_overrides`` are held to. A subclass of ``ASHConfigValidationError``
    so every caller that refuses an invalid config refuses this one, and distinct
    so the MCP tools can report it as a refusal naming the field.
    """


class ASHConfigPolicyUnreadableError(ASHConfigValidationError):
    """The policy a client-delivered config is checked against cannot be established.

    The profile the session bound is no longer registered, or the trusted config
    has two sections that read as the same plugin. Raised only when the config
    being resolved has a client-delivered file in its chain, so a scan that reads
    no such file is unaffected.
    """


class ASHConfigUnsetVariableError(ASHConfigSourceError):
    """A config file references ``${VAR}``, with no default, and ``VAR`` is unset.

    Its text names the variable, as the file writes it, and the file that holds
    the reference once the reader that opened it has said so; with ``VAR`` unset
    there is no value to quote. A subclass of ``ASHConfigSourceError``, so every
    caller that refuses a config that did not load refuses this one with exit 3.

    ``variable`` is the name. ``config_file`` is the file holding the reference,
    or None before a reader has named it. ``detail`` is the message without the
    file, for a reader that names the file another way (the ``extends`` reader,
    which does not quote a base's path).
    """

    def __init__(
        self,
        message: str,
        *,
        variable: str,
        config_file: Optional[Path] = None,
        detail: Optional[str] = None,
    ):
        super().__init__(message)
        self.variable = variable
        self.config_file = config_file
        self.detail = message if detail is None else detail

    def __reduce__(self) -> tuple[Any, ...]:
        # BaseException rebuilds an exception as ``cls(*args)``, and ``variable``
        # is required and keyword-only, so copy.copy, copy.deepcopy and pickle
        # (a worker process handing the error back) failed with a TypeError.
        # Rebuilt from the message and the variable, with the instance's other
        # attributes restored from its ``__dict__``.
        message = self.args[0] if self.args else ""
        return (
            _rebuild_unset_variable_error,
            (type(self), message, self.variable),
            self.__dict__,
        )


def _rebuild_unset_variable_error(cls: Any, message: str, variable: str) -> Any:
    """``cls(message, variable=variable)``, for ``ASHConfigUnsetVariableError.__reduce__``."""
    return cls(message, variable=variable)


class ASHConfigEnvNotResolvedError(ASHConfigSourceError):
    """A config file an MCP client delivered uses ``!ENV``.

    Such a file does not resolve environment variables at all, and one that
    uses ``!ENV`` is refused rather than read with the reference dropped; see
    "Environment variables" in ``config/config_sources.py``. A subclass of
    ``ASHConfigSourceError`` so every path that refuses a config that did not
    load refuses this one, and distinct so ``ConfigValidator`` and the MCP tools
    can report it as its own error type.
    """


class WorkspacePatternError(ASHValidationError):
    """Exception raised when a glob pattern cannot be rebased between the
    project and workspace path spaces.

    Distinct from ASHConfigValidationError so a caller can map a bad pattern to
    the workspace definition error exit code rather than reporting it as a
    general configuration failure.
    """


class ScannerSelectionError(ASHValidationError):
    """Exception raised when ``--scanners`` names no scanner that exists.

    The same failure mode :class:`ShardSelectionError` guards against, reached by a
    different route: a scan that ran nothing and reported itself as a clean one.
    Selection is matched against a scanner's configured name by string equality, so
    ``--scanners detect_secrets`` -- underscore, where the registered name is
    ``detect-secrets`` -- matched nothing, every scanner was recorded SKIPPED, and
    the run produced zero findings and exit 0.

    SKIPPED cannot be what gives that away. It is how sharding and
    ``--exclude-scanners`` record work a run was never meant to do, so the
    completeness gate has to tolerate it; that is what leaves an unresolvable
    allowlist with no existing gate to fall foul of.

    Raised only when *nothing* the operator asked for resolved. A partly
    unresolvable allowlist warns and continues: those runs still scan and report
    what did resolve, and a CI matrix can produce that shape legitimately when its
    runners load different plugin modules.
    """


class ShardSelectionError(ASHValidationError):
    """Exception raised when ``--shard-index``/``--shard-count`` cannot be used as given.

    Every case this covers would otherwise produce a *partial* scan that reports
    itself as a whole one, which is the worst available outcome for a security
    scanner: a lone ``--shard-index`` with no ``--shard-count`` would scan shard 0
    of an unknown total, and an index at or past the count would scan nothing at
    all and exit 0.

    Refused rather than clamped. Clamping an out-of-range index onto the last
    shard would make a pipeline with an off-by-one in its matrix expression scan
    one shard twice and another never, and the reports would look healthy.
    """


class ShardCoverageError(ASHValidationError):
    """Exception raised when a set of shard results cannot be merged into a whole.

    A merge is only meaningful if the shards it is handed reconstruct exactly one
    full scan. This is raised when they do not: a missing index (a CI job that
    failed or whose artifact never uploaded), a duplicated index, shards that
    disagree about the total count, or two shards that both claim the same
    scanner.

    The failure mode this exists to prevent is silent and severe. Merging four of
    five shards produces a valid, well-formed, confidently-empty-looking report
    for whichever scanners lived on the missing shard, and nothing in the output
    says a fifth of the scan is absent. So the merge fails loudly and names the
    specific gap instead of reporting what it happens to have.
    """


class ToolDownloadIntegrityError(ASHValidationError):
    """Exception raised when a downloaded tool's bytes do not match its pinned digest.

    Raised before the download is moved into place, so a failed verification
    leaves nothing installed rather than installing the bad bytes and reporting
    the mismatch afterwards.

    The failure this exists to prevent is specific: without it, a scanner binary
    that had been substituted upstream, truncated by a proxy, or served from a
    cache poisoned in transit would be installed, found on PATH, and then trusted
    to produce the findings a security decision is made from. A digest field that
    is recorded but never compared is not a check, so this is raised on every
    mismatch and never downgraded to a warning.
    """


class DownloadTooLargeError(ASHValidationError):
    """Exception raised when a download's body exceeds the caller's byte bound.

    Raised while the bytes are still streaming into the download's temporary
    file -- or before any byte is read, when the response declares an oversize
    length -- so the transfer is ABORTED at the bound, never completed and then
    measured. Without it, a size limit checked only against a recorded claim
    (a lockfile's own ``size`` field, which the scanned repository wrote) was
    no limit at all: a lying claim bought an unbounded transfer spooled whole
    to disk.

    Never classified transient: the same URL serves the same body, so a retry
    only repeats the cost the bound exists to refuse.
    """


class ToolNotProvisionableError(ASHValidationError):
    """Exception raised when a tool cannot be installed on the current platform.

    Covers four distinct cases, all refused rather than approximated:

    * the tool has no install path in ASH at all,
    * the tool has one but publishes no asset for this platform/architecture,
    * the pinned version and the pinned digests disagree, which is what a
      half-applied version bump looks like,
    * ASH is offline and has no verified copy to install from, so the tool would
      have to be downloaded.

    Substituting a nearby architecture would install an executable that fails at
    exec time, and that surfaces in a scan report as an execution failure rather
    than as a bad install -- the diagnosis lands on the wrong thing. An absent
    asset is a real constraint and is reported as one.
    """


class ScanSetUnreadableError(ASHValidationError):
    """The run's scan set could not be read or built, so a scanner cannot run on it.

    Raised by utils/scan_output_dirs.py's scan_set_of in place of the empty list
    it returned, which told the scanner nothing was in scope. Not an OSError or a
    ValueError, so a handler that reads those as "nothing to exclude" does not
    catch it; the scanner stops, and the scan exits 1 with it incomplete.
    """


class WorkspaceDefinitionError(ASHValidationError):
    """Exception raised when a workspace definition cannot be used as given.

    Covers the whole fail-closed set: a malformed or unreadable
    ``.code-workspace`` file, a folder entry that does not exist, escapes the
    workspace root, is a symlink, or overlaps another entry, and two projects
    whose scanner version pins cannot both be satisfied.

    Maps to ``WorkspaceExitCode.WORKSPACE_ERROR`` (4). Kept distinct from
    ASHConfigValidationError, which maps to ``INVALID_PROJECT_CONFIG`` (3),
    because the two route to different people: 4 means the operator's workspace
    file is wrong and nothing could run, 3 means one project is misconfigured.

    The message is expected to name every offending entry rather than the first,
    so an operator with three typos fixes three in one pass.

    A refusal that lists its problems is built with :meth:`listing`, which keeps
    the layout in ``lines``: the headline, then ``  - <problem>`` per problem.
    The layout is ASH's own text and each line quotes the operator's text as it
    is, so a sink shows each line on one line (the CLI's refusal): a newline in a
    project name is then written ``\\x0a`` and cannot start a list item of its
    own. ``lines`` is empty for a refusal that is one message.
    """

    def __init__(self, message: str = "", *, lines: tuple[str, ...] = ()):
        super().__init__(message)
        self.lines: tuple[str, ...] = tuple(lines)

    @classmethod
    def listing(
        cls, headline: str, problems: Iterable[str]
    ) -> "WorkspaceDefinitionError":
        """A refusal of *headline* followed by one ``  - <problem>`` line each."""
        lines = (headline, *(f"  - {problem}" for problem in problems))
        return cls("\n".join(lines), lines=lines)


class WorkspacePathNotUtf8Error(WorkspaceDefinitionError):
    """A path the workspace plan would hold is not UTF-8, so it cannot be planned.

    The workspace file, its root, a project folder, the workspace policy file or
    the default config. A WorkspaceDefinitionError, so it exits 4 like every other
    definition refusal. Its message names each path as it is, surrogate escapes
    and any newline in a name included. Each sink shows it once, as the whole message
    through utils/terminal_text.py's shown_on_one_line: the CLI's refusal, the
    workspace run's handler in run_ash_scan, and the MCP tools' response, which is
    JSON and cannot hold a lone surrogate. On one line, so a newline in a name is
    written ``\\x0a`` and cannot start a line of its own.

    ``str()`` of it still holds those surrogate escapes, so a new sink that writes
    it as it is writes a lone surrogate: show it through ``shown_on_one_line`` as
    the three sinks above do.
    """
