from pathlib import Path
from typing import Any, Iterable, Optional


class ScannerError(Exception):
    """Exception raised when scanner execution fails."""


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
