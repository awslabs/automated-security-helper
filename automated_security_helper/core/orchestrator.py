#!/usr/bin/env python3
"""Main entry point for ASH multi-scanner execution."""

import json
import shutil
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import (
    Annotated,
    Any,
    Callable,
    Dict,
    Iterator,
    List,
    Literal,
    Optional,
    Set,
    Tuple,
    cast,
)

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, model_validator

from automated_security_helper.base.plugin_context import PluginContext

from automated_security_helper.config.path_trust import (
    derived_roots_scope,
    forget_derived_roots,
)
from automated_security_helper.config.recorded_config import take_own_values
from automated_security_helper.config.resolve_config import (
    LoggedResolutionWarning,
    resolve_config,
)
from automated_security_helper.core.enums import ExecutionStrategy
from automated_security_helper.core.scanner_selection import SelectionOrigin
from automated_security_helper.core.progress import (
    ExecutionPhaseType,
)
from automated_security_helper.core.constants import (
    ASH_WORK_DIR_NAME,
)
from automated_security_helper.core.phases.scan_phase import scan_phase_completed
from automated_security_helper.core.execution_engine import (
    ScanExecutionEngine as ScanExecutionEngine,
)

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.core import ignore_paths_that_skip_scanning
from automated_security_helper.config.client_config_policy import ClientConfigRules
from automated_security_helper.core.committed_output import (
    LOG_FILE_NAMES,
    PREVIOUS_RUN_FILE_NAMES,
    refuse_committed_entries,
    report_over_existing_results_writes,
)
from automated_security_helper.core.exceptions import (
    ASHConfigValidationError,
    ASHValidationError,
    OrchestratorAlreadyUsedError,
)
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    warning_of_dropped_keys,
)
from automated_security_helper.models.asharp_model import InputNotScanned
from automated_security_helper.models.core import IgnoreFileExclusions
from automated_security_helper.core.enums import ExportFormat
from automated_security_helper.utils.get_ash_version import get_ash_version
from automated_security_helper.utils.get_scan_set import (
    honors_ignore_files,
    new_run_id,
    scan_set,
)
from automated_security_helper.utils.inner_run_outcome import (
    ExistingResultsRefused,
    existing_results_problem,
    without_run_records,
)
from automated_security_helper.utils.error_text import (
    carry_environment_values,
    config_environment_values,
    error_text,
    text_without_values,
)
from automated_security_helper.utils.log import ASH_LOGGER, NO_MARKUP
from automated_security_helper.utils.process_env import (
    hold_environ,
    release_environ,
)
from automated_security_helper.utils.terminal_text import shown_on_one_line
from automated_security_helper.utils.suppression_matcher import active_ignore_paths
from automated_security_helper.utils.output_dir_links import (
    OUTPUT_WORKING_DIRS,
    OutputDirLinkRefused,
    ignore_output_dir_in_git,
    is_link,
    refuse_linked_output_dir,
)
from automated_security_helper.utils.report_path_links import (
    ensure_reports_dir,
    refuse_a_linked_reports_dir,
)
from automated_security_helper.utils.subprocess_utils import scanning_tree
from automated_security_helper.core.cancellation import (
    ScanCancelled,
    raise_if_cancelled,
)
from automated_security_helper.core.previous_results import PreviousResults

# One lock for every instance's used-check in execute_scan. Module-level rather
# than per instance: the sentinel is a pydantic PrivateAttr, and a per-instance
# lock would have to survive model_copy and deepcopy of the model. The guarded
# section is only the check and the mark, never any scan work.
_SCAN_SENTINEL_LOCK = threading.Lock()


def resolve_scan_config(
    *,
    config_path: Optional[str | Path],
    source_dir: str | Path,
    config_overrides: Optional[List[str]] = None,
    config_base_gate: Optional[Callable[[Path], bool]] = None,
    trusted_config_path: Optional[str | Path] = None,
    untrusted_config: bool = False,
    client_overrides: bool = False,
    client_config_policy: Optional[ClientConfigRules] = None,
    remote_client: bool = False,
) -> AshConfig:
    """The config a single-directory scan of ``source_dir`` runs with.

    The orchestrator resolves through here. ``trusted_config_path`` and
    ``untrusted_config`` decide whose sandbox settings stand, and with them
    ``resolve_config`` keeps the operator's sandbox mode as a floor. A resolution
    without them reads ``sandbox.mode`` from a file the scanned repository or an
    MCP client wrote, which the scan itself does not honor.
    """
    return resolve_config(
        config_path=config_path,
        source_dir=source_dir,
        config_overrides=list(config_overrides or []),
        permit_base=config_base_gate,
        trusted_config_path=trusted_config_path,
        untrusted_config=untrusted_config,
        client_overrides=client_overrides,
        client_config_policy=client_config_policy,
        remote_client=remote_client,
    )


def _refuse_a_named_config_that_is_not_a_file(
    config_path: Optional[str | Path],
) -> None:
    """Raise the refusal for a named ``config_path`` that is not a regular file.

    A scan given a config file that does not exist must not run with the
    defaults in its place: the file is there to configure the run, and the
    defaults would scan with its suppressions, ignore paths and settings
    switched off and report success. ``resolve_config`` keeps its documented
    fallback to the default config for a missing named path, so the scan
    refuses the path here, before resolution and before the engine is built,
    in the words the single-directory CLI uses for the same path
    (run_ash_scan._refuse_a_named_config_that_is_not_a_file). One stat
    classifies the path (utils/path_stat.py): a symbolic link loop and a denied
    stat are not a missing file, and a path that exists and is not a regular
    file (a directory, a FIFO) is named for what it is. None means discovery.
    An empty or blank path is left to ``resolve_config``, as before this check.
    """
    if config_path is None:
        return
    if isinstance(config_path, str) and not config_path.strip():
        return
    from automated_security_helper.config.config_sources import (
        not_a_regular_file_refusal,
    )
    from automated_security_helper.utils.path_stat import (
        LOOP,
        UNREADABLE,
        StatProblem,
        is_regular_file,
        stat_named_path,
    )

    named_config = stat_named_path(config_path)
    if is_regular_file(named_config):
        return
    path = Path(config_path)
    if isinstance(named_config, StatProblem):
        if named_config.kind == LOOP:
            raise ASHConfigValidationError(
                f"Config file is a symbolic link loop: {path.as_posix()}"
            ) from named_config.cause()
        if named_config.kind == UNREADABLE:
            raise ASHConfigValidationError(
                f"Config file cannot be read ({named_config.code}): {path.as_posix()}"
            ) from named_config.cause()
        # MISSING, the one kind left.
        raise ASHConfigValidationError(
            f"Configuration file not found: {path.as_posix()}"
        )
    raise not_a_regular_file_refusal(path)


class ASHScanOrchestrator(BaseModel):
    """Orchestrator class for ASH security scanning operations."""

    model_config = ConfigDict(arbitrary_types_allowed=True, extra="allow")

    # Defaults are computed per instance, not when this module is imported:
    # Path.cwd() at class definition froze the importing process's directory into
    # every orchestrator built later, and gave output_dir a cwd-derived value that
    # left model_post_init's source-derived default (``<source_dir>/.ash/ash_output``)
    # unreachable, so a caller naming only source_dir got an output directory
    # under some other tree.
    source_dir: Annotated[
        Path, Field(default_factory=Path.cwd, description="Source directory to scan")
    ]
    output_dir: Annotated[
        Path | None,
        Field(
            default=None,
            description=(
                "Output directory for results; None derives "
                "<source_dir>/.ash/ash_output when the orchestrator is built"
            ),
        ),
    ]
    work_dir: Annotated[
        Path | None, Field(description="Working directory for scan operations")
    ] = None
    config: Annotated[
        AshConfig | None, Field(description="The resolved ASH configuration")
    ] = None
    resolved_config: Annotated[
        AshConfig | None,
        Field(
            description=(
                "A configuration the caller has already resolved and merged. When "
                "set, initialize() adopts it verbatim instead of resolving one of "
                "its own, and leaves it as the value of `config`. Because "
                "resolution is skipped entirely, the caller must have applied any "
                "config_overrides itself before building this config: they cannot "
                "be supplied alongside it (see _reject_conflicting_config_inputs) "
                "and nothing here will apply them. A caller that resolves without "
                "overrides and then passes the result will silently drop them."
            )
        ),
    ] = None

    strategy: Annotated[
        ExecutionStrategy,
        Field(description="Whether to execute scanners in parallel or sequentially"),
    ] = ExecutionStrategy.PARALLEL
    config_path: Annotated[
        Optional[Path | str], Field(None, description="Path to configuration file")
    ]
    config_overrides: Annotated[
        Optional[List[str]],
        Field(None, description="Configuration overrides as key-value pairs"),
    ]
    config_base_gate: Annotated[
        Optional[Callable[[Path], bool]],
        Field(
            None,
            exclude=True,
            description=(
                "Check every `extends` base of the config must also pass, on top "
                "of the confinement config_sources applies. The MCP server passes "
                "the calling session's allowed config roots; None keeps the CLI "
                "rule."
            ),
        ),
    ] = None
    untrusted_config: Annotated[
        bool,
        Field(
            description=(
                "The config at config_path was written by the caller, not the "
                "operator, so its sandbox settings are restrict-only. Passed to "
                "resolve_config; see its docstring."
            ),
        ),
    ] = False
    client_overrides: Annotated[
        bool,
        Field(
            description=(
                "config_overrides came from an MCP client, not the operator, so a "
                "tool config path they name is not the operator's. Passed to "
                "resolve_config."
            ),
        ),
    ] = False
    remote_client: Annotated[
        bool,
        Field(
            description=(
                "The scan was started by a remote MCP client, so a config file "
                "the operator did not set aside resolves no !ENV. Passed to "
                "resolve_config; see its docstring."
            ),
        ),
    ] = False
    trusted_config_path: Annotated[
        Optional[Path | str],
        Field(
            None,
            description=(
                "The operator's config the sandbox grants come from when "
                "untrusted_config is set, in place of ASH_CONFIG or the defaults. "
                "Passed to resolve_config."
            ),
        ),
    ] = None
    client_config_policy: Annotated[
        Optional[ClientConfigRules],
        Field(
            None,
            description=(
                "The rules a config file an MCP client delivered is checked "
                "against (the session's). Passed to resolve_config; see "
                "config/client_config_policy.py."
            ),
        ),
    ] = None
    color_system: Annotated[
        Optional[str], Field(None, description="Color system to use for console output")
    ] = None
    verbose: Annotated[bool, Field(False, description="Enable verbose logging")] = False
    debug: Annotated[bool, Field(False, description="Enable debug logging")] = False
    show_progress: Annotated[
        bool,
        Field(True, description="Enable graphical progress visibility in the console."),
    ] = True
    simple_mode: Annotated[
        bool,
        Field(
            False,
            description="Enable simplified output mode for pre-commit hooks and CI.",
        ),
    ] = False
    offline: Annotated[bool, Field(False, description="Run in offline mode")] = False
    no_run: Annotated[bool, Field(False, description="Only build container image")] = (
        False
    )
    build_target: Annotated[
        str | None, Field("default", description="Build target for container image")
    ] = None
    enabled_scanners: Annotated[
        List[str],
        Field(
            description="List of enabled scanners. Defaults to all registered.",
        ),
    ] = []
    excluded_scanners: Annotated[
        List[str],
        Field(
            description="List of scanners to exclude. Takes precedence over enabled_scanners.",
        ),
    ] = []
    oci_runner: Annotated[str, Field("docker", description="OCI runner to use")] = (
        "docker"
    )
    no_cleanup: Annotated[
        bool, Field(False, description="Keep work directory after scan")
    ]
    ignore_suppressions: Annotated[
        bool,
        Field(
            False, description="Ignore all suppression rules and report all findings"
        ),
    ] = False

    metadata: Annotated[
        Dict[str, Any] | None,
        Field(default_factory=dict, description="Additional metadata for the scan"),
    ]

    # Core components
    execution_engine: Annotated[ScanExecutionEngine | None, Field()] = None

    output_formats: List[ExportFormat] = []

    existing_results_path: Annotated[
        Optional[Path],
        Field(description="Path to existing ash_aggregated_results.json file"),
    ] = None

    workspace_output_dir: Annotated[
        Optional[Path],
        Field(
            description=(
                "In a workspace scan, the workspace's output directory, which holds "
                "this project's output directory and every other project's. Left "
                "out of the scan like output_dir: for a project at the workspace "
                "root it is inside the scanned tree (PluginContext."
                "workspace_output_dir)."
            )
        ),
    ] = None

    python_based_plugins_only: Annotated[
        bool,
        Field(
            False,
            description="Exclude execution of any plugins or tools that have dependencies external to Python",
        ),
    ] = False

    ash_plugin_modules: Annotated[
        List[str],
        Field(
            description="List of Python modules to import containing ASH plugins and/or event subscribers",
            default_factory=list,
        ),
    ]

    plugin_module_names: Annotated[
        Dict[str, str],
        Field(
            description=(
                "How the whole run names its plugin modules in log lines, for a "
                "run whose modules come from more than one config (a workspace "
                "run's projects): a name another project read from the "
                "environment is named by its masked form here too."
            ),
            default_factory=dict,
        ),
    ]

    shard_index: Annotated[
        Optional[int],
        Field(
            None,
            description=(
                "Zero-based index of this shard when one scan is split across "
                "several executors. Requires shard_count. Carried through to the "
                "scan phase, which owns both the validation and the partition -- "
                "see core.sharding for why the split cannot be computed above it."
            ),
        ),
    ] = None

    shard_count: Annotated[
        Optional[int],
        Field(
            None,
            description=(
                "Total number of shards the scan is split across. Requires shard_index."
            ),
        ),
    ] = None

    selection_origin: Annotated[
        SelectionOrigin,
        Field(
            description=(
                "Who made the scanner selection: 'cli' for --scanners and "
                "--exclude-scanners, 'mcp' for the MCP workspace tool's scanners and "
                "excluded_scanners parameters. A SKIPPED row names what was used."
            ),
        ),
    ] = "cli"

    changed_files: Annotated[
        Optional[Set[Path]],
        Field(
            None,
            description=(
                "Resolved paths of the files changed against the base ref, from "
                "--changed-files-only. Every scanner still scans everything; the "
                "engine drops findings located outside these files before the "
                "summary counts and the reports are written. None means no filter; "
                "an empty set matches nothing."
            ),
        ),
    ] = None

    show_summary: Annotated[
        bool,
        Field(
            True,
            description="Show metrics table and results summary after scan completion",
        ),
    ] = True

    severity_threshold_restriction: Annotated[
        Optional[str],
        Field(
            None,
            description=(
                "A global severity threshold the scan must be at least as strict "
                "as. The scan runs at the stricter of this and the threshold the "
                "configuration resolves to, so a caller can tighten the "
                "configured threshold and never loosen it."
            ),
        ),
    ] = None

    keep_previous_results: Annotated[
        bool,
        Field(
            description=(
                "Set the previous scan's results aside when the scan starts and put "
                "them back if it ends without results of its own, instead of "
                "deleting them. The MCP server asks for this, and records on the "
                "scan's entry when the files it put back are not that scan's. The "
                "CLI does not, and deletes them, as it always has."
            ),
        ),
    ] = False

    # Sentinel: True after initialize() has run successfully
    _initialized: bool = False
    # The previous scan's results while this one runs; see core/previous_results.py.
    # None when keep_previous_results is off, or this is a report-only run over
    # existing results. Kept when set_aside failed, so that a held set an earlier
    # killed scan left is still dropped once this scan has its results (below).
    _previous_results: Optional[PreviousResults] = None
    # Whether set_aside moved this scan's predecessor out of the way. False when
    # it raised: this scan then replaced the previous results as it wrote, and a
    # restore at its end would put back not them but whatever older set the
    # directory held, so nothing is put back; the held set is dropped on success.
    _previous_results_set_aside: bool = PrivateAttr(default=False)

    # This scan's ID. The scan set is written to the output directory under it, and
    # the plugins get it on their context (PluginContext.run_id), so they read back
    # the list this scan wrote and no other (utils/get_scan_set.scan_set).
    _run_id: str = PrivateAttr(default_factory=new_run_id)

    # Set at the start of the first execute_scan, finished or not: the run id,
    # the scan set recorded under it and the previous-results set-aside are
    # that scan's state, so a second scan takes a new instance.
    _scan_executed: bool = PrivateAttr(default=False)

    @model_validator(mode="after")
    def _reject_conflicting_config_inputs(self) -> "ASHScanOrchestrator":
        """Refuse a pre-resolved config alongside the inputs to resolution.

        `resolved_config` says resolution already happened; `config_path` and
        `config_overrides` say how to perform it. Accepting both would mean
        honouring one and dropping the other, which is the failure
        `resolved_config` exists to fix — so refuse instead of picking a winner.
        Empty values do not conflict: callers routinely pass `... or []`.

        The consequence for the caller is that they own the overrides. Nothing
        downstream of this point applies them, so a caller that resolves without
        them and hands the result over drops them silently. The error below says
        so, because whoever hits it is exactly who needs to know.
        """
        if self.resolved_config is None:
            return self
        conflicting = [
            name
            for name, value in (
                ("config_path", self.config_path),
                ("config_overrides", self.config_overrides),
                ("config_base_gate", self.config_base_gate),
                ("untrusted_config", self.untrusted_config),
                ("client_overrides", self.client_overrides),
                ("remote_client", self.remote_client),
                ("trusted_config_path", self.trusted_config_path),
                ("client_config_policy", self.client_config_policy),
            )
            if value
        ]
        if conflicting:
            supplied = " and ".join(conflicting)
            raise ValueError(
                f"resolved_config cannot be combined with {supplied}. A resolved "
                f"config means resolution has already happened, so {supplied} "
                "would have no effect. Apply them yourself before building the "
                "config you pass as resolved_config, because nothing else will, "
                "or drop resolved_config and let the orchestrator resolve."
            )
        return self

    def model_post_init(self, context):
        """Post initialization — data-only; no filesystem I/O."""
        super().model_post_init(context)
        # Coerce source_dir / output_dir to Path so callers never get str
        if self.source_dir is None:
            self.source_dir = Path.cwd()
        elif not isinstance(self.source_dir, Path):
            self.source_dir = Path(self.source_dir)

        if self.output_dir is None:
            self.output_dir = self.source_dir.joinpath(".ash", "ash_output")
        elif not isinstance(self.output_dir, Path):
            self.output_dir = Path(self.output_dir)

        if self.config is not None:
            # initialize() assigns the configuration it resolves, or adopts
            # resolved_config, over this field, so a config given here was read
            # by nothing. A caller that built one wants resolved_config.
            ASH_LOGGER.warning(
                "The config passed to the constructor is not used: initialize() "
                "resolves its own configuration, or adopts resolved_config when "
                "one is given. Pass the configuration as resolved_config."
            )

    def __copy__(self) -> "ASHScanOrchestrator":
        return self._with_its_own_run_id(super().__copy__())

    def __deepcopy__(
        self, memo: Optional[Dict[int, Any]] = None
    ) -> "ASHScanOrchestrator":
        return self._with_its_own_run_id(super().__deepcopy__(memo))

    @staticmethod
    def _with_its_own_run_id(
        copied: "ASHScanOrchestrator",
    ) -> "ASHScanOrchestrator":
        """A copy of an orchestrator that has not been initialized gets a run id
        of its own.

        ``model_copy`` copies the private attributes, so two copies of one
        template shared a run id, wrote their scan sets to the same file under
        it and read each other's list back. An initialized orchestrator holds
        the engine and the context built under its id, so its copy keeps it.
        """
        if not copied._initialized:
            copied._run_id = new_run_id()
        return copied

    def initialize(self) -> None:
        """Perform all filesystem I/O and engine setup.

        Idempotent: subsequent calls are no-ops once _initialized is True.
        Call this explicitly, or use the .create() factory which calls it for you.
        """
        if self._initialized:
            return
        # Building the plugins already looks tools up, so source_dir is the scanned
        # tree for this as well as for execute_scan; see
        # utils/subprocess_utils.scanning_tree. Scoped to the call, so nothing is
        # left registered if it raises.
        with scanning_tree(self.source_dir), self._offline_scope():
            self._initialize()

    @contextmanager
    def _offline_scope(self) -> Iterator[None]:
        """Hold ``ASH_OFFLINE=YES`` for the body when this run is offline.

        ``offline`` was a declared field that nothing read: the environment
        variable is the one thing the plugins read (core/constants.is_offline_mode),
        so a caller that built the orchestrator with ``offline=True`` and set no
        variable of its own ran every scanner online. The hold is counted
        (utils/process_env.hold_environ), so it nests with the CLI's and the
        workspace's own, and the variable returns to what it was when the last
        holder leaves.
        """
        if not self.offline:
            yield
            return
        hold_environ("ASH_OFFLINE", "YES")
        try:
            yield
        finally:
            release_environ("ASH_OFFLINE")

    def _initialize(self) -> None:
        ASH_LOGGER.info(f"Initializing ASH v{get_ash_version()}")

        if self.resolved_config is not None:
            ASH_LOGGER.verbose(
                "Using the configuration supplied by the caller; skipping resolution"
            )
            config = self.resolved_config
            if self.severity_threshold_restriction is not None:
                # The restriction below rewrites thresholds in place. The caller
                # keeps this object, and a workspace hands the same one to more
                # than one scan, so the scan works on a copy of its own.
                config = config.model_copy(deep=True)
        else:
            # Before resolution: resolve_config answers a missing named file
            # with the default config, and this scan must not run on it.
            _refuse_a_named_config_that_is_not_a_file(self.config_path)
            config = resolve_scan_config(
                config_path=self.config_path,
                source_dir=self.source_dir,
                config_overrides=self.config_overrides,
                config_base_gate=self.config_base_gate,
                trusted_config_path=self.trusted_config_path,
                untrusted_config=self.untrusted_config,
                client_overrides=self.client_overrides,
                client_config_policy=self.client_config_policy,
                remote_client=self.remote_client,
            )
        self.config = config

        if self.severity_threshold_restriction is not None:
            self._restrict_severity_threshold(
                config, self.severity_threshold_restriction
            )

        # Surface config resolution warnings prominently, once: resolution has
        # already logged some of them (LoggedResolutionWarning). A warning can
        # quote a parser's message, which names the config file: the file's path
        # is the caller's text, so the whole warning is one log line, every
        # newline written as \x0a, and NO_MARKUP, since Rich would read a "[/"
        # in the path as a closing tag. The parser's own layout is flattened
        # with it, deliberately: resolve_config discovers the file itself, so
        # this record cannot tell the name's newlines from the parser's (the
        # scan's exit-3 refusal, which knows the file, keeps the parser's lines;
        # see run_ash_scan._printed_config_refusal).
        if self.config._resolution_warnings:
            for warning in self.config._resolution_warnings:
                if not isinstance(warning, LoggedResolutionWarning):
                    ASH_LOGGER.warning(
                        shown_on_one_line(f"⚠️  CONFIG WARNING: {warning}"),
                        extra=NO_MARKUP,
                    )

        # The engine first. Building it is where an option a loaded plugin does not
        # accept, a scanner selection that cancels itself and an allowlist naming
        # no registered scanner are refused, and it starts no process and writes
        # nothing. Every step after it asks git or changes the output directory, so
        # a command line ASH refuses does neither: it starts no `git ls-files`
        # for the committed-files check and deletes no previous results.
        #
        # One exception, an output directory that is itself a link: the engine's
        # context registers the directory it writes below and refuses a link there
        # (base/plugin_context.py, _guard_output_dir), as a pydantic
        # ValidationError, which no entry point reads as a refusal. Such a run is
        # refused whatever the engine would say, so for it the committed check and
        # the link refusal run first, in that order: a link the repository
        # committed is refused as the committed entry it is, with exit 3 and its
        # path, as the CLI and the MCP tools refuse it (core/committed_output.py),
        # and one git does not track as a link (_refuse_linked_output_dir).
        if is_link(self.output_dir):
            self._refuse_committed_results_paths()
            self._refuse_linked_output_dir()
        self._build_engine(config)
        self._refuse_committed_results_paths()

        if self.existing_results_path is None:
            if self.keep_previous_results:
                self._set_previous_results_aside()
            else:
                self._remove_kept_previous_results()

        # Once they are set aside, every way out of the rest of the set-up puts
        # them back, and the scan then never reaches execute_scan, which is what
        # settles them otherwise.
        try:
            self._prepare_output_dir()
            self._apply_metadata()
        except BaseException:
            self.settle_previous_results(restore=True)
            raise

        self._initialized = True
        ASH_LOGGER.info("ASH Orchestrator and ScanExecutionEngine initialized")

    def _set_previous_results_aside(self) -> None:
        """keep_previous_results: move them out of this scan's way (execute_scan).

        Not fatal when they cannot be moved: the scan then deletes them as it
        would without keep_previous_results, and they do not come back if it
        fails.
        """
        self._previous_results = PreviousResults(self.output_dir)
        try:
            self._previous_results.set_aside()
            self._previous_results_set_aside = True
        except OSError as e:
            ASH_LOGGER.warning(
                f"Could not set the previous results in {self.output_dir} aside "
                f"({error_text(e)}); this scan replaces them as it writes, and they will not "
                "come back if it fails."
            )
            # The handle stays: a held set a killed earlier scan left (which
            # set_aside would have kept as the last complete results) is still
            # discarded when this scan finishes. Dropping the handle here left
            # that stale set in place, and the next MCP scan took it for the
            # last complete results and deleted this scan's.
            self._previous_results_set_aside = False
            # The scan goes on and replaces what is at the top level
            # (_prepare_output_dir removes it), so the marker a restore left
            # beside it no longer describes the directory: with it in place,
            # holds_restored_results read this scan's own output as results put
            # back after a failed scan. A set aside that completes removes the
            # marker itself.
            self._previous_results.forget_restored_marker()

    def _remove_kept_previous_results(self) -> None:
        """Without keep_previous_results: remove what a scan that kept them left.

        The previous results themselves are deleted where they always were, in
        ensure_directories and _remove_previous_result_files. This removes the
        set an MCP scan holds while it runs, its staging directory and the marker
        a restore leaves, without following links. A held set left by a killed MCP
        scan is the last complete results only to the MCP server: left in place
        beside this scan's results, the next MCP scan would take it for the last
        complete set and remove this scan's.
        """
        try:
            PreviousResults(self.output_dir).discard()
        except OSError as e:
            ASH_LOGGER.warning(
                f"Could not remove the previous results an MCP scan kept in "
                f"{self.output_dir}: {error_text(e)}"
            )

    def _prepare_output_dir(self) -> None:
        """Clear the working directories and the previous run's result files.

        After the engine is built and the committed-files check has passed, so a
        refused command line leaves the output directory as it was.

        The previous run's result files go unless this scan set them aside: a
        set aside that FAILED leaves them at the top level (the handle stays,
        for the stale held set it still discards), and this scan replaces them
        as it writes, so they are removed here as they are for a scan that
        keeps nothing. Left in place, the previous results file passed for this
        run's until its own write, which the MCP progress tracker reads as a
        complete scan.
        """
        ASH_LOGGER.verbose("Setting up working directories")

        self.ensure_directories()

        if self.existing_results_path is None and not self._previous_results_set_aside:
            self._remove_previous_result_files()

    def _build_engine(self, config: AshConfig) -> None:
        """Construct the execution engine, which refuses an unusable selection.

        *config* is the run's resolved configuration, ``self.config``. Reads the
        existing results when asked to report over them, and touches nothing else
        on disk: the plugins create their directories when they run.
        """
        exec_engine_params: Dict[str, Any] = {}
        if self.existing_results_path is not None:
            # UTF-8, as every writer of the results file writes it; the locale
            # encoding read it as cp1252 on Windows and failed, or re-saved it as
            # mojibake, on non-ASCII text in the findings.
            with warning_of_dropped_keys(self.existing_results_path) as context:
                try:
                    existing_text = Path(self.existing_results_path).read_text(
                        encoding="utf-8"
                    )
                except (OSError, UnicodeDecodeError) as e:
                    # The same refusal execute_scan gives for a file that goes
                    # away or cannot be read after this point, not a bare OSError
                    # that no entry point reads as one.
                    values = config_environment_values(config)
                    raise ASHValidationError(
                        f"Failed to load existing results: {error_text(e, values)}"
                    ) from e
                asharp_model = AshAggregatedResults.model_validate_json(
                    existing_text,
                    context=context,
                )
            self._adopt_this_runs_values(asharp_model, config)
            exec_engine_params = {"asharp_model": asharp_model}

        # Under this scan's run id, so the context records its directories on
        # *config* as this run's (config/path_trust.derived_roots_scope) and
        # execute_scan can remove them when the scan ends.
        with derived_roots_scope(self._run_id):
            self.execution_engine = ScanExecutionEngine(
                context=PluginContext(
                    source_dir=self.source_dir,
                    output_dir=self.output_dir,
                    # The caller's work_dir when one was given: it is the
                    # directory the end-of-scan cleanup removes, and it was never
                    # the one the plugins wrote (the context always got
                    # output_dir/converted), so the cleanup deleted a directory
                    # ASH never used while the converted tree stayed.
                    work_dir=self.engine_work_dir(),
                    config=config,
                    ignore_suppressions=self.ignore_suppressions,
                    run_id=self._run_id,
                    workspace_output_dir=self.workspace_output_dir,
                ),
                strategy=self.strategy,
                enabled_scanners=self.enabled_scanners,
                excluded_scanners=self.excluded_scanners,
                show_progress=self.show_progress,
                show_summary=self.show_summary,
                # Only the entries that have not expired, and of those only the
                # ones the operator supplied: a client_supplied path is left to
                # the SARIF step, and none apply under --ignore-suppressions
                # (models/core.ignore_paths_that_skip_scanning). This list is
                # what the scanners that pre-filter their files exclude.
                global_ignore_paths=ignore_paths_that_skip_scanning(
                    active_ignore_paths(config.global_settings.ignore_paths),
                    ignore_suppressions=self.ignore_suppressions,
                ),
                color_system=self.color_system,  # type: ignore[arg-type]
                verbose=self.verbose,
                debug=self.debug,
                python_based_plugins_only=self.python_based_plugins_only,
                # Declared on this class, documented as the pre-commit and CI
                # mode, and read by the engine, which was never told.
                simple_mode=self.simple_mode,
                ash_plugin_modules=self.ash_plugin_modules,
                plugin_module_names=self.plugin_module_names,
                output_formats=[f.value for f in self.output_formats] or None,
                asharp_model=exec_engine_params.get("asharp_model"),
                shard_index=self.shard_index,
                shard_count=self.shard_count,
                selection_origin=self.selection_origin,
                changed_files=self.changed_files,
            )

    def engine_work_dir(self) -> Path:
        """The directory the plugins convert into: ``work_dir`` when the caller
        set one, else ``<output_dir>/converted``.

        One answer for the engine's context and for the end-of-scan cleanup, so
        what the cleanup removes (``work_dir``, when set) is what the plugins
        used. With ``work_dir`` unset the default under the output directory is
        the plugins', and the cleanup leaves it, as it always has.
        """
        if self.work_dir is not None:
            return Path(self.work_dir)
        return self.output_dir.joinpath(ASH_WORK_DIR_NAME)

    def restrict_to_changed_files(self, changed_files: Optional[Set[Path]]) -> None:
        """Narrow this run's results to *changed_files*, after :meth:`initialize`.

        The same filter as passing ``changed_files`` to the constructor, for a
        caller that works the set out once the command is known to go ahead:
        run_ash_scan does, because the set comes from git, and a command line
        ``initialize`` refuses starts no process. Call it before
        :meth:`execute_scan`. ``None`` means no filter.
        """
        self.changed_files = changed_files
        if self.execution_engine is not None:
            self.execution_engine.restrict_to_changed_files(changed_files)

    def _apply_metadata(self) -> None:
        """Copy ``self.metadata`` onto the results model's own metadata.

        ``metadata`` has been a declared parameter of this class for its whole
        life, documented as "Additional metadata for the scan", and read nowhere.
        Workspace mode is the first caller that needs it, and what it needs it for
        is the thing that makes the PER_PROJECT reporter ruling honest.

        Every project in a workspace is scanned as a complete single-project run,
        so its model's ``workspace`` is ``None`` -- a project does not know it is
        in a workspace. Without something on the metadata, its reports cannot say
        which project they describe. That mattered concretely rather than
        aesthetically: the engine sets ``metadata.project_name`` from
        ``AshConfig.project_name``, which a workspace project need not declare,
        so without it every project's ``html``, ``markdown`` and ``text`` report
        would print the same project name; and the ``s3`` reporter derives its
        object key from a timestamp with one shared prefix, so two projects
        starting in the same instant would overwrite each other's report.

        Applied here, at the end of ``initialize``, because the report phase runs
        inside ``execute_scan`` -- setting it any later would be after the reports
        that need it have been written.

        ``project_name`` is set through validation rather than by raw assignment,
        so an empty or whitespace value is refused and the default kept. Assigning
        past a pydantic validator produces a model that fails to serialise much
        later, a long way from the assignment.

        Over results loaded from a saved set (``existing_results_path``, ``ash
        scan --use-existing``) the two markers the aws-security-hub reporter
        archives by are the saved set's, not this run's: this run did not scan
        those results. ``scan_source`` is never applied to them, and
        ``changed_files_only`` only when this run's is True (its report is
        narrowed to the changed files), never a False over a saved None or a set
        that does not say. On a fresh model a True is likewise never cleared.
        """
        if not self.metadata or self.execution_engine is None:
            return
        model = getattr(self.execution_engine, "_asharp_model", None)
        if model is None or model.metadata is None:  # pragma: no cover - defensive
            return
        loaded = self.existing_results_path is not None

        # The values this run's configuration read from the environment: a
        # project name among them is a value, not a label, and the reports print
        # metadata.project_name as text.
        environment_values = set(config_environment_values(self.config))
        for key, value in self.metadata.items():
            if key == "project_name":
                if isinstance(value, str) and value.strip() in environment_values:
                    # A workspace hands each project its resolved display label,
                    # which can be the project_name its config read from the
                    # environment; written here it reached the per-project HTML,
                    # Markdown, text and flat JSON reports as text. The name the
                    # engine recorded (the masked or reference form) stands.
                    ASH_LOGGER.warning(
                        "Ignoring a project_name in scan metadata that is a value "
                        "the configuration read from the environment; keeping "
                        f"{model.metadata.project_name!r}"
                    )
                elif isinstance(value, str) and value.strip():
                    model.metadata.project_name = value.strip()
                else:
                    ASH_LOGGER.warning(
                        f"Ignoring unusable project_name {value!r} in scan metadata; "
                        f"keeping {model.metadata.project_name!r}"
                    )
                continue
            if key == "scan_source" and loaded:
                # This run's directory, not the one the saved results scanned:
                # "." over a saved services/api would archive the whole
                # repository's findings outside services/api.
                continue
            if key == "changed_files_only" and value is not True:
                # A run without the flag says False (run_ash_scan writes it on
                # every run). Over a loaded set that would claim an unknown, or a
                # filtered set, is a full scan, and the reporter's archiving
                # trusts an explicit False. Nor is a True ever cleared.
                if loaded or getattr(model.metadata, key, None) is True:
                    continue
            # ReportMetadata allows extras, so anything else is carried through
            # verbatim for a reporter to read.
            setattr(model.metadata, key, value)

    def add_metadata(self, **values: Any) -> None:
        """Record metadata that is worked out after :meth:`initialize`.

        For a value a caller should not work out until the command is known to go
        ahead: run_ash_scan's ``scan_source`` starts git, and ``initialize`` is
        where an invalid configuration or a scanner selection that cancels itself
        stops a command that should start no process.

        Call it before :meth:`execute_scan`, whose report phase reads the
        metadata. The values join ``self.metadata`` as well as the model, because
        a report over existing results replaces the model and applies
        ``self.metadata`` to the one it loaded. There ``scan_source`` is not
        applied, and ``changed_files_only`` only when True: the loaded results
        keep the scan markers they were saved with (see :meth:`_apply_metadata`).
        """
        if self.metadata is None:
            self.metadata = {}
        self.metadata.update(values)
        self._apply_metadata()

    @classmethod
    def create(cls, **kwargs: Any) -> "ASHScanOrchestrator":
        """Construct and fully initialize an orchestrator.

        Equivalent to ASHScanOrchestrator(**kwargs) followed by .initialize().
        Use this in production code; use the bare constructor in tests that
        need an uninitialized instance.
        """
        from automated_security_helper.utils.error_text import (
            carry_environment_values,
            config_environment_values,
        )

        instance = cls(**kwargs)
        try:
            instance.initialize()
        except Exception as error:
            # The caller's failure handler never sees this instance, so it cannot
            # redact the error's text with the values the resolved config read
            # from the environment -- a plugin module that crashes at import can
            # name its own env-read module. They ride on the error instead
            # (error_text.carried_environment_values).
            carry_environment_values(
                error, config_environment_values(getattr(instance, "config", None))
            )
            raise
        return instance

    def _refuse_linked_output_dir(self) -> None:
        """Refuse an output directory that ASH would write or clear through a link.

        Called first by ensure_directories, whatever the sandbox mode:
        ensure_directories clears the working directories under the output
        directory, initialize then removes files at its top level, and a sandbox
        mounts it. Refused, with the link in the message and --output-dir as the
        remedy: a component below the source directory on the way to it (the
        repository's own, as the default ``.ash/ash_output`` is), the output
        directory itself or a real path that differs from its spelling, each of
        ``analysis``, ``reports``, ``scanners`` and ``converted``, and each file ASH
        writes there by a fixed name. See utils/output_dir_links.py. Components above an
        output directory outside the tree are the operator's spelling (``/tmp`` on
        macOS is one) and are not examined.

        Raises:
            ASHValidationError: one of those is a symlink or a junction.
        """
        try:
            refuse_linked_output_dir(self.source_dir, self.output_dir)
        except OutputDirLinkRefused as refusal:
            raise ASHValidationError(str(refusal)) from refusal

    def _adopt_this_runs_values(
        self, loaded: AshAggregatedResults, config: AshConfig
    ) -> None:
        """Make the config recorded in loaded results this run's own.

        A field the record holds as an environment reference it cannot hold
        takes this run's value (config/recorded_config.py), and the severity
        restriction the caller asked for applies to the recorded thresholds as it
        does to *config*: the report over saved results gates on what the saved
        config says, so a restriction that reached only ``self.config`` did not
        change whether the run it was asked for passed.
        """
        take_own_values(loaded.ash_config, config)
        restriction = self.severity_threshold_restriction
        if restriction is not None and loaded.ash_config is not None:
            self._restrict_severity_threshold(
                loaded.ash_config, restriction, announce=False
            )

    def _restrict_severity_threshold(
        self, config: AshConfig, restriction: str, announce: bool = True
    ) -> None:
        """Run at the stricter of ``restriction`` and every configured threshold
        of *config*, the run's resolved configuration (``self.config``) or the
        one saved results record.

        The global threshold and each scanner's own one, which decides that
        scanner's verdict when it is set (the executor's determine_status and
        ScannerStatisticsCalculator.get_scanner_threshold_info both prefer it).
        Tightening only the global one left a repository's bandit CRITICAL in
        charge of bandit when the client asked for HIGH. A scanner with no
        threshold of its own follows the global one, so it is left unset.

        A restriction that is not a ladder value is refused: ``stricter_of`` ranks
        an unknown string after CRITICAL, so it won every comparison and was
        written into the configuration as the threshold. Blank means none.
        ``announce`` False leaves the log lines to the first application.

        Raises:
            ASHValidationError: *restriction* names no threshold.
        """
        from automated_security_helper.utils.severity_ladder import (
            normalize_threshold,
            stricter_of,
        )

        if not restriction.strip():
            return
        requested = normalize_threshold(restriction)
        if requested is None:
            raise ASHValidationError(
                f"The severity threshold {restriction!r} is not one of ALL, LOW, "
                "MEDIUM, HIGH or CRITICAL."
            )
        values = config_environment_values(config)

        def shown(text: object) -> str:
            # A ladder word prints as it is. Anything else in a threshold field
            # can be a value the configuration read from the environment.
            if normalize_threshold(text) is not None:
                return str(text)
            return text_without_values(str(text), values)

        settings = config.global_settings
        configured = settings.severity_threshold
        effective = stricter_of(configured, requested)
        if effective != configured:
            if announce:
                ASH_LOGGER.info(
                    f"Severity threshold {shown(effective)} requested, stricter "
                    f"than the configured {shown(configured)}; the scan uses "
                    f"{shown(effective)}"
                )
            # The configured threshold is a ladder value, and stricter_of ranks
            # every value that is not one after CRITICAL, so it is replaced only
            # by a stricter ladder value: the cast names that and checks nothing.
            settings.severity_threshold = cast(
                Literal["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"], effective
            )
        elif requested != configured and announce:
            ASH_LOGGER.info(
                f"Severity threshold {requested} requested, looser than "
                f"the configured {shown(configured)}; the configured threshold stands"
            )

        for name, options in self._scanner_options(config):
            own = (
                options.get("severity_threshold")
                if isinstance(options, dict)
                else getattr(options, "severity_threshold", None)
            )
            if own is None:
                continue
            if not isinstance(own, str):
                # Not a threshold the ladder can rank (False, 0, a list): left
                # as the scanner's own setting for its validation to refuse,
                # never handed to stricter_of, which reads strings.
                if announce:
                    ASH_LOGGER.warning(
                        f"{name}'s severity_threshold is not a ladder value "
                        f"({type(own).__name__}); the requested {requested} is not "
                        f"applied to it"
                    )
                continue
            if not own.strip():
                # An empty string is set, not unset: the executor reads it as
                # the scanner's own threshold and grades that scanner with no
                # gate, so the client's floor was loosened for exactly it. It
                # takes the run's effective global threshold, which is what an
                # unset threshold follows.
                tightened = effective
            else:
                tightened = stricter_of(own, requested)
            if tightened == own:
                continue
            if announce:
                ASH_LOGGER.info(
                    f"Severity threshold {requested} requested, stricter than "
                    f"{name}'s configured {shown(own)}; {name} uses "
                    f"{shown(tightened)}"
                )
            if isinstance(options, dict):
                options["severity_threshold"] = tightened
            else:
                options.severity_threshold = tightened

    def _record_config_warnings(self, results: Any) -> None:
        """Add this run's config resolution warnings to *results*' validation
        checkpoints, each once.

        Over saved results the checkpoints already hold the warnings the saved
        run recorded, so an unconditional append doubled every one that this
        run's resolution also gave, and a warning that repeated in the list was
        appended each time. A checkpoint is the same one when its type and
        message are.
        """
        if self.config is None or not self.config._resolution_warnings:
            return
        checkpoints = results.validation_checkpoints
        recorded = {
            str(checkpoint.get("message"))
            for checkpoint in checkpoints
            if isinstance(checkpoint, dict)
            and checkpoint.get("type") == "config_warning"
        }
        for warning in self.config._resolution_warnings:
            if str(warning) in recorded:
                continue
            recorded.add(str(warning))
            checkpoints.append(
                {
                    "type": "config_warning",
                    "severity": "warning",
                    "message": warning,
                    "metadata": {
                        "source": "config_resolution",
                        "impact": (
                            "A configuration input was not applied as "
                            "written; the message says which and how."
                        ),
                    },
                }
            )

    def _writes_results_file(self, phases: List[str]) -> bool:
        """Whether this run owns the results file: a scan ran (not a report over
        existing results) and there is an output directory to write into."""
        return bool(
            "scan" in phases and self.existing_results_path is None and self.output_dir
        )

    def _remove_results_file_written_before_a_cancel(self) -> None:
        """Remove the results file this run wrote when the cancel landed during
        the write. Only its own file: the previous results, if any were kept,
        sit in the held set, and the caller puts them back. A removal that fails
        is logged; the cancel is what the caller sees."""
        results_file = Path(self.output_dir) / "ash_aggregated_results.json"
        try:
            results_file.unlink(missing_ok=True)
        except OSError as e:
            ASH_LOGGER.warning(
                f"The scan was cancelled while its results file was written, and "
                f"the file could not be removed: {error_text(e)}"
            )

    def _write_results_after_failure(self, phases: List[str]) -> None:
        """Write the results the engine holds when a phase AFTER the scan raised.

        The scan phase used to write ash_aggregated_results.json at its own
        end, so a report phase that raised still left the scan's results on
        disk for a later --use-existing. The one write now sits after every
        phase; this keeps that file on a failure after the scan phase, from
        the model the engine built. Whether the scan phase ran to its end is
        read from the phase's own record (``scan_phase_completed``: the
        checkpoint named ``SCAN_PHASE_COMPLETION_CHECKPOINT`` in scan_phase.py,
        which the phase records once its results are complete), not from the
        model's existence: the engine holds its model from construction, so a
        failure in the convert phase or anywhere before the scan phase, or a
        scan phase that raised midway, writes nothing, as the base did. Also
        nothing when this run does not own the file. A write that fails is
        logged, never raised: the original failure is what the caller sees.
        """
        if not self._writes_results_file(phases):
            return
        engine = self.execution_engine
        # The model the phases hand along is the engine's ``_results``: the
        # scan phase may return a new object rather than the one it was given
        # (scan_phase.py allows either), and the engine syncs ``_asharp_model``
        # to ``_results`` only at the end of its final suppression pass, in
        # the changed-files narrowing and after the report phase. A failure
        # between the scan phase's end and that sync (the suppression and
        # metrics steps at the start of the report arm, or in the scan arm
        # when there is no report phase) leaves ``_asharp_model`` holding the
        # model the engine started with, which carries no completion
        # checkpoint, so nothing was written for a scan phase that did run to
        # its end. ``_asharp_model`` is the fallback: an engine that holds no
        # ``_results`` model (the stubs the tests stand in) is read as before.
        results = None
        if engine is not None:
            results = getattr(engine, "_results", None)
            if not isinstance(results, AshAggregatedResults):
                results = getattr(engine, "_asharp_model", None)
        if not isinstance(results, AshAggregatedResults):
            return
        if not scan_phase_completed(results):
            ASH_LOGGER.debug(
                "No results file written after the failure: the scan phase did "
                "not run to its end"
            )
            return
        try:
            results.save_model(self.output_dir)
            ASH_LOGGER.info(
                f"Saved the scan's results to {self.output_dir} before the failure "
                f"is reported"
            )
        except Exception as e:
            ASH_LOGGER.warning(
                f"Could not save the scan's results after the failure: {error_text(e)}"
            )

    def _scanner_options(self, config: Any) -> List[Tuple[str, Any]]:
        """Each scanner's ``options`` in *config*: declared scanners and extra ones.

        Of the configuration it is given, not ``self.config``: the severity
        restriction is applied to the saved results' recorded config as well, and
        read ``self.config`` (None in a caller that passes its own) whatever it
        was handed.
        """
        segment = getattr(config, "scanners", None)
        if segment is None:
            return []
        entries: List[Tuple[str, Any]] = [
            (name, getattr(segment, name, None)) for name in type(segment).model_fields
        ]
        entries += list((segment.model_extra or {}).items())
        found: List[Tuple[str, Any]] = []
        for name, entry in entries:
            options = (
                entry.get("options")
                if isinstance(entry, dict)
                else getattr(entry, "options", None)
            )
            if options is not None:
                found.append((name, options))
        return found

    def _remove_previous_result_files(self) -> None:
        """Delete the previous run's top-level result files.

        ensure_directories removes the working directories; this removes the
        files beside them: the results file, the scan-start files and the record
        of the run that wrote them. Not when they were set aside. A file that
        cannot be removed is left: the scan overwrites it. Not the log files: the
        logger truncates them when it opens them. run_ash_scan's
        _discard_prior_run_artifacts removes the same names. An earlier inner
        run's outcome record (utils/inner_run_outcome.py) is one of them, so
        the committed-output refusal sees it where it used to be named here
        alone.
        """
        for name in PREVIOUS_RUN_FILE_NAMES:
            old_file = self.output_dir / name
            try:
                old_file.unlink(missing_ok=True)
            except OSError as e:
                ASH_LOGGER.debug(f"Could not remove {old_file}: {error_text(e)}")

    def _refuse_committed_results_paths(self) -> None:
        """Stop a scan that would delete or overwrite a file git tracks.

        Before anything is deleted: ensure_directories clears the working
        directories, and the previous results file and scan-start files are removed
        after it. With the default output directory, .ash/ash_output, a file the
        repository committed to one of those paths was deleted from the working
        tree by every scan. Files git tracks elsewhere in the output directory are
        never touched, and stop nothing. See
        utils/scan_output_dirs.committed_files_at_results_paths for why the scan
        refuses rather than writing its results under another name. The CLI and
        the MCP tools refuse the same way before they write anything themselves
        (core/committed_output.py).

        A report over existing results deletes none of those and clears no working
        directory, so only what it writes stops it
        (committed_output.report_over_existing_results_writes); analysis/, which
        only its inspect phase writes, is checked in execute_scan, where the phases
        are known.

        When git cannot list the repository's index, what is on disk at those paths
        refuses the scan instead, all but the log files: the CLI's logger has them
        open by now, as this run's own, and the CLI counted them on disk before it
        opened them; nothing here writes them.
        """
        if self.existing_results_path is None:
            refuse_committed_entries(self.output_dir, not_on_disk=LOG_FILE_NAMES)
            return
        files, directories = report_over_existing_results_writes(
            inspect=False, cleanup=not self.no_cleanup
        )
        refuse_committed_entries(
            self.output_dir,
            files=files,
            directories=directories,
            not_on_disk=LOG_FILE_NAMES,
        )

    def ensure_directories(self):
        """Ensure required directories exist in a thread-safe manner.

        Creates work_dir if it doesn't exist or if no_cleanup
        is True, and output_dir if it doesn't exist. A working directory left by a
        previous run is removed first. An output directory or working directory
        that is a link is refused before anything here runs, so the clean-up cannot
        delete inside wherever it points. An output directory inside the source
        directory gets a ``.gitignore`` that ignores everything in it, unless one is
        there already (utils/output_dir_links.ignore_output_dir_in_git).

        Raises:
            ASHValidationError: the output directory, or a working directory or
                result file under it, is reached through a link.
            ReportPathLinkRefused: ``reports/`` is a symlink or a directory
                junction, dangling or not. Refused before anything here clears or
                creates it: rmtree fails on a link to a directory, and mkdir on a
                dangling one.
        """
        self._refuse_linked_output_dir()
        refuse_a_linked_reports_dir(self.output_dir.joinpath("reports"))
        try:
            # Create output directory if it doesn't exist
            ASH_LOGGER.debug(
                f"Creating output directory if it does not exist: {self.output_dir}"
            )
            self.output_dir.mkdir(parents=True, exist_ok=True)
            # Inside the scanned tree, a .gitignore keeps ASH's output from a tool
            # that reads the tree and honors one, such as snyk code test, which
            # uploads what it reads. Before any scanner starts.
            ignore_output_dir_in_git(self.source_dir, self.output_dir)

            # If we're using existing results, only ensure the reports directory
            # exists. A plain mkdir: a link there was refused at the top of this
            # method, and the existing-results load refuses one made since.
            #
            # By whether a path was given, not whether the file is there: a file
            # that has gone fails to load with that said, instead of the scan
            # falling through to the branch that clears the working directories
            # and then reporting a scan that never ran.
            if self.existing_results_path is not None:
                self.output_dir.joinpath("reports").mkdir(parents=True, exist_ok=True)
            else:
                # Otherwise, set up all working directories. initialize has made
                # sure git tracks nothing in them (_refuse_committed_results_paths).
                for working_dir in OUTPUT_WORKING_DIRS:
                    path_working_dir = self.output_dir.joinpath(working_dir)
                    if path_working_dir.exists() and self.existing_results_path is None:
                        ASH_LOGGER.verbose(
                            f"Cleaning up working directory from previous run: {path_working_dir.as_posix()}"
                        )
                        shutil.rmtree(path_working_dir)
                        # Without exist_ok, so anything at the name after the
                        # removal makes this fail rather than be taken for the
                        # directory.
                        path_working_dir.mkdir()
                    else:
                        path_working_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            ASH_LOGGER.error(f"Error ensuring directories: {error_text(e)}")
            raise ASHValidationError(f"Failed to ensure directories: {error_text(e)}")

    def scan_set_for_this_run(self) -> List[str]:
        """The files this scan covers, written to its output directory under its ID.

        ASH's own output is left out: the output directory, and in a workspace scan
        the workspace's (``workspace_output_dir``), which a project at the
        workspace root holds (``utils/get_scan_set.scan_set``).
        """
        return scan_set(
            source=str(self.source_dir),
            output=str(self.output_dir),
            debug=self.debug,
            run_id=self._run_id,
            honor_ignore_files=honors_ignore_files(self.config),
            workspace_output_dir=(
                None
                if self.workspace_output_dir is None
                else str(self.workspace_output_dir)
            ),
        )

    def execute_scan(
        self,
        phases: List[ExecutionPhaseType] | None = None,
        settle_on_success: bool = True,
    ) -> AshAggregatedResults:
        """Execute the security scan and return results.

        One scan per instance: the run id is fixed at construction, the scan
        set is recorded under it, and the same id reads the recorded list
        back instead of walking the tree again, so a second call would
        silently scan the first call's file list. A second call, whether the
        first finished or failed, raises OrchestratorAlreadyUsedError before
        any phase launches; build a new ASHScanOrchestrator for a new scan.
        The check and the mark happen under one lock, so two threads racing
        on a shared instance get exactly one scan.

        With keep_previous_results, the previous scan's results, set aside by
        initialize, are dropped once the phases have finished, and put back if the
        scan ends any other way: an exception, a cancel (ScanCancelled), Ctrl-C. A
        cancel that lands after the last phase counts as ending without results;
        one read at the results-file write itself puts them back too when
        settle_on_success is True, and leaves them set aside, for the caller to
        settle, when it is False (_write_results_file).

        Args:
            phases (List[ExecutionPhaseType], optional): The phases to execute.
                Defaults to ["convert", "scan", "report"].
            settle_on_success: False leaves the previous results set aside when
                the phases finish, for a caller that still has work to do before
                the scan counts as having results; it then calls
                settle_previous_results. They are put back on failure either way.

        Returns:
            AshAggregatedResults: The results of the scan.
        """
        with _SCAN_SENTINEL_LOCK:
            if self._scan_executed:
                raise OrchestratorAlreadyUsedError(
                    "this orchestrator already ran its scan: the run id and the "
                    "scan set recorded under it belong to that scan, so a second "
                    "execute_scan would silently reuse the first scan's file "
                    "list. This orchestrator is single-scan; build a new "
                    "ASHScanOrchestrator for a new scan."
                )
            self._scan_executed = True
        # Resolved once, here, so the phases that ran and the phases the write
        # reads are the same list: the write reads "scan" in them, and a None
        # that reached it unresolved read as no scan, so the default call
        # (every phase) wrote no results file.
        if phases is None:
            phases = ["convert", "scan", "report"]
        try:
            # The run id the plugin context recorded its directories under
            # (_build_engine), in this thread and in the scanner pool's copies
            # of its context. source_dir is the scanned tree for the phases' tool
            # lookups too (utils/subprocess_utils.scanning_tree).
            with (
                scanning_tree(self.source_dir),
                derived_roots_scope(self._run_id),
                self._offline_scope(),
            ):
                results = self._execute_scan(phases)
            raise_if_cancelled()
        except BaseException:
            self.settle_previous_results(restore=True)
            raise
        finally:
            # The scan has ended: its roots leave the config's record, so a
            # config that serves many scans does not keep every finished
            # scan's directories.
            forget_derived_roots(self.config, self._run_id)
        # Outside the arm above: a cancel read at the write ends the scan with no
        # results file. With settle_on_success False the previous results stay
        # set aside for the caller to settle, as the CLI's own write after its
        # own check left them. With True the caller settles nothing later (that
        # is what True says), so they are put back here: left set aside, a
        # cancel at the write stranded them in the held directory.
        try:
            self._write_results_file(phases, results)
        except BaseException:
            if settle_on_success:
                self.settle_previous_results(restore=True)
            raise
        if settle_on_success:
            self.settle_previous_results(restore=False)
        return results

    def _write_results_file(
        self, phases: List[str] | None, results: AshAggregatedResults
    ) -> None:
        """Write ash_aggregated_results.json once, after every phase has run.

        The scan phase used to write it at its own end, before the engine's
        changed-files narrowing, final suppression pass, metrics rebuild and
        report phase, and the MCP progress tracker reads the file's existence
        as the scan being complete. The CLI rewrites the file after execute_scan
        returns; a direct caller of the orchestrator keeps this one as the final
        file. Not for a report over existing results, which rewrites nothing of
        the scan it reports on.

        The cancel is read before the write and once more after it. A cancel
        read before the write leaves no file; one that lands while the file is
        being written takes the file this run wrote with it: a client polling a
        cancelled scan reads that file as finished results. Either way the
        cancel propagates from here, outside execute_scan's arm that puts the
        previous results back. execute_scan puts them back when it settles (its
        ``settle_on_success``), and otherwise they stay set aside for the caller
        to settle, as the CLI's single write (after its own check) left them.

        A write that FAILS is a failed scan, as it was when the write sat inside
        _execute_scan: the previous results are put back here, and the failure
        is raised as ASHValidationError with the run's environment values
        redacted and carried, the shape _execute_scan's own arm gives a failure.
        """
        if not self._writes_results_file(phases or []):
            return
        raise_if_cancelled()
        if not isinstance(results, AshAggregatedResults):
            ASH_LOGGER.warning(
                f"The engine returned {type(results).__name__}, not "
                f"AshAggregatedResults; no results file was written to "
                f"{self.output_dir}"
            )
            return
        ASH_LOGGER.debug(f"Saving AshAggregatedResults to {self.output_dir}")
        try:
            results.save_model(self.output_dir)
        except Exception as e:
            values = config_environment_values(self.config)
            ASH_LOGGER.error(
                f"Could not write the results file: {error_text(e, values)}"
            )
            self.settle_previous_results(restore=True)
            wrapper = ASHValidationError(
                f"Scan execution failed: {error_text(e, values)}"
            )
            carry_environment_values(wrapper, values)
            raise wrapper
        try:
            raise_if_cancelled()
        except ScanCancelled:
            self._remove_results_file_written_before_a_cancel()
            raise

    def settle_previous_results(self, restore: bool) -> None:
        """Put the previous results back, or drop them. Never raises.

        A failure here is logged and does not replace how the scan ended: a
        restore runs while an exception is propagating, and a scan that finished
        has its results whether or not the old ones could be deleted.
        """
        if self._previous_results is None:
            return
        if restore and not self._previous_results_set_aside:
            # Nothing of this scan's predecessor was moved, so there is nothing
            # of it to put back; what the held set holds is an older scan's.
            return
        try:
            if restore:
                self._previous_results.restore()
            else:
                self._previous_results.discard()
        except OSError as e:
            ASH_LOGGER.error(
                f"Could not {'put back' if restore else 'remove'} the previous "
                f"results in {self.output_dir}: {error_text(e)}"
            )

    def _execute_scan(
        self, phases: List[ExecutionPhaseType] | None = None
    ) -> AshAggregatedResults:
        """execute_scan without the handling of the previous results.

        Every line it logs about an error, and the text of every error it
        builds, is redacted with the values this run's config read from the
        environment, and an error leaving it carries them: a plugin's event
        handler can fail with text that quotes one, and the run's handlers above
        hold no config to redact it with.
        """
        values = config_environment_values(self.config)
        if phases is None:
            phases = ["convert", "scan", "report"]
        ASH_LOGGER.verbose(f"Source directory: {self.source_dir}")
        ASH_LOGGER.verbose(f"Output directory: {self.output_dir}")
        ASH_LOGGER.verbose(f"Work directory: {self.work_dir}")
        ASH_LOGGER.verbose(f"Configuration path: {self.config_path}")
        ASH_LOGGER.verbose(f"Executing phases: {phases}")

        try:
            # If existing results path is provided, load the model from it. By
            # whether a path was given: a file that has gone fails below as
            # results that could not be loaded, where a scan would otherwise
            # start and the phases would find no model.
            if self.existing_results_path is not None:
                if "inspect" in phases:
                    # The inspect phase writes analysis/, which initialize did not
                    # check for a report over existing results.
                    refuse_committed_entries(
                        self.output_dir, files=(), directories=("analysis",)
                    )
                ASH_LOGGER.info(
                    f"Loading existing results from {self.existing_results_path}"
                )
                problem = None
                try:
                    with open(self.existing_results_path, "r", encoding="utf-8") as f:
                        model_data = json.load(f)

                    # Load the model from the existing results
                    asharp_model = AshAggregatedResults.from_json(model_data)
                    # Results that hold no scan, or record a refused run, would be
                    # reported as a clean scan. Read before the run records go.
                    problem = existing_results_problem(asharp_model)
                    # Without the records an earlier container or nix run left
                    # about itself, before any reporter sees the model. See
                    # utils/inner_run_outcome.py.
                    asharp_model.validation_checkpoints = without_run_records(
                        asharp_model.validation_checkpoints
                    )
                    # This run's own values and severity restriction over the
                    # recorded config (config/recorded_config.py).
                    self._adopt_this_runs_values(asharp_model, self.config)

                    # Update the execution engine's model
                    if self.execution_engine is not None and hasattr(
                        self.execution_engine, "_asharp_model"
                    ):
                        self.execution_engine._asharp_model = asharp_model
                        # initialize() applied this run's metadata to the model it
                        # loaded; this reload replaced that model, and with it the
                        # metadata (changed_files_only among it).
                        self._apply_metadata()

                    # When using existing results, only run the report phase
                    ASH_LOGGER.info(
                        "Using existing results - only running report phase"
                    )
                    phases = [
                        phase
                        for phase in [
                            "report",
                            "inspect" if "inspect" in phases else None,
                        ]
                        if phase is not None
                    ]

                except Exception as e:
                    ASH_LOGGER.error(
                        f"Failed to load existing results: {error_text(e, values)}"
                    )
                    raise ASHValidationError(
                        f"Failed to load existing results: {error_text(e, values)}"
                    )
                # Outside the handler above, so the refusal is not reported as
                # results that failed to load.
                if problem is not None:
                    raise ExistingResultsRefused(
                        f"--use-existing was given, but "
                        f"{self.existing_results_path.as_posix()} {problem}. Run the "
                        "scan without --use-existing."
                    )
                # Ensure the reports directory exists but don't clean up any other
                # directories. Outside the handler above, which would report a link
                # refused here as results that failed to load.
                ensure_reports_dir(self.output_dir.joinpath("reports"))
            # Only identify files to scan if we're not using existing results
            elif "convert" in phases or "scan" in phases:
                # Before the walk: a scan with no engine walked the whole tree and
                # wrote its scan set before the check below said it had nothing to
                # run the phases with.
                if self.execution_engine is None:
                    raise RuntimeError(
                        "Execution engine was never initialized; cannot execute scan phases."
                    )
                ASH_LOGGER.info("Identifying non-ignored files to include in scans")
                exclusions: Dict[str, Any] = {}
                links_not_scanned: List[Dict[str, str]] = []
                self.source_scan_set = scan_set(
                    source=str(self.source_dir),
                    output=str(self.output_dir),
                    debug=self.debug,
                    run_id=self._run_id,
                    workspace_output_dir=(
                        None
                        if self.workspace_output_dir is None
                        else str(self.workspace_output_dir)
                    ),
                    honor_ignore_files=honors_ignore_files(self.config),
                    exclusions=exclusions,
                    links_not_scanned=links_not_scanned,
                )
                # Recorded on the results the phases build on, so the aggregated
                # JSON and every summary say whether the repository's ignore files
                # were honored and how many files they removed. Empty only for a
                # scan set reused from the output directory, which initialize()
                # removes before every scan.
                if exclusions and self.execution_engine is not None:
                    self.execution_engine._asharp_model.metadata.ignore_file_exclusions = IgnoreFileExclusions.model_validate(
                        exclusions
                    )
                # The links the scan set left out, which no reader of it scanned:
                # listed as ASH's inputs not scanned in the results, the summaries
                # and the console (unified_metrics.inputs_not_scanned). Set only when
                # there are some, so other results keep their exact shape.
                if links_not_scanned and self.execution_engine is not None:
                    self.execution_engine._asharp_model.metadata.inputs_not_scanned = [
                        InputNotScanned.model_validate(entry)
                        for entry in links_not_scanned
                    ]
                ASH_LOGGER.info(
                    f"Found {len(self.source_scan_set)} files within the provided source directory to scan. Please see the 'ash-scan-set-files-list.txt' in the output folder for the full list of files identified to scan within the source directory identified."
                )

            # Before the phases, so the report phase writes them: they were added
            # to the returned model after the reports were out, so no report said
            # that a configuration input had not been applied as written.
            held_model = getattr(self.execution_engine, "_asharp_model", None)
            if isinstance(held_model, AshAggregatedResults):
                self._record_config_warnings(held_model)

            try:
                # Execute all phases.
                #
                # Raise rather than assert. This guard narrows the type for the
                # checker, but an `assert` is stripped under `python -O`, and
                # without it the next line fails with `'NoneType' object has no
                # attribute 'execute_phases'` — which the handler below catches
                # and logs as a generic "Execution failed", losing the actual
                # cause. A raise keeps the narrowing and says what went wrong in
                # both optimized and unoptimized runs.
                if self.execution_engine is None:
                    raise RuntimeError(
                        "Execution engine was never initialized; cannot execute scan phases."
                    )
                asharp_model_results = self.execution_engine.execute_phases(
                    phases=phases,
                )

                ASH_LOGGER.debug("Scan execution completed successfully")
            except Exception as e:
                ASH_LOGGER.error(f"Execution failed: {error_text(e, values)}")
                # The scan phase used to write the results file at its own
                # end, so a report phase that raised still left the scan's
                # results for a later --use-existing. The write moved below
                # this block; a failure after the scan phase keeps that file
                # by writing what the engine holds. A cancel is not an
                # Exception and still writes nothing.
                self._write_results_after_failure(phases)
                raise

            # Again on what the phases returned: a model the engine replaced
            # while it ran did not get the first pass, and one that did is not
            # given its warnings twice.
            self._record_config_warnings(asharp_model_results)

            # The results file is written by execute_scan once this returns,
            # outside the arm that puts the previous results back
            # (_write_results_file): the scan phase used to write it at its own
            # end, before the engine's changed-files narrowing, final
            # suppression pass, metrics rebuild and report phase.

            if not self.no_cleanup:
                if self.work_dir and Path(self.work_dir).exists():
                    ASH_LOGGER.verbose("Cleaning up working directory...")
                    try:
                        shutil.rmtree(self.work_dir)
                    except OSError as e:
                        # Every phase has finished and the results are written
                        # next; a working directory that could not be removed is
                        # not a failed scan. Raised, it turned a completed scan into
                        # a failure and, with keep_previous_results, deleted the
                        # new results and restored the old ones.
                        ASH_LOGGER.warning(
                            f"Could not remove the working directory "
                            f"{Path(self.work_dir).as_posix()}: {error_text(e, values)}"
                        )
            return asharp_model_results

        except ASHValidationError as e:
            carry_environment_values(e, values)
            raise
        except Exception as e:
            ASH_LOGGER.error(
                f"Unexpected error during scan execution: {error_text(e, values)}"
            )
            # The wrapper's own text is redacted, and it carries the values for
            # the traceback of what it wraps.
            wrapper = ASHValidationError(
                f"Scan execution failed: {error_text(e, values)}"
            )
            carry_environment_values(wrapper, values)
            raise wrapper
