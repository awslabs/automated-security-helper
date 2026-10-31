"""ScannerExecutor — owns scanner task lifecycle for ScanPhase."""

import contextvars
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Tuple

from automated_security_helper.base.plugin_base import PluginBase
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    plugin_missing_dependency_reason,
)
from automated_security_helper.core.enums import ExecutionPhase, ScannerStatus
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerSeverityCount,
)
from automated_security_helper.models.scan_results_container import (
    InputNotScanned,
    ScanResultsContainer,
)
from automated_security_helper.utils.scan_output_dirs import (
    drop_results_in_ash_output_dirs,
    mark_converted_results,
)
from automated_security_helper.core.cancellation import (
    ScanCancelled,
    current_cancel_event,
    raise_if_cancelled,
    shutdown_requested,
)
from automated_security_helper.utils.get_shortest_name import home_as_tilde
from automated_security_helper.utils.error_text import (
    config_environment_values,
    error_text,
    plugin_environment_values,
    text_without_values,
    timeout_limit_token,
    traceback_text,
)
from automated_security_helper.utils.log import (
    ASH_LOGGER,
    NO_MARKUP,
    TRACE_LEVEL,
    escape_markup,
)
from automated_security_helper.utils.threads import ash_thread
from automated_security_helper.utils.sandbox.fs_guard import (
    refuse_links_below,
    sweep_writable,
)
from automated_security_helper.utils.sandbox.scope import (
    SandboxBackendUnavailable,
    SandboxUnavailable,
    sandbox_refusal_grades_missing,
    sandbox_scope,
    scanner_sandbox_scope,
)
from automated_security_helper.utils.subprocess_utils import (
    COULD_NOT_STOP_ENDING,
    SPAWN_FAILURE_RETURNCODE,
    WAS_KILLED_ENDING,
    could_not_stop_sentence,
)
from automated_security_helper.utils.sarif_utils import (
    apply_suppressions_to_sarif,
    exclude_output_dir_results,
    sanitize_sarif_paths,
)
from automated_security_helper.utils.tool_config_dir import tool_config_scope
from automated_security_helper.utils.severity_ladder import (
    resolve_missing_levels,
    resolve_scanner_threshold,
)

_ResultsFn = Callable[
    [ScanResultsContainer, AshAggregatedResults], AshAggregatedResults
]

# Statuses the severity re-grade must leave alone, because they were computed from
# information the re-grade cannot see.
#
# A set rather than the single ``!= ERROR`` comparison this replaced, and MISSING is why.
# ``determine_status`` has four return sites -- ERROR, SKIPPED, FAILED, PASSED -- so it
# cannot reproduce MISSING even in principle, and re-grading a MISSING container did not
# refine the verdict, it destroyed it: ``targets_attempted`` is None for a scanner that
# does not count targets, both per-target guards are skipped, and the all-zero severity
# counts resolve to PASSED. "This scanner could not run" was recorded and then overwritten
# with "this scanner ran and found nothing" further down the same finally block, with only
# bookkeeping in between.
#
# Holds the same members as ``interactions.run_ash_scan._INCOMPLETE_SCANNER_STATUSES``,
# which is the set the completeness gate collects into the incomplete list and the exit
# code reads -- a status preserved here and absent there is the drift that produced the
# defect. Not imported from there: that module is the CLI layer and pulls in the container
# and nix runners, so importing it from a core phase would invert the dependency direction.
# ``test_preserved_statuses_match_the_completeness_gate`` holds the two in step instead.
#
# Narrow on purpose, and PASSED must never be added. It is the ``ScanResultsContainer``
# default, so carving it out would leave every container ungraded and make FAILED
# unreachable, since the severity gate is the only route to FAILED here. SKIPPED is
# likewise excluded: it is a verdict the scanner reached about its own input, the
# completeness gate counts it as complete because sharding records every scanner another
# shard owns as SKIPPED, and nothing in this module assigns it ahead of the re-grade.
_TERMINAL_SCANNER_STATUSES = frozenset(
    {
        ScannerStatus.ERROR,
        ScannerStatus.MISSING,
    }
)

# The ``status`` values of a returned dict that say its tool completed, compared
# case-insensitively. Any other status means it did not: ``failed`` is the one the
# template and the scan phase write, and a dict graded on its zero findings would
# read as a clean scan.
_COMPLETED_RESULT_STATUSES = frozenset({"passed", "completed", "success", "ok"})


def _refuse_to_grade(container: ScanResultsContainer, reason: str) -> None:
    """Make the row ERROR with ``reason``, in its errors and in the log."""
    container.status = ScannerStatus.ERROR
    ASH_LOGGER.error(reason)
    container.add_error(reason)


def _completed_result_status(status: Any) -> bool:
    return isinstance(status, str) and status.lower() in _COMPLETED_RESULT_STATUSES


def _failure_text(error: BaseException, values: Iterable[str]) -> str:
    """``error_text``, with a SystemExit named as the plugin's own exit.

    ``str(SystemExit(3))`` is ``3`` and ``str(SystemExit())`` is empty, so a row
    for a scanner that called ``sys.exit`` read "Failed to execute X on source: 3",
    or ended in nothing, and never said what the plugin did. The exit is named
    with its code; a message the plugin passed (``sys.exit("no rules")``) is the
    code and follows the name once.

    The code's text goes through the same redaction as the rest of the row's
    error text (``text_without_values`` with the row's environment values):
    a plugin can exit with a message that quotes a value the configuration read
    from the environment, and the named exit reaches ash.log, the row's errors,
    the failure dict and the ERROR event; written from the raw code, it carried
    the value in clear beside a description that had hidden it.
    """
    described = error_text(error, values)
    if not isinstance(error, SystemExit):
        return described
    code_text = text_without_values(repr(error.code), values)
    named = f"the scanner called sys.exit({code_text})"
    if not described or described == text_without_values(str(error.code), values):
        return named
    return f"{named}: {described}"


def _exit_is_the_shutdowns(error: BaseException) -> bool:
    """Whether a SystemExit reaching a scanner's handler is the process's shutdown.

    A scanner's own ``sys.exit`` (a tool run as a library, a plugin's guard) is
    that scanner's failure. A SystemExit raised while a shutdown signal has asked
    the registered scans to stop is not: ASH's SIGTERM handler chains to the one
    installed before it, and an embedder's handler that calls ``sys.exit`` raises
    on the main thread, inside whatever scanner a sequential scan is running.
    Recorded as that scanner's failure, the scan went on to the next scanner
    instead of ending. ``shutdown_requested`` is the record the handler sets
    before anything else, so the two exits tell apart by it.
    """
    return isinstance(error, SystemExit) and shutdown_requested()


#: The fields of ScannerSeverityCount a returned dict's ``severity_counts`` can set.
_SEVERITY_COUNT_FIELDS = ("suppressed", "critical", "high", "medium", "low", "info")

#: The levels a target report can record it was graded against
#: (``ScanResultsContainer.scanner_severity_threshold``). An unrecognised
#: threshold (an external section's number, say) grades CRITICAL only and is not
#: a level the report can carry, so the row keeps the value it was built with.
_GRADED_LEVELS = frozenset({"ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"})


def _severity_counts_from_dict(raw_counts: Any) -> ScannerSeverityCount:
    """``raw_counts``, a scanner's own ``severity_counts``, as a ScannerSeverityCount.

    Keys are matched to the model's fields by name whatever their case, so a
    count a tool writes under ``HIGH`` or ``High`` reaches the severity gate.
    Validated as before, such a key was kept as a pydantic extra and the field
    stayed 0, and a result with high findings graded PASSED. A key that names no
    field counts as info, as a findings-list entry whose severity ASH cannot
    place does (the contract test_scanner_executor_lifecycle pins, "unknown
    severities fall back to info"): a tool's own vocabulary (grype's
    ``unknown`` and ``negligible``, npm audit's ``moderate``) is a claim the gate
    cannot rank, kept at the lowest level and still counted, so the row's
    finding_count holds every finding the tool counted. Left out, as before,
    those findings were in no count at all, and the two dict paths disagreed on
    one idea. ``total`` is the model's own sum, never a count of its own, and is
    left out; so is a key that is not text. A value that is not a count (not a
    whole number, so a fractional, infinite or not-a-number float too; or
    negative) raises ValueError, under any key: the caller refuses to grade the
    row rather than inventing a count. A whole-number float (``2.0``) is the
    count it spells.
    """
    if isinstance(raw_counts, ScannerSeverityCount):
        return raw_counts
    if not isinstance(raw_counts, dict):
        raise ValueError(
            f"severity_counts is a {type(raw_counts).__name__}, not a mapping"
        )
    counts: Dict[str, int] = {}
    for key, value in raw_counts.items():
        name = key.strip().lower() if isinstance(key, str) else ""
        if name == "total" or not name:
            continue
        if name not in _SEVERITY_COUNT_FIELDS:
            name = "info"
        if isinstance(value, bool) or not isinstance(value, (int, float, str)):
            raise ValueError(f"severity_counts[{key!r}] is not a count: {value!r}")
        # int() would truncate 0.9 to 0 (a finding gone) and raise OverflowError,
        # not ValueError, on an infinite float.
        if isinstance(value, float) and not value.is_integer():
            raise ValueError(
                f"severity_counts[{key!r}] is not a whole number: {value!r}"
            )
        try:
            count = int(value)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError(
                f"severity_counts[{key!r}] is not a count: {value!r}"
            ) from exc
        if count < 0:
            raise ValueError(f"severity_counts[{key!r}] is negative: {value!r}")
        counts[name] = counts.get(name, 0) + count
    return ScannerSeverityCount(**counts)


# How often a running scanner announces that it is still running. Long enough that
# a normal scan logs nothing extra (most scanners finish inside a minute), short
# enough that a hung one is named well before a CI job timeout kills the run.
SCANNER_HEARTBEAT_INTERVAL_SECONDS = 60.0


class _ScannerHeartbeat:
    """Log "<scanner> still running (Ns elapsed)" at INFO while a scanner runs.

    Why this exists
    ---------------
    Scanner subprocesses run buffered, so nothing about one is logged until it
    exits. A scanner that hangs until the CI job is killed therefore produced no
    line at any log level naming it (issue #628). The Rich live panel shows
    elapsed time per task, but it is disabled in CI and in the container, which
    are exactly where nobody can watch a terminal.

    INFO rather than VERBOSE so it needs no flag: the case it serves is the one
    where the operator did not know in advance to ask for more output. It runs on
    a daemon thread so a scanner that never returns cannot keep the process
    alive through it, and ``stop`` is idempotent so the ``finally`` that calls it
    is safe however the scan ended.
    """

    def __init__(self, scanner_name: str, target_type: str, interval: float):
        self._scanner_name = scanner_name
        self._target_type = target_type
        self._interval = interval
        self._started = time.monotonic()
        self._stop = threading.Event()
        # Made here, in the scanner's own context, and run in a copy of it, so
        # each "still running" line is this scan's: in the MCP server it goes to
        # this scan's ash.log and no other session's.
        self._thread = ash_thread(
            self._run,
            name=f"ash-heartbeat-{scanner_name}",
            daemon=True,
        )

    def start(self) -> "_ScannerHeartbeat":
        # The elapsed time counts from the scan's start, not from the moment the
        # object was made: the sandbox is resolved in between, and every "still
        # running" line charged that wait to the scanner.
        self._started = time.monotonic()
        if self._interval > 0:
            self._thread.start()
        return self

    def _run(self) -> None:
        while not self._stop.wait(self._interval):
            elapsed = int(time.monotonic() - self._started)
            ASH_LOGGER.info(
                f"{self._scanner_name} still running on {self._target_type} "
                f"({elapsed}s elapsed)"
            )

    def stop(self) -> None:
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=5)


def _timed_out_after(scanner_plugin: Any) -> float | None:
    """The timeout the plugin's tool was killed at, or None.

    Coerced at the boundary like ``_target_count_attr``: a plugin is an arbitrary
    object, and a MagicMock answers any attribute with a truthy mock.
    """
    value = getattr(scanner_plugin, "scan_timed_out_after", None)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    return None


def _spawn_failure(scanner_plugin: Any) -> str | None:
    """Why the plugin's tool could not be started, or None. Coerced like
    ``_timed_out_after``: only a real string counts."""
    value = getattr(scanner_plugin, "scan_spawn_failure", None)
    return value if isinstance(value, str) and value else None


def _post_run_error(scanner_plugin: Any) -> str | None:
    """Why ASH could not record the output of the plugin's tool, which ran, or
    None. Coerced like ``_spawn_failure``."""
    value = getattr(scanner_plugin, "scan_post_run_error", None)
    return value if isinstance(value, str) and value else None


def _kept_flag(scanner_plugin: Any) -> Tuple[str, str] | None:
    """The flag, and its reason, of the plugin's run that did not finish, or None.
    Coerced like ``_spawn_failure``: only a pair of real strings counts."""
    value = getattr(scanner_plugin, "scan_kept_flag", None)
    if (
        isinstance(value, tuple)
        and len(value) == 2
        and all(isinstance(part, str) and part for part in value)
    ):
        return value[0], value[1]
    return None


def _could_not_stop(scanner_plugin: Any) -> str | None:
    """The recorded reason the plugin's run ended with a tool ASH could not stop,
    or None. Coerced like ``_spawn_failure``: only a real string counts."""
    value = getattr(scanner_plugin, "scan_could_not_stop", None)
    return value if isinstance(value, str) and value else None


#: How a timeout headline ends when the scanner's run recorded a tool ASH could
#: not stop, but the run that did not finish most recently is not the timeout: a
#: later run's tool may still be running, and the timed-out tool is not said to be
#: killed either. Built from the shared sentence, like the two endings in
#: subprocess_utils, so no site words its own.
UNSTOPPED_LATER_RUN_ENDING = (
    f", and {could_not_stop_sentence('a later run of its tool')}"
)


def _timeout_ending(scanner_plugin: Any) -> str:
    """How this plugin's timeout headline ends.

    ``scan_could_not_stop`` is one record for the whole plugin, set by any run
    whose stop failed (a timeout's, a cancel's) and kept across the launches of
    one ``scan()``, so by itself it cannot say WHICH run ASH could not stop. Read
    alone, a scan whose first launch timed out and was killed and whose second
    launch was cancelled and could not be stopped said the timed-out tool "may
    still be running": the wrong tool. The kept flag names the most recent run
    that did not finish, and settles what the record can and cannot say:

    - no could-not-stop recorded: the was-killed ending, as before;
    - recorded, and the most recent unfinished run is the timeout (or no flag is
      readable): the timeout's own could-not-stop ending, as before;
    - recorded, and the most recent unfinished run was CANCELLED, the one other
      ending that goes through a stop: the later run's tool may still be
      running, and the timed-out tool is not said to be killed, because one
      record cannot tell whether both stops failed;
    - recorded, and the most recent unfinished run ended ``signaled`` (its tool
      died on a signal ASH did not send) or ``result_rejected``: those runs
      have no stop of their own, so the record can only be the timeout's, and
      the timeout's own ending is right.

    Exact attribution comes from the plugin's per-run record
    (``scan_could_not_stop_runs`` on ``plugin_base``: one entry per run whose
    stop failed, keyed by the flag that run ended with, ``timed_out`` among
    them). With that record the reading is exact: ``timed_out`` in it means the
    timeout's own stop failed (the timeout's ending); a record of other runs only
    means a later run's tool may still be running while the timed-out tool was
    killed; an empty record means every stop succeeded (the was-killed ending).
    The kept-flag reading above is the fallback for a plugin that carries no such
    record (an older plugin class, a double).
    """
    runs = getattr(scanner_plugin, "scan_could_not_stop_runs", None)
    if isinstance(runs, dict):
        if "timed_out" in runs:
            return COULD_NOT_STOP_ENDING
        if runs:
            return UNSTOPPED_LATER_RUN_ENDING
        return WAS_KILLED_ENDING
    if _could_not_stop(scanner_plugin) is None:
        return WAS_KILLED_ENDING
    kept = _kept_flag(scanner_plugin)
    if kept is not None and kept[0] == "cancelled":
        return UNSTOPPED_LATER_RUN_ENDING
    return COULD_NOT_STOP_ENDING


def _unfinished_run_reason(
    scanner_name: str,
    target_type: str,
    kept: Tuple[str, str],
    timed_out_after: float | None,
    values: Iterable[str] = (),
) -> str:
    """The scan's error for a run that kept ``kept``'s flag, its reason after it.
    ``values`` are the run's environment values, for the limit's token."""
    flag, reason = kept
    if flag == "timed_out":
        # The limit through the token every timeout message shares
        # (timeout_limit_token): a quoted whole number, which redact_values
        # replaces only where the text quotes it whole, or the option's name
        # where the environment wrote the limit in another spelling. The
        # caller redacts the whole text.
        limit = (
            f" after {timeout_limit_token(timed_out_after, values)}"
            if timed_out_after is not None
            else ""
        )
        return f"{scanner_name} timed out{limit} on {target_type}: {reason}"
    if flag == "cancelled":
        return f"{scanner_name} was cancelled on {target_type}: {reason}"
    if flag == "result_rejected":
        return f"{scanner_name}'s result on {target_type} was rejected: {reason}"
    return f"{scanner_name} did not finish on {target_type}: {reason}"


def _dependencies_recorded_unavailable(scanner_plugin: Any) -> bool:
    """True when the plugin says its dependencies are unavailable, and something said so.

    A plugin model's ``dependencies_satisfied`` defaults to False before any check
    runs. ScanPhase assigns the dependency check's answer to every scanner it
    dispatches, a scanner's own check or scan() may assign it, and so may a test;
    a pydantic model records each assignment in ``model_fields_set``. A False that
    nothing assigned says no check ran, not that a tool is absent, so it does not
    count; neither does an absent attribute. For a plugin that is not a model, an
    attribute that reads False is taken as recorded. bool() coerces at the boundary
    for the reason _target_count_attr gives: the plugin is an arbitrary object.
    """
    if bool(getattr(scanner_plugin, "dependencies_satisfied", True)):
        return False
    fields_set = getattr(scanner_plugin, "model_fields_set", None)
    if isinstance(fields_set, (set, frozenset)):
        return "dependencies_satisfied" in fields_set
    return True


def _unevaluated_targets(scanner_plugin: Any) -> List[str]:
    """The targets the plugin's tool never evaluated, or an empty list.

    Coerced like ``_timed_out_after``: a plugin is an arbitrary object. A single
    str is one target, never iterated character by character, and anything that
    is not a str, list or tuple of str answers as no claim.
    """
    value = getattr(scanner_plugin, "unevaluated_targets", None)
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, (list, tuple)):
        return [name for name in value if isinstance(name, str) and name]
    return []


def _missing_reason_after_scan(
    scanner_plugin: Any,
    scanner_name: str,
    target_type: str,
    values: Iterable[str] = (),
) -> str:
    """The reason for a container whose ``scan()`` returned a falsy value.

    That return means the scanner found its dependencies unavailable when it ran.
    The plugin's own explanation is used when it gives one as text; anything else,
    including the Mock a test double answers with, gets a message naming the scan.
    Returned as the plugin gave it: the caller logs it so and writes it to the row
    through home_as_tilde.
    """
    reason = plugin_missing_dependency_reason(scanner_plugin, values)
    if reason:
        return reason
    return (
        f"{scanner_name} reported its dependencies unavailable when it was run on "
        f"the {target_type} files; ash.log has the scanner's own message"
    )


def _skipped_reason_after_scan(
    scanner_plugin: Any,
    scanner_name: str,
    target_type: str,
    values: Iterable[str] = (),
) -> str:
    """The reason for a container a tracking scanner left with no target attempted.

    The scanner's ``nothing_scanned_reason`` when it states one, so a scanner whose
    ``nothing_to_scan_reason`` parses both trees is not asked it once per target
    right after scan() looked at every candidate. The value its scan() recorded for
    this target (``_nothing_scanned_reason``) comes before the class's.
    """
    for_this_target = getattr(scanner_plugin, "_nothing_scanned_reason", None)
    if isinstance(for_this_target, str) and for_this_target:
        return for_this_target
    stated = getattr(type(scanner_plugin), "nothing_scanned_reason", None)
    if isinstance(stated, str) and stated:
        return stated
    ask = getattr(scanner_plugin, "nothing_to_scan_reason", None)
    if callable(ask):
        try:
            reason = ask()
        except Exception as e:
            ASH_LOGGER.debug(
                f"{type(scanner_plugin).__name__}.nothing_to_scan_reason() raised "
                f"{type(e).__name__}: {error_text(e, values)}; "
                "recording the generic reason",
                extra=NO_MARKUP,
            )
        else:
            if isinstance(reason, str) and reason:
                return reason
    return f"{scanner_name} ran on the {target_type} files and found nothing it scans"


def _target_count_attr(obj: Any, name: str) -> int | None:
    """Read a target counter off a scanner plugin, or None when it makes no usable claim.

    None is the answer for an absent attribute and for a present-but-unusable one alike, and
    that conflation is deliberate: both mean "this scanner has told us nothing about targets",
    which is the state ``ScanResultsContainer.targets_attempted`` uses None for. Returning 0
    instead would assert "it tracked targets and attempted none", which for a non-tracking
    scanner is a false statement that resolves to SKIPPED.

    A plain ``getattr(obj, name, None)`` is not safe here. Scanner plugins are arbitrary
    objects, and a ``MagicMock`` auto-creates any attribute asked of it -- so the default never
    applies and a mock lands in an int field, which is not validated on assignment. The first
    comparison downstream then raises
    ``TypeError: '>=' not supported between instances of 'MagicMock' and 'int'``.

    Coercing at this boundary keeps the trust boundary where the untrusted value enters,
    rather than teaching every consumer to be defensive about a field typed ``int``.

    A negative is the one unusable value that gets a warning, because it is the only one that is
    evidence of a defect rather than of a scanner that simply does not count targets. An absent
    attribute, a MagicMock, a string or a float all mean "no counter here", which is the normal
    state for nine of the builtin scanners; warning about those would fire on every clean run.

    The warning matters because the silence used to be total, and the silence is what made two
    individually-correct halves compose into a wrong answer. ``determine_status`` sends a negative
    ``targets_attempted`` to ERROR, so the model looks defended -- but the negative never reaches
    it, because this function turns it into None first. The scanner then reads as making no claim,
    falls past both per-target guards into the severity gate, and reports PASSED off a broken
    counter with nothing anywhere to say so.

    The value is still dropped rather than passed through. Letting it reach the model would report
    ERROR, which asserts "it tried and everything broke" -- a claim nobody has evidence for. All
    that is known is that the plugin's accounting is wrong; its findings come from SARIF rather
    than from the counter and remain usable, so failing the scan over an accounting bug would be
    a worse answer than naming it. Raising is rejected for the same reason.
    """
    value = getattr(obj, name, None)
    # bool is an int subclass; excluded because a True/False counter is a caller bug and
    # silently reading it as 1/0 would hide that.
    if isinstance(value, int) and not isinstance(value, bool):
        if value >= 0:
            return value
        ASH_LOGGER.warning(
            f"Scanner plugin {type(obj).__name__} reported {name}={value}. A target count "
            "cannot be negative, so it is being ignored and the scanner treated as making no "
            "claim about targets. Its status will come from findings alone, which means a scan "
            "that evaluated nothing cannot be reported as SKIPPED. This is a defect in the "
            "scanner plugin's own accounting."
        )
    return None


def _inputs_not_scanned(obj: Any) -> List[InputNotScanned]:
    """The inputs a scanner plugin reported it did not scan, as ``{path, reason}``.

    Coerced at the boundary like ``_target_count_attr``: the plugin is an arbitrary
    object, so only a list of mappings with string ``path`` and ``reason`` counts.
    """
    value = getattr(obj, "inputs_not_scanned", None)
    if not isinstance(value, list):
        return []
    entries = []
    for item in value:
        if not isinstance(item, dict):
            continue
        path, reason = item.get("path"), item.get("reason")
        if isinstance(path, str) and path and isinstance(reason, str) and reason:
            entries.append(InputNotScanned(path=path, reason=reason))
    return entries


def _non_negative_int_attr(obj: Any, name: str) -> int:
    """``_target_count_attr`` for a counter whose absence is indistinguishable from zero.

    ``targets_failed`` is such a counter: it is only ever read against ``targets_attempted``,
    so "no claim" and "zero failures" lead to the same decision and there is nothing to gain
    from keeping them apart. One coercion rule serves both callers, so the two cannot drift
    apart on what counts as a usable value -- including on warning about a negative, which is
    just as much an accounting defect in a failure count as in an attempt count.
    """
    return _target_count_attr(obj, name) or 0


def _recorded_the_timed_out_target(
    scanner_plugin: Any, kept: Tuple[str, str], raw_results: Any
) -> bool:
    """Whether a scan that kept a timeout flag already graded the timed-out run itself.

    A scanner that runs its tool once per target (cfn-guard, once per template)
    records a run that timed out in its own accounting: the target counts as
    failed, the failure is named in its errors, and the scan goes on to the next
    target and returns the merged report. The executor used to read the kept flag
    alone and raise, which replaced that whole report with one failure record and
    lost every other target's findings. The report is kept when all three hold:

    - the kept flag is the timeout (a cancel, a rejected result or a signal says
      nothing about the other targets' runs, and the raise stands);
    - the scan returned a result (``None`` or ``False`` is nothing to keep);
    - the plugin counts targets and recorded at least one failed target among
      more attempted, so the failure is in its own accounting and the report
      holds the other targets' results.

    A plugin that counts no targets, or whose every attempted target failed,
    produced nothing the row can grade, and the raise stands for it as before.
    The row is still ERROR: the post-scan grading adds the timeout to it.
    """
    if kept[0] != "timed_out" or not raw_results:
        return False
    attempted = _target_count_attr(scanner_plugin, "targets_attempted")
    failed = _non_negative_int_attr(scanner_plugin, "targets_failed")
    return attempted is not None and failed >= 1 and attempted > failed


def _tool_lines(
    lines: Any, values: Tuple[str, ...], *, tilde: bool = False
) -> List[Any]:
    """A plugin's ``errors`` or ``output`` lines, as the results keep them.

    The tool's own stdout and stderr: a line can name an option the config
    read from the environment, a file it could not load say, so each text line
    is redacted with *values*. With ``tilde``, the home directory in each text
    line is then written as ``~`` - the one decision for both streams of a
    failed run's raw_results, redaction first so a value under the home
    directory still matches. Anything else in the list is kept as it is.
    """
    kept: List[Any] = []
    for line in lines or []:
        if isinstance(line, str):
            line = text_without_values(line, values)
            if tilde:
                line = home_as_tilde(line)
        kept.append(line)
    return kept


@contextmanager
def _cancel_scan_on_interrupt(executor: ThreadPoolExecutor) -> Iterator[None]:
    """Latch the scan's cancel event when an interrupt reaches the pool's exit.

    Entered on the same ``with`` statement as the ThreadPoolExecutor, after
    it, so it exits first: a KeyboardInterrupt raised on the main thread (a
    terminal Ctrl-C) sets the scan's cancel event before the pool's own exit
    joins the workers. A worker's cancellable spawn watches that event between
    wait slices, so the tool it is running stops through its existing stop
    path instead of running to its own end -- nothing else on the CLI path
    sets the event on SIGINT; the signal handler covers SIGTERM only. The
    queue shutdown then keeps freed workers from dequeuing further scanners
    while the interrupt unwinds; one that is dequeued first is stopped by the
    pre-start cancel check either way.
    """
    try:
        yield
    except KeyboardInterrupt:
        event = current_cancel_event()
        if event is not None:
            event.set()
        executor.shutdown(wait=False, cancel_futures=True)
        raise


class ResultsProcessingFailed(Exception):
    """One target's results could not be merged; the others were.

    Raised by ``ScannerExecutor._process_each`` after every container of a
    scanner has been offered to the processor, naming the first target whose
    processing raised and carrying its ``container``. The scanner-level handlers
    catch it as they catch any failure and file the failure on that container,
    so the target's report keeps what the scan recorded (its status, errors and
    counts), gains the reason it could not be merged, and never replaces a
    merged target's file. Every further target whose processing raised is on
    ``later``, one instance each with its own container, and the handlers file
    each of those the same way: before this only the first was kept, and a
    second failed target's report stayed as the processor had dumped it before
    the raise, which reads as a normal report.
    """

    def __init__(
        self,
        target_type: Optional[str],
        error: BaseException,
        container: Optional[ScanResultsContainer] = None,
    ) -> None:
        self.target_type = target_type
        self.container = container
        self.later: List["ResultsProcessingFailed"] = []
        super().__init__(
            f"could not process its results on {target_type}: {error_text(error)}"
        )


class ScannerExecutor:
    """Runs scanner tasks in parallel or sequential mode.

    Parameters
    ----------
    plugin_context:
        Shared plugin context (paths, config, …).
    progress_display:
        Progress display instance (may be a mock in tests).
    scanner_tasks:
        List of (scanner_name, plugin_instance, scan_targets) triples.
    max_workers:
        Thread-pool size for parallel execution.
    notify_fn:
        Optional callable(event_type, **kwargs) wired to the parent phase's
        notify_event.  When None, event notifications are silently skipped.
    process_results_fn:
        Callable(container, aggregated) → AshAggregatedResults.  Wired to
        ScanResultProcessor.process_container by ScanPhase.
    """

    def __init__(
        self,
        plugin_context: Any,
        progress_display: Any,
        scanner_tasks: List[Tuple[str, ScannerPluginBase, List[Dict[str, Any]]]],
        max_workers: int = 4,
        notify_fn: Optional[Callable[..., Any]] = None,
        process_results_fn: Optional[_ResultsFn] = None,
    ) -> None:
        self.plugin_context = plugin_context
        self.progress_display = progress_display
        self.scanner_tasks = scanner_tasks
        self.max_workers = max_workers
        self._notify_fn = notify_fn
        self._process_fn: _ResultsFn = process_results_fn or (lambda c, a: a)  # type: ignore[assignment]
        self.completed_scanners: List[ScannerPluginBase] = []
        # Set once any scanner's work raises ScanCancelled, and read beside
        # raise_if_cancelled before each start: a cancel that reaches one
        # scanner directly, with the scan's event unset, must still stop the
        # rest. A worker can dequeue a queued scanner faster than the cancel's
        # queue-shutdown cancels it; this is the check that refuses the start.
        # Each run begins with a fresh event.
        self._cancel_seen = threading.Event()
        # Populated by caller when scanner must respect ignored paths
        self._global_ignore_paths: List[Any] = []

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _environment_values(self) -> Tuple[str, ...]:
        """The values the config read from the environment, to redact.

        An exception can name an option the config read from the environment,
        and what a handler here records of it goes to ash.log, the report and the
        results files, so each handler redacts these from it.
        """
        return config_environment_values(getattr(self.plugin_context, "config", None))

    def _plugin_environment_values(self, scanner_plugin: Any) -> Tuple[str, ...]:
        """:meth:`_environment_values` and *scanner_plugin*'s own.

        For every handler here that records text the plugin is the source of:
        what its tool wrote, its reasons, its run's exception and its config. A
        plugin can know a value the config does not, and that text can quote it
        (``utils.error_text.plugin_environment_values``).
        """
        return plugin_environment_values(scanner_plugin, self._environment_values())

    def _notify(self, event_type: Any, **kwargs: Any) -> None:
        if self._notify_fn is not None:
            try:
                self._notify_fn(event_type, **kwargs)
            except Exception as e:
                ASH_LOGGER.error(
                    f"Failed to notify event {event_type}: {error_text(e)}",
                    extra=NO_MARKUP,
                )

    def _process_results_fn(
        self,
        results: ScanResultsContainer,
        aggregated_results: AshAggregatedResults,
    ) -> AshAggregatedResults:
        """Forward to the injected process function, or no-op if not wired."""
        return self._process_fn(results, aggregated_results)

    def _notify_scan_start(
        self, scanner_name: str, scanner_plugin: Any, scan_targets: Any
    ) -> None:
        """Announce SCAN_START for one scanner; a failure to issue it is logged."""
        try:
            from automated_security_helper.plugins.events import AshEventType

            self._notify(
                AshEventType.SCAN_START,
                scanner=scanner_name,
                scanner_class=scanner_plugin.__class__.__name__,
                scan_targets=scan_targets,
                message=f"Starting scanner: {scanner_name}",
            )
        except Exception as notify_error:
            # See the ERROR guard in _execute_scanner: _notify already handles a
            # raising subscriber, so this only covers the local import and kwargs
            # construction.
            ASH_LOGGER.debug(
                f"SCAN_START notification for {scanner_name} could not be "
                f"issued: {notify_error!r}",
                extra=NO_MARKUP,
            )

    def _announce_scan_complete(
        self,
        scanner_name: str,
        remaining_scanners: List[str],
        completed_count: int,
        total: int,
        succeeded: bool = True,
    ) -> None:
        """Take *scanner_name* off *remaining_scanners* and announce SCAN_COMPLETE.

        Every finished turn is announced, with ``succeeded`` saying whether the
        scanner's results were recorded (False for a turn that ended in a
        failure container, a scan() that raised or a merge that failed), the
        contract docs/content/plugins/event-subscribers.md states: "after each
        scanner, including one that failed". Announced only for recorded
        results, a scanner whose scan() raised was still announced (its failure
        container comes back down the normal path) while one whose results
        failed to merge was not, so whether a failed scanner got SCAN_COMPLETE
        depended on how it failed, and when the last scanner to finish was a
        merge failure no SCAN_COMPLETE with ``remaining_count == 0`` was ever
        sent, so the completion logger never said the scan was complete. The
        subscriber gets a copy of the list: the executor keeps changing its own,
        and a subscriber that kept the live list (as the sequential loop passed
        it) saw it change under it. ``completed_scanners`` is a separate record
        and still names only the scanners whose results were recorded.
        """
        self._drop_from_remaining(scanner_name, remaining_scanners)
        try:
            from automated_security_helper.plugins.events import AshEventType

            remaining_count = len(remaining_scanners)
            remaining_list = (
                ", ".join(remaining_scanners) if remaining_scanners else "None"
            )
            outcome = "completed" if succeeded else "failed"
            self._notify(
                AshEventType.SCAN_COMPLETE,
                scanner=scanner_name,
                completed_count=completed_count,
                total_count=total,
                remaining_count=remaining_count,
                remaining_scanners=remaining_scanners.copy(),
                succeeded=succeeded,
                message=f"Scanner {scanner_name} {outcome}. {remaining_count} remaining: {remaining_list}",
            )
        except Exception as notify_error:
            # See the ERROR guard in _execute_scanner: _notify already handles a
            # raising subscriber, so this only covers the local import and kwargs
            # construction.
            ASH_LOGGER.debug(
                f"SCAN_COMPLETE notification for {scanner_name} could not be "
                f"issued: {notify_error!r}",
                extra=NO_MARKUP,
            )

    @staticmethod
    def _drop_from_remaining(scanner_name: str, remaining_scanners: List[str]) -> None:
        """Take *scanner_name* off *remaining_scanners*; its turn is over.

        Called by ``_announce_scan_complete`` before it sends SCAN_COMPLETE, which
        every finished turn sends, a failed one with ``succeeded`` False.
        """
        if scanner_name in remaining_scanners:
            remaining_scanners.remove(scanner_name)

    @staticmethod
    def _completion_outcome(
        scanner_succeeded: bool, results_list: List[ScanResultsContainer]
    ) -> str:
        """How a scanner's recorded turn ended: "failed", "errors" or "clean".

        The run loops print one description per outcome, written inline where
        they call the progress display (the markup check reads each one there).
        Green is for "clean" only: a run that raised (its results are a failure
        container) or graded a target ERROR was shown "[green] Completed scan"
        like a clean one, so the progress display said the opposite of the row.
        """
        if not scanner_succeeded:
            return "failed"
        if any(
            getattr(container, "status", None) == ScannerStatus.ERROR
            for container in results_list
        ):
            return "errors"
        return "clean"

    def _process_each(
        self,
        results_list: List[ScanResultsContainer],
        aggregated_results: AshAggregatedResults,
    ) -> AshAggregatedResults:
        """Process every container of one scanner, then raise for one that could not be.

        Each container is offered to the processor on its own, so a raise while
        merging one target's results (a report the processor cannot read)
        leaves the scanner's other targets' containers merged. Before this the
        raise left the loop, dropped the remaining containers, and the
        scanner-level handler then filed one failure container with no target,
        whose per-target results file is written under "source" and so replaced
        the source target's. The first failure is re-raised after the loop as
        :class:`ResultsProcessingFailed`, which names its target: the
        scanner-level handler logs it as it logs any failure and files the
        failure under that target, so nothing overwrites a merged target's file
        and the scanner stays out of completed_scanners.
        """
        failed: Optional[ResultsProcessingFailed] = None
        for container in results_list:
            try:
                aggregated_results = self._process_results_fn(
                    container, aggregated_results
                )
            except Exception as process_error:
                failure = ResultsProcessingFailed(
                    getattr(container, "target_type", None),
                    process_error,
                    container,
                )
                failure.__cause__ = process_error
                if failed is None:
                    failed = failure
                else:
                    # Kept, not dropped: the handler files and logs each one.
                    failed.later.append(failure)
        if failed is not None:
            raise failed
        return aggregated_results

    def _file_failure_row(
        self,
        scanner_name: str,
        failure_container: ScanResultsContainer,
        aggregated_results: AshAggregatedResults,
        *,
        refiled: bool,
        head: str,
        exception: BaseException,
        environment_values: Iterable[str],
    ) -> AshAggregatedResults:
        """Offer *failure_container* to the processor; a refiled row that raises
        again is filed as a fresh failure row.

        A results-processing failure is refiled on the target's own row with the
        failure added, so the report keeps what the scan recorded. Everything
        else on that row stays as it was (its metadata, its unscanned inputs,
        its counts, its target path), and when one of those is what the
        processor raised on, the second offer raises too; logged alone, that
        target had no row in the results, and a single-target scanner had none
        at all. The fallback is the fresh container the handler filed before
        rows were refiled, carrying the target type so its file lands under the
        target's key, the could-not-stop record run_ash_scan's gate reads off
        the target's report, the same failure record, and the ERRORS the
        refiled row carried: text only, so nothing of what made the row raise
        comes along, but what the scan recorded before the merge failed does. A
        fresh row built from the head alone replaced the refiled row's record
        in additional_reports (the processor stores a row there before it
        writes the row's file), so a refused sandbox's own error text, the one
        the probing-scanner contract reads off that report, was gone whenever
        the write itself was what raised. A raise on the fresh row is logged,
        as before; a fresh row (*refiled* False) gets no second offer, since
        nothing of the scan's is on it to raise on.
        """
        try:
            return self._process_results_fn(failure_container, aggregated_results)
        except Exception as process_error:
            # Redacted like every other handler's text: the error can quote
            # a value the plugin's config read from the environment.
            ASH_LOGGER.error(
                f"Failed to process error results for {scanner_name}: "
                f"{error_text(process_error, environment_values)}",
                extra=NO_MARKUP,
            )
            if not refiled:
                return aggregated_results
        # The refiled row's errors end in *head* (the handler added it before
        # the offer); an empty list falls back to the head alone.
        fresh = ScanResultsContainer.for_failure(
            scanner_name,
            errors=list(failure_container.errors) or [head],
            exception=exception,
            values=environment_values,
        )
        fresh.target_type = failure_container.target_type
        fresh.could_not_stop = failure_container.could_not_stop
        fresh.status = ScannerStatus.ERROR
        fresh.raw_results = failure_container.raw_results
        try:
            return self._process_results_fn(fresh, aggregated_results)
        except Exception as process_error:
            ASH_LOGGER.error(
                f"Failed to process error results for {scanner_name} on a fresh "
                f"row: {error_text(process_error, environment_values)}",
                extra=NO_MARKUP,
            )
            return aggregated_results

    def _file_later_failures(
        self,
        scanner_name: str,
        failed: ResultsProcessingFailed,
        environment_values: Any,
        log_head: str,
        row_head: str,
        aggregated_results: AshAggregatedResults,
    ) -> AshAggregatedResults:
        """File every target failure after the first as the handler filed the first.

        Each is logged under *log_head* as the first was, added to its own row
        with *row_head*, graded ERROR, given the failure's raw_results record and
        offered to the processor; a processor that raises on the record is
        logged and the next one is still filed.
        """
        for later in failed.later:
            described = error_text(later, environment_values)
            stack_trace = traceback_text(
                later.__cause__ or later, values=environment_values
            )
            ASH_LOGGER.debug(
                f"Stack trace for scanner {scanner_name} failure:\n{stack_trace}",
                extra=NO_MARKUP,
            )
            ASH_LOGGER.error(
                f"{log_head}: {scanner_name} - {described}", extra=NO_MARKUP
            )
            container = later.container
            if not isinstance(container, ScanResultsContainer):
                # Logged above; only a row can be refiled (a substituted runner
                # can hand the processor anything, see the first-failure path).
                continue
            container.add_error(f"{row_head}: {described}")
            container.set_exception(later, environment_values)
            container.status = ScannerStatus.ERROR
            container.raw_results = {
                "errors": [home_as_tilde(f"{row_head}: {described}")],
                "status": "failed",
                "exception": home_as_tilde(described),
                "stack_trace": home_as_tilde(stack_trace),
            }
            aggregated_results = self._file_failure_row(
                scanner_name,
                container,
                aggregated_results,
                refiled=True,
                head=f"{row_head}: {described}",
                exception=later,
                environment_values=environment_values,
            )
        return aggregated_results

    def _assess_content_databases(self, scanner_plugin: Any, raw_results: Any) -> list:
        """Hold the scanner's content databases to their declared age bounds.

        Here, at the one place every scanner's result passes through, rather than in each
        scanner's ``scan()``: trivy overrides ``scan()`` entirely, and a check that lived in
        the base template would silently skip it. Only a SARIF result is assessed; see
        ``utils/content_db_staleness.py`` for what is measured and where it is recorded.

        Returns the records, so the caller can tell a database that does not exist
        and grade a clean result the policy rejects.
        """
        from automated_security_helper.schemas.sarif_schema_model import SarifReport
        from automated_security_helper.utils.content_db_staleness import (
            assess_scanner,
            resolve_offline_image_default,
            resolve_overrides,
            resolve_policy,
        )

        if not isinstance(raw_results, SarifReport):
            return []
        config = getattr(self.plugin_context, "config", None)
        return assess_scanner(
            scanner_plugin,
            raw_results,
            resolve_policy(config),
            overrides=resolve_overrides(config),
            offline_image=resolve_offline_image_default(config),
        )

    # ------------------------------------------------------------------
    # Single-scanner execution
    # ------------------------------------------------------------------

    def _execute_scanner(
        self,
        scanner_name: str,
        scanner_plugin: ScannerPluginBase,
        scan_targets: List[Dict[str, Any]],
    ) -> List[ScanResultsContainer]:
        """Execute a single scanner across all its targets."""
        results: List[ScanResultsContainer] = []

        try:
            ASH_LOGGER.debug("EVALUATING CONFIGURED SCANNERS")
            scanner_config = scanner_plugin.config
            if scanner_config is None:
                raise ValueError(f"Scanner {scanner_name} has no config")
            # Which settings, never their values: a value can be one the config
            # file read from the environment, or a credential, and ash.log keeps
            # DEBUG lines under --debug.
            from automated_security_helper.config.environment_record import (
                setting_names,
            )

            ash_config = getattr(
                getattr(scanner_plugin, "context", None), "config", None
            )
            names = setting_names(
                scanner_config,
                getattr(ash_config, "_environment_references", ()) or (),
                at=("scanners", str(getattr(scanner_config, "name", "") or "")),
            )
            ASH_LOGGER.debug(f"scanner_plugin.config setting: {names}", extra=NO_MARKUP)

            for target_info in scan_targets:
                scan_target = target_info["path"]
                target_type = target_info["type"]

                if not scan_target or not Path(scan_target).exists():
                    ASH_LOGGER.debug(
                        f"Skipping {target_type} directory {scan_target} - does not exist",
                        extra=NO_MARKUP,
                    )
                    continue

                # Named as the scan phase named the task: its display name, which
                # falls back to the class name when the config has none. The
                # phase keys its rows, tasks and validation state by that name,
                # and the failure containers the run loops file carry it too;
                # str(config.name) here filed a nameless config's containers
                # under "None", apart from everything else that scanner wrote.
                scanner_config_name: str = scanner_name
                container = ScanResultsContainer(
                    scanner_name=scanner_config_name,
                    target=scan_target,
                    target_type=target_type,
                    scanner_severity_threshold=scanner_config.options.severity_threshold,
                )

                raw_results: Any = None
                # Set when the scanner's tool reports that a content database it
                # matches against does not exist; see below.
                databases_absent: List[str] = []
                # The content-database records for this target; see below.
                content_db_records: List[Any] = []
                # Whether scan() was called on this target. The plugin's exit_code,
                # times, target counters and unscanned inputs belong to the last
                # target it scanned, so a target it never scanned (disabled, or
                # refused by the sandbox) records none of them.
                scan_called = False
                # Whether the scanner is disabled in its config: its row is
                # SKIPPED and excluded, and nothing below grades it.
                disabled = False
                # Whether the failure handler already put the run's recorded cause
                # (a timeout) and the unevaluated targets on the row, so the blocks
                # after grading do not name them twice.
                cause_recorded = False
                # The timeout flag a per-target scanner kept while recording the
                # timed-out target itself (_recorded_the_timed_out_target): the
                # raise is skipped for it, and the grading below makes the row
                # ERROR from this, not from scan_timed_out_after, which the run
                # recorder can fail to set while the flag is kept.
                kept_timeout: Optional[Tuple[str, str]] = None
                heartbeat = _ScannerHeartbeat(
                    scanner_config_name,
                    target_type,
                    SCANNER_HEARTBEAT_INTERVAL_SECONDS,
                )
                try:
                    if scanner_config and scanner_config.enabled:
                        ASH_LOGGER.debug(
                            f"Executing {scanner_config_name}.scan() on {target_type}"
                        )
                        if (
                            not hasattr(scanner_plugin, "context")
                            or scanner_plugin.context is None
                        ):
                            scanner_plugin.context = self.plugin_context
                        scanner_plugin.results_dir = (
                            self.plugin_context.output_dir.joinpath(
                                "scanners"
                            ).joinpath(scanner_config_name)
                        )
                        if isinstance(scanner_plugin, PluginBase):
                            scanner_plugin.clear_scan_timeout()
                            scanner_plugin.clear_scan_spawn_failure()
                            scanner_plugin.clear_scan_post_run_error()
                            scanner_plugin.clear_scan_kept_flag()
                            scanner_plugin.clear_scan_could_not_stop()
                            scanner_plugin.clear_unevaluated_targets()
                        # Resolved before the scan, so a scanner that cannot be
                        # sandboxed as requested never starts and never runs
                        # unsandboxed. The grade follows what was asked: a
                        # backend missing under auto is MISSING, like any
                        # missing dependency, whoever set auto (the split is
                        # auto vs a named backend, not who chose the mode); a
                        # backend the operator named that is unavailable is
                        # ERROR with the start-failure code, and any refusal
                        # that is not availability is ERROR with the refusal's
                        # reason.
                        try:
                            sandbox = scanner_sandbox_scope(
                                scanner_plugin,
                                self.plugin_context,
                                Path(scan_target),
                            )
                            sandbox_refusal = None
                        except SandboxUnavailable as refusal:
                            sandbox, sandbox_refusal = None, refusal
                        # The same test ScanPhase used to decide whether to run
                        # the dependency check, so the two cannot disagree.
                        # The refusal's text can name a configured value (a
                        # backend option read from the environment), and it goes
                        # to ash.log, the row and the results files, so it is
                        # redacted as every sibling handler redacts its text.
                        refusal_values = (
                            self._plugin_environment_values(scanner_plugin)
                            if sandbox_refusal is not None
                            else ()
                        )
                        if sandbox_refusal is not None and not (
                            sandbox_refusal_grades_missing(sandbox_refusal)
                        ):
                            reason = home_as_tilde(
                                text_without_values(
                                    str(sandbox_refusal), refusal_values
                                )
                            )
                            if isinstance(sandbox_refusal, SandboxBackendUnavailable):
                                # The operator named this backend: the tool could
                                # not start as requested, with the start-failure
                                # code.
                                text = (
                                    f"{scanner_config_name} could not start its "
                                    f"tool: {reason}"
                                )
                                scanner_plugin.exit_code = SPAWN_FAILURE_RETURNCODE
                                # scan() is never called, so the carry-over below
                                # does not reach this row: it takes the code here.
                                container.exit_code = SPAWN_FAILURE_RETURNCODE
                            else:
                                # Refused for a reason that is not availability:
                                # nothing is missing, and no tool started, so the
                                # row carries no exit code.
                                text = (
                                    f"{scanner_config_name}'s scanner sandbox "
                                    f"was refused: {reason}"
                                )
                                scanner_plugin.exit_code = None
                            ASH_LOGGER.error(text, extra=NO_MARKUP)
                            container.add_error(text)
                            # A failed dict, not the False of the MISSING branch:
                            # the finally below grades it ERROR, with no
                            # missing_reason, and the scanner never runs.
                            raw_results = {"errors": [text], "status": "failed"}
                        elif sandbox_refusal is not None:
                            reason = text_without_values(
                                str(sandbox_refusal), refusal_values
                            )
                            ASH_LOGGER.error(
                                f"{scanner_config_name} not run: scanner sandbox "
                                f"unavailable: {reason}",
                                extra=NO_MARKUP,
                            )
                            container.add_error(
                                f"Scanner sandbox unavailable: {reason}"
                            )
                            # The row's reason. Assigned rather than appended, so the
                            # per-target report keeps it (see ScanResultsContainer).
                            container.missing_reason = home_as_tilde(
                                f"scanner sandbox unavailable: {reason}"
                            )
                            # Recorded on the plugin too: scanner_results reads the
                            # plugin's flag, and a MISSING row claiming satisfied
                            # dependencies would contradict its own status.
                            scanner_plugin.dependencies_satisfied = False
                            if hasattr(scanner_plugin, "dependency_unavailable_reason"):
                                scanner_plugin.dependency_unavailable_reason = (
                                    f"scanner sandbox unavailable: {reason}"
                                )
                            raw_results = False
                        else:
                            # Not recorded as container metadata: any metadata at
                            # all makes the SARIF tool_invocation gain exit_code and
                            # duration (scan_result_processor), so sandboxed and
                            # unsandboxed results would differ in shape. The backend
                            # is in ash.log ("Scanner sandbox: using ...").
                            if sandbox is not None:
                                ASH_LOGGER.info(
                                    f"Scanner sandbox: {scanner_config_name} on "
                                    f"{target_type} runs under {sandbox.backend.name}"
                                )
                                # A link already there is refused as ASH's writes
                                # refuse one; the sweep after each spawn would
                                # remove it without a word.
                                refuse_links_below(sandbox.results_dir)
                            # The config files ASH writes for this run's tool live
                            # in a directory of the run's own, outside the scanned
                            # tree, which the sandbox lets the scanner read and
                            # which is removed when the run ends.
                            # The exception leaving the scan, if any, recorded for
                            # the sweep in the finally below, which must not
                            # replace it. Recorded here rather than read from
                            # sys.exc_info() in the finally: that call also
                            # answers an exception an enclosing handler is busy
                            # with, so a sweep failure after a clean scan would
                            # have been dropped if this ran inside one.
                            propagating: Optional[BaseException] = None
                            try:
                                with (
                                    sandbox_scope(sandbox),
                                    tool_config_scope(self.plugin_context),
                                ):
                                    try:
                                        # Started inside the try whose finally
                                        # stops it: started before the scopes,
                                        # a raise while entering them left the
                                        # daemon thread announcing a scanner
                                        # that never ran until the process
                                        # ended.
                                        heartbeat.start()
                                        scan_called = True
                                        raw_results = scanner_plugin.scan(
                                            target=scan_target,
                                            config=scanner_config,
                                            target_type=target_type,
                                            global_ignore_paths=self._global_ignore_paths,
                                        )
                                    finally:
                                        heartbeat.stop()
                                    # A tool that never started found nothing, so the
                                    # scan is an error even when scan() returned
                                    # normally. A scanner that overrides scan() may have
                                    # read the empty output as "no findings", or accepted
                                    # the exit code; neither may stand.
                                    spawn_failure = _spawn_failure(scanner_plugin)
                                    if spawn_failure is not None:
                                        raise ScannerError(
                                            f"{scanner_config_name} could not start its "
                                            f"tool on {target_type}: {spawn_failure}"
                                        )
                                    # Next, a run whose response kept a flag that says
                                    # it did not finish: a timeout (or a stop that did
                                    # not end it), a cancel, a rejected result, a signal
                                    # ASH did not send. What it wrote is not the whole
                                    # scan, so scan() may have read it as clean. This
                                    # gates BEFORE the post-run error, matching the run
                                    # recorder's own flag order: a killed tool commonly
                                    # fails its record step too, and the reason raised
                                    # has to lead with the cause (the run did not
                                    # finish), not that consequence.
                                    #
                                    # Not raised for a per-target scanner that
                                    # recorded the timed-out target itself and
                                    # returned the other targets' merged report:
                                    # the raise replaced that report with one
                                    # failure record, so one template's timeout
                                    # cost every other template its findings.
                                    # The row is still graded ERROR below, with
                                    # the timeout on it (_recorded_the_timed_out_target).
                                    kept = _kept_flag(scanner_plugin)
                                    if (
                                        kept is not None
                                        and _recorded_the_timed_out_target(
                                            scanner_plugin, kept, raw_results
                                        )
                                    ):
                                        ASH_LOGGER.debug(
                                            f"{scanner_config_name} recorded a timed-out "
                                            f"target on {target_type} in its own "
                                            "accounting; keeping its report",
                                            extra=NO_MARKUP,
                                        )
                                        kept_timeout = kept
                                    elif kept is not None:
                                        raise ScannerError(
                                            _unfinished_run_reason(
                                                scanner_config_name,
                                                target_type,
                                                kept,
                                                _timed_out_after(scanner_plugin),
                                                self._plugin_environment_values(
                                                    scanner_plugin
                                                ),
                                            )
                                        )
                                    # And for a tool that ran to completion when ASH
                                    # could not record its output: the exit code is
                                    # the tool's own, so scan() may have read the run
                                    # as clean. After the unfinished gate: on a run
                                    # both states describe, the record failure is the
                                    # detail, not the reason.
                                    post_run_error = _post_run_error(scanner_plugin)
                                    if post_run_error is not None:
                                        raise ScannerError(
                                            f"{scanner_config_name} ran on {target_type}, "
                                            "but ASH could not record the scanner's "
                                            f"output: {post_run_error}"
                                        )
                                    # Inside the scope: this runs the scanner's own
                                    # binary (`grype db status`), which is that
                                    # scanner's code like any other spawn of it.
                                    content_db_records = records = (
                                        self._assess_content_databases(
                                            scanner_plugin, raw_results
                                        )
                                        or []
                                    )
                                    databases_absent = [
                                        record.message()
                                        for record in records or []
                                        if getattr(record, "absent", False)
                                    ]
                            except BaseException as exc:
                                propagating = exc
                                raise
                            finally:
                                if sandbox is not None:
                                    # Again after the scan, for anything a process
                                    # that outlived its spawn left behind, before the
                                    # results are written into this directory. In a
                                    # finally, so the sweep runs on every raise above
                                    # too: a tool that could not start, a run that
                                    # did not finish (the timeout and could-not-stop
                                    # case, which is when a process that outlived its
                                    # spawn is most likely), a post-run error, or a
                                    # scan() that raised.
                                    #
                                    # In its own handler: a raise from the sweep
                                    # inside this finally would replace the exception
                                    # already on its way out (a cancel, a keyboard
                                    # interrupt, the scan's own failure) and be
                                    # recorded as this target's error in its place,
                                    # so a cancel would not end the scan and a failed
                                    # scan would name the sweep. The sweep's error is
                                    # logged, and raised only when nothing else is
                                    # propagating (``propagating``, recorded above).
                                    try:
                                        sweep_writable(
                                            [sandbox.results_dir],
                                            sandbox.environment_values,
                                            values_unread=sandbox.environment_values_unread,
                                        )
                                    except Exception as sweep_error:
                                        ASH_LOGGER.error(
                                            f"Sweep of {scanner_name}'s results directory "
                                            f"after the scan on {target_type} failed: "
                                            f"{error_text(sweep_error, sandbox.environment_values)}",
                                            extra=NO_MARKUP,
                                        )
                                        if propagating is None:
                                            raise
                    else:
                        # NO_MARKUP, as the sibling records: the scanner name is
                        # data, and a "[/x]" in one is a closing Rich tag that
                        # raises instead of printing.
                        ASH_LOGGER.warning(
                            f"{scanner_config_name} is not enabled!", extra=NO_MARKUP
                        )
                        # Left unscanned, as the scan phase leaves a scanner the
                        # config disables: the row is SKIPPED and excluded, with
                        # the reason. Left as it was, the None result below graded
                        # it ERROR "returned no result", a failure of a scanner
                        # nobody asked to run.
                        disabled = True
                        container.status = ScannerStatus.SKIPPED
                        container.excluded = True
                        container.skipped_reason = (
                            f"{scanner_config_name} is disabled in the configuration"
                        )
                # SystemExit too: a scanner's in-process code that calls sys.exit
                # (a tool run as a library, a plugin's own guard) is that scanner's
                # failure, graded like any other raise. Left to escape, it ended
                # the whole scan with no scanner recorded and the process exiting
                # with the plugin's code. A cancel (ScanCancelled) and a keyboard
                # interrupt are not Exceptions and still end the scan.
                except (Exception, SystemExit) as e:
                    if _exit_is_the_shutdowns(e):
                        # The process is going down, not this scanner.
                        raise
                    # Redacted with the config's environment values and the
                    # plugin's own: the exception can name an option either read
                    # from the environment, and this text goes to ash.log, the
                    # report and the results files.
                    environment_values = self._plugin_environment_values(scanner_plugin)
                    described = _failure_text(e, environment_values)
                    stack_trace = traceback_text(values=environment_values)
                    ASH_LOGGER.debug(
                        f"Stack trace for scanner {scanner_name} failure:\n{stack_trace}",
                        extra=NO_MARKUP,
                    )
                    err_str = f"Failed to execute {scanner_config_name} scanner on {target_type}: {described}"
                    # Lead with the timeout when there was one. A scanner that
                    # overrides scan() reports whatever the missing output caused
                    # -- typically "No such file or directory" -- and only
                    # _run_subprocess saw that the tool was killed.
                    timed_out_after = _timed_out_after(scanner_plugin)
                    spawn_failure = _spawn_failure(scanner_plugin)
                    post_run_error = _post_run_error(scanner_plugin)
                    if timed_out_after is not None and "timed out" not in described:
                        # The limit through timeout_limit_token (why and how
                        # redaction reads it: that function's docstring), and
                        # the line redacted whole. "Was killed" only when the
                        # stop worked: a timeout whose stop failed left the
                        # tool running, and the one thing this line must not
                        # tell the operator is that it is gone. Which run the
                        # could-not-stop record belongs to: _timeout_ending.
                        limit = timeout_limit_token(timed_out_after, environment_values)
                        ending = _timeout_ending(scanner_plugin)
                        err_str = text_without_values(
                            f"{scanner_config_name} timed out after "
                            f"{limit} on {target_type}{ending}: {described}",
                            environment_values,
                        )
                    elif (
                        spawn_failure is not None and "could not start" not in described
                    ):
                        # Same for a tool that never started: the exception is
                        # usually the results file it did not write.
                        err_str = (
                            f"{scanner_config_name} could not start its tool on "
                            f"{target_type} "
                            f"({text_without_values(spawn_failure, environment_values)})"
                            f": {described}"
                        )
                    elif (
                        post_run_error is not None
                        and "could not record" not in described
                        # Not over the acceptance step's own raise: a run that
                        # kept a flag (a cancel, a rejected result) and failed
                        # its record step too is led by the cause, as the gate
                        # order above says, not by the record failure.
                        and _kept_flag(scanner_plugin) is None
                    ):
                        # And for a tool that ran: the exception is usually what
                        # its scan() made of the output ASH could not record.
                        err_str = (
                            f"{scanner_config_name} ran on {target_type}, but ASH "
                            "could not record the scanner's output "
                            f"({text_without_values(post_run_error, environment_values)})"
                            f": {described}"
                        )
                    ASH_LOGGER.error(err_str, extra=NO_MARKUP)
                    # On the row as well as in raw_results: the row is what says why
                    # it is ERROR (a rejected exit code, a timeout, a missing file).
                    container.add_error(err_str)
                    # Persisted failure text: ASH's own message first, then the
                    # tool's recorded lines. Every text line is redacted and
                    # then writes the home directory as a tilde, one decision
                    # for both streams (_tool_lines' tilde mode).
                    raw_results = {
                        "errors": [
                            home_as_tilde(err_str),
                            *_tool_lines(
                                scanner_plugin.errors, environment_values, tilde=True
                            ),
                        ],
                        "output": _tool_lines(
                            scanner_plugin.output, environment_values, tilde=True
                        ),
                        "status": "failed",
                        "exception": home_as_tilde(described),
                        "stack_trace": home_as_tilde(stack_trace),
                    }
                    # A target the tool never evaluated is named on this path
                    # too: the raise that brought the run here (a kept flag, a
                    # spawn failure) does not undo the scanner's accounting,
                    # and on a failed run raw_results holds the row's reasons.
                    # The name is the plugin's own text: redacted, then the home
                    # directory written as a tilde, as the lines above are.
                    for name in _unevaluated_targets(scanner_plugin):
                        raw_results["errors"].append(
                            home_as_tilde(
                                text_without_values(
                                    f"no rule was evaluated against {name}",
                                    environment_values,
                                )
                            )
                        )
                    # The run's cause and its unevaluated targets are on the row
                    # now; the blocks after grading do not add them again.
                    cause_recorded = True
                    try:
                        from automated_security_helper.plugins.events import (
                            AshEventType,
                        )

                        self._notify(
                            AshEventType.ERROR,
                            message=err_str,
                            scanner=scanner_name,
                            exception=e,
                        )
                    except Exception as notify_error:
                        # _notify already catches and error-logs anything the
                        # subscriber callback raises, so what reaches here is a
                        # failure to get as far as the call: the local import above,
                        # or building the keyword arguments. Kept broad and
                        # swallowed so a bookkeeping failure cannot mask the
                        # scanner error already recorded in raw_results, but logged
                        # so it is not invisible.
                        ASH_LOGGER.debug(
                            f"ERROR notification for {scanner_name} could not be "
                            f"issued: {notify_error!r}",
                            extra=NO_MARKUP,
                        )
                except BaseException:
                    # A cancel (ScanCancelled) or a keyboard interrupt out of
                    # scan(): the scan is ending, and this target is not the
                    # scanner's failure. The row built below is discarded with the
                    # raise; what it must not do is log "returned no result" at
                    # ERROR for every scanner that was in flight, which the None
                    # result did.
                    ASH_LOGGER.debug(
                        f"{scanner_config_name} was interrupted on {target_type}",
                        extra=NO_MARKUP,
                    )
                    raw_results = {
                        "errors": [
                            (
                                f"{scanner_config_name} did not finish on "
                                f"{target_type}: the scan was interrupted"
                            )
                        ],
                        "status": "failed",
                        "exception": "the scan was interrupted",
                    }
                    raise
                finally:
                    # Formatted only when TRACE is on: the f-string rendered the
                    # whole result (a SARIF model's repr) on every target at
                    # every level, and printed it unredacted.
                    if ASH_LOGGER.isEnabledFor(TRACE_LEVEL):
                        ASH_LOGGER.trace(
                            text_without_values(
                                f"{scanner_plugin.__class__.__name__} raw_results "
                                f"for {target_type}: {raw_results!r}",
                                self._plugin_environment_values(scanner_plugin),
                            ),
                            extra=NO_MARKUP,
                        )
                    if raw_results is None and not disabled:
                        # ASH's own message first: it is the row's reason
                        # (unified_metrics.recorded_error reads the first error).
                        # The tool's stderr is not the cause of a missing result,
                        # and it can say anything; its lines are kept after it,
                        # redacted with the plugin's own values too.
                        environment_values = self._plugin_environment_values(
                            scanner_plugin
                        )
                        no_result = (
                            f"{scanner_config_name} returned no result on {target_type}"
                        )
                        # NO_MARKUP: the text holds the scanner's name, data as
                        # in the sibling records above.
                        ASH_LOGGER.error(no_result, extra=NO_MARKUP)
                        # On the row too, so the row says why it is ERROR.
                        container.add_error(no_result)
                        raw_results = {
                            "errors": [
                                (
                                    f"{scanner_config_name} returned no result on "
                                    f"{target_type}"
                                ),
                                *_tool_lines(
                                    scanner_plugin.errors,
                                    environment_values,
                                    tilde=True,
                                ),
                            ],
                            "output": _tool_lines(
                                scanner_plugin.output, environment_values, tilde=True
                            ),
                            "status": "failed",
                            "exception": "Scanner returned None",
                        }
                    elif raw_results is False:
                        # False alone: the template's answer when its dependencies
                        # are unavailable. An empty dict, list or string is not
                        # that answer; it is a result the grading below refuses as
                        # ungradable, so a row no longer reads "dependencies
                        # unavailable" and ERROR at once.
                        container.status = ScannerStatus.MISSING
                        # The status is not the only channel this fact travels on, and the
                        # two must not disagree. ScannerStatisticsCalculator derives
                        # ``dependencies_missing`` from the status string when it reads a
                        # scanner-level report, and from this field when it reads a
                        # scanner_results entry, so a container that says MISSING while
                        # still claiming satisfied dependencies reports one way or the
                        # other depending on which of those a run happens to produce.
                        container.dependencies_satisfied = False
                        # A reason already on the container is the sandbox refusal,
                        # which its own ERROR above logged.
                        if container.missing_reason is None:
                            # Redacted with the config's environment values first:
                            # the plugin's explanation can name an option the config
                            # read from the environment, and a value under the home
                            # directory no longer matches once it is written as ~.
                            # The plugin's own values too.
                            environment_values = self._plugin_environment_values(
                                scanner_plugin
                            )
                            reason = text_without_values(
                                _missing_reason_after_scan(
                                    scanner_plugin,
                                    scanner_config_name,
                                    target_type,
                                    environment_values,
                                ),
                                environment_values,
                            )
                            # As ScanPhase's dependency WARNING: ash.log keeps the
                            # reason as the plugin gave it, absolute paths included,
                            # and the row gets it without the home directory.
                            ASH_LOGGER.warning(
                                f"Scanner {scanner_config_name} found its dependencies "
                                f"unavailable on the {target_type} files, marking as "
                                f"MISSING: {reason}",
                                extra=NO_MARKUP,
                            )
                            container.missing_reason = home_as_tilde(reason)

                    # The plugin's times are the last scan's. A target scan() never
                    # ran on records none, as it records no exit code: copied, a
                    # refused or disabled target carried the previous target's
                    # start, end and duration.
                    if scan_called:
                        container.start_time = scanner_plugin.start_time
                        container.end_time = scanner_plugin.end_time
                        container.duration = None
                        try:
                            if isinstance(
                                scanner_plugin.end_time, datetime
                            ) and isinstance(scanner_plugin.start_time, datetime):
                                container.duration = (
                                    scanner_plugin.end_time - scanner_plugin.start_time
                                ).total_seconds()
                        except Exception as dur_e:
                            ASH_LOGGER.debug(
                                f"Error calculating duration for scanner {scanner_config_name}: {dur_e}",
                                extra=NO_MARKUP,
                            )
                    else:
                        container.duration = None
                    container.raw_results = raw_results

                    from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import (
                        CycloneDXReport,
                    )
                    from automated_security_helper.schemas.sarif_schema_model import (
                        SarifReport,
                    )

                    # Reading the result is the one step here that runs on what the
                    # scanner returned, and a result ASH cannot read (a count that
                    # is not a number, a finding that is not a mapping) must not
                    # raise out of this finally: the raise left _execute_scanner
                    # through its outer handler, and _safe_execute_scanner then
                    # replaced every container this scanner had already built for
                    # its earlier targets with one failure container. A result that
                    # cannot be read makes this target's row ERROR, with the reason
                    # on the row, and the scanner's other targets keep theirs.
                    try:
                        if isinstance(raw_results, SarifReport):
                            if not raw_results.runs:
                                # Every field of a SARIF log is optional, so `{}`
                                # validates. The template refuses it before grading; a
                                # scan() override can return it as it is, and zero
                                # findings from no run reads as a clean scan.
                                _refuse_to_grade(
                                    container,
                                    f"{scanner_config_name} returned a result on "
                                    f"{target_type} that holds no SARIF run, so there is "
                                    "nothing to grade",
                                )
                            # A result that states no level is read at the level
                            # SARIF gives it (the rule's default, else warning)
                            # before this row's counts and status are graded.
                            # ScanResultProcessor resolves the same levels when
                            # the report enters the results, so the per-target
                            # row and the summary read one severity for one
                            # finding; counted first, a level-less result read as
                            # info here and as MEDIUM in ash.sarif. Idempotent: a
                            # result with a level keeps it.
                            resolve_missing_levels(raw_results)
                            raw_results = sanitize_sarif_paths(
                                raw_results, self.plugin_context.source_dir
                            )
                            # Before suppressions, and whatever --ignore-suppressions
                            # says: ASH's own output is not part of the scanned tree.
                            # Most scanners are told to skip it; this catches the ones
                            # whose tool has no such option (snyk-code) or was not
                            # told (bandit, and any third-party scanner).
                            drop_results_in_ash_output_dirs(
                                raw_results,
                                self.plugin_context,
                                scanner_name=scanner_config_name,
                            )
                            # So a converted file's finding keeps its id wherever the
                            # output directory is.
                            mark_converted_results(raw_results, self.plugin_context)
                            if not self.plugin_context.ignore_suppressions:
                                raw_results = apply_suppressions_to_sarif(
                                    sarif_report=raw_results,
                                    plugin_context=self.plugin_context,
                                )
                            else:
                                # The flag lifts suppressions and ignore paths, not
                                # the exclusion of ASH's own output directory.
                                raw_results = exclude_output_dir_results(
                                    sarif_report=raw_results,
                                    plugin_context=self.plugin_context,
                                )
                            severity_counts, finding_count = (
                                self._extract_metrics_from_sarif(raw_results)
                            )
                            container.severity_counts = severity_counts
                            container.finding_count = finding_count
                        elif isinstance(raw_results, dict):
                            if "status" in raw_results and not _completed_result_status(
                                raw_results["status"]
                            ):
                                container.status = ScannerStatus.ERROR
                                # "failed" dicts carry their own errors: the template's
                                # and the scan phase's failure responses. Any other
                                # status, "FAILED" and "Failed" among them, is refused
                                # by name below: only the one spelling the templates
                                # write says the tool reported its own failure.
                                status = raw_results["status"]
                                failed_status = status == "failed"
                                if not failed_status:
                                    # The status is the plugin's own text, redacted
                                    # as every other plugin-sourced text here is.
                                    environment_values = (
                                        self._plugin_environment_values(scanner_plugin)
                                    )
                                    _refuse_to_grade(
                                        container,
                                        text_without_values(
                                            f"{scanner_config_name} returned a result on "
                                            f"{target_type} with status "
                                            f"{status!r}, which does not say "
                                            "its tool completed, so it was not graded",
                                            environment_values,
                                        ),
                                    )
                                elif not container.errors and not any(
                                    isinstance(error, str) and error
                                    for error in (
                                        raw_results.get("errors")
                                        if isinstance(raw_results.get("errors"), list)
                                        else []
                                    )
                                ):
                                    # A failed dict with no error anywhere: the row
                                    # was ERROR with nothing to say why.
                                    _refuse_to_grade(
                                        container,
                                        f"{scanner_config_name} reported that its run "
                                        f"on {target_type} failed without saying why",
                                    )
                            elif not (
                                "status" in raw_results
                                or "severity_counts" in raw_results
                                or isinstance(raw_results.get("findings"), list)
                            ):
                                # Nothing here to grade: a tool's own JSON that a scanner
                                # returned because it did not parse. Graded on its zero
                                # findings it read as a clean scan.
                                _refuse_to_grade(
                                    container,
                                    f"{scanner_config_name} returned a result on "
                                    f"{target_type} that could not be graded: it is not "
                                    "SARIF and carries no status, severity_counts or "
                                    "findings",
                                )
                            else:
                                if "severity_counts" in raw_results:
                                    # Keys matched by name whatever their case: a
                                    # count under "HIGH" validated as a pydantic
                                    # extra, never reached the gate, and the row
                                    # graded PASSED over high findings. A value that
                                    # is not a count raises, and the guard around
                                    # this chain makes the row ERROR for it.
                                    container.severity_counts = (
                                        _severity_counts_from_dict(
                                            raw_results["severity_counts"]
                                        )
                                    )
                                    container.finding_count = (
                                        container.severity_counts.total
                                        + container.severity_counts.suppressed
                                    )
                                elif isinstance(raw_results.get("findings"), list):
                                    # Counted into a fresh model and ASSIGNED, not
                                    # incremented on the field's default: an
                                    # increment on the default never marks the
                                    # field set, and the processor dumps the row
                                    # with exclude_unset, so the counts a findings
                                    # list graded FAILED on were left out of the
                                    # per-target report, read as 0 by the summary,
                                    # and the row rolled up PASSED.
                                    counted = ScannerSeverityCount()
                                    for finding in raw_results["findings"]:
                                        # Two defaults, on purpose. A finding that
                                        # STATES NO severity (the key is missing or
                                        # null, the finding is not a mapping, or the
                                        # value is not text: a number is no name the
                                        # ladder can read, so it states nothing) is
                                        # read at the level SARIF gives a result that
                                        # states none, warning, so it is MEDIUM here
                                        # as a level-less SARIF result is above;
                                        # counted in finding_count alone, as before,
                                        # such a finding never reached the gate, and
                                        # a non-text value read as info graded a
                                        # CVSS 9.8 PASSED at MEDIUM. A finding that
                                        # STATES a severity ASH cannot place (a name
                                        # increment does not know) counts as info: that is
                                        # the contract the lifecycle tests pin
                                        # (test_findings_list_increments_counts_per_
                                        # severity, "unknown severities fall back to
                                        # info"), and a tool's own vocabulary is a
                                        # claim this gate cannot rank, so it is kept
                                        # at the lowest level rather than promoted
                                        # above a finding that said nothing.
                                        # increment raises ValueError for both.
                                        severity = (
                                            finding.get("severity")
                                            if isinstance(finding, dict)
                                            else None
                                        )
                                        if not isinstance(severity, str):
                                            severity = "medium"
                                        try:
                                            counted.increment(severity)
                                        except ValueError:
                                            counted.increment("info")
                                    container.severity_counts = counted
                                    container.finding_count = len(
                                        raw_results["findings"]
                                    )
                        elif raw_results is not None and not (
                            raw_results is True
                            or raw_results is False
                            or isinstance(raw_results, CycloneDXReport)
                        ):
                            # Nothing the executor reads: a scan() override's own list,
                            # string or number, empty or not. Graded on its zero
                            # findings it read as a clean scan; empty, it read as
                            # MISSING with a dependency reason it never gave. False
                            # alone is MISSING, above; None was recorded above too.
                            _refuse_to_grade(
                                container,
                                f"{scanner_config_name} returned a result on "
                                f"{target_type} that could not be graded: a "
                                f"{type(raw_results).__name__}, not SARIF, CycloneDX or "
                                "a dict",
                            )
                    except Exception as grading_error:
                        # Redacted as the per-target handler redacts: the text
                        # can quote a value from the scanner's own result.
                        environment_values = self._plugin_environment_values(
                            scanner_plugin
                        )
                        described = error_text(grading_error, environment_values)
                        reason = text_without_values(
                            f"{scanner_config_name} returned a result on "
                            f"{target_type} that could not be graded: {described}",
                            environment_values,
                        )
                        _refuse_to_grade(container, reason)
                        if isinstance(
                            container.raw_results, (SarifReport, CycloneDXReport)
                        ):
                            # The try covers ASH's own steps on a report too (the
                            # missing levels, the path sanitizing, the output-dir
                            # drop, the converted marks, the suppressions). A
                            # raise partway left the report on the row, possibly
                            # changed in place, and the processor merged it as it
                            # stood: suppressed findings counted as actionable,
                            # paths never made relative. The row is ERROR; its
                            # record is the failure, as a failed scan's is, so
                            # none of the half-processed report reaches the
                            # results. Written as the failure handlers write
                            # theirs, so the processor files it the same way.
                            container.raw_results = {
                                "errors": [home_as_tilde(reason)],
                                "status": "failed",
                                "exception": home_as_tilde(described),
                            }

                    # Not for a target scan() never ran on (disabled, or refused by
                    # the sandbox, where an unavailable named backend records its
                    # own code): the plugin's exit_code belongs to the last
                    # target it scanned. Not for a MISSING container: its tool
                    # never ran, so it has no exit code, and the unset field keeps
                    # the per-target report and the scanner row from claiming 0.
                    # Nor when the scanner says it started no tool, with an exit
                    # code of None (npm-audit with a yarn.lock and no yarn,
                    # cfn-nag with only a template the model rejects), or attempted
                    # no target and kept the 0 it started with (a scanner that does
                    # not reset it and had nothing to scan). A tool that did start
                    # keeps its code, 0 included.
                    plugin_exit_code = getattr(scanner_plugin, "exit_code", 0)
                    # Read once for the whole target: the helper warns about a
                    # negative count, and two reads warned twice per target.
                    # Read only for a target scan() ran on; the counters belong
                    # to the last target the plugin scanned.
                    attempted_claim = (
                        _target_count_attr(scanner_plugin, "targets_attempted")
                        if scan_called
                        else None
                    )
                    never_started = plugin_exit_code is None or (
                        attempted_claim == 0 and plugin_exit_code == 0
                    )
                    if (
                        scan_called
                        and container.status != ScannerStatus.MISSING
                        and not never_started
                    ):
                        container.exit_code = plugin_exit_code

                    # Carried across like exit_code, for the same reason: the
                    # per-target report is where the exit-code floor reads it.
                    # Assigned only when recorded, so an unset field stays out of
                    # the exclude_unset dump.
                    could_not_stop_reason = _could_not_stop(scanner_plugin)
                    if could_not_stop_reason is not None:
                        container.could_not_stop = could_not_stop_reason

                    # Carried across the same way exit_code is, so the field is closed for
                    # every container rather than only for the falsy-return branch above. A
                    # scanner that overrides scan() can find its tool absent, record that on
                    # itself and still return a report; without this copy that container
                    # reached the statistics calculator claiming satisfied dependencies.
                    #
                    # Narrowing rather than assigning, because neither the plugin's flag nor
                    # the getattr default may widen a MISSING container back to "dependencies
                    # were fine". A scan() override is free to return falsy without touching
                    # its own flag, and the template's empty-target guard returns before the
                    # flag is recomputed at all, so a plain assignment would restore True over
                    # the False recorded above.
                    #
                    # Only a flag something recorded counts (_dependencies_recorded_
                    # unavailable): an absent attribute, or the default no check ever
                    # replaced, is not evidence of a problem.
                    container.dependencies_satisfied = (
                        container.dependencies_satisfied
                        and not _dependencies_recorded_unavailable(scanner_plugin)
                    )
                    # A report returned with the dependencies unsatisfied is a target
                    # the scanner did not evaluate, and the statistics read it as
                    # missing (target_report_is_missing). It gets the reason and the
                    # WARNING a False return gets, so its row says why. The branch
                    # above has already given a False return or a sandbox refusal its
                    # reason. Not a row already ERROR: a result ASH could not grade
                    # (an empty dict, a list) is the row's one cause, and a reason
                    # written here, with the "marking as MISSING" line beside it,
                    # said the row was MISSING and ERROR at once, the contradiction
                    # the False-only MISSING branch above exists to end.
                    if (
                        not container.dependencies_satisfied
                        and container.missing_reason is None
                        and container.status != ScannerStatus.ERROR
                    ):
                        # Redacted with the config's environment values first,
                        # and the plugin's own, as for a falsy return above.
                        environment_values = self._plugin_environment_values(
                            scanner_plugin
                        )
                        reason = text_without_values(
                            _missing_reason_after_scan(
                                scanner_plugin,
                                scanner_config_name,
                                target_type,
                                environment_values,
                            ),
                            environment_values,
                        )
                        ASH_LOGGER.warning(
                            f"Scanner {scanner_config_name} found its dependencies "
                            f"unavailable on the {target_type} files, marking as "
                            f"MISSING: {reason}",
                            extra=NO_MARKUP,
                        )
                        container.missing_reason = home_as_tilde(reason)

                    # Carry per-target outcome counts across, following the exit_code pattern
                    # above. This is what lets determine_status distinguish "scanned and found
                    # nothing" from "failed on everything it tried" and from "evaluated
                    # nothing" -- without it, status can only be derived from findings and both
                    # of the latter two report PASSED.
                    #
                    # This is the line where the tri-state has to be preserved rather than
                    # flattened. A scanner that does not track targets has no
                    # ``targets_attempted`` attribute at all, and _target_count_attr answers
                    # None for it, which determine_status reads as "no claim" and leaves alone.
                    # Reading an absent attribute as 0 here would assert that every
                    # non-tracking scanner attempted zero targets, and every one of them would
                    # report SKIPPED instead of PASSED.
                    #
                    # Only for a target scan() ran on, like the exit code and the
                    # times: the counters and the unscanned inputs are the last
                    # scanned target's, and a refused or disabled target that copied
                    # them inflated every summed coverage count.
                    if scan_called:
                        container.targets_attempted = attempted_claim
                        container.targets_failed = _non_negative_int_attr(
                            scanner_plugin, "targets_failed"
                        )
                        # Assigned only when there is something to record, so every
                        # other scanner's serialized report keeps its exact shape
                        # (the dump excludes unset fields).
                        not_scanned = _inputs_not_scanned(scanner_plugin)
                        if not_scanned:
                            container.inputs_not_scanned = not_scanned

                    # A scan with no database had nothing to match against, so its
                    # zero findings are not a result. ERROR whatever the staleness
                    # policy: content_db_staleness relaxes the age bound of a database
                    # that exists. The SARIF and its records are kept, so the stale
                    # database is reported as well.
                    if databases_absent:
                        container.status = ScannerStatus.ERROR
                        for message in databases_absent:
                            container.add_error(message)

                    # A disabled scanner's row was graded SKIPPED above and is not
                    # re-graded: determine_status knows nothing of the config.
                    if (
                        not disabled
                        and container.status not in _TERMINAL_SCANNER_STATUSES
                    ):
                        # Graded against the threshold the summary and the scanner
                        # row use, not the scanner's own option alone: that is None
                        # unless its config sets one, and None turns the gate off.
                        threshold, _ = resolve_scanner_threshold(
                            scanner_config.options.severity_threshold,
                            getattr(self.plugin_context, "config", None),
                        )
                        # The level this row is graded against, recorded on the
                        # report beside its counts. A reader of the results file
                        # (ash report, ash merge, --existing-results) grades
                        # from it: the configuration record keeps a threshold
                        # the scan read from the environment as the reference
                        # its file wrote, never the level, so re-deriving the
                        # threshold from that record gave the reader the
                        # reference text or the field's default, and re-reading
                        # the reader's own environment could grade a report
                        # differently from the scan, silently.
                        if threshold in _GRADED_LEVELS:
                            container.scanner_severity_threshold = str(threshold)
                        container.status = container.determine_status(threshold)
                        # A clean result from a database the policy rejects is not a
                        # clean result: under content_db_staleness: fail the scan fails
                        # on it, so PASSED here would say the opposite of the exit code.
                        # ERROR, the status for "no verdict that can be graded", with
                        # the database named. Findings from such a database are real,
                        # so a FAILED row stays FAILED, and under warn the operator
                        # accepted the database and the status is left alone.
                        if container.status == ScannerStatus.PASSED:
                            enforced = [
                                record
                                for record in content_db_records
                                if getattr(record, "enforced", False) is True
                            ]
                            if enforced:
                                container.status = ScannerStatus.ERROR
                                container.rejected_content_databases = [
                                    record.name for record in enforced
                                ]
                                for record in enforced:
                                    container.add_error(record.message())
                    # A target the scanner's tool never evaluated is not a clean
                    # result either, whatever the failure type: a scanner that
                    # names unevaluated targets keeps the evaluated targets'
                    # findings, and PASSED here would read as "evaluated and
                    # clean" for a target nothing evaluated. Each such target is
                    # named on the container, so the results row says which file
                    # has no result, whatever the status is. The name is the
                    # plugin's own text, redacted as the timeout line below is,
                    # then the home directory written as a tilde.
                    #
                    # Outside the grading guard above, so a row that is already
                    # ERROR or MISSING for another cause (an absent database, a
                    # result that could not be graded) names its unevaluated
                    # targets too, as the row's reasons claimed it did. Not for a
                    # target scan() never ran on (the names are the last scan's),
                    # and not again after the failure handler named them.
                    unevaluated = (
                        _unevaluated_targets(scanner_plugin)
                        if scan_called and not cause_recorded
                        else []
                    )
                    unevaluated_values = (
                        self._plugin_environment_values(scanner_plugin)
                        if unevaluated
                        else ()
                    )
                    for name in unevaluated:
                        container.add_error(
                            home_as_tilde(
                                text_without_values(
                                    f"no rule was evaluated against {name}",
                                    unevaluated_values,
                                )
                            )
                        )
                        # SKIPPED is refused like PASSED: the completeness
                        # gate counts a SKIPPED row complete, and the
                        # skipped_reason the block below would write
                        # ("found nothing it scans") contradicts the error
                        # naming a file with no result on the same row.
                        if container.status in (
                            ScannerStatus.PASSED,
                            ScannerStatus.SKIPPED,
                        ):
                            container.status = ScannerStatus.ERROR
                    # A tool-level cause recorded for the run is never dropped by
                    # the per-target accounting. A timeout that killed one
                    # target's run among others that rendered used to surface
                    # through a raise; when scan() returns normally instead, the
                    # cause still reaches the results, and a run whose tool was
                    # killed has no result that can be graded. Whatever the row's
                    # status: a row already ERROR for another cause keeps the
                    # timeout among its reasons, and a MISSING row keeps MISSING
                    # (its tool did not run as a tool) with the line beside it.
                    timed_out_after = (
                        _timed_out_after(scanner_plugin)
                        if scan_called and not cause_recorded
                        else None
                    )
                    if timed_out_after is not None:
                        # The limit through timeout_limit_token (why: that
                        # function's docstring); the line redacted like
                        # every sibling site. For a PluginBase scanner that
                        # keeps its kept flag, the acceptance step's raise
                        # runs before this block; it grades a scanner that
                        # cleared its flag, or a plugin recording the
                        # attribute alone.
                        environment_values = self._plugin_environment_values(
                            scanner_plugin
                        )
                        # The same was-killed contract as the failed-scan
                        # lead above: a stop that failed left the tool
                        # running, so this line must not say it is gone,
                        # and the record is attributed as _timeout_ending
                        # reads it.
                        ending = _timeout_ending(scanner_plugin)
                        container.add_error(
                            text_without_values(
                                f"{scanner_config_name} timed out after "
                                f"{timeout_limit_token(timed_out_after, environment_values)} "
                                f"on {target_type}{ending}",
                                environment_values,
                            )
                        )
                        if container.status != ScannerStatus.MISSING:
                            container.status = ScannerStatus.ERROR
                    elif kept_timeout is not None and not cause_recorded:
                        # The run kept its timeout flag and recorded no limit:
                        # the recorder sets the flag before the limit and can
                        # raise between the two (its record step is the plugin's
                        # own code), so a scanner that recorded the timed-out
                        # target itself graded PASSED or FAILED over a run that
                        # did not finish, with the kept reason on no row. The
                        # flag alone says the run did not finish; the row is
                        # ERROR with the reason, as the skip promised.
                        environment_values = self._plugin_environment_values(
                            scanner_plugin
                        )
                        container.add_error(
                            text_without_values(
                                _unfinished_run_reason(
                                    scanner_config_name,
                                    target_type,
                                    kept_timeout,
                                    None,
                                    environment_values,
                                ),
                                environment_values,
                            )
                        )
                        if container.status != ScannerStatus.MISSING:
                            container.status = ScannerStatus.ERROR
                    if container.status == ScannerStatus.SKIPPED and not disabled:
                        # determine_status reaches SKIPPED only for a scanner that
                        # tracks targets and attempted none. The scanner's own
                        # answer, when it has one, so a tree that is SKIPPED both
                        # ways reads the same whether or not its tool was
                        # installed. cfn-nag and cdk-nag say a template could not
                        # be parsed only for a file the tool-absent check counts,
                        # and that tree without the tool is MISSING, not SKIPPED.
                        # Redacted with the config's environment values and
                        # the plugin's own: the plugin's stated reason can
                        # name a configured value, and the row and ash.log
                        # keep it; then the home directory written as a tilde,
                        # as a missing_reason is, so a path in it does not
                        # reach the reports as written.
                        environment_values = self._plugin_environment_values(
                            scanner_plugin
                        )
                        container.skipped_reason = home_as_tilde(
                            text_without_values(
                                _skipped_reason_after_scan(
                                    scanner_plugin,
                                    scanner_config_name,
                                    target_type,
                                    environment_values,
                                ),
                                environment_values,
                            )
                        )
                        ASH_LOGGER.info(
                            f"Scanner {scanner_config_name} is SKIPPED on the "
                            f"{target_type} files: {container.skipped_reason}",
                            extra=NO_MARKUP,
                        )
                    # Only a mapping is metadata. A tool's own JSON can carry
                    # ``"metadata": null`` (or a list); read as a mapping it raised
                    # here, after the row was graded, and the raise discarded the
                    # scanner's other targets' containers with this one.
                    if isinstance(raw_results, dict) and isinstance(
                        raw_results.get("metadata"), dict
                    ):
                        for key, value in raw_results["metadata"].items():
                            container.add_metadata(key, value)

                    results.append(container)

            return results

        except Exception as e:
            ASH_LOGGER.error(
                f"Failed to execute {scanner_plugin.__class__.__name__} scanner: "
                f"{error_text(e, self._plugin_environment_values(scanner_plugin))}",
                extra=NO_MARKUP,
            )
            raise

    def _extract_metrics_from_sarif(
        self, sarif_report: Any
    ) -> Tuple["ScannerSeverityCount", int]:
        """Return (severity counts, total finding count) for a SARIF report.

        get_severity_metrics_from_sarif returns a single ScannerSeverityCount
        model, not a tuple. Returning it directly broke the caller: pydantic models
        are iterable, so "severity_counts, finding_count = ..." tried to unpack the
        model's six fields into two names and raised
        "too many values to unpack (expected 2)". Every scanner therefore failed
        with status ERROR and zero findings.

        The (counts, total) contract here matches ScanPhase._extract_metrics_from_sarif,
        including counting suppressed findings toward the total.
        """
        # Imported lazily, as the original did: sarif_utils pulls in PluginContext,
        # and a module-level import here would create a cycle through core.phases.
        from automated_security_helper.utils.sarif_utils import (
            get_severity_metrics_from_sarif,
        )

        counts = get_severity_metrics_from_sarif(sarif_report, self.plugin_context)
        return counts, counts.total + counts.suppressed

    def _safe_execute_scanner(
        self,
        scanner_name: str,
        scanner_plugin: ScannerPluginBase,
        scan_targets: List[Dict[str, Any]],
    ) -> Tuple[List[ScanResultsContainer], bool]:
        """Wrap _execute_scanner so unexpected exceptions become failure containers.

        Returns a tuple of (results, succeeded) where succeeded is False when
        _execute_scanner raised an unhandled exception.  Callers use the flag to
        decide whether to record the scanner in completed_scanners.

        A cancelled scan starts no further scanner: ScanCancelled is raised here,
        before the try, and is not an Exception, so it ends the scan instead of
        being recorded as this scanner's failure. Two checks make that true.
        raise_if_cancelled reads the scan's cancel event. _cancel_seen covers a
        cancel that reached one scanner directly with that event unset: the
        scanner's own ScanCancelled sets it, and the next start is refused even
        when a worker dequeued it before the queue-shutdown could cancel it.

        SCAN_START is issued here, after those checks and on the thread that
        runs the scanner, so the event means the scanner starts. Sent by the
        loops before this call, it meant "queued": a parallel run of fifteen
        scanners on four workers announced all fifteen at once, and a queued
        scanner the cancel removed got a SCAN_START with no SCAN_COMPLETE or
        ERROR after it. Issued unconditionally, and the signature stays at
        these three arguments: a keyword the loops passed to switch it on
        broke every three-argument double of this method (the loop caught the
        TypeError as the scanner's failure, and no scanner completed).
        """
        raise_if_cancelled()
        if self._cancel_seen.is_set():
            raise ScanCancelled(
                f"the scan was cancelled; scanner {scanner_name} is not started"
            )
        self._notify_scan_start(scanner_name, scanner_plugin, scan_targets)
        try:
            return self._execute_scanner(
                scanner_name, scanner_plugin, scan_targets
            ), True
        except ScanCancelled:
            self._cancel_seen.set()
            raise
        # SystemExit for the reason the per-target handler gives: a plugin that
        # calls sys.exit is one scanner's failure, not the end of the scan. In
        # parallel mode an escaping SystemExit made the pool run every queued
        # scanner to completion and then exit the process with the plugin's code,
        # recording none of their results.
        except (Exception, SystemExit) as e:
            if _exit_is_the_shutdowns(e):
                # The process is going down, not this scanner (see the
                # per-target handler).
                raise
            # Redacted as the per-target handler redacts: see
            # _plugin_environment_values.
            environment_values = self._plugin_environment_values(scanner_plugin)
            described = _failure_text(e, environment_values)
            stack_trace = traceback_text(values=environment_values)
            error_msg = f"Unexpected error in scanner {scanner_name}: {described}"
            ASH_LOGGER.error(error_msg, extra=NO_MARKUP)
            ASH_LOGGER.debug(
                f"Stack trace for scanner {scanner_name} failure:\n{stack_trace}",
                extra=NO_MARKUP,
            )

            failure_container = ScanResultsContainer.for_failure(
                scanner_name,
                errors=[error_msg],
                exception=e,
                values=environment_values,
            )
            failure_container.raw_results = {
                "errors": [home_as_tilde(error_msg)],
                "status": "failed",
                "exception": home_as_tilde(described),
                "stack_trace": home_as_tilde(stack_trace),
            }
            try:
                from automated_security_helper.plugins.events import AshEventType

                self._notify(
                    AshEventType.ERROR,
                    message=error_msg,
                    scanner=scanner_name,
                    exception=e,
                )
            except Exception as notify_error:
                # See the ERROR guard in _execute_scanner: _notify already handles
                # a raising subscriber, so this only covers the local import and
                # kwargs construction.
                ASH_LOGGER.debug(
                    f"ERROR notification for {scanner_name} could not be issued: "
                    f"{notify_error!r}",
                    extra=NO_MARKUP,
                )

            return [failure_container], False

    # ------------------------------------------------------------------
    # Sequential execution
    # ------------------------------------------------------------------

    def run_sequential(
        self, aggregated_results: AshAggregatedResults
    ) -> AshAggregatedResults:
        """Execute scanner_tasks one at a time."""
        self._cancel_seen = threading.Event()
        total = len(self.scanner_tasks)
        completed = 0
        all_scanner_names = [t[0] for t in self.scanner_tasks]
        remaining_scanners = all_scanner_names.copy()

        for scanner_name, scanner_plugin, scan_targets in self.scanner_tasks:
            scanner_task = self.progress_display.add_task(
                phase=ExecutionPhase.SCAN,
                description=f"[cyan]({escape_markup(scanner_name)}) Scanning directories...",
                total=100,
            )

            try:
                self.progress_display.update_task(
                    phase=ExecutionPhase.SCAN, task_id=scanner_task, completed=50
                )
                ASH_LOGGER.info(f"Running scanner: {scanner_name}")

                # SCAN_START is issued inside, once the cancel checks pass.
                results_list, scanner_succeeded = self._safe_execute_scanner(
                    scanner_name, scanner_plugin, scan_targets
                )

                if results_list is None:
                    ASH_LOGGER.error(f"Scanner {scanner_name} returned None results")
                    failure_container = ScanResultsContainer.for_failure(
                        scanner_name,
                        errors=[f"Scanner {scanner_name} failed with no results"],
                    )
                    failure_container.raw_results = {
                        "errors": [f"Scanner {scanner_name} failed with no results"],
                        "status": "failed",
                        "exception": "Scanner returned None results",
                    }
                    processed = self._process_results_fn(
                        failure_container, aggregated_results
                    )
                    aggregated_results = processed
                    self.progress_display.update_task(
                        phase=ExecutionPhase.SCAN,
                        task_id=scanner_task,
                        completed=100,
                        description=f"[red]({escape_markup(scanner_name)}) Failed: returned None results",
                    )
                else:
                    aggregated_results = self._process_each(
                        results_list, aggregated_results
                    )

                    # A scanner with no row at all did not complete a scan: every
                    # target it was given was missing, so nothing was evaluated,
                    # and the completeness check should say so rather than read
                    # an empty list as "no ERROR row".
                    if (
                        scanner_succeeded
                        and results_list
                        and all(
                            getattr(c, "status", None) != ScannerStatus.ERROR
                            for c in results_list
                        )
                    ):
                        ASH_LOGGER.debug(
                            f"Appending {scanner_plugin.__class__.__name__} to completed_scanners"
                        )
                        self.completed_scanners.append(scanner_plugin)

                    outcome = self._completion_outcome(scanner_succeeded, results_list)
                    if outcome == "failed":
                        self.progress_display.update_task(
                            phase=ExecutionPhase.SCAN,
                            task_id=scanner_task,
                            completed=100,
                            description=f"[red]({escape_markup(scanner_name)}) Scan failed",
                        )
                    elif outcome == "errors":
                        self.progress_display.update_task(
                            phase=ExecutionPhase.SCAN,
                            task_id=scanner_task,
                            completed=100,
                            description=f"[yellow]({escape_markup(scanner_name)}) Completed scan with errors",
                        )
                    else:
                        self.progress_display.update_task(
                            phase=ExecutionPhase.SCAN,
                            task_id=scanner_task,
                            completed=100,
                            description=f"[green]({escape_markup(scanner_name)}) Completed scan",
                        )
                    self._announce_scan_complete(
                        scanner_name,
                        remaining_scanners,
                        completed + 1,
                        total,
                        succeeded=scanner_succeeded,
                    )

            except Exception as e:
                # Redacted as the per-target handler redacts: see
                # _plugin_environment_values.
                environment_values = self._plugin_environment_values(scanner_plugin)
                described = error_text(e, environment_values)
                stack_trace = traceback_text(values=environment_values)
                ASH_LOGGER.debug(
                    f"Stack trace for scanner {scanner_name} failure:\n{stack_trace}",
                    extra=NO_MARKUP,
                )
                self.progress_display.update_task(
                    phase=ExecutionPhase.SCAN,
                    task_id=scanner_task,
                    completed=100,
                    description=(
                        f"[red]({escape_markup(scanner_name)}) Failed: {escape_markup(described)}"
                    ),
                )
                ASH_LOGGER.error(
                    f"Scanner failed: {scanner_name} - {described}", extra=NO_MARKUP
                )
                refiled = isinstance(e, ResultsProcessingFailed) and isinstance(
                    e.container, ScanResultsContainer
                )
                if refiled:
                    # A results-processing failure carries the target's own row:
                    # it is filed again with the failure added, so the report
                    # keeps what the scan recorded (its errors, its counts, its
                    # could-not-stop and dependency facts), its status becomes
                    # ERROR, it names why it could not be merged, and it never
                    # replaces a merged target's file. By type, not by a
                    # ``container`` attribute: a plugin's own exception class may
                    # carry one. Only a row is refiled: _execute_scanner builds
                    # one per target, but a substituted runner (a test's fake, a
                    # plugin stand-in) can hand the processor anything, and that
                    # item is filed below as a fresh failure row instead.
                    failure_container = e.container
                    failure_container.add_error(
                        f"Scanner {scanner_name} failed: {described}"
                    )
                    failure_container.set_exception(e, environment_values)
                    failure_container.status = ScannerStatus.ERROR
                else:
                    failure_container = ScanResultsContainer.for_failure(
                        scanner_name,
                        errors=[f"Scanner {scanner_name} failed: {described}"],
                        exception=e,
                        values=environment_values,
                    )
                failure_container.raw_results = {
                    "errors": [
                        home_as_tilde(f"Scanner {scanner_name} failed: {described}")
                    ],
                    "status": "failed",
                    "exception": home_as_tilde(described),
                    "stack_trace": home_as_tilde(stack_trace),
                }
                aggregated_results = self._file_failure_row(
                    scanner_name,
                    failure_container,
                    aggregated_results,
                    refiled=refiled,
                    head=f"Scanner {scanner_name} failed: {described}",
                    exception=e,
                    environment_values=environment_values,
                )
                if isinstance(e, ResultsProcessingFailed):
                    # The merge of the scanner's targets' results failed: the
                    # first failure is filed above, any later one here.
                    aggregated_results = self._file_later_failures(
                        scanner_name,
                        e,
                        environment_values,
                        "Scanner failed",
                        f"Scanner {scanner_name} failed",
                        aggregated_results,
                    )
                # The scanner's turn is over, its failure recorded: it leaves
                # the remaining list and the turn is announced, succeeded False,
                # so a subscriber sees every turn end (_announce_scan_complete).
                self._announce_scan_complete(
                    scanner_name,
                    remaining_scanners,
                    completed + 1,
                    total,
                    succeeded=False,
                )
            finally:
                completed += 1

        return aggregated_results

    # ------------------------------------------------------------------
    # Parallel execution
    # ------------------------------------------------------------------

    def run_parallel(
        self, aggregated_results: AshAggregatedResults
    ) -> AshAggregatedResults:
        """Execute scanner_tasks via a ThreadPoolExecutor."""
        import threading

        self._cancel_seen = threading.Event()
        total = len(self.scanner_tasks)
        ASH_LOGGER.debug(f"Total scanners: {total}")

        if total <= 1:
            ASH_LOGGER.debug("Single scanner detected, executing directly")
            return self.run_sequential(aggregated_results)

        scanner_tasks_map: Dict[str, Any] = {}
        all_scanner_names = [t[0] for t in self.scanner_tasks]
        remaining_scanners = all_scanner_names.copy()
        remaining_scanners_lock = threading.Lock()

        with (
            ThreadPoolExecutor(max_workers=self.max_workers) as executor,
            _cancel_scan_on_interrupt(executor),
        ):
            futures: List[Future[Tuple[List[ScanResultsContainer], bool]]] = []

            for index, (scanner_name, scanner_plugin, scan_targets) in enumerate(
                self.scanner_tasks
            ):
                # Keyed by position as well as name: two tasks that share a
                # display name shared one progress task, and the completed plugin
                # was looked up by name, so the first plugin was recorded twice.
                task_key = f"{index}:{scanner_name}"
                scanner_task = self.progress_display.add_task(
                    phase=ExecutionPhase.SCAN,
                    description=f"[magenta]({escape_markup(scanner_name)}) Scanning directories...",
                    total=100,
                )
                scanner_tasks_map[task_key] = scanner_task
                self.progress_display.update_task(
                    phase=ExecutionPhase.SCAN,
                    task_id=scanner_task,
                    completed=10,
                    description=f"[blue]({escape_markup(scanner_name)}) Queued scan...",
                )
                ASH_LOGGER.debug(f"Submitting {scanner_name} to thread pool")
                # SCAN_START is issued by the worker that runs the scanner, once
                # its cancel checks pass (_safe_execute_scanner), so the event
                # means the scanner starts: sent from here it meant "queued",
                # every scanner at once, and a scanner the cancel took off the
                # queue announced a start it never made. Subscribers are
                # therefore called from worker threads for this event,
                # concurrently and under no lock; SCAN_COMPLETE and ERROR are
                # announced on the recording thread as each future is read.
                # Run in a copy of this thread's context, which carries the
                # scanned-tree scope (utils/subprocess_utils.scanning_tree) and
                # the scan's cancel event (core/cancellation.py) into the
                # scanner's thread. A pool thread does not inherit context, and
                # one copy per task, because a context cannot be entered by two
                # threads at once.
                future = executor.submit(
                    contextvars.copy_context().run,
                    self._safe_execute_scanner,
                    scanner_name,
                    scanner_plugin,
                    scan_targets,
                )
                future.scanner_name = scanner_name  # type: ignore[attr-defined]
                future.scanner_task_key = task_key  # type: ignore[attr-defined]
                # For the handler below, which redacts with its values.
                future.scanner_plugin = scanner_plugin  # type: ignore[attr-defined]
                futures.append(future)

            # A cancel ends the run, but a scanner that had finished by then stays
            # recorded, as in the sequential loop. Once a future's result is the
            # scan's ScanCancelled, the loop stops waiting on completions and
            # works in four steps: cancel the queue, sweep, drain, sweep.
            # - Cancel the queue (shutdown(wait=False, cancel_futures=True)):
            #   queued futures are cancelled at once, so no further scanner
            #   starts. This comes BEFORE the first sweep, because a worker
            #   freed while that sweep's recording runs dequeues the next
            #   queued scanner, and the drain then waits on a scan the cancel
            #   had already ended.
            # - First sweep: every future already done is recorded AT ONCE, in
            #   submission order (the completion order is not observable). A
            #   finished sibling's result can be in hand before the drain --
            #   as_completed may hand the cancel over first -- and recorded only
            #   after the drain it sat behind a scanner that cannot see the
            #   cancel event (busy in pure Python) for as long as it chose to
            #   run, and an interrupt during that wait threw it away.
            # - Drain (shutdown(wait=True)): the futures still running are
            #   waited for once -- their tools see the scan's cancel event, so
            #   that wait is their stop, not their full scan. The pool's own
            #   exit performs the same wait either way (shutdown(wait=True)
            #   in __exit__).
            # - Second sweep: scanners that finished during the drain, where
            #   sweeping only before it threw such results away.
            # One that returned is recorded as usual, and one that failed with
            # an ordinary error is recorded as that scanner's failure. Then the
            # cancel is re-raised.
            cancelled: List[BaseException] = []

            def _futures_to_record() -> Iterable[
                Future[Tuple[List[ScanResultsContainer], bool]]
            ]:
                handed = set()

                def done_and_unhanded() -> Iterable[
                    Future[Tuple[List[ScanResultsContainer], bool]]
                ]:
                    for future in futures:
                        if future in handed or not future.done() or future.cancelled():
                            continue
                        held = future.exception()
                        # Not one holding a BaseException that is not an Exception:
                        # another ScanCancelled adds nothing, and a KeyboardInterrupt
                        # or SystemExit would pass the loop's handlers and replace
                        # the cancel this run re-raises.
                        if held is None or isinstance(held, Exception):
                            handed.add(future)
                            yield future

                for future in as_completed(futures):
                    handed.add(future)
                    yield future
                    if cancelled:
                        break
                if cancelled:
                    # The scan's own cancel event too: a cancel that reached one
                    # scanner directly leaves it unset, and the running siblings'
                    # tools watch that event between wait slices. Unset, the
                    # drain below waited for each of them to run to its end.
                    event = current_cancel_event()
                    if event is not None:
                        event.set()
                    executor.shutdown(wait=False, cancel_futures=True)
                    yield from done_and_unhanded()
                    executor.shutdown(wait=True)
                    yield from done_and_unhanded()

            completed_count = 0
            for future in _futures_to_record():
                scanner_name = future.scanner_name  # type: ignore[attr-defined]
                task_key = future.scanner_task_key  # type: ignore[attr-defined]
                task_id = scanner_tasks_map.get(task_key)

                try:
                    results_list, scanner_succeeded = future.result()

                    if results_list is None:
                        ASH_LOGGER.error(
                            f"Scanner {scanner_name} returned None results"
                        )
                        failure_container = ScanResultsContainer.for_failure(
                            scanner_name,
                            errors=[f"Scanner {scanner_name} failed with no results"],
                        )
                        failure_container.raw_results = {
                            "errors": [
                                f"Scanner {scanner_name} failed with no results"
                            ],
                            "status": "failed",
                            "exception": "Scanner returned None results",
                        }
                        processed = self._process_results_fn(
                            failure_container, aggregated_results
                        )
                        aggregated_results = processed
                        if task_id is not None:
                            self.progress_display.update_task(
                                phase=ExecutionPhase.SCAN,
                                task_id=task_id,
                                completed=100,
                                description=f"[red]({escape_markup(scanner_name)}) Failed: returned None results",
                            )
                    else:
                        ASH_LOGGER.debug(f"Got results from {scanner_name}, processing")
                        # The future's own plugin, not a lookup by name: two tasks
                        # with one display name found the same plugin.
                        plugin_inst = getattr(future, "scanner_plugin", None)
                        if plugin_inst is None:
                            plugin_inst = next(
                                (
                                    t[1]
                                    for t in self.scanner_tasks
                                    if t[0] == scanner_name
                                ),
                                None,
                            )
                        aggregated_results = self._process_each(
                            results_list, aggregated_results
                        )

                        # As in run_sequential: no row at all is not a completed
                        # scan.
                        if (
                            scanner_succeeded
                            and results_list
                            and all(
                                getattr(c, "status", None) != ScannerStatus.ERROR
                                for c in results_list
                            )
                        ):
                            if plugin_inst is not None:
                                ASH_LOGGER.debug(
                                    f"Appending {scanner_name} to completed_scanners"
                                )
                                self.completed_scanners.append(plugin_inst)

                        if task_id is not None:
                            outcome = self._completion_outcome(
                                scanner_succeeded, results_list
                            )
                            if outcome == "failed":
                                self.progress_display.update_task(
                                    phase=ExecutionPhase.SCAN,
                                    task_id=task_id,
                                    completed=100,
                                    description=f"[red]({escape_markup(scanner_name)}) Scan failed",
                                )
                            elif outcome == "errors":
                                self.progress_display.update_task(
                                    phase=ExecutionPhase.SCAN,
                                    task_id=task_id,
                                    completed=100,
                                    description=f"[yellow]({escape_markup(scanner_name)}) Completed scan with errors",
                                )
                            else:
                                self.progress_display.update_task(
                                    phase=ExecutionPhase.SCAN,
                                    task_id=task_id,
                                    completed=100,
                                    description=f"[green]({escape_markup(scanner_name)}) Completed scan",
                                )

                        with remaining_scanners_lock:
                            self._announce_scan_complete(
                                scanner_name,
                                remaining_scanners,
                                completed_count + 1,
                                total,
                                succeeded=scanner_succeeded,
                            )

                    # A completion: the scanner returned, or returned None and
                    # was recorded as a failure. The cancel's own future is not
                    # a completion, so the ScanCancelled arm does not count.
                    completed_count += 1
                except ScanCancelled as stop:
                    # Re-raised after the finished futures are recorded.
                    cancelled.append(stop)
                except Exception as e:
                    # Redacted as the per-target handler redacts: see
                    # _plugin_environment_values.
                    environment_values = self._plugin_environment_values(
                        getattr(future, "scanner_plugin", None)
                    )
                    described = error_text(e, environment_values)
                    stack_trace = traceback_text(values=environment_values)
                    ASH_LOGGER.debug(
                        f"Stack trace for scanner {scanner_name} thread failure:\n{stack_trace}",
                        extra=NO_MARKUP,
                    )
                    if task_id is not None:
                        self.progress_display.update_task(
                            phase=ExecutionPhase.SCAN,
                            task_id=task_id,
                            completed=100,
                            description=(
                                f"[red]({escape_markup(scanner_name)}) Failed: "
                                f"{escape_markup(described)}"
                            ),
                        )
                    ASH_LOGGER.error(
                        f"Scanner execution failed in thread pool: {scanner_name} - {described}",
                        extra=NO_MARKUP,
                    )
                    refiled = isinstance(e, ResultsProcessingFailed) and isinstance(
                        e.container, ScanResultsContainer
                    )
                    if refiled:
                        # See run_sequential: a results-processing failure
                        # carries the target's own row, filed again with the
                        # failure added; matched by type, not by attribute, and
                        # only a row is refiled (anything else gets a fresh one).
                        failure_container = e.container
                        failure_container.add_error(
                            f"Scanner {scanner_name} failed in thread pool: {described}"
                        )
                        failure_container.set_exception(e, environment_values)
                        failure_container.status = ScannerStatus.ERROR
                    else:
                        failure_container = ScanResultsContainer.for_failure(
                            scanner_name,
                            errors=[
                                f"Scanner {scanner_name} failed in thread pool: {described}"
                            ],
                            exception=e,
                            values=environment_values,
                        )
                    failure_container.raw_results = {
                        "errors": [
                            home_as_tilde(
                                f"Scanner {scanner_name} failed in thread pool: "
                                f"{described}"
                            )
                        ],
                        "status": "failed",
                        "exception": home_as_tilde(described),
                        "stack_trace": home_as_tilde(stack_trace),
                    }
                    aggregated_results = self._file_failure_row(
                        scanner_name,
                        failure_container,
                        aggregated_results,
                        refiled=refiled,
                        head=f"Scanner {scanner_name} failed in thread pool: {described}",
                        exception=e,
                        environment_values=environment_values,
                    )
                    if isinstance(e, ResultsProcessingFailed):
                        # See run_sequential: the first merge failure is filed
                        # above, any later one here.
                        aggregated_results = self._file_later_failures(
                            scanner_name,
                            e,
                            environment_values,
                            "Scanner execution failed in thread pool",
                            f"Scanner {scanner_name} failed in thread pool",
                            aggregated_results,
                        )
                    # The scanner's turn is over, its failure recorded: it leaves
                    # the remaining list and the turn is announced, succeeded
                    # False (_announce_scan_complete).
                    with remaining_scanners_lock:
                        self._announce_scan_complete(
                            scanner_name,
                            remaining_scanners,
                            completed_count + 1,
                            total,
                            succeeded=False,
                        )
                    # A recorded failure counts toward the run's progress.
                    completed_count += 1

            if cancelled:
                # The first cancel to land is not the informative one: a
                # cancel whose stop could not end its tool carries the
                # (tool, pid) records the exit line prints, and it can lose
                # to whichever clean cancel finished first -- including one
                # held by a future the recording loop never hands over,
                # since another ScanCancelled adds no new ending. The cancel
                # raised carries the union of every record collected.
                sources: List[BaseException] = list(cancelled)
                for future in futures:
                    if future.done() and not future.cancelled():
                        held = future.exception()
                        if held is not None and not isinstance(held, Exception):
                            sources.append(held)
                survivors: Tuple[Tuple[str, int], ...] = ()
                for source in sources:
                    for record in getattr(source, "could_not_stop", ()):
                        if record not in survivors:
                            survivors = survivors + (record,)
                first = cancelled[0]
                if survivors and tuple(getattr(first, "could_not_stop", ())) != (
                    survivors
                ):
                    raise ScanCancelled(str(first), could_not_stop=survivors) from first
                raise first

        return aggregated_results
