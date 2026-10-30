# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Unified metrics calculation for ASH scan results.

This module provides a centralized implementation for calculating and accessing scanner metrics
across all components of ASH. It serves as the single source of truth for scanner statistics,
ensuring consistency across all reports and displays.

The module defines the ScannerMetrics data structure and provides functions to generate
unified scanner metrics from the final aggregated SARIF data. These metrics include counts
for different severity levels, suppressed findings, actionable findings based on thresholds,
and scanner status information.

All components that need to display or process scanner statistics should use this module
to ensure consistency and avoid duplication of calculation logic.

Example usage:
    ```python
    from automated_security_helper.core.unified_metrics import get_unified_scanner_metrics

    # Get unified metrics for all scanners
    scanner_metrics = get_unified_scanner_metrics(asharp_model)

    # Access metrics for a specific scanner
    for metrics in scanner_metrics:
        if metrics.scanner_name == "bandit":
            print(f"Bandit found {metrics.actionable} actionable findings")
    ```
"""

from __future__ import annotations

import logging
import math
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional
from pydantic import ConfigDict, Field, computed_field

from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerTargetStatusInfo,
    SummaryStats,
    ScannerSeverityCount,
)
from automated_security_helper.core.scanner_statistics_calculator import (
    ScannerStatisticsCalculator,
)
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.models.workspace import is_workspace_scan
from automated_security_helper.utils.log import ASH_LOGGER


class ScannerMetrics(ScannerSeverityCount):
    """Unified scanner metrics data structure.

    This is the single source of truth for scanner metrics that should be used
    by all table generators and reporters. It contains comprehensive statistics
    for a single scanner, including counts for different severity levels, suppressed
    findings, actionable findings, and status information.

    All components that need to display or process scanner statistics should use
    this data structure to ensure consistency across all reports and displays.

    Inherits severity fields (suppressed, critical, high, medium, low, info) and
    the ``total`` / ``actionable_count()`` helpers from ``ScannerSeverityCount``.
    """

    # Text fields are kept as given, not stripped as the severity-count model
    # strips its own: the threshold shown has to be the threshold graded (a
    # padded "HIGH " grades as an unrecognized level, critical only, and shown
    # stripped it read as HIGH), and the scanner name is the key the rebuilt
    # scanner_results row is written under, which has to match the scanner's
    # reports and its existing row.
    model_config = ConfigDict(str_strip_whitespace=False)

    scanner_name: str  # Name of the scanner (e.g., "bandit", "semgrep")
    actionable: int = 0  # Number of findings at or above the threshold severity
    duration: Optional[float] = (
        None  # Time taken by the scanner in seconds, None for skipped/missing scanners
    )
    status: str = (
        "PASSED"  # Scanner status: "PASSED", "FAILED", "SKIPPED", or "MISSING"
    )
    threshold: str = ""  # Severity threshold used for this scanner
    threshold_source: str = ""  # Source of the threshold ("global", "config", etc.)
    # True when ``threshold`` is the written reference of a value the resolver read
    # from the environment. Provenance, so a surface that abbreviates a reference
    # does not infer it from the text's shape.
    threshold_from_env: bool = False
    excluded: bool = False  # Whether the scanner was explicitly excluded
    dependencies_missing: bool = False  # Whether the scanner has missing dependencies

    # How much of its input the scanner actually evaluated, summed over every target it reported
    # under. Present here because this class is the only model the summary table and every
    # reporter read: the counters existed on ``ScanResultsContainer`` and in the serialized
    # per-target reports, and had no route to any human-facing output at all.
    #
    # That mattered because ``determine_status`` only returns ERROR once
    # ``targets_failed >= targets_attempted``. A scanner that failed on some of its targets keeps
    # whatever status the severity gate gives it, so partial coverage loss renders exactly like a
    # scan that read everything. Measured against cdk-nag on this repository: 10 targets
    # attempted, 4 failed, rolled up to FAILED on its findings -- and two of those four were
    # CloudFormation templates that genuinely went unscanned rather than files that were never
    # templates. FAILED is as silent about the four as PASSED would have been, which is the
    # reason these are fields rather than a status.
    #
    # ``targets_attempted`` keeps the container's tri-state meaning rather than defaulting to 0.
    # None means the scanner does not track per-target outcomes and is making no claim; bandit,
    # checkov, semgrep, grype, syft, detect-secrets and opengrep are all in that state (cdk-nag,
    # cfn-nag and npm-audit track targets). Reading them as "attempted zero" would report every
    # one of them as having evaluated nothing.
    # Strict: a string, float or bool here is a producer bug that lax coercion
    # would turn into an invented count ("3" -> 3, True -> 1), and the readers
    # downstream decide completeness off these numbers. target_counts above is
    # the one builder and only ever passes genuine ints or None.
    targets_attempted: int | None = Field(default=None, strict=True)
    # None only on a row whose counters are unusable (``counters_unusable``): a literal -1
    # must never serialize as if it were a count.
    targets_failed: int | None = Field(default=0, strict=True)

    # True when the stored per-target counters could not be trusted (a string, float, bool or
    # negative counter, or a failure count with no attempt count). Both counts above are then
    # None and the row's status is ERROR, because the scanner made a coverage claim that cannot
    # be read and completing the scan on the writer's behalf would be a false clean.
    counters_unusable: bool = False

    # What happened to a scanner that did not run, or did not run on one of its
    # trees, and what the one that did exited with. Carried here so the scanner_results row rebuilt from these metrics, and
    # every reporter reading them, says the same as the scan phase recorded. See
    # ``recorded_reason`` and ``tool_exit_code``.
    missing_reason: Optional[str] = None
    skipped_reason: Optional[str] = None
    exit_code: Optional[int] = None

    @computed_field
    @property
    def passed(self) -> bool:
        """True when the scanner did not produce actionable failures.

        MISSING counts as passed, which reads wrong and is deliberate. Three
        reasons it was left alone when the exit code was taught to distinguish an
        incomplete scan from a clean one:

        1. It is not the mechanism. ``run_ash_scan._compute_exit_code`` never
           reads this field; it derives the verdict from finding counts and, when
           ``fail_on_incomplete_scanners`` is set, from the statuses directly.
           Flipping this would change report text while leaving the exit code
           exactly as it was.
        2. The unambiguous answer is already adjacent. Every consumer reaches this
           through ``ReportContentEmitter.get_scanner_results()``, whose dict
           carries ``status`` and ``dependencies_missing`` in the same row. Nothing
           has to infer completeness from a boolean named ``passed``.
        3. Changing it would move report output on the default path. As a
           ``computed_field`` it is serialized, and ``flatjson_reporter`` puts
           ``get_scanner_results()`` into ``ash.flat.json`` verbatim, so every
           environment with a missing scanner tool -- four of ten on a stock
           workstation -- would see these rows flip true to false. The behaviour is
           also asserted on purpose in three places, including
           ``tests/unit/models/test_severity_counts_typed.py`` and
           ``tests/integration/test_scanner_statistics_flow.py``.

        So read this as "produced no actionable findings", not as "ran and was
        clean". For "did the scanners I selected actually run", use
        ``run_ash_scan.incomplete_scanners``, the ``status`` field, or
        ``summary_stats``, whose five outcome counters now partition the scanner
        set. Making the field mean the stricter thing is a report-schema change,
        not a bug fix.

        Re-examined when ``fail_on_incomplete_scanners`` was added, and again when
        its default became True, and left as it is both times. The default being on
        weakens reason 3 -- a run with a MISSING scanner now exits non-zero, so the
        ``passed: true`` row in ``ash.flat.json`` is no longer the only thing
        standing between a reader and a false clean -- without making the field
        wrong. The argument against changing it never depended on the exit code: a
        boolean named ``passed`` is the wrong place to encode completeness when
        ``status`` sits in the same row and says it outright, and reasons 1 and 2
        are untouched.
        """
        return self.status in ("PASSED", "SKIPPED", "MISSING")


#: What ``target_counts`` answers for a scanner whose stored counters cannot be trusted. Never a
#: real count and never serialized: ``get_unified_scanner_metrics`` replaces it with None counts
#: and the ``counters_unusable`` flag.
UNUSABLE_COUNTERS = (-1, -1)


def counters_unusable(attempted: int | None, failed: int) -> bool:
    """True when ``(attempted, failed)`` is the poisoned pair or any negative count."""
    return (attempted is not None and attempted < 0) or failed < 0


def own_target_reports(
    asharp_model: AshAggregatedResults, scanner_name: str
) -> Dict[Any, Dict[str, Any]]:
    """The per-target reports filed under *scanner_name* that are this scanner's.

    ``additional_reports`` is keyed by scanner name, and a results file merged from
    another, or written by hand, can file a report under the wrong key. A mapping
    that names another scanner is not read as this scanner's; one that names no
    scanner is kept and read for the key it is filed under. The counters, the exit
    code, the reasons and the unscanned inputs of a name-less report are what the
    console summary prints (tests/unit/core/test_metrics_table_names_unscanned_inputs.py)
    and what a partial audit's "N of M targets unevaluated" is read from
    (tests/unit/interactions/test_partial_audit_counts_as_ran.py); a results file
    written before the field existed carries no name at all. The calculator's
    status reader is the one reader that refuses a name-less report, because a
    STATUS filed under the wrong key would flip a row (``_own_reports``); dropping
    the name-less case here as well left Security Hub's archive scope blind to a
    failed target and the two readers above with nothing to print. Every reader of
    the per-target reports in this module goes through here, so they agree on
    which reports are the scanner's. The key and the recorded name are matched in
    any case, as the calculator's ``_own_reports`` matches them: the name a row is
    read under is the union's first spelling, and the reports can sit under
    another.
    """
    reports = ScannerStatisticsCalculator.reports_for(asharp_model, scanner_name)
    if not isinstance(reports, dict):
        return {}
    return {
        key: report
        for key, report in reports.items()
        if isinstance(report, dict)
        and (
            report.get("scanner_name") is None
            or ScannerStatisticsCalculator._same_scanner(
                report.get("scanner_name"), scanner_name
            )
        )
    }


def target_counts(
    asharp_model: AshAggregatedResults, scanner_name: str
) -> tuple[int | None, int]:
    """``(targets_attempted, targets_failed)`` summed over every target the scanner reported.

    Summed rather than read off ``"source"``, because ``ScanPhase`` gives each scanner one task
    carrying both the source tree and the converted tree and either of them can lose coverage.
    Reading one report would under-report by whatever the other did, which is the same
    single-target mistake that made a converted-target failure invisible in the first place.

    Returns None for the attempt count when NO target report carries one. That is the
    scanner-does-not-track state, and it must not collapse to 0: ``0`` is a claim -- "I tracked
    targets and attempted none" -- while absence is the absence of a claim. ``targets_failed``
    stays a plain int because it has no independent meaning; a failure count with no attempt count
    is a producer bug rather than a third state.

    ``bool`` is rejected explicitly even though it is an ``int`` subclass. A True/False counter is
    a producer bug, and reading it as 1/0 would silently invent a target.

    A counter that is PRESENT but unusable never reads as the absence of a claim. A report
    carrying a string, float, bool or negative counter, a nonzero failure count with no attempt
    count, or an attempt count above zero with no failure accounting, has made a claim about
    coverage that cannot be trusted -- and dropping it would complete the scan on the writer's
    behalf. Those reports answer the poisoned pair ``UNUSABLE_COUNTERS`` (``(-1, -1)``), which
    no writer produces (the executor boundary coerces negatives away). It is an internal
    sentinel: ``get_unified_scanner_metrics`` turns it into a row with None counts, the
    ``counters_unusable`` flag and status ERROR (the status derivation measured PASSED for it),
    and ``coverage_shortfalls`` lists the scanner with unknown counts. Only two shapes
    stay the no-claim state: both counters absent (or None), and a zero failure count beside no
    attempt count, which is what a non-tracking scanner's stored report looks like when a writer
    emits the zero default. A zero attempt count with no failure count stays a usable claim:
    zero attempts leaves nothing unaccounted for.

    Only this scanner's own reports are read (``own_target_reports``).
    """
    reports = own_target_reports(asharp_model, scanner_name)
    if not reports:
        return None, 0

    attempted: int | None = None
    failed = 0
    for target_report in reports.values():
        raw_attempted = target_report.get("targets_attempted")
        raw_failed = target_report.get("targets_failed")
        attempted_absent = raw_attempted is None
        failed_absent = raw_failed is None
        if attempted_absent and failed_absent:
            continue
        # Narrowed once into typed locals: a genuine count or None. After the
        # shape gate below, None here means exactly "absent" -- a present
        # non-count has already poisoned the pair.
        attempted_count: int | None = (
            raw_attempted
            if isinstance(raw_attempted, int) and not isinstance(raw_attempted, bool)
            else None
        )
        failed_count: int | None = (
            raw_failed
            if isinstance(raw_failed, int) and not isinstance(raw_failed, bool)
            else None
        )
        if (attempted_count is None and not attempted_absent) or (
            failed_count is None and not failed_absent
        ):
            return -1, -1
        if (attempted_count is not None and attempted_count < 0) or (
            failed_count is not None and failed_count < 0
        ):
            return -1, -1
        if attempted_count is None:
            if raw_failed == 0:
                # The zero default beside no attempt claim: still no claim.
                continue
            return -1, -1
        if failed_count is None and attempted_count > 0:
            return -1, -1
        # More failures than attempts is a claim nobody can read either: 0
        # attempted with 2 failed, or 3 attempted with 5 failed. Read as usable,
        # it printed a negative evaluated count in the coverage line.
        if failed_count is not None and failed_count > attempted_count:
            return -1, -1
        attempted = (attempted or 0) + attempted_count
        if failed_count is not None:
            failed += failed_count
    return attempted, failed


#: The ``missing_reason`` of a MISSING row whose scanner recorded none. The exit-1
#: message tells it apart from a recorded reason and gives the generic advice instead.
NO_MISSING_REASON_RECORDED = (
    "its dependencies were not available; no reason was recorded, and ash.log has "
    "the scanner's own message"
)


def _report_order(key: object) -> tuple[int, str]:
    """Per-target reports in the order a reason is looked up in.

    The report a scanner gets when the scan phase decided its status before it ran
    first -- keyed None in memory and "None" once the results were written and read
    back -- then the source tree's, then any other.
    """
    if key is None or key == "None":
        return (0, "")
    if key == "source":
        return (1, "")
    return (2, str(key))


def recorded_reason(
    asharp_model: AshAggregatedResults, scanner_name: str, field: str
) -> str | None:
    """The ``missing_reason`` or ``skipped_reason`` recorded for *scanner_name*.

    From the scanner's ``scanner_results`` row when it carries one, which is where
    the scan phase writes a reason it decided before the scanner ran, and where an
    earlier rebuild left it (``ash report`` and ``ash merge`` rebuild a model read
    back from disk). Otherwise from its per-target reports, which is where the
    executor writes one for a scanner that was dispatched -- a scanner it could not
    sandbox, or one that evaluated nothing.

    Per-target reports are read in ``_report_order``, with one exception: a
    ``skipped_reason`` saying a CloudFormation template could not be parsed wins over
    the others, because "no template" from the source tree would hide a damaged
    template in the converted tree that the target's own report names.

    A ``missing_reason`` read off the per-target reports names the trees it applies
    to when another tree was evaluated: ``on the converted files: <reason>``. The
    plugin's reason says what was unavailable, not where, and the scanner did scan
    the other tree. A reason already on the row is returned as it is, so a rebuild
    does not name the tree twice.
    """
    from automated_security_helper.utils.cfn_template_model import (
        NO_PARSEABLE_CLOUDFORMATION_TEMPLATE,
    )

    row = (asharp_model.scanner_results or {}).get(scanner_name)
    value = getattr(row, field, None)
    if isinstance(value, str) and value:
        return value
    reports = own_target_reports(asharp_model, scanner_name)
    if not reports:
        return None
    recorded = [reports[key].get(field) for key in sorted(reports, key=_report_order)]
    recorded = [value for value in recorded if isinstance(value, str) and value]
    if field == "skipped_reason" and NO_PARSEABLE_CLOUDFORMATION_TEMPLATE in recorded:
        return NO_PARSEABLE_CLOUDFORMATION_TEMPLATE
    if not recorded:
        return None
    if field == "missing_reason":
        missing_trees = _trees_missing_while_another_ran(reports)
        if missing_trees:
            return f"on the {' and '.join(missing_trees)} files: {recorded[0]}"
    return recorded[0]


def _trees_missing_while_another_ran(reports: dict[Any, Any]) -> list[str]:
    """The trees whose report is missing, when some other tree's report is not.

    Missing as ``ScannerStatisticsCalculator.target_report_is_missing`` reads it.
    Empty when every tree is missing or none is. Only the per-target reports count:
    the one keyed None is the scan phase's decision for the whole run.
    """
    trees = [
        key
        for key in sorted(reports, key=_report_order)
        if key is not None and key != "None" and isinstance(reports[key], dict)
    ]
    missing = [
        key
        for key in trees
        if ScannerStatisticsCalculator.target_report_is_missing(reports[key])
    ]
    return missing if 0 < len(missing) < len(trees) else []


def recorded_error(
    asharp_model: AshAggregatedResults,
    scanner_name: str,
    values: Iterable[str] = (),
) -> str | None:
    """The first error *scanner_name*'s per-target reports recorded, or None.

    An ERROR row has no reason field. The cause is on a report, in one of two
    places: the scan phase passes its errors to the container, so a scanner that
    could not be constructed has the constructor's error in the report's
    ``errors``; the executor records a scan() that raised, timed out, never
    started its tool or returned no result in ``raw_results``, whose ``errors``
    lead with its own message about that, and leaves the report's own unset. The
    report's own come first, then ``raw_results``. Only messages are read: the
    ``exception`` and ``stack_trace`` beside them stay in the results file.
    Reports are read in ``_report_order``, the same order ``recorded_reason``
    reads in.

    The message is returned redacted with *values*, the config's environment
    values (``utils.error_text.config_environment_values``): it is shown where
    env values are never written, and a recorded error can name an option the
    config read from the environment.
    """
    from automated_security_helper.utils.error_text import text_without_values

    reports = own_target_reports(asharp_model, scanner_name)
    for key in sorted(reports, key=_report_order):
        report = reports[key]
        raw_results = report.get("raw_results")
        for errors in (
            report.get("errors"),
            raw_results.get("errors") if isinstance(raw_results, dict) else None,
        ):
            if not isinstance(errors, list):
                continue
            for error in errors:
                if isinstance(error, str) and error:
                    return text_without_values(error, values)
    return None


def dependencies_recorded_satisfied(
    asharp_model: AshAggregatedResults, scanner_name: str
) -> bool:
    """True when a MISSING scanner's reports say its dependencies were not the cause.

    MISSING usually means a dependency was unavailable, and its report says
    ``dependencies_satisfied: false``. ScanPhase also records MISSING for a scanner
    whose filtering raised before any dependency was checked, and assigns
    ``dependencies_satisfied: true`` on that report, because the tool may well be
    present. True when some MISSING report carries that True and none carries False,
    so the rebuilt row and ash.flat.json do not tell the operator to install a tool
    nothing found missing.
    """
    reports = own_target_reports(asharp_model, scanner_name)
    recorded = [
        report.get("dependencies_satisfied")
        for report in reports.values()
        if getattr(report.get("status"), "value", report.get("status")) == "MISSING"
        and isinstance(report.get("dependencies_satisfied"), bool)
    ]
    return bool(recorded) and all(recorded)


def tool_exit_code(asharp_model: AshAggregatedResults, scanner_name: str) -> int | None:
    """The exit code of the scanner's tool for its consolidated row, or None.

    Read from the per-target reports, which the executor writes the plugin's exit
    code into for every target it ran. The row stands for every target, so it takes
    the code that explains it: the largest code among targets whose status is ERROR,
    else the largest code of any target. An ERROR target's code comes first because
    the largest code overall can be an accepted one (grype's 2 for a match at
    ``--fail-on``) that would hide another target's error exit (grype's 1).

    A target that did not run carries none, so a scanner that never ran its tool --
    MISSING, or left out of the run -- has None rather than a 0 that reads as a
    clean exit. A missing report (``ScannerStatisticsCalculator.target_report_is_missing``)
    is skipped whatever exit code it claims, because the tool did not run on that
    target; a scanner missing on one tree keeps the code its tool returned on the
    other. ``bool`` is rejected for the reason ``target_counts`` gives.
    """
    reports = own_target_reports(asharp_model, scanner_name)
    codes: list[int] = []
    error_codes: list[int] = []
    for report in reports.values():
        if ScannerStatisticsCalculator.target_report_is_missing(report):
            continue
        code = report.get("exit_code")
        if not isinstance(code, int) or isinstance(code, bool):
            continue
        codes.append(code)
        # Equal for the enum and for the plain string a report read back from JSON has.
        if report.get("status") == ScannerStatus.ERROR:
            error_codes.append(code)
    if error_codes:
        return max(error_codes)
    return max(codes) if codes else None


def coverage_shortfalls(
    asharp_model: AshAggregatedResults,
) -> list[tuple[str, int | None, int | None]]:
    """``(scanner, attempted, failed)`` for every scanner that could not evaluate some input.

    The structured form on purpose. The renderer formats these, and a test that asserted the
    rendered sentence would keep passing through a change that got the numbers wrong -- so the
    numbers are pinned here, where they are data, and the renderer is only checked for whether it
    emits at all.

    Includes the total-loss case as well as the partial one. Total loss already reaches the status
    column as ERROR, but the count of what went unevaluated is exactly as absent from the table
    there as it is when only some targets failed.

    A scanner making no claim is never a shortfall: absent counters mean the scanner does not
    track targets, not that it lost all of them.

    A scanner whose stored counters are unusable (``counters_unusable``) is a shortfall of
    unknown size: its entry carries None for both counts. Dropping it would hide a scanner that
    made a coverage claim nobody can read. Both consumers take it: the renderer prints "coverage
    unknown" for it and the report summary reads only the names.
    """
    shortfalls: list[tuple[str, int | None, int | None]] = []
    for scanner_name in sorted(asharp_model.additional_reports or {}):
        attempted, failed = target_counts(asharp_model, scanner_name)
        if counters_unusable(attempted, failed):
            shortfalls.append((scanner_name, None, None))
            continue
        if attempted is None or failed <= 0:
            continue
        shortfalls.append((scanner_name, attempted, failed))
    return shortfalls


#: The name :func:`inputs_not_scanned` gives the inputs ASH itself left out of its scan
#: set, in place of a scanner's: every scanner that reads the scan set did not scan
#: them.
SCAN_SET_OWNER = "ASH"


def inputs_not_scanned(
    asharp_model: AshAggregatedResults,
) -> list[tuple[str, str, str]]:
    """``(scanner, path, reason)`` for every input a scanner found and did not scan.

    Read off the serialized per-target reports (``ScanResultsContainer.
    inputs_not_scanned``), in scanner order. A scanner that did not scan an input says
    nothing about it in its findings, and its status cannot say which input it was, so
    the summaries list them beside the table, as they do coverage shortfalls.

    The files ASH left out of its scan set come first, under :data:`SCAN_SET_OWNER`
    (``ReportMetadata.inputs_not_scanned``): no reader of the scan set scanned them.

    For a workspace scan, whose unified results carry no per-target reports, they are
    read off each project's entry (``WorkspaceProjectResult.inputs_not_scanned``,
    workspace-relative paths), in workspace order, after any per-target ones.
    """
    entries = []
    metadata = getattr(asharp_model, "metadata", None)
    for item in getattr(metadata, "inputs_not_scanned", None) or []:
        entries.append((SCAN_SET_OWNER, item.path, item.reason))
    for scanner_name in sorted(asharp_model.additional_reports or {}):
        for target_report in own_target_reports(asharp_model, scanner_name).values():
            # Only a list is read: a results file put together by hand can hold
            # a scalar here, and iterating it raised out of the console summary.
            recorded = target_report.get("inputs_not_scanned")
            if not isinstance(recorded, list):
                continue
            for item in recorded:
                if not isinstance(item, dict):
                    continue
                path, reason = item.get("path"), item.get("reason")
                if isinstance(path, str) and isinstance(reason, str):
                    entries.append((scanner_name, path, reason))
    workspace = asharp_model.workspace
    # is_workspace_scan implies a workspace block; the None check says so to the
    # type checker.
    if workspace is not None and is_workspace_scan(asharp_model):
        for project in workspace.projects:
            for item in project.inputs_not_scanned:
                entries.append((item.scanner, item.path, item.reason))
    return entries


def format_duration(duration_seconds: Optional[float]) -> str:
    """Format duration in seconds to a human-readable string.

    This utility function converts a duration in seconds to a human-readable
    string format. It handles different time scales appropriately:

    - Less than 1 millisecond: "<1ms"
    - Less than 1 second: "Xms" (e.g., "500ms")
    - Less than 1 minute: "Xs" (e.g., "45s")
    - 1-59 minutes: "Xm Ys" (e.g., "1m 30s")
    - 1 hour or more: "Xh Ym Zs" (e.g., "1h 1m 5s")
    - None value: "N/A"

    Args:
        duration_seconds: Duration in seconds, or None if duration is not available

    Returns:
        Formatted duration string (e.g., "45s", "1m 30s", "1h 1m 5s", "N/A")

    Example:
        ```python
        print(format_duration(0.0005))  # "<1ms"
        print(format_duration(0.5))     # "500ms"
        print(format_duration(45))      # "45s"
        print(format_duration(90))      # "1m 30s"
        print(format_duration(3665))    # "1h 1m 5s"
        print(format_duration(None))    # "N/A"
        ```
    """
    if duration_seconds is None:
        return "N/A"
    # A duration read back from a results file can be NaN or infinite; neither
    # is a duration, and int() of either raised out of every table that
    # renders one.
    if not math.isfinite(duration_seconds):
        return "N/A"

    if duration_seconds < 0.001:  # Less than 1 millisecond
        return "<1ms"
    elif duration_seconds < 1:  # Less than 1 second
        return f"{int(duration_seconds * 1000)}ms"
    elif duration_seconds < 60:  # Less than 1 minute
        # Keep decimal for seconds if present
        if duration_seconds == int(duration_seconds):
            return f"{int(duration_seconds)}s"
        # A value just under a minute rounds up to a whole minute at one decimal:
        # 59.96 printed "60.0s" where the next branch prints a minute.
        shown = f"{duration_seconds:.1f}"
        if shown == "60.0":
            return "1m 0s"
        return f"{shown}s"
    else:
        # Convert to total minutes for test compatibility with large values
        total_minutes = int(duration_seconds) // 60
        seconds = int(duration_seconds) % 60

        hours, minutes = divmod(total_minutes, 60)

        if hours > 0:
            return f"{hours}h {minutes}m {seconds}s"
        else:
            return f"{total_minutes}m {seconds}s"


def get_unified_scanner_metrics(
    asharp_model: AshAggregatedResults,
) -> List[ScannerMetrics]:
    """Generate unified scanner metrics from AshAggregatedResults.

    This is the single source of truth for scanner metrics that should be used
    by all table generators and reporters. It processes the final SARIF data
    to ensure it captures both native scanner suppressions and ASH-applied suppressions.

    The function extracts statistics for all scanners using the ScannerStatisticsCalculator
    and converts them to ScannerMetrics objects. It handles edge cases such as excluded
    scanners and scanners with missing dependencies, ensuring consistent status reporting.

    The metrics include counts for different severity levels, suppressed findings,
    actionable findings based on thresholds, and scanner status information.

    Args:
        asharp_model: The AshAggregatedResults model containing scan data

    Returns:
        List of ScannerMetrics with unified data for all scanners, sorted by scanner name

    Example:
        ```python
        scanner_metrics = get_unified_scanner_metrics(asharp_model)
        for metrics in scanner_metrics:
            print(f"{metrics.scanner_name}: {metrics.status}")
        ```
    """
    metrics_list = []

    # Use the centralized scanner statistics calculator to get statistics for all scanners
    scanner_stats = ScannerStatisticsCalculator.extract_scanner_statistics(asharp_model)

    # Convert the statistics to ScannerMetrics objects
    for scanner_name, stats in scanner_stats.items():
        # Determine status. The order of these branches is observable, not cosmetic:
        #
        #   error                -- no usable results came back at all, which is the loudest
        #                           thing that can be said about a scanner.
        #   actionable > 0       -- it produced findings. Checked ahead of the three
        #                           "did not run" branches below, and this is the ordering that
        #                           matters. Those three all resolve to a status for which
        #                           ``passed`` is True, so a row reaching one of them while
        #                           carrying findings renders green-or-yellow with no red row in
        #                           the summary table -- while ``run_ash_scan`` sums the same
        #                           ``actionable`` counts and fails the build. A report that
        #                           contradicts the exit code is worse than either verdict.
        #   excluded             -- the operator switched this scanner off.
        #   dependencies_missing -- it could not run in this environment.
        #   evaluated_nothing    -- it ran and had no input to evaluate. Separate from
        #                           ``excluded`` on purpose: conflating the two is what made
        #                           this reorder necessary in the first place.
        #   otherwise            -- nothing above applies and there are no actionable findings.
        scanner_targets_attempted, scanner_targets_failed = target_counts(
            asharp_model, scanner_name
        )
        unusable_counters = counters_unusable(
            scanner_targets_attempted, scanner_targets_failed
        )
        # Unusable counters grade ERROR here because the stats above do not read them:
        # measured, a stored report with a string, negative or orphaned counter beside a
        # recorded PASSED came out PASSED. They are never graded on findings either, as in
        # ``ScanResultsContainer.determine_status``.
        if stats["error"] or unusable_counters:
            status = "ERROR"
        elif stats["actionable"] > 0:
            status = "FAILED"
        elif stats["excluded"]:
            status = "SKIPPED"
        elif stats["dependencies_missing"]:
            status = "MISSING"
        elif stats["evaluated_nothing"]:
            status = "SKIPPED"
        else:
            scan_result: ScannerTargetStatusInfo | None = (
                asharp_model.scanner_results.get(scanner_name, None)
            )
            recorded_status = (
                scan_result.status if scan_result and scan_result.status else "PASSED"
            )
            # The recorded row is not authoritative about the finding count: a
            # FAILED it carries from an earlier rebuild stayed on a scanner whose
            # findings a later run dropped or suppressed, so the table and
            # summary_stats said FAILED with 0 actionable while the exit code,
            # from the finding counts, passed. With nothing actionable the gate
            # passes, so FAILED here reads PASSED; what else the row says (a
            # SKIPPED a shard recorded) is kept. Only when the counts were
            # recorded, though: a dict-result report written before the
            # executor assigned a findings list's counts carries its findings
            # in raw_results and no severity_counts, so 0 actionable there says
            # nothing, and the row's FAILED is the only evidence the gate failed.
            # And only when the reports record the level they were graded
            # against: a results file written before that was recorded is
            # re-graded here at whatever level the configuration record
            # resolves to now, so a scan that failed at LOW read as 0
            # actionable at MEDIUM and its row flipped PASSED, and
            # _populate_scanner_results_from_unified_metrics then wrote PASSED
            # over the one record of the scan's own graded status.
            status = (
                "PASSED"
                if getattr(recorded_status, "value", recorded_status)
                == ScannerStatus.FAILED.value
                and not ScannerStatisticsCalculator.dict_counts_unrecorded(
                    asharp_model, scanner_name
                )
                and ScannerStatisticsCalculator.graded_level_recorded(
                    asharp_model, scanner_name
                )
                else recorded_status
            )

        # Read straight off the serialized per-target reports rather than through
        # ``extract_scanner_statistics``. These two are the only values here that describe how
        # much input was consumed rather than what was found in it, and they are the reason the
        # summary table could not previously say a scan was partial -- see ScannerMetrics.
        # A SKIPPED or MISSING row always says why: the recorded reason, or, for a
        # results file written before reasons were recorded, what the flags say.
        # So does a FAILED row that found its dependencies unavailable on one of its
        # trees: its findings outrank MISSING in the status, and the tree it could
        # not scan is not dropped with that (contract clause 3i).
        missing_reason = None
        skipped_reason = None
        if status == "MISSING" or (
            status == "FAILED" and stats["dependencies_missing"]
        ):
            missing_reason = (
                recorded_reason(asharp_model, scanner_name, "missing_reason")
                or NO_MISSING_REASON_RECORDED
            )
        elif status == "SKIPPED":
            skipped_reason = recorded_reason(
                asharp_model, scanner_name, "skipped_reason"
            )
            if skipped_reason is None:
                if stats["excluded"]:
                    skipped_reason = "left out of this run"
                elif stats["evaluated_nothing"]:
                    skipped_reason = "it found nothing it scans"
                else:
                    skipped_reason = "skipped; no reason was recorded"

        # No exit code for a scanner the run left out, nor from a target its tool
        # did not run on, whatever that target's report claims (tool_exit_code).
        exit_code = (
            None if stats["excluded"] else tool_exit_code(asharp_model, scanner_name)
        )

        # Create metrics entry. total and passed are computed, so we do not pass
        # them in explicitly — they're derived from severity fields and status.
        metrics = ScannerMetrics(
            scanner_name=scanner_name,
            suppressed=stats["suppressed"],
            critical=stats["critical"],
            high=stats["high"],
            medium=stats["medium"],
            low=stats["low"],
            info=stats["info"],
            actionable=stats["actionable"],
            duration=stats["duration"],
            status=status,
            threshold=stats["threshold"],
            threshold_source=stats["threshold_source"],
            # A stats row without the key claims no env read.
            threshold_from_env=stats.get("threshold_from_env", False),
            excluded=stats["excluded"],
            dependencies_missing=(
                stats["dependencies_missing"]
                and not dependencies_recorded_satisfied(asharp_model, scanner_name)
            ),
            targets_attempted=None if unusable_counters else scanner_targets_attempted,
            targets_failed=None if unusable_counters else scanner_targets_failed,
            counters_unusable=unusable_counters,
            missing_reason=missing_reason,
            skipped_reason=skipped_reason,
            exit_code=exit_code,
        )

        metrics_list.append(metrics)

    # Sort by scanner name for consistent ordering
    metrics_list.sort(key=lambda m: m.scanner_name)

    return metrics_list


def populate_metrics_from_unified_source(
    aggregated_results: AshAggregatedResults,
) -> AshAggregatedResults:
    """Populate summary_stats and scanner_results from unified metrics.

    This function ensures that all metrics are driven from the same source of truth:
    the final SARIF data via get_unified_scanner_metrics(). It replaces any existing
    summary_stats and updates scanner_results to consolidate source/converted layers.

    This should be called after the SARIF data is finalized to ensure consistency
    across all metrics reporting.

    Args:
        aggregated_results: The AshAggregatedResults model to update
    """
    ASH_LOGGER.verbose(
        "Aligning all metrics using unified scanner metrics as source of truth"
    )

    # Get unified metrics from the final SARIF data
    unified_metrics = get_unified_scanner_metrics(aggregated_results)

    # 1. Populate summary_stats from unified metrics
    aggregated_results = _populate_summary_stats_from_unified_metrics(
        aggregated_results, unified_metrics
    )

    # 2. Update scanner_results to consolidate source/converted and align with unified metrics
    aggregated_results = _populate_scanner_results_from_unified_metrics(
        aggregated_results, unified_metrics
    )

    # Here, where both sides are final: see metrics_consistency_discrepancies.
    for discrepancy in metrics_consistency_discrepancies(aggregated_results):
        ASH_LOGGER.warning(f"Metrics consistency check failed for {discrepancy}")

    ASH_LOGGER.verbose(
        "Metrics alignment completed - all sources now use unified metrics"
    )
    return aggregated_results


def metrics_consistency_discrepancies(
    aggregated_results: AshAggregatedResults, logger: logging.Logger = ASH_LOGGER
) -> List[str]:
    """``"<metric>: scanner_results total=<n>, summary_stats=<m>"`` for each mismatch.

    Sums the severity counts, the finding total and the actionable count over the
    ``scanner_results`` rows and compares each with ``summary_stats``. Meaningful only
    once both are written, which is the end of ``populate_metrics_from_unified_source``:
    before that a scanner that ran has no row, so the totals compare a partial set of
    rows with complete stats.

    Three row shapes are read. ``ScannerTargetStatusInfo`` is the declared element type
    and what the rebuild writes; ``ScannerStatusInfo`` is the legacy scanner-level shape
    with source/converted, tried first because its children also carry
    severity_counts; ``ScannerMetrics`` is the unified per-scanner row. A row of any
    other shape is logged at debug and skipped. A row that raises is logged as an error
    through *logger* and the check returns no discrepancies, so it can never stop a scan.
    """
    try:
        scanner_totals = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "suppressed": 0,
            "total": 0,
            "actionable": 0,
        }

        for scanner_name, scanner_info in aggregated_results.scanner_results.items():
            # The declared element type is ScannerTargetStatusInfo, which mypy reads
            # as never also a ScannerMetrics, so it would skip that branch. A row
            # assigned to the dict directly can be one; as an object, it is checked.
            row: object = scanner_info
            if hasattr(scanner_info, "source") and hasattr(scanner_info, "converted"):
                for target_info in [scanner_info.source, scanner_info.converted]:
                    if target_info and target_info.severity_counts:
                        counts = target_info.severity_counts
                        scanner_totals["critical"] += counts.critical
                        scanner_totals["high"] += counts.high
                        scanner_totals["medium"] += counts.medium
                        scanner_totals["low"] += counts.low
                        scanner_totals["info"] += counts.info
                        scanner_totals["suppressed"] += counts.suppressed
                        scanner_totals["total"] += target_info.finding_count or 0
                        scanner_totals["actionable"] += (
                            target_info.actionable_finding_count or 0
                        )
            elif hasattr(scanner_info, "severity_counts") and not hasattr(
                scanner_info, "source"
            ):
                counts = scanner_info.severity_counts
                if counts:
                    scanner_totals["critical"] += counts.critical
                    scanner_totals["high"] += counts.high
                    scanner_totals["medium"] += counts.medium
                    scanner_totals["low"] += counts.low
                    scanner_totals["info"] += counts.info
                    scanner_totals["suppressed"] += counts.suppressed
                scanner_totals["total"] += scanner_info.finding_count or 0
                scanner_totals["actionable"] += (
                    scanner_info.actionable_finding_count or 0
                )
            elif isinstance(row, ScannerMetrics):
                scanner_totals["critical"] += row.critical
                scanner_totals["high"] += row.high
                scanner_totals["medium"] += row.medium
                scanner_totals["low"] += row.low
                scanner_totals["info"] += row.info
                scanner_totals["suppressed"] += row.suppressed
                scanner_totals["total"] += row.total
                scanner_totals["actionable"] += row.actionable
            else:
                logger.debug(
                    f"Unknown scanner_info structure for {scanner_name}: "
                    f"{type(scanner_info)}"
                )

        summary_stats = aggregated_results.metadata.summary_stats
        actual_totals = {
            "critical": summary_stats.critical,
            "high": summary_stats.high,
            "medium": summary_stats.medium,
            "low": summary_stats.low,
            "info": summary_stats.info,
            "suppressed": summary_stats.suppressed,
            "total": summary_stats.total,
            "actionable": summary_stats.actionable,
        }
        return [
            f"{metric}: scanner_results total={expected}, "
            f"summary_stats={actual_totals[metric]}"
            for metric, expected in scanner_totals.items()
            if expected != actual_totals[metric]
        ]
    except Exception as e:
        import traceback

        logger.error(f"Error validating metrics consistency: {str(e)}")
        logger.debug(f"Stack trace: {traceback.format_exc()}")
        return []


def _populate_summary_stats_from_unified_metrics(
    aggregated_results: AshAggregatedResults, unified_metrics: List[ScannerMetrics]
) -> AshAggregatedResults:
    """Populate summary_stats from unified metrics.

    Args:
        aggregated_results: The AshAggregatedResults model to update
        unified_metrics: List[ScannerMetrics] from get_unified_scanner_metrics()
    """
    # Calculate totals from unified metrics
    total_suppressed = sum(m.suppressed for m in unified_metrics)
    total_critical = sum(m.critical for m in unified_metrics)
    total_high = sum(m.high for m in unified_metrics)
    total_medium = sum(m.medium for m in unified_metrics)
    total_low = sum(m.low for m in unified_metrics)
    total_info = sum(m.info for m in unified_metrics)
    total_findings = sum(m.total for m in unified_metrics)
    total_actionable = sum(m.actionable for m in unified_metrics)

    # Count scanner statuses. One counter per ScannerStatus member, so the five
    # sum to len(unified_metrics) and a consumer can tell a complete scan from a
    # partial one. ERROR had no counter until this was added, which made the other
    # four sum to less than the scanner count on exactly the runs where the
    # difference mattered.
    passed_count = sum(1 for m in unified_metrics if m.status == "PASSED")
    failed_count = sum(1 for m in unified_metrics if m.status == "FAILED")
    skipped_count = sum(1 for m in unified_metrics if m.status == "SKIPPED")
    missing_count = sum(1 for m in unified_metrics if m.status == "MISSING")
    # Every other status is an error: a status that is not one of ASH's own is
    # no result, and counted in no column the five no longer summed to the
    # scanner count.
    error_count = sum(
        1
        for m in unified_metrics
        if m.status not in ("PASSED", "FAILED", "SKIPPED", "MISSING")
    )

    # Preserve timing information if it exists
    existing_start = aggregated_results.metadata.summary_stats.start
    existing_end = aggregated_results.metadata.summary_stats.end
    existing_duration = aggregated_results.metadata.summary_stats.duration

    # Create new summary stats with unified metrics
    aggregated_results.metadata.summary_stats = SummaryStats(
        start=(
            existing_start.isoformat(timespec="seconds")
            if isinstance(existing_start, datetime)
            else existing_start
        ),
        end=(
            existing_end.isoformat(timespec="seconds")
            if isinstance(existing_end, datetime)
            else existing_end
        ),
        duration=existing_duration,
        suppressed=total_suppressed,
        critical=total_critical,
        high=total_high,
        medium=total_medium,
        low=total_low,
        info=total_info,
        total=total_findings,
        actionable=total_actionable,
        passed=passed_count,
        failed=failed_count,
        missing=missing_count,
        skipped=skipped_count,  # Add the missing skipped field
        error=error_count,
    )

    ASH_LOGGER.debug(
        f"Updated summary_stats: {total_actionable} actionable findings across {len(unified_metrics)} scanners"
    )

    return aggregated_results


#: Fields of the legacy two-target row (ScannerStatusInfo) that consolidation replaces
#: rather than carries: the per-target children are what the metrics combine.
_PER_TARGET_ROW_FIELDS = frozenset({"source", "converted"})


def _row_fields(row: object) -> Dict[str, Any]:
    """The fields a scanner_results row was given, extras included.

    Only the fields that were set, so a field the row never had keeps its default and
    stays out of dumps that exclude unset fields. A dict arrives from JSON, a legacy
    ScannerStatusInfo from a writer that assigned the old shape; both are read the
    same way, without their per-target children.
    """
    if row is None:
        return {}
    if isinstance(row, dict):
        fields = dict(row)
    else:
        names = set(getattr(row, "model_fields_set", ())) | set(
            getattr(row, "model_extra", None) or {}
        )
        fields = {name: getattr(row, name) for name in names}
    return {
        name: value
        for name, value in fields.items()
        if name not in _PER_TARGET_ROW_FIELDS
    }


#: The rebuilt statuses under which the scanner's tool ran: a recorded exit code
#: on such a row is the tool's, and is kept when the per-target reports carry
#: none. A MISSING or SKIPPED tool never ran, so its row carries None.
_RAN_STATUSES = frozenset(
    {ScannerStatus.PASSED, ScannerStatus.FAILED, ScannerStatus.ERROR}
)


def _populate_scanner_results_from_unified_metrics(
    aggregated_results: AshAggregatedResults, unified_metrics: List[ScannerMetrics]
) -> AshAggregatedResults:
    """Update scanner_results to consolidate source/converted layers and align with unified metrics.

    This function updates the scanner_results to use consolidated metrics from the unified
    source instead of maintaining separate source/converted counts that may not align
    with the final SARIF data.

    Args:
        aggregated_results: The AshAggregatedResults model to update
        unified_metrics: List[ScannerMetrics] from get_unified_scanner_metrics()
    """
    for metrics in unified_metrics:
        scanner_name = metrics.scanner_name
        total_duration = metrics.duration

        # Create consolidated severity counts from unified metrics
        consolidated_severity_counts = ScannerSeverityCount(
            suppressed=metrics.suppressed,
            critical=metrics.critical,
            high=metrics.high,
            medium=metrics.medium,
            low=metrics.low,
            info=metrics.info,
        )

        # Convert status from string to enum
        if metrics.status == "PASSED":
            status = ScannerStatus.PASSED
        elif metrics.status == "FAILED":
            status = ScannerStatus.FAILED
        elif metrics.status == "SKIPPED":
            status = ScannerStatus.SKIPPED
        elif metrics.status == "MISSING":
            status = ScannerStatus.MISSING
        elif metrics.status == "ERROR":
            status = ScannerStatus.ERROR
        else:
            # Not a status of ASH's: no result that can be read, so the row
            # says ERROR, never a PASSED nothing graded.
            ASH_LOGGER.warning(
                f"Scanner {scanner_name} has an unrecognized status "
                f"{metrics.status!r}; its row is written as ERROR"
            )
            status = ScannerStatus.ERROR

        # Built from the scanner's existing row, with only the fields the metrics
        # compute replaced. Building it from the metrics alone dropped everything
        # else: an excluded scanner's ``excluded: true`` came back false, the same as
        # a scanner that ran and had nothing to scan, and exit_code and any extra
        # field were lost too.
        fields = _row_fields(aggregated_results.scanner_results.get(scanner_name))
        fields.update(
            severity_counts=consolidated_severity_counts,
            finding_count=metrics.total,
            actionable_finding_count=metrics.actionable,
            suppressed_finding_count=metrics.suppressed,
            duration=total_duration,
            status=status,
            missing_reason=metrics.missing_reason,
        )
        # The exit code is written as the metrics have it, None included: the
        # model's default is 0, which reads as a tool that ran and exited clean,
        # so a tool that never ran (missing, excluded, refused before its start)
        # has to carry an explicit None. One exception: the metrics read the
        # code from the per-target reports, and a results file whose rows carry
        # a code while its reports carry none (an older writer, a merged file)
        # has the row as the code's only record. A row whose status says the
        # tool ran keeps that code rather than having it erased by the rebuild.
        # The skipped reason is written when the metrics have one and dropped
        # when they have none (the metrics are the authority: a row's stale
        # reason is not kept), without passing a None that would mark the field
        # set on every row.
        recorded_code = fields.get("exit_code")
        if (
            metrics.exit_code is None
            and status in _RAN_STATUSES
            and isinstance(recorded_code, int)
            and not isinstance(recorded_code, bool)
        ):
            fields["exit_code"] = recorded_code
        else:
            fields["exit_code"] = metrics.exit_code
        if metrics.skipped_reason is None:
            fields.pop("skipped_reason", None)
        else:
            fields["skipped_reason"] = metrics.skipped_reason
        # The scan phase's reason for a MISSING row comes with the row's other fields:
        # the metrics know the status, not why. It stays while the row is MISSING, and
        # on a FAILED row whose dependencies were missing on one tree, the reason
        # get_unified_scanner_metrics computes for it (contract clause 3i): dropped
        # here, the rebuilt row said FAILED and nothing said which tree went unscanned.
        if status not in (
            ScannerStatus.MISSING,
            ScannerStatus.FAILED,
        ) or not isinstance(fields.get("missing_reason"), str):
            fields.pop("missing_reason", None)
        # The two flags say why the status is what it is, so they follow the
        # metrics when the metrics found the scanner missing or excluded. Every
        # later reader of this scanner -- the report phase, and the exit-code gate
        # through get_unified_scanner_metrics -- reads this row before the
        # per-target reports, and a scanner recorded MISSING during its scan
        # (scan() returned False) has no earlier row to carry the flag: left at its
        # default of True it read as having its dependencies, and one target that
        # evaluated nothing then graded it SKIPPED, which the completeness gate lets
        # through. Set in those cases, and on a row that already carries the field
        # (so a stale value follows the metrics), so a row that had no flag keeps
        # its serialized shape (dumps that exclude unset fields, such as the S3
        # and CloudWatch payloads, leave the defaults out). Passed on every row,
        # as the update above once did, both flags were set on every row and the
        # shape preservation described here never happened.
        if metrics.dependencies_missing or "dependencies_satisfied" in fields:
            fields["dependencies_satisfied"] = not metrics.dependencies_missing
        if metrics.excluded or "excluded" in fields:
            fields["excluded"] = metrics.excluded
        consolidated_target_info = ScannerTargetStatusInfo(**fields)

        # Update scanner_results with consolidated information.
        #
        # The assignment below replaces the entry outright. It does NOT put the
        # metrics in a 'source' field and zero 'converted' -- that was an earlier
        # design, and the comment describing it survived the change. Direct
        # replacement is correct: scanner_results is declared
        # Dict[str, ScannerTargetStatusInfo] and the published schema agrees
        # (AshAggregatedResults.json, additionalProperties -> ScannerTargetStatusInfo).
        aggregated_results.scanner_results[scanner_name] = consolidated_target_info

    ASH_LOGGER.debug(
        f"Updated scanner_results for {len(unified_metrics)} scanners with consolidated metrics"
    )
    return aggregated_results
