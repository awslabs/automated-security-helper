# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Recombine the shard results of one sharded scan into a single report.

Why this exists
---------------
``ash scan --shard-index k --shard-count n`` splits one scan across n CI
executors by partitioning the *scanner* set (see
:mod:`automated_security_helper.core.sharding` for why scanners and not files).
Each executor writes its own ``ash_aggregated_results.json`` holding the results
of the scanners it owned. Something has to put them back together, and the whole
value of sharding depends on that recombination being trustworthy: a partial
merge that reads as a complete scan is worse than no sharding at all, because a
reviewer cannot tell the difference by looking at it.

The verdict is the sharpest version of this. A shard that happened to own only
syft and grype finds nothing and exits 0. Five such shards mean five green CI
jobs and a repository full of critical findings that nobody was told about.
``ash merge`` therefore owns the real verdict for a sharded run, computed over
the union, and CI must gate on this command rather than on per-shard success.

Why one collapsed SARIF run, unlike workspace mode
--------------------------------------------------
Merging goes through :meth:`SarifReport.merge_sarif_report`, which collapses
everything into ``runs[0]``. That is deliberate, and it is the opposite of the
choice :mod:`automated_security_helper.workspace.aggregation` makes.

Read that module's docstring for the full argument; the short version is that a
SARIF run can declare only one root. Workspace mode has N project roots, so it
must keep one run per project or consumers that ingest SARIF against a single
repository root -- GitHub code scanning above all -- mis-locate or reject the
results. Shards all scan the *same* root, so there is exactly one root to
declare and one collapsed run is the honest shape.

``WorkspaceAggregator`` was considered and rejected for this reason. Using it
here would emit n runs for one repository, each identical in root and differing
only in which scanners contributed, which describes a workspace that does not
exist and would make every consumer's per-run attribution meaningless.

What merge_sarif_report does not do, and why there is an extra step
------------------------------------------------------------------
``merge_sarif_report`` was written to fold one *scanner's* SARIF into ASH's
aggregate, so it reads ``runs[0].tool.driver`` and never looks at
``runs[0].tool.extensions``. Merging two ASH *aggregates* is the case it was not
written for: every shard's driver is ASH itself, and each shard's per-scanner
tool components live in ``extensions``. Left alone, the rule metadata for every
scanner owned by shards 1..n-1 would be silently dropped, and the merged report
would carry results whose ``ruleId`` resolves to no rule -- findings with no
description or help URI, which is a quiet quality loss rather than a visible
error. :func:`_merge_tool_extensions` unions them afterwards, matching
components on the same ``(name, fullName, organization)`` triple
``merge_sarif_report`` itself uses so the two paths cannot disagree.

Deduplication is deliberately absent, here as elsewhere. Two shards never own
the same scanner (:func:`verify_shard_coverage` refuses that), so there is no
legitimate duplicate to collapse, and a merge that quietly dropped
similar-looking findings from different scanners would be hiding real results.

The aggregated suppression pass, and why omitting it broke equivalence
---------------------------------------------------------------------
``AshExecutionEngine`` applies ``apply_suppressions_to_sarif`` to the aggregated
SARIF just before the report phase, because per-scanner passes miss findings
whose paths only become matchable after merge and normalization. This command
originally went from ``merge_sarif_report`` straight to metrics and reports, so
nothing applied suppressions to the cross-shard product: a suppression that only
matched post-merge applied in an unsharded scan and not in a sharded one, and
``ash merge`` exited 2 where ``ash scan`` exited 0 on the same tree.
:func:`apply_aggregated_suppressions` closes that, and ``--ignore-suppressions``
makes the other half of the contract expressible.

That the equivalence was reported as verified end to end before this existed is
the useful part of the story. The verification used a tree with no suppressions
at all, so it could not have failed. A parity property has to be exercised on
input where the two paths could actually disagree, which for suppressions means a
suppression that matches only after the collapse.

Shard provenance, and the field that does not exist yet
-------------------------------------------------------
Coverage is verified from the result files alone rather than from a
``--shard-count`` argument, so that an operator who changes their CI matrix in
one place and not the other gets a loud failure instead of a short merge.

That requires each shard to record what it was asked to run.
``ScanPhase._shard_assignment`` computes exactly that, but as of this commit
nothing persists it: ``AshAggregatedResults`` has no shard field, and the
stamping would have to happen in the scan phase or execution engine.
:func:`read_shard_assignment` therefore accepts provenance from either of the
two places it could plausibly land -- a top-level ``shard`` attribute, if the
model later grows a first-class field, or a ``shard`` key inside ``metadata``,
which works today because ``ReportMetadata`` is declared ``extra="allow"`` and
so round-trips unknown keys through JSON untouched. Being liberal about which
carrier is used costs three lines and means this command stays correct whichever
way the scan side lands it. :func:`stamp_shard_assignment` writes the
``metadata`` form and is what the scan side should call.

A results file with no provenance is refused rather than guessed at. The
alternative -- treating an unstamped file as "probably the only shard" -- would
make ``ash merge`` silently accept a single unsharded scan as a complete merge
of a five-way split.

Why the merged report drops its own shard key
--------------------------------------------
The merged output deliberately does *not* carry a ``shard`` key. It records
``merged_shard_count`` and ``merged_shard_indices`` instead. Copying the base
shard's assignment through would make the merged file look like shard 0 of n, so
a second ``ash merge`` over an output directory would accept it and report a
whole scan as one fifth of itself.

Known limitations
-----------------
A directory passed to ``--results`` must resolve to exactly one results file.
Pointing it at a parent holding every shard's artifact directory is refused with
a message naming what was found. Merging everything found beneath a directory
was considered and rejected: it makes the set of merged shards depend on
whatever else happens to be in the tree, including a previous merged output, and
the repeatable ``--results`` flag already expresses "these n shards" exactly.

``cyclonedx`` is adopted from the first shard that produced a non-empty SBOM
rather than merged. This matches single-scan behaviour, where
``scan_result_processor`` assigns ``aggregated_results.cyclonedx`` outright and
the last SBOM-producing scanner wins; there is no CycloneDX merge primitive in
the codebase to reuse. With the default scanner set only syft produces one, so
it lands on exactly one shard and nothing is lost. Splitting two SBOM scanners
across shards would keep only one SBOM.

``summary_stats.duration`` is the longest shard's duration, not the sum. Shards
run concurrently, so summing would report a wall-clock time several times longer
than the run actually took; the longest shard is the critical path and is the
number an operator comparing sharded against unsharded wants. Total compute
across shards is not recorded.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Annotated, Any, Dict, List, Optional, Sequence, Tuple

import typer
from pydantic import ValidationError
from rich import print

from automated_security_helper.base.plugin_context import PluginContext

# Imported at module scope, and not lazily inside the functions that need it,
# because importing this module is what calls AshAggregatedResults.model_rebuild().
# AshAggregatedResults declares ash_config as a forward reference to AshConfig, so
# until that rebuild runs the model has no validator at all and
# model_validate_json raises PydanticUserError. ``ash report`` gets the same
# rebuild by side effect of importing resolve_config; relying on an import made
# for another purpose is what makes this fragile, so the dependency is named here.
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.enums import AshLogLevel, ExportFormat
from automated_security_helper.core.exceptions import ShardCoverageError
from automated_security_helper.core.phases.report_phase import ReportPhase
from automated_security_helper.core.progress import LiveProgressDisplay
from automated_security_helper.core.sharding import (
    ShardAssignment,
    verify_shard_coverage,
)
from automated_security_helper.core.unified_metrics import (
    populate_metrics_from_unified_source,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugins import ash_plugin_manager
from automated_security_helper.plugins.loader import load_plugins
from automated_security_helper.utils.log import get_logger

#: The filename every ASH scan writes its aggregated results to. A ``--results``
#: directory is searched for this name.
RESULTS_FILE_NAME = "ash_aggregated_results.json"

#: Key under ``AshAggregatedResults.metadata`` carrying one shard's assignment.
SHARD_PROVENANCE_KEY = "shard"

#: Keys the merged report carries in place of ``SHARD_PROVENANCE_KEY``.
MERGED_SHARD_COUNT_KEY = "merged_shard_count"
MERGED_SHARD_INDICES_KEY = "merged_shard_indices"

#: Relative locations searched, in order, when ``--results`` names a directory.
#: These mirror the candidates ``ash report`` already probes, so an operator who
#: can point ``ash report`` at a directory can point ``ash merge`` at the same one.
_RESULTS_DIR_CANDIDATES = (
    Path(RESULTS_FILE_NAME),
    Path("ash_output") / RESULTS_FILE_NAME,
    Path(".ash") / "ash_output" / RESULTS_FILE_NAME,
)


def _normalized(name: str) -> str:
    """Canonical form for comparing scanner names across shards.

    Scanner display names reach the results as ``config.name`` verbatim, so one
    shard can record "Bandit" where another records "bandit". Every comparison in
    this module goes through here because the rest of the CLI already treats
    scanner names case insensitively -- ``ScanPhase`` lowercases both sides of the
    exclusion check, and ``sharding._normalized`` lowercases the partition. A
    case-sensitive comparison here would read one scanner as two and report the
    owning shard's real result alongside another shard's skip marker.
    """
    return name.strip().lower()


# ---------------------------------------------------------------------------
# Shard provenance
# ---------------------------------------------------------------------------


def stamp_shard_assignment(
    results: AshAggregatedResults, assignment: ShardAssignment
) -> None:
    """Record *assignment* on *results* so ``ash merge`` can verify coverage.

    This is what the scan side should call once a shard's results are final.

    Assigns the ``ShardAssignment`` itself, not ``model_dump()``. Dumping first
    was tried and rejected: ``ReportMetadata`` declares ``shard`` as a real field
    and does not enable ``validate_assignment``, so a dict is stored raw and every
    later ``model_dump_json`` emits ``PydanticSerializationUnexpectedValue:
    Expected ShardAssignment``. The JSON comes out correct, but the warning is
    noise on every serialization, and worse, a fixture that stored a dict would
    exercise a shape the scan side never produces -- ``execution_engine`` assigns
    the object.

    Args:
        results: The shard's aggregated results.
        assignment: What this shard was asked to run.
    """
    setattr(results.metadata, SHARD_PROVENANCE_KEY, assignment)


def read_shard_assignment(results: AshAggregatedResults) -> ShardAssignment | None:
    """Return the shard assignment recorded on *results*, or None if absent.

    Two carriers are accepted; see the module docstring for why. A top-level
    ``shard`` attribute wins over the ``metadata`` key, on the grounds that a
    first-class field would be the deliberate later choice and the metadata key
    could linger from an older run.

    Returns None rather than raising so the caller can name the offending file.

    Args:
        results: A single shard's aggregated results.

    Returns:
        The recorded assignment, or None when the file carries no provenance.
    """
    for carrier in (results, results.metadata):
        raw = getattr(carrier, SHARD_PROVENANCE_KEY, None)
        if raw is None:
            continue
        if isinstance(raw, ShardAssignment):
            return raw
        try:
            return ShardAssignment.model_validate(raw)
        except ValidationError:
            # A malformed value is reported as missing provenance rather than
            # crashing with a validation traceback. The caller's message names
            # the file, which is what an operator needs; the shape of the bad
            # value is not.
            #
            # ValidationError rather than Exception: model_validate is the only
            # call in the try, and it raises exactly this for every rejected
            # shape -- dict with a bad field type, empty dict, int, str, list and
            # a bare object were each checked. Anything else escaping this
            # function is a defect worth a traceback rather than a silent None.
            continue
    return None


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def resolve_results_file(target: str | Path) -> Path:
    """Resolve one ``--results`` value to a single results file.

    A file is used as given. A directory is searched at the well-known relative
    locations first, and only then recursively -- the recursive search must find
    exactly one candidate, because picking one of several would silently drop
    shards.

    Args:
        target: A results file, or a directory containing one.

    Returns:
        The path to the results file.

    Raises:
        ShardCoverageError: If *target* does not exist, or is a directory holding
            no results file or more than one.
    """
    path = Path(target)
    if path.is_file():
        return path
    if not path.exists():
        raise ShardCoverageError(
            f"--results path does not exist: {path}. Refusing to merge, because "
            f"skipping an unreadable shard would produce a partial report that "
            f"reads as complete."
        )
    if not path.is_dir():
        raise ShardCoverageError(
            f"--results path is neither a file nor a directory: {path}."
        )

    for candidate in _RESULTS_DIR_CANDIDATES:
        resolved = path.joinpath(candidate)
        if resolved.is_file():
            return resolved

    found = sorted(path.rglob(RESULTS_FILE_NAME))
    if not found:
        raise ShardCoverageError(
            f"No {RESULTS_FILE_NAME} found in {path}. Checked "
            f"{', '.join(c.as_posix() for c in _RESULTS_DIR_CANDIDATES)} and then "
            f"recursively. Check that the shard's CI job succeeded and uploaded "
            f"its output directory."
        )
    if len(found) > 1:
        listed = "\n  ".join(p.as_posix() for p in found)
        raise ShardCoverageError(
            f"{path} contains {len(found)} results files:\n  {listed}\n"
            f"Pass one --results per shard rather than a parent directory. Merging "
            f"everything found beneath a directory would make the merged set depend "
            f"on whatever else is in the tree, including a previous merged report."
        )
    return found[0]


def load_shard_results(
    targets: Sequence[str | Path],
) -> List[Tuple[Path, AshAggregatedResults]]:
    """Load every shard's results, in the order given.

    Args:
        targets: The ``--results`` values.

    Returns:
        (path, results) pairs.

    Raises:
        ShardCoverageError: If a path cannot be resolved or parsed. Parse failures
            are reported here rather than skipped, because a shard that produced
            an unreadable file did not contribute its scanners.
    """
    loaded: List[Tuple[Path, AshAggregatedResults]] = []
    for target in targets:
        results_file = resolve_results_file(target)
        try:
            with open(results_file, "r", encoding="utf-8") as handle:
                loaded.append(
                    (
                        results_file,
                        AshAggregatedResults.model_validate_json(handle.read()),
                    )
                )
        except ShardCoverageError:
            raise
        except Exception as exc:
            raise ShardCoverageError(
                f"Could not read shard results from {results_file}: {exc}"
            ) from exc
    return loaded


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def _collect_assignments(
    loaded: Sequence[Tuple[Path, AshAggregatedResults]],
) -> List[Tuple[Path, AshAggregatedResults, ShardAssignment]]:
    """Attach each shard's assignment, refusing any file that carries none.

    Raises:
        ShardCoverageError: If any file has no usable shard provenance.
    """
    if not loaded:
        # Delegated so the "no shards at all" wording lives in one place.
        verify_shard_coverage([])

    unstamped: List[Path] = []
    stamped: List[Tuple[Path, AshAggregatedResults, ShardAssignment]] = []
    for results_file, results in loaded:
        assignment = read_shard_assignment(results)
        if assignment is None:
            unstamped.append(results_file)
        else:
            stamped.append((results_file, results, assignment))

    if unstamped:
        listed = "\n  ".join(p.as_posix() for p in unstamped)
        raise ShardCoverageError(
            f"No shard provenance found in {len(unstamped)} results file(s):\n  {listed}\n"
            f"Only a scan run with --shard-index and --shard-count records which "
            f"scanners it owned, and without that record there is no way to tell a "
            f"complete set of shards from a partial one. Refusing to guess: an "
            f"unstamped file could equally be a whole unsharded scan or one shard "
            f"of many."
        )
    return stamped


def _verify_scanner_union(
    shards: Sequence[Tuple[Path, AshAggregatedResults, ShardAssignment]],
) -> Dict[str, int]:
    """Map each scanner to the position of the shard that owned it.

    ``verify_shard_coverage`` checks the shard *indices* reconstruct one run and
    that no scanner is claimed twice. It cannot see the failure the sharding
    module calls the residual risk: two executors resolving *different* scanner
    sets, so that both partitions are internally valid and the union has a hole.
    That is visible here and nowhere else, by comparing the scanners the shards
    claim against the scanners their results actually mention.

    Args:
        shards: Verified shard results, with assignments.

    Returns:
        Normalized scanner name to index into *shards*.

    Raises:
        ShardCoverageError: If a scanner appears in some shard's results but no
            shard claims it, or if the shard that claims a scanner has no result
            for it.
    """
    owner_by_scanner: Dict[str, int] = {}
    for position, (_, _, assignment) in enumerate(shards):
        for scanner in assignment.assigned_scanners:
            # verify_shard_coverage has already refused any scanner claimed by
            # two shards, so this cannot overwrite a different owner.
            owner_by_scanner[_normalized(scanner)] = position

    seen: Dict[str, Path] = {}
    for results_file, results, _ in shards:
        for scanner in results.scanner_results:
            seen.setdefault(_normalized(scanner), results_file)

    unclaimed = sorted(set(seen) - set(owner_by_scanner))
    if unclaimed:
        listed = ", ".join(
            f"{name} (seen in {seen[name].as_posix()})" for name in unclaimed
        )
        raise ShardCoverageError(
            f"These scanners appear in shard results but no shard was assigned "
            f"them: {listed}. The executors resolved different scanner sets -- one "
            f"was missing a plugin module, or --python-only or a config override "
            f"was applied to some jobs and not others. Every shard excluded these "
            f"scanners, so no shard ran them, and merging would report them as "
            f"deliberately skipped rather than never attempted."
        )

    missing_from_owner = sorted(
        name
        for name, position in owner_by_scanner.items()
        if name in seen
        and not any(
            _normalized(scanner) == name
            for scanner in shards[position][1].scanner_results
        )
    )
    if missing_from_owner:
        details = ", ".join(
            f"{name} (owned by shard {shards[owner_by_scanner[name]][2].shard_index})"
            for name in missing_from_owner
        )
        raise ShardCoverageError(
            f"The shard that owned these scanners recorded no result for them: "
            f"{details}. Another shard's skip marker is the only trace left, and "
            f"adopting it would report a scanner that never ran as deliberately "
            f"skipped. Check whether that shard's scan phase completed."
        )

    return owner_by_scanner


def _completed(entry: Any) -> bool:
    """Whether one ``scanner_results`` entry represents a scanner that ran.

    ERROR and MISSING are the two statuses that mean it did not. Everything else
    -- including SKIPPED, which is how a run-wide exclusion is recorded -- counts
    as completed, because the scanner either produced a result or was never
    supposed to.

    The status set is imported from ``run_ash_scan`` rather than re-listed, so
    this and ``ash scan``'s gate cannot drift apart. Imported inside the function
    for the same reason :func:`_merged_exit_code` imports from there lazily:
    ``run_ash_scan`` pulls in ``run_ash_container`` at module scope, and there is
    no reason for a command that does not scan to carry that import graph. There
    is no cycle between the two modules -- ``run_ash_scan`` does not import this
    one -- so the laziness is about cost, not about breaking a loop.
    """
    from automated_security_helper.interactions.run_ash_scan import (
        _INCOMPLETE_SCANNER_STATUSES,
    )

    status = getattr(entry, "status", None)
    status_value = getattr(status, "value", status)
    return status_value not in _INCOMPLETE_SCANNER_STATUSES


def _verify_shard_contributions(
    shards: Sequence[Tuple[Path, AshAggregatedResults, ShardAssignment]],
) -> None:
    """Refuse a merge where a shard owned scanners but completed none of them.

    The distributed shape of the false-green exit code, and the one thing the
    checks above cannot see. ``verify_shard_coverage`` reads shard *indices*;
    :func:`_verify_scanner_union` reads which scanner *names* appear. Neither
    reads a status. So a shard whose every scanner came back MISSING satisfies
    both and merges into a report that reads as a complete scan of the whole tree,
    a fraction of which never ran -- and because that fraction produced no
    findings, the merged verdict is the same 0 a genuinely clean scan produces.

    Also catches the case a status check structurally cannot: an owned scanner
    with no entry at all, where there is no status to inspect.
    :func:`_verify_scanner_union` catches that only when some *other* shard left a
    skip marker under the same name, which is the usual but not the only shape.

    A shard that owns nothing is not an offender. A shard count above the scanner
    count leaves surplus shards with an empty assignment, which
    :mod:`automated_security_helper.core.sharding` calls wasteful rather than
    wrong; reading an empty assignment as a failure would turn an over-large
    shard count into a pipeline that cannot merge at all.

    Gated by the caller rather than unconditional, unlike every other refusal in
    this module. Those all describe a set of shards that cannot reconstruct one
    scan whatever the environment. This one describes an environment: four of the
    ten default scanners are MISSING on a machine without cdk-nag, cfn-nag, grype
    and syft installed, and refusing by default would break merges that have
    nothing wrong with them.

    Args:
        shards: Verified shard results, with assignments, in index order.

    Raises:
        ShardCoverageError: If any shard that owned at least one scanner completed
            none of them.
    """
    offenders: List[str] = []
    for _, results, assignment in shards:
        owned = [_normalized(name) for name in assignment.assigned_scanners]
        if not owned:
            continue

        entries = {
            _normalized(name): entry for name, entry in results.scanner_results.items()
        }
        if any(name in entries and _completed(entries[name]) for name in owned):
            continue

        detail = []
        for name in owned:
            entry = entries.get(name)
            if entry is None:
                detail.append(f"{name} (no result recorded)")
            else:
                status = getattr(entry, "status", None)
                detail.append(f"{name} ({getattr(status, 'value', status)})")
        offenders.append(
            f"shard {assignment.shard_index} of {assignment.shard_count}: "
            f"{', '.join(detail)}"
        )

    if offenders:
        listed = "\n  ".join(offenders)
        raise ShardCoverageError(
            f"These shards completed none of the scanners they owned:\n  {listed}\n"
            f"Their scanners contributed no findings because they did not run, not "
            f"because there was nothing to find, so merging would report a partial "
            f"scan as a whole one. Check whether those CI jobs had the scanners' "
            f"tools available. Drop --fail-on-incomplete-scanners to merge anyway."
        )


# ---------------------------------------------------------------------------
# Merging
# ---------------------------------------------------------------------------


def _merge_tool_extensions(
    base: AshAggregatedResults, other: AshAggregatedResults
) -> None:
    """Union ``runs[0].tool.extensions`` from *other* into *base*.

    Needed because ``merge_sarif_report`` reads only ``runs[0].tool.driver``; see
    the module docstring. Components are matched on the same triple
    ``merge_sarif_report`` uses, and rules are unioned by id for a component that
    already exists, so a scanner appearing on two shards -- which coverage
    verification forbids, but which would otherwise corrupt rule metadata --
    cannot produce duplicate components.
    """
    if base.sarif is None or other.sarif is None:
        return
    if not base.sarif.runs or not other.sarif.runs:
        return

    incoming = other.sarif.runs[0].tool.extensions or []
    if not incoming:
        return

    target_run = base.sarif.runs[0]
    if target_run.tool.extensions is None:
        target_run.tool.extensions = []

    for component in incoming:
        existing = next(
            (
                candidate
                for candidate in target_run.tool.extensions
                if candidate.name == component.name
                and candidate.fullName == component.fullName
                and candidate.organization == component.organization
            ),
            None,
        )
        if existing is None:
            target_run.tool.extensions.append(component)
            continue
        if not component.rules:
            continue
        if existing.rules is None:
            existing.rules = []
        known_rule_ids = {rule.id for rule in existing.rules}
        for rule in component.rules:
            if rule.id not in known_rule_ids:
                existing.rules.append(rule)
                known_rule_ids.add(rule.id)


def _merge_timing(
    base: AshAggregatedResults,
    shards: Sequence[Tuple[Path, AshAggregatedResults, ShardAssignment]],
) -> None:
    """Set the merged run's start, end and duration across every shard.

    ``populate_metrics_from_unified_source`` recomputes every count but preserves
    these three, so they are set before it runs. Duration is the longest shard
    rather than the sum; see the module docstring.
    """
    starts = [
        shard.metadata.summary_stats.start
        for _, shard, _ in shards
        if shard.metadata.summary_stats.start
    ]
    ends = [
        shard.metadata.summary_stats.end
        for _, shard, _ in shards
        if shard.metadata.summary_stats.end
    ]
    durations = [shard.metadata.summary_stats.duration or 0.0 for _, shard, _ in shards]

    # Compared as strings. Every writer emits ISO-8601 through
    # SummaryStats.set_times, and ISO-8601 sorts lexicographically in the same
    # order it sorts chronologically, so min/max are correct without parsing.
    # Mixed types would not compare, so the two lists are filtered to one kind.
    if starts and all(isinstance(value, str) for value in starts):
        base.metadata.summary_stats.start = min(starts)
    if ends and all(isinstance(value, str) for value in ends):
        base.metadata.summary_stats.end = max(ends)
    if durations:
        base.metadata.summary_stats.duration = max(durations)


def merge_shard_results(
    loaded: Sequence[Tuple[Path, AshAggregatedResults]],
    require_scanner_completion: bool = False,
) -> AshAggregatedResults:
    """Merge every shard's results into one report covering the whole scan.

    Coverage is verified before anything is merged, so a partial or duplicated
    set of shards fails without leaving a half-written report behind.

    Does not mutate its inputs; the base is a deep copy of the lowest-indexed
    shard. That shard supplies the report's identity -- name, description,
    ``ash_config``, ``converter_results`` -- because those are properties of the
    scan rather than of the shard, and taking them from the *lowest index* rather
    than from the first ``--results`` argument makes the merged report
    independent of the order the operator listed the shards in.

    Args:
        loaded: (path, results) pairs, in any order.
        require_scanner_completion: When True, also refuse a set where some shard
            owned scanners and completed none of them. Off by default; see
            :func:`_verify_shard_contributions` for why this one refusal is opted
            into while the rest are unconditional.

    Returns:
        One merged ``AshAggregatedResults`` with recomputed statistics.

    Raises:
        ShardCoverageError: If the shards do not reconstruct exactly one whole
            scan.
    """
    shards = _collect_assignments(loaded)
    verify_shard_coverage([assignment for _, _, assignment in shards])

    # Sorted by shard index, not by argument order, so the merged report is
    # byte-identical whichever order the shards were passed in. Two invocations
    # that disagree only in --results order producing different reports would
    # make the output impossible to diff across CI runs.
    shards.sort(key=lambda entry: entry[2].shard_index)
    owner_by_scanner = _verify_scanner_union(shards)
    if require_scanner_completion:
        _verify_shard_contributions(shards)

    merged = shards[0][1].model_copy(deep=True)

    for _, shard, _ in shards[1:]:
        if merged.sarif is None:
            merged.sarif = shard.sarif.model_copy(deep=True) if shard.sarif else None
        elif shard.sarif is not None:
            merged.sarif.merge_sarif_report(shard.sarif)
            _merge_tool_extensions(merged, shard)

        merged.validation_checkpoints.extend(shard.validation_checkpoints)
        merged.used_suppressions.update(shard.used_suppressions)

        for name, converter_result in shard.converter_results.items():
            # Converters are not sharded: every shard converts the whole tree, so
            # the entries agree and the first one is as good as any. setdefault
            # rather than assignment keeps the lowest-indexed shard's copy, which
            # is what makes the result order-independent.
            merged.converter_results.setdefault(name, converter_result)

        for name, report in shard.additional_reports.items():
            merged.additional_reports.setdefault(name, report)

        if not _has_sbom_components(merged.cyclonedx) and _has_sbom_components(
            shard.cyclonedx
        ):
            merged.cyclonedx = shard.cyclonedx

    _adopt_owning_shard_results(merged, shards, owner_by_scanner)
    _merge_timing(merged, shards)
    _record_merge_provenance(merged, shards)

    # Recomputes summary_stats and per-scanner counts from the merged SARIF, the
    # same call the execution engine makes before the report phase. Without it
    # every count would still be the base shard's, so a merged report would show
    # the union's findings under one shard's totals.
    return populate_metrics_from_unified_source(aggregated_results=merged)


def _has_sbom_components(cyclonedx: Any) -> bool:
    """Return True when *cyclonedx* carries at least one component."""
    return bool(getattr(cyclonedx, "components", None))


def _adopt_owning_shard_results(
    merged: AshAggregatedResults,
    shards: Sequence[Tuple[Path, AshAggregatedResults, ShardAssignment]],
    owner_by_scanner: Dict[str, int],
) -> None:
    """Keep only the owning shard's status for each scanner.

    This is the step that decides whether the merged report is usable at all.
    Every shard records the scanners it did *not* own as excluded -- status
    SKIPPED in ``scanner_results``, and a skip marker under
    ``additional_reports[name]["None"]``. A shard's own scanners get real entries
    under ``additional_reports[name]["source"]``.

    Both matter, and ``additional_reports`` matters more.
    ``ScannerStatisticsCalculator.get_scanner_status_info`` consults
    ``additional_reports[name]["None"]`` *before* ``scanner_results``, so a merged
    report that kept both a skip marker and a real entry for one scanner would
    read ``excluded=True`` from the marker. ``get_unified_scanner_metrics`` maps
    excluded to SKIPPED regardless of the finding count, so every sharded scanner
    would report SKIPPED with its findings present but attributed to a scanner
    the report claims never ran -- and ``summary_stats.skipped`` would count the
    whole scanner set. Unioning these two dictionaries is the single mistake that
    turns a working merge into a report that says nothing ran.

    Ownership comes from ``assigned_scanners`` rather than from sniffing statuses,
    because that field *is* the record of who was asked to run what.
    ``ShardAssignment`` documents that it holds the assignment and not the
    outcome, which is exactly the property needed here: a scanner that the
    operator excluded globally, or whose dependencies were missing, still has a
    single owning shard, and that shard's SKIPPED or MISSING entry is the true
    one. Inferring ownership from "whichever entry is not SKIPPED" would find no
    owner for those scanners and fall back to an arbitrary shard's marker.
    """
    scanner_results: Dict[str, Any] = {}
    additional_reports: Dict[str, Any] = {}

    for position, (_, shard, _) in enumerate(shards):
        for name, entry in shard.scanner_results.items():
            if owner_by_scanner.get(_normalized(name)) == position:
                scanner_results[name] = entry
        for name, report in shard.additional_reports.items():
            if owner_by_scanner.get(_normalized(name)) == position:
                additional_reports[name] = report

    merged.scanner_results = scanner_results

    # Entries whose key names no known scanner are carried through untouched.
    # additional_reports is a free-form dictionary and a plugin may write to it
    # under a key that is not a scanner name; dropping those would lose data that
    # has nothing to do with sharding.
    for name, report in merged.additional_reports.items():
        if _normalized(name) not in owner_by_scanner:
            additional_reports.setdefault(name, report)
    merged.additional_reports = additional_reports


def _record_merge_provenance(
    merged: AshAggregatedResults,
    shards: Sequence[Tuple[Path, AshAggregatedResults, ShardAssignment]],
) -> None:
    """Replace the base shard's provenance with the merge's own.

    The ``shard`` value is cleared rather than updated. Leaving it would describe
    the merged report as one shard of n, so re-merging an output directory would
    be accepted and would report a whole scan as a fraction of itself.

    Cleared to None rather than deleted, which was tried and rejected.
    ``ReportMetadata`` declares ``shard`` as a real field, and pydantic does allow
    ``delattr`` on a declared field -- but afterwards a plain
    ``results.metadata.shard`` raises AttributeError instead of returning the
    field's default, and the field vanishes from ``model_dump_json`` entirely.
    That leaves a booby-trapped model for every consumer that reads the attribute
    without a default: reporters, the committed JSON schema, and any later lane.
    None is the field's own default, serializes as ``"shard": null``, and
    :func:`read_shard_assignment` treats it as absent, so clearing achieves
    everything deleting did without the landmine.
    """
    for carrier in (merged, merged.metadata):
        if getattr(carrier, SHARD_PROVENANCE_KEY, None) is not None:
            setattr(carrier, SHARD_PROVENANCE_KEY, None)

    setattr(merged.metadata, MERGED_SHARD_COUNT_KEY, shards[0][2].shard_count)
    setattr(
        merged.metadata,
        MERGED_SHARD_INDICES_KEY,
        [assignment.shard_index for _, _, assignment in shards],
    )


def apply_aggregated_suppressions(
    merged: AshAggregatedResults, plugin_context: PluginContext
) -> AshAggregatedResults:
    """Run the aggregated suppression pass ``ash scan`` runs, over the merged SARIF.

    Why this has to exist here
    --------------------------
    ``AshExecutionEngine`` applies ``apply_suppressions_to_sarif`` to the
    *aggregated* SARIF immediately before the report phase, and then re-runs
    ``populate_metrics_from_unified_source`` so the exit code reflects the
    post-suppression state. Its stated reason is that the per-scanner passes miss
    findings whose paths only become matchable after merge and normalization.

    ``ash merge`` folded n shard SARIFs and went straight to metrics and reports,
    so nothing ever applied suppressions to the cross-shard product. A suppression
    that only matches post-merge therefore applied in an unsharded scan and not in
    a sharded one: ``ash merge`` exited 2 where ``ash scan`` exited 0 on identical
    inputs. That is precisely the divergence ``_merged_exit_code``'s own docstring
    argues must not exist, and it is worse than an ordinary bug because the two
    commands are supposed to be interchangeable -- CI gates on the sharded one.

    Why the ignore_suppressions guard is duplicated from the engine
    --------------------------------------------------------------
    ``apply_suppressions_to_sarif`` also checks ``ignore_suppressions`` itself, so
    the guard here looks redundant, and on the configuration the tests cover it
    provably is: calling the function with ``ignore_suppressions=True`` was
    measured to produce byte-identical SARIF to not calling it at all, and
    deleting this condition kills no test.

    It is kept for two reasons that the measurement does not cover. The engine
    carries the identical guard, and the property being fixed is that the two
    paths agree -- a merge path relying on the callee's check while the scan path
    relies on the caller's would drift apart the moment either changed. And the
    equivalence was only measured for a config with no ``ignore_paths``: inside
    the function, the ignore-path branch is gated on ``not ignore_suppressions``
    combined with a path match, so a config that sets ``ignore_paths`` could
    behave differently between "skipped" and "called with the flag set". Skipping
    the call is what ``ash scan`` does, so skipping it is what keeps the verdicts
    equal in the configurations no fixture here exercises.

    Args:
        merged: The merged results, with metrics already populated from the union.
        plugin_context: Carries the scan's own config and ``ignore_suppressions``.

    Returns:
        *merged*, with suppressions applied and metrics recomputed. Returned
        rather than mutated in place only because
        ``populate_metrics_from_unified_source`` returns the model.
    """
    if (
        not plugin_context.ignore_suppressions
        and merged is not None
        and merged.sarif is not None
    ):
        # Imported here, matching the engine, which imports it inside the report
        # branch. sarif_utils pulls in the SARIF model and the config tree, and
        # ``ash merge`` reaches this point only after a successful merge.
        from automated_security_helper.utils.sarif_utils import (
            apply_suppressions_to_sarif,
        )

        merged.sarif = apply_suppressions_to_sarif(
            sarif_report=merged.sarif,
            plugin_context=plugin_context,
            used_suppressions=getattr(merged, "used_suppressions", None),
        )

    # Recomputed unconditionally, not only when suppressions ran. Under
    # ``--ignore-suppressions`` the counts merge_shard_results already produced are
    # correct, so this is a no-op there; making it conditional would put the "did
    # the counts get refreshed" question on the same branch as "did suppressions
    # run", and the exit code depends on the first.
    return populate_metrics_from_unified_source(aggregated_results=merged)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parse_output_formats(raw: Optional[List[str]]) -> List[str]:
    """Split and validate comma-separated ``--output-formats`` values.

    Validated against ``ExportFormat`` the same way ``ash scan`` validates it, so
    a typo fails immediately with the list of valid formats rather than silently
    producing no report of that kind.
    """
    parsed: List[str] = []
    for item in raw or []:
        for candidate in item.split(","):
            candidate = candidate.strip()
            if not candidate:
                continue
            try:
                parsed.append(ExportFormat(candidate).value)
            except ValueError:
                valid = ", ".join(fmt.value for fmt in ExportFormat)
                raise typer.BadParameter(
                    f"'{candidate}' is not a valid format. Valid formats are: {valid}"
                )
    return parsed


def merge_command(
    results: Annotated[
        List[str],
        typer.Option(
            "--results",
            help=(
                f"A shard's {RESULTS_FILE_NAME}, or a directory containing one. "
                f"Repeat once per shard."
            ),
        ),
    ],
    output_dir: Annotated[
        str,
        typer.Option(
            "--output-dir",
            help="Directory to write the merged results and reports to.",
            envvar="ASH_OUTPUT_DIR",
        ),
    ],
    output_formats: Annotated[
        Optional[List[str]],
        typer.Option(
            "--output-formats",
            help=(
                "Comma-separated report formats to generate. Defaults to the "
                "formats the scan's own configuration asks for."
            ),
        ),
    ] = None,
    min_severity: Annotated[
        str,
        typer.Option(
            "--min-severity",
            help="Minimum severity that counts as actionable for the exit code.",
        ),
    ] = "low",
    ignore_suppressions: Annotated[
        bool,
        typer.Option(
            "--ignore-suppressions",
            help=(
                "Ignore all suppression rules and report every finding regardless "
                "of suppression status. Mirrors 'ash scan --ignore-suppressions', "
                "so the same tree gives the same verdict sharded or not."
            ),
        ),
    ] = False,
    fail_on_findings: Annotated[
        Optional[bool],
        typer.Option(
            "--fail-on-findings/--no-fail-on-findings",
            help=(
                "Exit non-zero when the merged report has actionable findings. "
                "Defaults to the scan configuration's value, then to true."
            ),
        ),
    ] = None,
    fail_on_incomplete_scanners: Annotated[
        Optional[bool],
        typer.Option(
            "--fail-on-incomplete-scanners/--no-fail-on-incomplete-scanners",
            help=(
                "Refuse the merge when a shard completed none of the scanners it "
                "owned, and exit 1 when any scanner in the union is ERROR or "
                "MISSING. Without this, a shard whose scanners never ran "
                "contributes no findings and the merged report reads as a "
                "complete, clean scan. Defaults to the scan configuration's "
                "value, then to false."
            ),
        ),
    ] = None,
    log_level: Annotated[
        AshLogLevel, typer.Option("--log-level", help="Set the log level.")
    ] = AshLogLevel.INFO,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Enable verbose logging")
    ] = False,
    debug: Annotated[
        bool, typer.Option("--debug", "-d", help="Enable debug logging")
    ] = False,
    color: Annotated[bool, typer.Option(help="Enable/disable colorized output")] = True,
):
    """Merge the shard results of a sharded scan into one unified report.

    Each executor of ``ash scan --shard-index k --shard-count n`` writes its own
    results file. This command checks that the shards given reconstruct exactly
    one whole scan, merges them, writes the unified
    ``ash_aggregated_results.json`` and every requested report format, and exits
    with the verdict for the union.

    A shard that owned no failing scanner exits 0, so CI must gate on this
    command and not on per-shard success.
    """
    final_log_level = (
        AshLogLevel.VERBOSE
        if verbose
        else (
            AshLogLevel.DEBUG
            if debug
            else (
                AshLogLevel.ERROR
                if log_level
                in [AshLogLevel.QUIET, AshLogLevel.ERROR, AshLogLevel.SIMPLE]
                else log_level
            )
        )
    )
    logger = get_logger(
        level=logging._nameToLevel.get(final_log_level.value, logging.INFO),
        show_progress=False,
        use_color=color,
    )

    parsed_formats = _parse_output_formats(output_formats)

    try:
        loaded = load_shard_results(results)
        # Resolved before merging, because the contribution refusal has to happen
        # before a merged report exists on disk. Read from the shard results' own
        # config for the same reason the verdict is: a collector job need not have
        # the source tree checked out, and a config file found on this host could
        # disagree with the one the shards scanned under. The lowest-indexed shard
        # supplies the report's identity elsewhere in this module, so it supplies
        # this too.
        require_completion = _resolve_require_scanner_completion(
            loaded, fail_on_incomplete_scanners
        )
        merged = merge_shard_results(
            loaded, require_scanner_completion=require_completion
        )
    except ShardCoverageError as exc:
        # Printed rather than raised as a traceback: every one of these is an
        # operator-actionable statement about their CI matrix or artifacts, and
        # the message already says what to check. Exit 1 is ASH's "error during
        # execution" code, which is the honest verdict -- the scan's findings are
        # unknown, which is not the same as "no findings".
        print(f"[red]Refusing to merge: {exc}[/red]")
        raise typer.Exit(1)

    output_dir_path = Path(output_dir)
    output_dir_path.mkdir(parents=True, exist_ok=True)

    # The scan's own configuration, carried through the shard results, rather
    # than a config file resolved on this host. The collector job need not have
    # the source tree checked out at all, and a config file found here could
    # disagree with the one the shards actually scanned under -- which would move
    # the verdict without moving the findings.
    plugin_context = PluginContext(
        source_dir=Path.cwd(),
        output_dir=output_dir_path,
        work_dir=output_dir_path.joinpath("work"),
        config=merged.ash_config or AshConfig(),
        ignore_suppressions=ignore_suppressions,
    )

    merged = apply_aggregated_suppressions(merged, plugin_context)

    # Written after the suppression pass, not before. Writing first was the
    # original order and it would now leave the merged results file describing a
    # pre-suppression state while the reports and the exit code describe the
    # post-suppression one -- two artifacts of the same run disagreeing about
    # which findings are actionable.
    merged_file = output_dir_path.joinpath(RESULTS_FILE_NAME)
    merged_file.write_text(merged.model_dump_json(indent=2), encoding="utf-8")
    logger.info(f"Wrote merged results to {merged_file}")

    ash_plugin_manager.set_context(plugin_context)
    load_plugins(plugin_context=plugin_context)

    # ReportPhase writes reports/ash.<extension> for every enabled reporter, and
    # its progress display is used unconditionally, so a display is supplied with
    # output turned off rather than None.
    report_phase = ReportPhase(
        plugins=ash_plugin_manager.plugin_modules(plugin_type="reporter"),
        plugin_context=plugin_context,
        progress_display=LiveProgressDisplay(show_progress=False),
        asharp_model=merged,
    )
    merged = report_phase.execute(
        report_dir=output_dir_path.joinpath("reports"),
        cli_output_formats=parsed_formats or None,
        aggregated_results=merged,
        python_based_plugins_only=False,
    )

    exit_code = _merged_exit_code(
        merged,
        output_dir_path,
        min_severity,
        fail_on_findings,
        fail_on_incomplete_scanners,
    )
    _print_merge_summary(merged, merged_file, exit_code)
    if exit_code != 0:
        raise typer.Exit(exit_code)


def _resolve_require_scanner_completion(
    loaded: Sequence[Tuple[Path, AshAggregatedResults]],
    cli_value: Optional[bool],
) -> bool:
    """Whether to refuse a merge whose shards completed nothing.

    The CLI flag wins; otherwise the scan's own ``fail_on_incomplete_scanners``,
    carried in the shard results; otherwise off. The same precedence
    ``fail_on_findings`` follows, so an operator does not have to remember which
    of the two knobs reads the config first.

    Called before coverage has been verified, so the shards are in whatever order
    ``--results`` listed them and any of them may be unstamped. Every shard of one
    run carries the same config, so the first that carries one is as good as any;
    reading them all would only matter for a set that is about to be refused for
    disagreeing anyway.
    """
    if cli_value is not None:
        return cli_value
    for _, results in loaded:
        value = getattr(results.ash_config, "fail_on_incomplete_scanners", None)
        if isinstance(value, bool):
            return value
    return False


def _merged_exit_code(
    merged: AshAggregatedResults,
    output_dir: Path,
    min_severity: str,
    fail_on_findings: Optional[bool],
    fail_on_incomplete_scanners: Optional[bool] = None,
) -> int:
    """Compute the verdict for the union using the scan's own exit-code rules.

    Delegates to ``run_ash_scan._compute_exit_code`` rather than re-deriving the
    severity tables. Those tables were duplicated once already, which is why
    ``utils/severity_ladder.py`` exists; a third copy here would let ``ash merge``
    and ``ash scan`` disagree about the same findings, and the disagreement would
    only show up as a CI job that passes when it should fail.

    Called after the report phase because ``_compute_exit_code`` reads
    ``reports/ash.sarif`` to apply ``severity_threshold``, and that file is
    written by the SARIF reporter. When no SARIF report was requested it falls
    back to the in-memory unified metrics -- the same fallback a single scan with
    the SARIF reporter disabled takes, so parity holds either way.

    Delegating also means the completeness gate is inherited rather than
    reimplemented. It answers a narrower question than the pre-merge contribution
    refusal: a shard that ran two of its three scanners contributed something, so
    it is not refused, but the union is still short one scanner and this reports
    it.
    """
    from automated_security_helper.interactions.run_ash_scan import (
        ScanOptions,
        _compute_exit_code,
    )

    options = ScanOptions(
        source_dir=Path.cwd(),
        output_dir=output_dir,
        min_severity=min_severity,
        fail_on_findings=fail_on_findings,
        fail_on_incomplete_scanners=fail_on_incomplete_scanners,
        show_summary=False,
        progress=False,
    )
    config_fail_on_findings = getattr(merged.ash_config, "fail_on_findings", None)
    config_fail_on_incomplete = getattr(
        merged.ash_config, "fail_on_incomplete_scanners", None
    )
    return _compute_exit_code(
        merged, options, config_fail_on_findings, config_fail_on_incomplete
    )


def _print_merge_summary(
    merged: AshAggregatedResults, merged_file: Path, exit_code: int
) -> None:
    """Report what was merged and what the union's verdict is."""
    stats = merged.metadata.summary_stats
    indices = getattr(merged.metadata, MERGED_SHARD_INDICES_KEY, []) or []
    count = getattr(merged.metadata, MERGED_SHARD_COUNT_KEY, len(indices))

    print(
        f"\n[cyan]=== ASH Merge: {len(indices)} of {count} shards recombined ===[/cyan]"
    )
    print(f"Merged results: {merged_file.as_posix()}")
    print(
        f"Scanners: {len(merged.scanner_results)} | "
        f"Findings: {stats.total} | Actionable: {stats.actionable} | "
        f"Suppressed: {stats.suppressed}"
    )
    if exit_code == 2:
        print(
            f"[bold red]ERROR (2) Exiting due to {stats.actionable} actionable "
            f"findings across the merged shards[/bold red]"
        )
    elif exit_code == 1:
        # Reached when the union carries an ERROR or MISSING scanner but no shard
        # was empty enough to be refused outright. Naming the scanners matters
        # more here than in a single scan: the operator has n CI jobs and no other
        # way to tell which one to look at.
        from automated_security_helper.interactions.run_ash_scan import (
            incomplete_scanners,
        )

        incomplete = incomplete_scanners(merged)
        if incomplete:
            print(
                f"[bold red]ERROR (1) Exiting because {len(incomplete)} scanner(s) "
                f"in the merged scan did not complete[/bold red]"
            )
            for name, status in incomplete:
                print(f"  [red]{name}: {status}[/red]")
