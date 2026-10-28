# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The partial-loss rollup rule, read on the rows a real scan writes.

WHY THIS FILE EXISTS
--------------------
``test_scanner_status_across_targets`` builds its models by hand, with an empty
``scanner_results``, so every cell there reaches the ``"source"`` report branch of
``get_scanner_status_info``. Whether a scan reaches that branch depends on what is in
``scanner_results`` when the rebuild runs, and the scan writes that: a scanner whose
run returned an ERROR container is not recorded as completed, and the scan phase's
completeness check then writes the scanner an ERROR row of its own. The rebuild reads
that row first (``get_scanner_status_info``'s ``scanner_results`` branch), so a rule
that lives only in the ``"source"`` branch never runs for a scanner with an ERROR tree.

These cells run ``ScanPhase`` with the real executor loop, the real
``ScanResultProcessor`` and the real validation manager. Only the executor's
per-scanner work is replaced, and it returns containers graded by the container's own
``determine_status``, so the reports are the ones a run writes. Each cell reads the
row at three points: as the phase leaves it, after the rebuild the engine runs, and
after a JSON round trip and a second rebuild (what ``ash report`` and ``ash merge`` do).
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.phases.scan_phase import ScanPhase
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.core.unified_metrics import (
    populate_metrics_from_unified_source,
)
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerSeverityCount,
)
from automated_security_helper.models.scan_results_container import (
    ScanResultsContainer,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_nag_scanner import (
    CfnNagScanner,
)

SCANNER = "cfn-nag"
THRESHOLD = "MEDIUM"


def _sarif_with_one_high(scanner: str, uri: str):
    """A SARIF report carrying one HIGH result attributed to *scanner*."""
    from automated_security_helper.schemas.sarif_schema_model import (
        ArtifactLocation,
        Level,
        Location,
        Message,
        Message1,
        PhysicalLocation,
        PhysicalLocation2,
        PropertyBag,
        Region,
        Result,
        Run,
        SarifReport,
        Tool,
        ToolComponent,
    )

    return SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name=scanner, version="test")),
                results=[
                    Result(
                        ruleId=f"{scanner}-RULE-1",
                        level=Level("error"),
                        message=Message(root=Message1(text=f"{scanner} finding")),
                        properties=PropertyBag(
                            scanner_name=scanner, issue_severity="HIGH"
                        ),
                        locations=[
                            Location(
                                physicalLocation=PhysicalLocation(
                                    root=PhysicalLocation2(
                                        artifactLocation=ArtifactLocation(uri=uri),
                                        region=Region(startLine=1),
                                    )
                                )
                            )
                        ],
                    )
                ],
                invocations=[],
                properties=PropertyBag(),
            )
        ],
    )


def _tree(
    target_type: str,
    *,
    attempted: int,
    failed: int,
    high: int = 0,
    errors: tuple[str, ...] = (),
    force_error: bool = False,
    raw_failed: bool = False,
    could_not_stop: str | None = None,
) -> ScanResultsContainer:
    """One tree's container, graded the way the executor grades it.

    ``determine_status`` decides the status from the counters and the one gate, so a
    partial-loss ERROR here is the ERROR a run produces. *force_error* is the executor
    overwriting the grade (a killed tool: ``container.status = ERROR`` after grading),
    *raw_failed* is the ``scan()``-returned-None record, and *errors* are the lines the
    executor adds.
    """
    container = ScanResultsContainer(scanner_name=SCANNER, target_type=target_type)
    container.record_target_attempt(attempted)
    for index in range(failed):
        container.record_target_failure(f"template-{index}.json", "not evaluated")
    # The executor assigns the failure count on every tracked tree, zero included
    # (``scanner_executor``: ``container.targets_failed = ...``). The per-target report
    # is dumped with ``exclude_unset``, so a tree that lost nothing and never had the
    # field written would store an attempt count with no failure accounting, which the
    # stored-counter rule reads as unreadable and never complete.
    container.targets_failed = failed
    if high:
        container.severity_counts = ScannerSeverityCount(high=high)
        container.finding_count = high
        container.raw_results = _sarif_with_one_high(SCANNER, f"{target_type}/app.json")
    container.status = container.determine_status(THRESHOLD)
    for line in errors:
        container.add_error(line)
    if raw_failed:
        container.raw_results = {
            "status": "failed",
            "exception": "Scanner returned None",
        }
    if could_not_stop:
        container.could_not_stop = could_not_stop
    if force_error or raw_failed:
        container.status = ScannerStatus.ERROR
    return container


def _scan(
    tmp_path, *trees: ScanResultsContainer, raises: bool = False
) -> AshAggregatedResults:
    """``ScanPhase.execute`` over one scanner whose run returned *trees*, or raised.

    The executor loop, the result processor and the validation manager are the real
    ones; only the scanner's own run is replaced.
    """
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("print('hello')\n", encoding="utf-8")
    output = tmp_path / "output"
    (output / ASH_WORK_DIR_NAME).mkdir(parents=True)
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / ASH_WORK_DIR_NAME,
        config=get_default_config(),
    )

    class _WithTool(CfnNagScanner):
        def validate_plugin_dependencies(self) -> bool:
            return True

    _WithTool.__name__ = CfnNagScanner.__name__
    _WithTool.__module__ = CfnNagScanner.__module__

    aggregated = AshAggregatedResults()
    phase = ScanPhase(
        plugin_context=context,
        plugins=[_WithTool],
        progress_display=MagicMock(),
        asharp_model=aggregated,
    )

    def _execute(executor_self, scanner_name, scanner_plugin, scan_targets):
        if raises:
            raise RuntimeError("the scanner's run raised")
        return list(trees)

    with patch.object(
        ScannerExecutor, "_execute_scanner", autospec=True, side_effect=_execute
    ):
        return phase.execute(aggregated_results=aggregated, parallel=False)


def _rows(results: AshAggregatedResults):
    """The scanner's row as the phase leaves it (None when it left none), as the
    engine rebuilds it, and as ``ash report`` and ``ash merge`` rebuild it after
    reading the JSON back. Each with the model it belongs to."""
    left = results.scanner_results.get(SCANNER)
    left = left.model_copy(deep=True) if left is not None else None
    rebuilt = populate_metrics_from_unified_source(aggregated_results=results)
    reloaded = populate_metrics_from_unified_source(
        aggregated_results=AshAggregatedResults.model_validate_json(
            rebuilt.model_dump_json()
        )
    )
    return [
        ("as the phase leaves it", left, results),
        ("rebuilt", rebuilt.scanner_results[SCANNER], rebuilt),
        ("reloaded", reloaded.scanner_results[SCANNER], reloaded),
    ]


def _after_rebuild(rows):
    """The rows a report or a merge reads: everything after the phase's own."""
    return [(when, row, model) for when, row, model in rows if when != rows[0][0]]


def _listed_as_incomplete(model: AshAggregatedResults):
    from automated_security_helper.interactions.run_ash_scan import (
        scan_incompleteness,
    )

    return scan_incompleteness(model, gate=True).scanners


class TestThePhaseLeavesAnErrorRowForAnErrorTree:
    """Why a rule that lives only in the ``"source"`` report branch never runs.

    Measured on this tree: a scanner whose run returned a partial-loss ERROR tree is not
    recorded as completed, so the phase's completeness check writes it an ERROR row
    before the rebuild runs, and the rebuild reads that row first. A scanner whose trees
    are all clean gets no row until the rebuild.
    """

    def test_the_row_is_error_and_counts_nothing(self, tmp_path):
        results = _scan(
            tmp_path,
            _tree("source", attempted=10, failed=4),
            _tree("converted", attempted=3, failed=0, high=1),
        )

        row = results.scanner_results[SCANNER]

        assert row.status == ScannerStatus.ERROR, row
        assert row.finding_count == 0, row

    def test_a_scanner_with_only_clean_trees_has_no_row_yet(self, tmp_path):
        results = _scan(
            tmp_path,
            _tree("source", attempted=10, failed=0),
            _tree("converted", attempted=3, failed=0),
        )

        assert SCANNER not in results.scanner_results


class TestAPartialLossTreeBesideFindingsThroughTheRealPath:
    """The accepted rollup rule, read on the rows a scan writes.

    A tree that lost SOME of its targets does not outrank a gate-failing finding on
    either tree; a tree that lost EVERY target does. The partial loss stays visible in
    the completeness gate's list, with its denominator.
    """

    @pytest.mark.parametrize(
        "lost_tree",
        ["source", "converted"],
    )
    def test_partial_loss_beside_a_failed_sibling_rolls_up_failed(
        self, tmp_path, lost_tree
    ):
        """Both orientations, so the fix cannot be a source-versus-converted swap."""
        lost = _tree(lost_tree, attempted=10, failed=4)
        kept_name = "converted" if lost_tree == "source" else "source"
        kept = _tree(kept_name, attempted=3, failed=0, high=1)
        trees = (lost, kept) if lost_tree == "source" else (kept, lost)

        rows = _rows(_scan(tmp_path, *trees))

        assert lost.status == ScannerStatus.ERROR
        assert kept.status == ScannerStatus.FAILED
        for when, row, model in _after_rebuild(rows):
            assert row.status == ScannerStatus.FAILED, (when, row)
            assert (row.severity_counts.high, row.actionable_finding_count) == (
                1,
                1,
            ), (when, row)
            assert (
                SCANNER,
                "FAILED (4 of 13 targets unevaluated)",
            ) in _listed_as_incomplete(model), when

    def test_a_partial_loss_beside_a_clean_sibling_stays_error(self, tmp_path):
        rows = _rows(
            _scan(
                tmp_path,
                _tree("source", attempted=10, failed=4),
                _tree("converted", attempted=3, failed=0),
            )
        )

        for when, row, model in _after_rebuild(rows):
            assert row.status == ScannerStatus.ERROR, (when, row)
            assert (
                SCANNER,
                "ERROR (4 of 13 targets unevaluated)",
            ) in _listed_as_incomplete(model), when

    def test_a_total_loss_tree_still_outranks_a_failed_sibling(self, tmp_path):
        rows = _rows(
            _scan(
                tmp_path,
                _tree("source", attempted=10, failed=10),
                _tree("converted", attempted=3, failed=0, high=1),
            )
        )

        for when, row, _model in _after_rebuild(rows):
            assert row.status == ScannerStatus.ERROR, (when, row)
            assert row.severity_counts.high == 1, (when, row)

    def test_a_partial_loss_with_its_finding_on_the_same_tree_reads_failed(
        self, tmp_path
    ):
        """The same-tree twin: ``determine_status`` grades the tree FAILED itself."""
        tree = _tree("source", attempted=10, failed=4, high=1)

        rows = _rows(_scan(tmp_path, tree))

        assert tree.status == ScannerStatus.FAILED
        for when, row, _model in _after_rebuild(rows):
            assert row.status == ScannerStatus.FAILED, (when, row)

    def test_a_run_that_raised_stays_error(self, tmp_path):
        """An ERROR row no per-target report explains is not deferred: the executor
        records no completion for a run that raised, and that row is the only record."""
        rows = _rows(_scan(tmp_path, raises=True))

        for when, row, _model in _after_rebuild(rows):
            assert row.status == ScannerStatus.ERROR, (when, row)


class TestAnErrorACauseOverwroteIsNotAPartialLoss:
    """The counters alone do not make an ERROR tree a partial loss.

    ``determine_status`` grades a partial loss ERROR only when the tree's own findings
    pass the gate, and the executor writes ERROR over other grades for causes of its
    own: a killed tool, a ``scan()`` that returned nothing, a tool it could not stop.
    Those trees keep partial counters, and treating them as partial losses reads a
    killed tool as a graded partial audit (``FAILED`` beside a finding).
    """

    KILLED = f"{SCANNER} timed out after 300s on source and was killed"

    @pytest.mark.parametrize("killed_tree", ["source", "converted"])
    def test_a_killed_tool_with_a_finding_on_its_own_tree_stays_error(
        self, tmp_path, killed_tree
    ):
        """The review's shape: the tool is killed on one template after the others
        rendered, and the surviving finding sits on the same tree."""
        killed = _tree(
            killed_tree,
            attempted=10,
            failed=1,
            high=1,
            errors=(self.KILLED,),
            force_error=True,
        )
        other_name = "converted" if killed_tree == "source" else "source"
        other = _tree(other_name, attempted=3, failed=0)
        trees = (killed, other) if killed_tree == "source" else (other, killed)

        rows = _rows(_scan(tmp_path, *trees))

        # The finding passes the gate on its own tree, so ``determine_status`` would
        # have graded this tree FAILED: the ERROR is the kill's.
        for when, row, _model in _after_rebuild(rows):
            assert row.status == ScannerStatus.ERROR, (when, row)
            assert row.severity_counts.high == 1, (when, row)

    def test_a_scan_that_returned_nothing_beside_a_failed_sibling_stays_error(
        self, tmp_path
    ):
        rows = _rows(
            _scan(
                tmp_path,
                _tree("source", attempted=10, failed=4, raw_failed=True),
                _tree("converted", attempted=3, failed=0, high=1),
            )
        )

        for when, row, _model in _after_rebuild(rows):
            assert row.status == ScannerStatus.ERROR, (when, row)

    def test_a_tool_that_could_not_be_stopped_beside_a_failed_sibling_stays_error(
        self, tmp_path
    ):
        rows = _rows(
            _scan(
                tmp_path,
                _tree("source", attempted=10, failed=4, could_not_stop="pid 4242"),
                _tree("converted", attempted=3, failed=0, high=1),
            )
        )

        for when, row, _model in _after_rebuild(rows):
            assert row.status == ScannerStatus.ERROR, (when, row)

    def test_a_genuine_partial_loss_still_reads_failed(self, tmp_path):
        """The control: the same counters with no cause beside them are the accepted
        per-tree rule (a partial loss does not outrank a failed sibling)."""
        rows = _rows(
            _scan(
                tmp_path,
                _tree("source", attempted=10, failed=4),
                _tree("converted", attempted=3, failed=0, high=1),
            )
        )

        for when, row, _model in _after_rebuild(rows):
            assert row.status == ScannerStatus.FAILED, (when, row)
