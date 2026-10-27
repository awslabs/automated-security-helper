# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``incomplete_converters_for_project`` maps each converter to its reason.

``run_ash_scan.incomplete_converters`` returns three-field rows (name, reason,
kinds). The workspace layer turned them into a ``{name: reason}`` mapping with
``dict(...)``, which needs two-item rows and raised ``ValueError`` for the first
incomplete converter of any project. These tests call the function directly, then
hand its result to the two readers of the mapping, so the shape each of them
receives is the one the workspace outcome carries.
"""

from __future__ import annotations

from pathlib import Path

from automated_security_helper.interactions.run_ash_scan import incomplete_converters
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ConverterStatusInfo,
    FailedInputInfo,
    RefusedInputInfo,
)
from automated_security_helper.models.workspace import (
    ProjectRunStatus,
    WorkspaceProjectResult,
)
from automated_security_helper.workspace.aggregation import (
    incomplete_converters_for_project,
)

OVER_LIMIT_REASON = (
    "refused 1 input over an extraction limit: vendor/big.zip (max_total_bytes)"
)


def _results(**rows: ConverterStatusInfo) -> AshAggregatedResults:
    model = AshAggregatedResults()
    for name, row in rows.items():
        model.converter_results[name] = row
    return model


def _archive_over_a_limit() -> ConverterStatusInfo:
    return ConverterStatusInfo(
        refused_inputs=[
            RefusedInputInfo(
                path="vendor/big.zip",
                reason="its members declare more bytes than the limit",
                limit="max_total_bytes",
            )
        ]
    )


class TestAProjectWithAnIncompleteConverter:
    def test_an_archive_over_a_limit_maps_to_its_reason(self):
        mapping = incomplete_converters_for_project(
            _results(archive=_archive_over_a_limit())
        )

        assert mapping == {"archive": OVER_LIMIT_REASON}
        assert type(mapping) is dict

    def test_a_crashed_converter_maps_to_its_failure_text(self):
        mapping = incomplete_converters_for_project(
            _results(jupyter=ConverterStatusInfo(failure="RuntimeError: boom"))
        )

        assert mapping == {"jupyter": "RuntimeError: boom"}

    def test_each_recorded_converter_keeps_its_own_reason_in_recorded_order(self):
        results = _results(
            archive=_archive_over_a_limit(),
            jupyter=ConverterStatusInfo(
                failed_inputs=[
                    FailedInputInfo(path="nb.ipynb", reason="nbconvert timed out")
                ]
            ),
            unavailable=ConverterStatusInfo(
                dependencies_satisfied=False, candidate_inputs=1
            ),
        )

        mapping = incomplete_converters_for_project(results)

        rows = incomplete_converters(results)
        assert [row.name for row in rows] == ["archive", "jupyter", "unavailable"]
        assert list(mapping.items()) == [(row.name, row.reason) for row in rows]
        assert mapping["jupyter"] == "could not convert 1 input: nb.ipynb"
        assert mapping["unavailable"] == "dependencies unavailable, so it never ran"


class TestAProjectWithNothingIncomplete:
    """Controls: the mapping is empty exactly when no converter lost coverage."""

    def test_no_results_map_to_nothing(self):
        assert incomplete_converters_for_project(None) == {}

    def test_converters_that_ran_map_to_nothing(self):
        results = _results(
            jupyter=ConverterStatusInfo(converted_paths=["converted/nb.py"])
        )

        assert incomplete_converters_for_project(results) == {}

    def test_an_excluded_converter_maps_to_nothing(self):
        results = _results(
            jupyter=ConverterStatusInfo(excluded=True, dependencies_satisfied=False)
        )

        assert incomplete_converters_for_project(results) == {}


class TestTheMappingReachesItsReaders:
    def test_the_mcp_project_coverage_lists_the_converter(self, tmp_path):
        from automated_security_helper.cli.mcp.workspace import _project_coverage

        outcome = WorkspaceProjectResult(
            project="app",
            relative_path="app",
            display_label="app",
            status=ProjectRunStatus.COMPLETED,
            output_path=str(Path(tmp_path)),
            scanners={"bandit": "PASSED"},
            incomplete_converters=incomplete_converters_for_project(
                _results(archive=_archive_over_a_limit())
            ),
            scan_incomplete=True,
        )

        coverage = _project_coverage(outcome)

        assert coverage["incomplete_converters"] == [
            {"converter": "archive", "reason": OVER_LIMIT_REASON}
        ]
