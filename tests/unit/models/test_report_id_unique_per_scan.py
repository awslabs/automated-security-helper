# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``metadata.report_id`` names one scan, not one day.

Why this exists
---------------
Every scan carries its own ``report_id``, the field whose description is "Unique
identifier for the report", so two CI runs on one day, or the shards of one sharded
scan, are told apart by it. A workspace scan gets one too, not a fixed
``ASH-WORKSPACE-<file stem>``, which a stem with a space would turn into an id the
model's own pattern rejects.

The id is ``ASH-<UTC YYYYMMDDHHMMSS>-<12 hex digits>``: ``ASH-`` and the scan's
date first, so ids sort by time and an ``ASH-YYYYMMDD`` prefix identifies the day,
plus a random part that separates scans started in the
same second. Saved results keep their id when reports are rendered again, and
``ash merge`` derives one id for the union from its shards' ids (see
``tests/unit/cli/test_merge.py::TestMergedReportId``).
"""

import re
from datetime import datetime, timezone

import pytest

from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ReportMetadata,
)
from automated_security_helper.workspace.aggregation import WorkspaceAggregator
from automated_security_helper.workspace.plan import WorkspacePlan

pytestmark = pytest.mark.unit

REPORT_ID = re.compile(r"^ASH-(?P<stamp>\d{14})-(?P<token>[0-9a-f]{12})$")


def test_two_scans_get_different_ids():
    """Created back to back, so inside the same second: the date alone collided."""
    first = AshAggregatedResults().metadata.report_id
    second = AshAggregatedResults().metadata.report_id

    assert first != second


def test_the_id_starts_with_the_scan_time_in_utc():
    before = datetime.now(timezone.utc).replace(microsecond=0)
    report_id = AshAggregatedResults().metadata.report_id
    after = datetime.now(timezone.utc)

    match = REPORT_ID.match(report_id)
    assert match, f"unexpected report_id format: {report_id}"
    stamp = datetime.strptime(match["stamp"], "%Y%m%d%H%M%S").replace(
        tzinfo=timezone.utc
    )
    assert before <= stamp <= after


def test_the_id_passes_the_models_own_pattern():
    ReportMetadata.model_validate(
        {"report_id": AshAggregatedResults().metadata.report_id}
    )


def test_metadata_built_without_an_id_gets_a_unique_one():
    first = ReportMetadata().report_id
    second = ReportMetadata().report_id

    assert REPORT_ID.match(first)
    assert first != second


def test_saved_results_keep_their_id():
    """``ash report`` and ``--use-existing`` re-render from the results file."""
    model = AshAggregatedResults()

    reloaded = AshAggregatedResults.model_validate_json(model.model_dump_json())

    assert reloaded.metadata.report_id == model.metadata.report_id


def test_an_explicit_time_and_token_are_used():
    from automated_security_helper.models.asharp_model import new_report_id

    instant = datetime(2026, 10, 11, 15, 30, 12, tzinfo=timezone.utc)

    assert new_report_id(now=instant, token="0123456789ab") == (
        "ASH-20261011153012-0123456789ab"
    )


class TestWorkspaceReportId:
    @staticmethod
    def _write(tmp_path, stem: str, run: int) -> AshAggregatedResults:
        plan = WorkspacePlan(
            workspace_file=(tmp_path / f"{stem}.code-workspace").as_posix(),
            workspace_root=tmp_path.as_posix(),
            projects=[],
        )
        aggregator = WorkspaceAggregator(plan=plan, output_dir=tmp_path / f"out{run}")
        path = aggregator.write(exit_code=0, wall_clock_seconds=1.0)
        return AshAggregatedResults.model_validate_json(
            path.read_text(encoding="utf-8")
        )

    def test_two_runs_of_one_workspace_get_different_ids(self, tmp_path):
        first = self._write(tmp_path, "platform", 1).metadata.report_id
        second = self._write(tmp_path, "platform", 2).metadata.report_id

        assert first != second
        assert first.startswith("ASH-WORKSPACE-platform-")

    @pytest.mark.parametrize(
        "stem",
        ["my workspace", "team (prod)", "ünïcode", "proj²", "half½", "circled①"],
    )
    def test_any_workspace_file_name_gives_a_loadable_results_file(
        self, tmp_path, stem
    ):
        model = self._write(tmp_path, stem, 1)

        assert model.metadata.report_id.startswith("ASH-WORKSPACE-")
