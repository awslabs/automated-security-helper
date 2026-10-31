# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The workspace table names each project's unconverted inputs and its policy gate.

The row's detail is where a reader learns what the counts cannot say. It named a
converter that lost coverage (``incomplete_converters``) and never the input; the
unified file holds no per-project converter rows, so the input's name was in no
merged report at all. It also showed a policy-origin finding count with no word
on whether those findings decided the verdict. Both now come from the payload's
``converter_refusals`` and ``policy_scanners_gate``.
"""

from __future__ import annotations

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.workspace import (
    ProjectConverterRefusal,
    ProjectRunStatus,
    WorkspaceProjectResult,
    WorkspaceResults,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.workspace_section import (
    REFUSALS_SHOWN_IN_ROW,
    text_workspace_section,
    workspace_policy_gates,
    workspace_project_rows,
    workspace_project_scanner_thresholds,
)

pytestmark = pytest.mark.unit


def _model(tmp_path, *projects: WorkspaceProjectResult) -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.workspace = WorkspaceResults(
        workspace_file=(tmp_path / "fixture.code-workspace").as_posix(),
        workspace_root=tmp_path.as_posix(),
        exit_code=0,
        projects=list(projects),
    )
    return model


def _project(key: str, **fields) -> WorkspaceProjectResult:
    return WorkspaceProjectResult(
        project=key,
        relative_path=key,
        display_label=key,
        status=ProjectRunStatus.COMPLETED,
        severity_threshold="MEDIUM",
        output_path=f"projects/{key}",
        **fields,
    )


def _refusal(
    path: str, reason: str = "nested archive", **fields
) -> ProjectConverterRefusal:
    return ProjectConverterRefusal(
        converter="archive", path=path, reason=reason, **fields
    )


class TestRefusedInputsAreNamed:
    def test_each_refused_input_is_in_the_detail(self, tmp_path):
        model = _model(
            tmp_path,
            _project(
                "api",
                incomplete_converters={"archive": "refused 1 input over a limit"},
                converter_refusals=[
                    _refusal(
                        "api/vendor/big.zip",
                        reason="over the max_total_bytes limit",
                        limit="max_total_bytes",
                        scan_incomplete=True,
                    ),
                    _refusal("api/outer.zip", member="inner.zip"),
                ],
            ),
        )

        (row,) = workspace_project_rows(model)

        # RED at the base: the detail named the converter and never the input.
        assert (
            "inputs not converted: archive: 'api/vendor/big.zip' (over the "
            "max_total_bytes limit) [scan incomplete], archive: member 'inner.zip' "
            "of 'api/outer.zip' (nested archive)"
        ) in row["detail"]
        # The converter-level summary stays beside it.
        assert "conversion incomplete: archive" in row["detail"]

    def test_a_long_list_is_capped_with_a_count(self, tmp_path):
        refusals = [
            _refusal(f"api/vendor/{index}.zip")
            for index in range(REFUSALS_SHOWN_IN_ROW + 2)
        ]
        model = _model(tmp_path, _project("api", converter_refusals=refusals))

        (row,) = workspace_project_rows(model)

        assert f"api/vendor/{REFUSALS_SHOWN_IN_ROW - 1}.zip" in row["detail"]
        assert f"api/vendor/{REFUSALS_SHOWN_IN_ROW}.zip" not in row["detail"]
        assert row["detail"].endswith("and 2 more")

    def test_the_text_report_carries_the_input(self, tmp_path):
        model = _model(
            tmp_path,
            _project("api", converter_refusals=[_refusal("api/outer.zip")]),
        )

        lines = text_workspace_section(model)

        assert any("api/outer.zip" in line for line in lines)


class TestThePolicyGateIsNamed:
    def test_a_non_gating_policy_count_says_so(self, tmp_path):
        model = _model(
            tmp_path,
            _project("api", policy_origin_finding_count=2, policy_scanners_gate=False),
        )

        (row,) = workspace_project_rows(model)

        # RED at the base: no such sentence; the count alone was shown nowhere.
        assert (
            "2 finding(s) from workspace-policy scanners do not gate this project"
            in row["detail"]
        )

    def test_a_gating_policy_count_says_so(self, tmp_path):
        model = _model(
            tmp_path,
            _project("api", policy_origin_finding_count=1, policy_scanners_gate=True),
        )

        (row,) = workspace_project_rows(model)

        assert (
            "1 finding(s) from workspace-policy scanners gate this project"
            in row["detail"]
        )

    def test_a_project_with_no_policy_findings_says_nothing(self, tmp_path):
        """Control: the sentence is for a count, not for the flag."""
        model = _model(tmp_path, _project("api", policy_scanners_gate=True))

        (row,) = workspace_project_rows(model)

        assert "workspace-policy" not in row["detail"]

    def test_a_record_written_before_the_field_reads_as_gating(self, tmp_path):
        """A pre-field file's verdict applied the gate before it wrote.

        Loaded from its JSON the field is absent (None); the row says the
        findings gate the project, the fail-closed side.
        """
        legacy = WorkspaceProjectResult.model_validate(
            {
                "project": "legacy",
                "relative_path": "legacy",
                "display_label": "legacy",
                "status": "completed",
                "severity_threshold": "MEDIUM",
                "output_path": "projects/legacy",
                "policy_origin_finding_count": 2,
            }
        )
        assert legacy.policy_scanners_gate is None

        (row,) = workspace_project_rows(_model(tmp_path, legacy))

        # RED at the base: the absent field read as False, so the row said the
        # findings "do not gate this project" for a verdict that counted them.
        assert (
            "2 finding(s) from workspace-policy scanners gate this project"
            in row["detail"]
        )


class TestTheReaderTables:
    def test_the_gate_table_names_every_project(self, tmp_path):
        model = _model(
            tmp_path,
            _project("legacy"),
            _project("watch", policy_scanners_gate=False),
            _project("strict", policy_scanners_gate=True),
        )

        # RED at the base: the table read the absent gate as False, so a reader
        # could not tell a pre-field record from a project that turned the gate off.
        assert workspace_policy_gates(model) == {
            "legacy": None,
            "watch": False,
            "strict": True,
        }

    def test_the_scanner_threshold_table_normalizes_and_drops_unknown_values(
        self, tmp_path
    ):
        model = _model(
            tmp_path,
            _project("api", scanner_thresholds={"bandit": "critical", "x": "LOUD"}),
            _project("web"),
        )

        assert workspace_project_scanner_thresholds(model) == {
            "api": {"bandit": "CRITICAL"}
        }

    def test_both_tables_are_empty_for_a_single_directory_scan(self):
        model = AshAggregatedResults()

        assert workspace_policy_gates(model) == {}
        assert workspace_project_scanner_thresholds(model) == {}
