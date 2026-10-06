# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The results files every other output is derived from, and the workspace manifest.

``ash_aggregated_results.json`` is what ``ashx report``, ``ashx merge``, the MCP server
and every downstream consumer read back, so its shape is a contract in its own right
and not only an input to the reporters.
"""

from __future__ import annotations

import json

import pytest

from tests.snapshot.support.fixture_model import (
    SKIPPED_WORKSPACE_FILE,
    WORKSPACE_FILE,
    finalize_fixture_model,
)
from tests.snapshot.support.reporter_catalog import reporter_classes

WORKSPACE_FIXTURES = {
    "workspace": ("fixture_workspace_model", WORKSPACE_FILE),
    "skipped-workspace": ("fixture_skipped_workspace_model", SKIPPED_WORKSPACE_FILE),
}


def test_aggregated_results_json(fixture_model, tmp_path, text_snapshot):
    """The single-directory file, byte for byte as ``save_model`` writes it.

    Taken from the model in its end-of-run state (timing stamped, metrics
    re-populated), which is the content ``run_ash_scan`` leaves on disk.
    """
    model = finalize_fixture_model(fixture_model)
    model.save_model(tmp_path / "final")

    written = (tmp_path / "final" / "ash_aggregated_results.json").read_text("utf-8")

    assert written == text_snapshot("json")


@pytest.mark.parametrize("variant", sorted(WORKSPACE_FIXTURES))
def test_workspace_aggregated_results_json(variant, request, tmp_path, text_snapshot):
    """The unified workspace file ``WorkspaceAggregator.write`` streams.

    Re-indented before comparison: the aggregator writes one header key per line
    and every SARIF run on a single line, which would make any change a one-line
    diff of the whole file. Key order and values are unchanged.
    """
    from automated_security_helper.workspace.aggregation import RESULTS_FILENAME

    request.getfixturevalue(WORKSPACE_FIXTURES[variant][0])
    written = (tmp_path / "ash_output" / RESULTS_FILENAME).read_text("utf-8")

    assert json.dumps(json.loads(written), indent=2) == text_snapshot("json")


@pytest.mark.parametrize("variant", sorted(WORKSPACE_FIXTURES))
def test_workspace_report_manifest(variant, request, tmp_path, text_snapshot):
    """``reports/workspace-reports.json``: which reporters merged, which were withheld.

    Built-in reporters only. The four AWS reporters read their region, profile and
    destination from the environment when their module is imported, so whether
    they are "skipped: dependencies" or "per-project" here would depend on the
    machine running the test rather than on ASH.
    """
    from automated_security_helper.plugin_modules.ash_builtin import ASH_REPORTERS
    from automated_security_helper.workspace.aggregation import RESULTS_FILENAME
    from automated_security_helper.workspace.reporting import emit_workspace_reports
    from automated_security_helper.workspace.resolver import resolve_workspace

    fixture_name, workspace_file = WORKSPACE_FIXTURES[variant]
    request.getfixturevalue(fixture_name)
    output_dir = tmp_path / "ash_output"
    plan = resolve_workspace(
        workspace_file, allow_missing_projects=variant == "skipped-workspace"
    )
    assert set(ASH_REPORTERS) <= set(reporter_classes().values())

    outcome = emit_workspace_reports(
        plan=plan,
        output_dir=output_dir,
        results_path=output_dir / RESULTS_FILENAME,
        reporter_classes=list(ASH_REPORTERS),
    )

    assert outcome.manifest_path.read_text("utf-8") == text_snapshot("json")
