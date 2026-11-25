# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The status family's vocabularies are enums, and their spellings live in one place.

Covers the scanner statuses (``ScannerStatus``), the MCP registry's two status
vocabularies and the error categories (``MCScanStatus``, ``MCScannerStatus``,
``ErrorCategory``), the ``--min-severity`` rank tables (``MinSeverity``), the
project and workspace run statuses (``ProjectRunStatus``, ``WorkspaceRunStatus``).

Two parts:

* Pins. Each derived table is checked against the enum it is keyed by, so a member
  added to the enum without a table row (or a table row with no member) fails here.
* A drift gate in two modes. Distinctive spellings (``PASSED``, ``refused`` ...) are
  scanned for as string constants in the files each vocabulary was cured in; the
  ambiguous short words are pinned at the sites instead. A planted stray spelling
  proves the scan is alive.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Iterable, List, Tuple

import pytest

from automated_security_helper.core.enums import MinSeverity, ScannerStatus
from automated_security_helper.core.resource_management import (
    result_filters,
    scan_tracking,
)
from automated_security_helper.core.resource_management.error_handling import (
    ErrorCategory,
)
from automated_security_helper.core.resource_management.scan_registry import (
    ENDED,
    MCScanStatus,
)
from automated_security_helper.core.resource_management.scan_tracking import (
    MCScannerStatus,
)
from automated_security_helper.models.asharp_model import SummaryStats
from automated_security_helper.models.workspace import (
    ProjectRunStatus,
    WorkspaceResults,
    WorkspaceRunStatus,
)

pytestmark = pytest.mark.unit

PACKAGE = Path(__file__).resolve().parents[3] / "automated_security_helper"


# ---------------------------------------------------------------------------
# Pins
# ---------------------------------------------------------------------------


def test_the_mcp_status_trio_is_str_enums_that_serialize_as_their_values():
    for enum in (MCScanStatus, MCScannerStatus, ErrorCategory):
        assert issubclass(enum, str), enum
        for member in enum:
            assert json.dumps({"k": member}) == json.dumps({"k": member.value})


def test_the_registry_status_has_cancelled_with_a_writer_set_already():
    """B6's verdict: the member exists and is terminal; nothing was added for it."""
    assert MCScanStatus.CANCELLED.value == "cancelled"
    assert MCScanStatus.CANCELLED in ENDED


def test_the_scanner_status_rollup_order_names_every_member_once():
    from automated_security_helper.workspace.aggregation import (
        _SCANNER_STATUS_SEVERITY,
        _worse_status,
    )

    assert sorted(_SCANNER_STATUS_SEVERITY) == sorted(ScannerStatus)
    assert len(set(_SCANNER_STATUS_SEVERITY)) == len(_SCANNER_STATUS_SEVERITY)
    # ERROR is the worst news, PASSED the best, as the table's comment says.
    assert _worse_status("PASSED", "ERROR") == "ERROR"
    assert _worse_status("SKIPPED", "FAILED") == "FAILED"
    assert _worse_status(None, "MISSING") == "MISSING"
    assert _worse_status("PASSED", "PASSED") == "PASSED"


def test_the_outcome_counters_are_one_per_member_and_name_summary_fields():
    assert set(result_filters._OUTCOME_COUNTERS) == set(ScannerStatus)
    assert set(result_filters._OUTCOME_COUNTERS.values()) <= set(
        SummaryStats.model_fields
    )
    # The five lowercase counters of the model are exactly the members' names.
    assert {member.value.lower() for member in ScannerStatus} <= set(
        SummaryStats.model_fields
    )
    for member in ScannerStatus:
        assert result_filters._OUTCOME_COUNTERS[member] == member.value.lower()


def test_the_outcome_counter_reads_the_word_without_regard_to_case():
    counter = result_filters._outcome_counter
    assert counter({"status": "passed"}) == "passed"
    assert counter({}) == "passed"
    assert counter({"status": "ERROR"}) == "error"
    assert counter({"status": "bogus"}) is None
    assert counter({"status": 3}) is None


def test_the_progress_status_map_covers_every_scanner_status_member():
    assert set(scan_tracking._SCANNER_STATUS_MAP) == set(ScannerStatus)
    from_results = scan_tracking.scanner_status_from_results
    assert from_results("passed") is MCScannerStatus.COMPLETED
    assert from_results("MISSING") is MCScannerStatus.SKIPPED
    assert from_results("ERROR") is MCScannerStatus.FAILED
    assert from_results("bogus") is MCScannerStatus.FAILED
    assert from_results(None) is MCScannerStatus.FAILED


def test_the_min_severity_rank_tables_are_keyed_by_every_member_and_agree():
    from automated_security_helper.interactions.run_ash_scan import _SEVERITY_RANK
    from automated_security_helper.workspace.aggregation import _MIN_SEVERITY_RANK

    assert set(_SEVERITY_RANK) == set(MinSeverity)
    assert dict(_SEVERITY_RANK) == dict(_MIN_SEVERITY_RANK)
    assert _SEVERITY_RANK[MinSeverity.CRITICAL] == _SEVERITY_RANK[MinSeverity.HIGH]
    assert _SEVERITY_RANK[MinSeverity.NONE] == 0
    # Text that arrives from a caller still finds its rank: the members are str.
    assert _SEVERITY_RANK.get("medium") == 2
    assert _SEVERITY_RANK.get("info") is None


def test_the_workspace_run_status_is_the_wire_vocabulary_and_defaults_completed():
    assert [m.value for m in WorkspaceRunStatus] == ["completed", "refused"]
    base = {"workspace_file": "w.ash-workspace", "workspace_root": "/w", "exit_code": 0}
    assert WorkspaceResults(**base).status is WorkspaceRunStatus.COMPLETED
    refused = WorkspaceResults(**base, status="refused")
    assert refused.status is WorkspaceRunStatus.REFUSED
    assert refused.model_dump(mode="json")["status"] == "refused"
    with pytest.raises(ValueError):
        WorkspaceResults(**base, status="exploded")


def test_a_refused_workspace_payload_says_refused():
    from automated_security_helper.workspace.execution import refused_results

    class _Plan:
        workspace_file = "w.ash-workspace"
        workspace_root = "/w"

    payload = refused_results(_Plan(), "no")  # type: ignore[arg-type]
    assert payload.status is WorkspaceRunStatus.REFUSED
    assert payload.model_dump(mode="json")["status"] == "refused"


def test_the_workspace_and_project_status_vocabularies_stay_separate():
    assert set(ProjectRunStatus) != set(WorkspaceRunStatus)
    assert WorkspaceRunStatus.REFUSED.value not in {m.value for m in ProjectRunStatus}


def test_the_monitor_reads_a_progress_status_into_a_member():
    from automated_security_helper.cli.mcp.progress_monitor import _scan_status

    assert _scan_status({"status": "cancelled"}) is MCScanStatus.CANCELLED
    assert _scan_status({"status": "failed"}) is MCScanStatus.FAILED
    assert _scan_status({"status": "not-a-status"}) is None
    assert _scan_status({}) is None


# ---------------------------------------------------------------------------
# The drift gate
# ---------------------------------------------------------------------------


def string_constants(source: str) -> List[Tuple[int, str]]:
    """Every string constant in *source* outside docstring position, with its line.

    Comments never reach the AST; a bare string statement (a docstring or a stray
    string expression) is skipped.
    """
    tree = ast.parse(source)
    skipped = {
        id(node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    }
    return sorted(
        (node.lineno, node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and id(node) not in skipped
    )


def stray_spellings(path: Path, spellings: Iterable[str]) -> List[Tuple[int, str]]:
    wanted = set(spellings)
    return [
        (line, value)
        for line, value in string_constants(path.read_text(encoding="utf-8"))
        if value in wanted
    ]


#: Strong mode. The distinctive spellings of each vocabulary and the files cured
#: for it. A file outside the scope is not claimed clean.
SCANNER_STATUS_SPELLINGS = [m.value for m in ScannerStatus if m.value != "ERROR"]
SCANNER_STATUS_SCOPE = [
    "core/unified_metrics.py",
    "core/scanner_statistics_calculator.py",
    "core/resource_management/scan_tracking.py",
    "core/resource_management/result_filters.py",
    "core/metrics_table.py",
    "workspace/aggregation.py",
    "workspace/execution.py",
    "plugin_modules/ash_aws_plugins/security_hub_reporter.py",
    "plugin_modules/ash_builtin/reporters/markdown_reporter.py",
    "plugin_modules/ash_builtin/reporters/html_reporter.py",
    "plugin_modules/ash_builtin/reporters/workspace_section.py",
]
#: ``"PASSED"``-shaped words that are not the scanner vocabulary, by (path, line text).
SCANNER_STATUS_ALLOWLIST: List[Tuple[str, str]] = []

WORKSPACE_STATUS_SPELLINGS = ["refused"]
WORKSPACE_STATUS_SCOPE = ["workspace/aggregation.py", "workspace/execution.py"]

MC_SCAN_STATUS_SPELLINGS = ["incomplete", "cancelled"]
MC_SCAN_STATUS_SCOPE = ["cli/mcp/progress_monitor.py"]


@pytest.mark.parametrize(
    "spellings,scope,label",
    [
        (SCANNER_STATUS_SPELLINGS, SCANNER_STATUS_SCOPE, "ScannerStatus"),
        (WORKSPACE_STATUS_SPELLINGS, WORKSPACE_STATUS_SCOPE, "WorkspaceRunStatus"),
        (MC_SCAN_STATUS_SPELLINGS, MC_SCAN_STATUS_SCOPE, "MCScanStatus"),
    ],
)
def test_no_stray_spelling_of_a_cured_vocabulary_outside_its_enum(
    spellings, scope, label
):
    found = {
        rel: hits
        for rel in scope
        if (hits := stray_spellings(PACKAGE / rel, spellings))
    }
    assert not found, f"{label} spelled as a bare string: {found}"


def test_the_scan_is_alive_a_planted_stray_spelling_is_flagged(tmp_path):
    planted = tmp_path / "planted.py"
    planted.write_text(
        '"""A docstring that says PASSED is skipped."""\n'
        "# a comment saying FAILED is not in the AST\n"
        "def f(row):\n"
        '    return row == "PASSED"\n',
        encoding="utf-8",
    )
    assert stray_spellings(planted, SCANNER_STATUS_SPELLINGS) == [(4, "PASSED")]


def test_the_cured_sites_of_the_short_words_are_gone():
    """Positive mode: the ambiguous words are pinned at the inventoried sites."""
    forbidden = [
        # (path, fragment that re-spells a table or a compare the cure removed)
        ("interactions/run_ash_scan.py", '{"critical": 3'),
        ("interactions/run_ash_scan.py", 'entry.status.value == "skipped"'),
        ("interactions/run_ash_scan.py", 'entry.status.value == "failed"'),
        ("workspace/aggregation.py", '"critical": 3'),
        ("workspace/aggregation.py", '"ERROR",\n    "FAILED"'),
        ("core/resource_management/scan_tracking.py", '"ERROR": MCScannerStatus'),
        ("core/resource_management/result_filters.py", '"error": "error"'),
        ("cli/mcp/progress_monitor.py", 'status == "failed"'),
        ("cli/mcp/progress_monitor.py", 'status == "completed"'),
        ("cli/mcp/progress_monitor.py", '"failed", "incomplete", "cancelled"'),
        ("cli/mcp_server.py", '"status": "running"'),
        ("cli/mcp_tools.py", '"status": "pending"'),
        ("core/scanner_statistics_calculator.py", 'case "ERROR"'),
        ("core/scanner_statistics_calculator.py", 'return "ERROR"'),
    ]
    present = [
        (rel, fragment)
        for rel, fragment in forbidden
        if fragment in (PACKAGE / rel).read_text(encoding="utf-8")
    ]
    assert not present, present
