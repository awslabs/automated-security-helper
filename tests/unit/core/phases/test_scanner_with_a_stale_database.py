"""A clean result from a database the policy rejects is not PASSED.

grype matches packages against a vulnerability database, and ASH holds that
database to an age bound after every scan (``utils/content_db_staleness.py``).
Under ``content_db_staleness: fail``, the default, a database past its bound fails
the scan: "a clean result from a stale database is not evidence of a clean
target". The scanner's own status agrees: a scanner whose result is clean and that
read a database past its bound under ``fail`` is ERROR in its per-target report, its
scanner row, ``ash.flat.json`` and the summary table, where the exit code says the
scan failed because of it. Under ``warn`` the operator has accepted the stale
database and the status is left alone, and a scanner that found something keeps
FAILED, since its findings are real.

The real GrypeScanner runs with its tool replaced (it writes a well-formed SARIF
report and exits 0), and ``grype`` on PATH is a stand-in answering
``grype db status -o json`` with the build time each test sets.
"""

from __future__ import annotations

import json
import os
import platform
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
    GrypeScanner,
)
from automated_security_helper.utils import subprocess_utils
from tests.utils.stand_ins import search_path, status_tool

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()


def _sarif(results):
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {"tool": {"driver": {"name": "grype", "rules": []}}, "results": results}
            ],
        }
    )


CRITICAL_FINDING = {
    "ruleId": "CVE-2020-0001",
    "level": "error",
    "message": {"text": "a vulnerable package"},
    "locations": [
        {
            "physicalLocation": {
                "artifactLocation": {"uri": "package.json"},
                "region": {"startLine": 1},
            }
        }
    ],
}


def _status_tool(bin_dir: Path, built: datetime, cache: Path) -> None:
    """A ``grype`` the host can start that reports a database built at ``built``."""
    status = {
        "schemaVersion": "v6.0.2",
        "built": built.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "path": str(cache / "6" / "vulnerability.db"),
        "valid": True,
    }
    status_tool(bin_dir, status, code=0)


def _make_layout(tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    cache = tmp_path / "grype-cache"
    (cache / "6").mkdir(parents=True)
    (cache / "6" / "vulnerability.db").write_text("", encoding="utf-8")
    monkeypatch.setenv("PATH", search_path(bin_dir))
    monkeypatch.setenv("ASH_BIN_PATH", str(bin_dir))
    monkeypatch.setenv("GRYPE_DB_CACHE_DIR", str(cache))
    monkeypatch.setenv("ASH_OFFLINE", "YES")
    subprocess_utils.clear_find_executable_cache()
    return tmp_path, bin_dir, cache


@pytest.fixture
def layout(tmp_path, monkeypatch):
    yield _make_layout(tmp_path, monkeypatch)
    subprocess_utils.clear_find_executable_cache()


def _context(tmp_path, policy: str) -> PluginContext:
    source = tmp_path / "source"
    source.mkdir()
    (source / "package.json").write_text("{}\n")
    output = tmp_path / "output"
    (output / ASH_WORK_DIR_NAME).mkdir(parents=True)
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / ASH_WORK_DIR_NAME,
        config=AshConfig(project_name="stale", content_db_staleness=policy),
    )


def _row(context, monkeypatch, sarif_text: str):
    scanner = GrypeScanner(context=context)
    captured = {}
    original = scanner._execute_scan

    def capture(*args, **kwargs):
        outcome = original(*args, **kwargs)
        captured["results_file"] = Path(outcome[1])
        return outcome

    def tool(*args, **kwargs):
        captured["results_file"].parent.mkdir(parents=True, exist_ok=True)
        captured["results_file"].write_text(sarif_text, encoding="utf-8")
        response = {"returncode": 0, "stdout": "", "stderr": ""}
        scanner._process_command_response(response)
        return response

    monkeypatch.setattr(scanner, "_execute_scan", capture)
    monkeypatch.setattr(scanner, "_run_subprocess", tool)
    monkeypatch.setattr(scanner, "validate_plugin_dependencies", lambda: True)
    executor = ScannerExecutor(
        plugin_context=context, progress_display=MagicMock(), scanner_tasks=[]
    )
    (row,) = executor._execute_scanner(
        "grype", scanner, [{"path": context.source_dir, "type": "source"}]
    )
    return row


def _days_ago(days: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=days)


def test_on_a_windows_host_the_grype_stand_in_is_a_launcher_on_a_readable_path(
    tmp_path, monkeypatch
):
    """The stand-in is a file Windows can start, found on a PATH it can read.

    ``CreateProcess`` runs executable images and nothing else, and ASH's lookup
    tries ``grype.exe``, ``grype.bat`` and ``grype.cmd`` before the bare name. A
    shebang file named ``grype`` is never started there, so the database status this
    file plants is never read. ``:`` joins nothing on Windows either, where one
    follows a drive letter. The host reports Windows to the lookup, and the search
    path separator is ``;``, only inside the block.
    """
    with monkeypatch.context() as host:
        host.setattr(platform, "system", lambda: "Windows")
        host.setattr(os, "pathsep", ";")
        _, bin_dir, cache = _make_layout(tmp_path, host)
        _status_tool(bin_dir, _days_ago(40), cache)

        entries = os.environ["PATH"].split(os.pathsep)
        files_the_lookup_finds = [
            name
            for name in subprocess_utils._executable_candidate_names("grype")
            if (bin_dir / name).is_file()
        ]

    assert entries[0] == str(bin_dir), (
        f"PATH must start with the stand-in's directory when split on ';': {entries}"
    )
    assert files_the_lookup_finds == ["grype.bat"], (
        "the lookup must find a grype.bat launcher and nothing it cannot start: "
        f"{files_the_lookup_finds}"
    )


def test_a_clean_result_from_a_stale_database_under_fail_is_an_error(
    layout, monkeypatch
):
    tmp_path, bin_dir, cache = layout
    _status_tool(bin_dir, _days_ago(40), cache)

    row = _row(_context(tmp_path, "fail"), monkeypatch, _sarif([]))

    assert row.status == ScannerStatus.ERROR, (
        "the scan fails on this database, so its clean result cannot read PASSED: "
        f"{row.status.value}"
    )
    assert any("stale" in str(error) for error in row.errors), row.errors


def test_under_warn_the_operator_accepted_the_database(layout, monkeypatch):
    tmp_path, bin_dir, cache = layout
    _status_tool(bin_dir, _days_ago(40), cache)

    row = _row(_context(tmp_path, "warn"), monkeypatch, _sarif([]))

    assert row.status == ScannerStatus.PASSED, row.status.value


def test_findings_from_a_stale_database_are_failed(layout, monkeypatch):
    tmp_path, bin_dir, cache = layout
    _status_tool(bin_dir, _days_ago(40), cache)

    row = _row(_context(tmp_path, "fail"), monkeypatch, _sarif([CRITICAL_FINDING]))

    assert row.status == ScannerStatus.FAILED, row.status.value


def test_a_current_database_is_graded_on_findings(layout, monkeypatch):
    """Control: a database built an hour ago leaves the clean result PASSED."""
    tmp_path, bin_dir, cache = layout
    _status_tool(bin_dir, datetime.now(timezone.utc) - timedelta(hours=1), cache)

    row = _row(_context(tmp_path, "fail"), monkeypatch, _sarif([]))

    assert row.status == ScannerStatus.PASSED, row.errors


# ---------------------------------------------------------------------------
# Listed once: the stale database, not an incomplete scanner as well
# ---------------------------------------------------------------------------
#
# A scanner recorded ERROR for a stale database did run, and the exit-1 message,
# the MCP payload and ``ash merge`` each treat it as a scanner that ran:
# ``scan_incompleteness`` drops its row so the condition is reported once, as a
# stale database with its refresh advice, and a shard whose only scanner it was
# merges and then exits 1 on staleness. Taken as any other ERROR, the row would sit
# as "ERROR (stale content database: ...)" under "Install the missing tools", the
# payload would list it as an incomplete scanner with reason "error", the set-level
# arm would read every scanner as not having run, and ``ash merge`` would refuse
# the shard as having completed nothing.


def _scan(context, monkeypatch, sarif_text: str) -> AshAggregatedResults:
    """The executor and the result processor over grype, then the rebuild."""
    from automated_security_helper.core.phases.scan_result_processor import (
        ScanResultProcessor,
    )
    from automated_security_helper.core.unified_metrics import (
        populate_metrics_from_unified_source,
    )

    scanner = GrypeScanner(context=context)
    captured = {}
    original = scanner._execute_scan

    def capture(*args, **kwargs):
        outcome = original(*args, **kwargs)
        captured["results_file"] = Path(outcome[1])
        return outcome

    def tool(*args, **kwargs):
        captured["results_file"].parent.mkdir(parents=True, exist_ok=True)
        captured["results_file"].write_text(sarif_text, encoding="utf-8")
        response = {"returncode": 0, "stdout": "", "stderr": ""}
        scanner._process_command_response(response)
        return response

    monkeypatch.setattr(scanner, "_execute_scan", capture)
    monkeypatch.setattr(scanner, "_run_subprocess", tool)
    monkeypatch.setattr(scanner, "validate_plugin_dependencies", lambda: True)
    aggregated = AshAggregatedResults()
    aggregated.ash_config = context.config
    executor = ScannerExecutor(
        plugin_context=context,
        progress_display=MagicMock(),
        scanner_tasks=[
            ("grype", scanner, [{"path": context.source_dir, "type": "source"}])
        ],
        process_results_fn=ScanResultProcessor(
            plugin_context=context
        ).process_container,
    )
    aggregated = executor.run_sequential(aggregated)
    return populate_metrics_from_unified_source(aggregated_results=aggregated)


@pytest.fixture
def stale_error(layout, monkeypatch):
    """Results of a scan whose only scanner found nothing in a 40-day-old database."""
    tmp_path, bin_dir, cache = layout
    _status_tool(bin_dir, _days_ago(40), cache)
    results = _scan(_context(tmp_path, "fail"), monkeypatch, _sarif([]))
    assert results.scanner_results["grype"].status == ScannerStatus.ERROR
    return results


def _as_read_back(results: AshAggregatedResults) -> AshAggregatedResults:
    """The model ``ash report`` and ``ash merge`` read from ash_aggregated_results.json."""
    return AshAggregatedResults.model_validate_json(results.model_dump_json())


@pytest.mark.parametrize("read_back", [False, True], ids=["in-memory", "from-disk"])
def test_a_stale_database_error_is_reported_once(stale_error, read_back):
    from automated_security_helper.interactions.run_ash_scan import (
        scan_incompleteness,
    )

    results = _as_read_back(stale_error) if read_back else stale_error
    facts = scan_incompleteness(results, gate=True)

    assert [record.scanner for record in facts.stale_content_databases] == ["grype"]
    assert facts.scanners == (), (
        "the stale database is reported as a stale database; listing grype as an "
        f"incomplete scanner too reports it twice: {facts.scanners}"
    )
    assert facts.no_scanner_ran is False, (
        "grype ran and reached a verdict the policy rejects; it is not a scan in "
        "which no scanner ran"
    )
    payload = facts.to_payload()
    assert payload["incomplete_scanners"] == [], payload
    assert payload["no_scanner_ran"] is False
    assert len(payload["stale_content_databases"]) == 1, payload


def test_the_console_gives_the_stale_database_advice_alone(stale_error, monkeypatch):
    import rich
    from rich.console import Console

    from automated_security_helper.interactions.run_ash_scan import (
        print_incompleteness_message,
        scan_incompleteness,
    )

    console = Console(record=True, width=200, color_system=None)
    monkeypatch.setattr(rich, "_console", console)
    facts = scan_incompleteness(stale_error, gate=True)

    print_incompleteness_message(
        list(facts.scanners),
        list(facts.converters),
        list(facts.stale_content_databases),
        no_scanner_ran=facts.no_scanner_ran,
        observed=list(facts.observed),
        unevaluated_rules=list(facts.unevaluated_rules),
    )
    out = console.export_text()

    assert out.count("past their declared age bound") == 1, out
    assert "To refresh it" in out, out
    assert "Install the missing tools" not in out, out
    assert "did not evaluate everything" not in out, out
    assert "no scanner ran" not in out, out


def test_the_exit_code_comes_from_the_stale_arm(stale_error, tmp_path, caplog):
    import logging

    from automated_security_helper.interactions.run_ash_scan import (
        ScanOptions,
        _compute_exit_code,
    )

    opts = ScanOptions(source_dir=tmp_path / "src", output_dir=tmp_path / "out")
    with caplog.at_level(logging.ERROR):
        code = _compute_exit_code(stale_error, opts)

    assert code == 1
    logged = caplog.text
    assert "past their declared age bound" in logged, logged
    assert "Scan incomplete" not in logged, logged
    assert "ran no scanners" not in logged, logged


def test_the_workspace_layer_counts_it_as_having_run(stale_error):
    """What ``_scan_one_project`` writes into the outcome, through ``_coverage_fields``."""
    from automated_security_helper.workspace.execution import _coverage_fields

    fields = _coverage_fields(stale_error)

    assert fields["no_scanner_ran"] is False
    # The scanner's row is dropped from the per-scanner list; the stale database
    # fails the project through its own field.
    assert fields["incomplete_scanners"] == []


def _one_shard(results: AshAggregatedResults) -> AshAggregatedResults:
    from automated_security_helper.cli.merge import stamp_shard_assignment
    from automated_security_helper.core.sharding import ShardAssignment

    shard = _as_read_back(results)
    stamp_shard_assignment(
        shard,
        ShardAssignment(
            shard_index=0,
            shard_count=1,
            assigned_scanners=["grype"],
            candidate_scanners=["grype"],
        ),
    )
    return shard


def test_merge_takes_the_shard_and_exits_one_on_staleness(stale_error, tmp_path):
    """As it did when the scanner was PASSED: merge, then exit 1 on staleness."""
    from automated_security_helper.cli.merge import merge_shard_results
    from automated_security_helper.interactions.run_ash_scan import (
        ScanOptions,
        _compute_exit_code,
        scan_incompleteness,
    )

    merged = merge_shard_results(
        [(Path("shard-0.json"), _one_shard(stale_error))],
        require_scanner_completion=True,
    )

    facts = scan_incompleteness(merged, gate=True)
    assert [record.scanner for record in facts.stale_content_databases] == ["grype"]
    assert facts.scanners == ()
    opts = ScanOptions(source_dir=tmp_path / "src", output_dir=tmp_path / "out")
    assert _compute_exit_code(merged, opts) == 1


def _drop_the_marker(results: AshAggregatedResults) -> AshAggregatedResults:
    """A grype ERROR for some other reason, against the same stale database."""
    copy = _as_read_back(results)
    for report in copy.additional_reports["grype"].values():
        report.pop("rejected_content_databases", None)
    return copy


def test_a_scanner_in_error_for_another_reason_keeps_its_row(stale_error):
    """Control: only the stale-database ERROR is folded into the stale arm."""
    from automated_security_helper.interactions.run_ash_scan import (
        scan_incompleteness,
    )

    assert stale_error.additional_reports["grype"]["source"].get(
        "rejected_content_databases"
    ), "the fixture must carry the marker the control removes"
    facts = scan_incompleteness(_drop_the_marker(stale_error), gate=True)

    assert [name for name, _ in facts.scanners] == ["grype"], facts.scanners
    assert facts.no_scanner_ran is True


def test_merge_refuses_a_shard_in_error_for_another_reason(stale_error):
    from automated_security_helper.cli.merge import merge_shard_results
    from automated_security_helper.core.exceptions import ShardCoverageError

    with pytest.raises(ShardCoverageError, match=r"completed none"):
        merge_shard_results(
            [(Path("shard-0.json"), _one_shard(_drop_the_marker(stale_error)))],
            require_scanner_completion=True,
        )


def _with_a_crashed_converted_target(results: AshAggregatedResults):
    """grype ERROR on the converted tree too, with no rejected database named."""
    copy = _as_read_back(results)
    copy.additional_reports["grype"]["converted"] = {
        "scanner_name": "grype",
        "target_type": "converted",
        "status": "ERROR",
    }
    return copy


def _with_the_database_record_not_enforced(results: AshAggregatedResults):
    """The marker stays; the stale record is a warning, so nothing enforces it."""
    from automated_security_helper.schemas.sarif_schema_model import Level
    from automated_security_helper.utils.content_db_staleness import (
        STALE_NOTIFICATION_ID,
    )

    copy = _as_read_back(results)
    demoted = 0
    for run in copy.sarif.runs:
        for invocation in run.invocations or []:
            for notification in invocation.toolConfigurationNotifications or []:
                if notification.descriptor.root.id == STALE_NOTIFICATION_ID:
                    notification.level = Level.warning
                    demoted += 1
    assert demoted, "the fixture must carry the record this demotes"
    return copy


def test_every_error_target_must_name_a_rejected_database(stale_error):
    """Two targets, one an ERROR for another reason: the scanner keeps its row."""
    from automated_security_helper.interactions.run_ash_scan import (
        scan_incompleteness,
    )
    from automated_security_helper.utils.content_db_staleness import (
        scanners_in_error_for_a_stale_database,
    )

    results = _with_a_crashed_converted_target(stale_error)

    assert scanners_in_error_for_a_stale_database(stale_error) == {"grype"}
    assert scanners_in_error_for_a_stale_database(results) == set()
    facts = scan_incompleteness(results, gate=True)
    assert [name for name, _ in facts.scanners] == ["grype"], facts.scanners
    assert facts.no_scanner_ran is True


def test_merge_refuses_a_shard_whose_other_target_errored(stale_error):
    from automated_security_helper.cli.merge import merge_shard_results
    from automated_security_helper.core.exceptions import ShardCoverageError

    with pytest.raises(ShardCoverageError, match=r"completed none"):
        merge_shard_results(
            [
                (
                    Path("shard-0.json"),
                    _one_shard(_with_a_crashed_converted_target(stale_error)),
                )
            ],
            require_scanner_completion=True,
        )


def test_the_marker_counts_only_with_an_enforced_record(stale_error):
    """A marker without a stale record the policy enforces does not fold the row."""
    from automated_security_helper.interactions.run_ash_scan import (
        scan_incompleteness,
    )
    from automated_security_helper.utils.content_db_staleness import (
        scanners_in_error_for_a_stale_database,
    )

    results = _with_the_database_record_not_enforced(stale_error)

    assert results.additional_reports["grype"]["source"].get(
        "rejected_content_databases"
    ), "the marker must still be there"
    assert scanners_in_error_for_a_stale_database(results) == set()
    facts = scan_incompleteness(results, gate=True)
    assert facts.stale_content_databases == ()
    assert [name for name, _ in facts.scanners] == ["grype"], facts.scanners
    assert facts.no_scanner_ran is True


def test_merge_refuses_a_shard_whose_marker_has_no_enforced_record(stale_error):
    from automated_security_helper.cli.merge import merge_shard_results
    from automated_security_helper.core.exceptions import ShardCoverageError

    with pytest.raises(ShardCoverageError, match=r"completed none"):
        merge_shard_results(
            [
                (
                    Path("shard-0.json"),
                    _one_shard(_with_the_database_record_not_enforced(stale_error)),
                )
            ],
            require_scanner_completion=True,
        )


def test_a_workspace_project_reports_the_stale_database_as_a_single_scan_does(
    stale_error,
):
    """The MCP coverage of a workspace project, against the single-scan payload.

    The project's outcome named grype in incomplete_scanners, so the coverage view
    listed it as an incomplete scanner with reason "error", and carried no stale
    record; the single-scan payload lists no incomplete scanner and one stale
    record. The coverage fields come from execution.py's own ``_coverage_fields``.
    """
    from automated_security_helper.cli.mcp.workspace import _project_coverage
    from automated_security_helper.core.resource_management.scan_tracking import (
        coverage_has_gap,
    )
    from automated_security_helper.interactions.run_ash_scan import (
        scan_incompleteness,
    )
    from automated_security_helper.models.workspace import (
        ProjectRunStatus,
        WorkspaceProjectResult,
    )
    from automated_security_helper.workspace.aggregation import (
        stale_content_databases_for_project,
    )
    from automated_security_helper.workspace.execution import _coverage_fields

    incompleteness = scan_incompleteness(stale_error, gate=True)
    single = incompleteness.to_payload()
    outcome = WorkspaceProjectResult(
        project="app",
        relative_path="app",
        display_label="app",
        status=ProjectRunStatus.COMPLETED,
        severity_threshold="MEDIUM",
        output_path="projects/app",
        scanners={"grype": "ERROR"},
        **_coverage_fields(stale_error),
        stale_content_databases=stale_content_databases_for_project(stale_error),
        scan_incomplete=True,
    )

    coverage = _project_coverage(outcome)

    assert coverage["incomplete_scanners"] == single["incomplete_scanners"] == []
    assert coverage["stale_content_databases"] == single["stale_content_databases"]
    assert len(coverage["stale_content_databases"]) == 1
    assert coverage_has_gap(coverage), "the project still reads INCOMPLETE"
