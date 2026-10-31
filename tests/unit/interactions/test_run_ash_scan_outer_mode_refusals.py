# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Four fixes at the scan entry point's outer modes and its exit code.

* The container mode's pre-run parse check decodes a JSON config as the scan's
  own reader does (``utf-8-sig``), so a file with a byte order mark the scan
  loads is not refused on the host.
* The two exit-3 handlers that print a config refusal with Rich markup escape
  the error's text: a bracket sequence in a path raised MarkupError out of the
  handler instead of exiting.
* ``--min-severity`` reads a result as qualifying only when it is actionable
  under its own scanner's threshold: a non-actionable finding at the minimum
  kept exit 2 for actionable findings below it.
* A workspace plan with ``--mode nix`` runs the workspace scan inside the Nix
  shell, as container mode runs it inside the container, instead of on the host.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from automated_security_helper.core.enums import RunMode
from automated_security_helper.core.exceptions import ASHConfigValidationError
from automated_security_helper.interactions import run_ash_container as rac
from automated_security_helper.interactions import run_ash_scan as ras
from automated_security_helper.models.workspace import WorkspaceExitCode
from automated_security_helper.utils.inner_run_outcome import record_reports_written
from automated_security_helper.utils.subprocess_utils import create_completed_process
from automated_security_helper.workspace.resolver import resolve_workspace

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# The parse check and a JSON byte order mark
# ---------------------------------------------------------------------------


def test_the_parse_check_accepts_a_json_config_with_a_byte_order_mark(tmp_path):
    marked = tmp_path / "ash.json"
    marked.write_bytes(b"\xef\xbb\xbf" + json.dumps({"project_name": "t"}).encode())
    opts = SimpleNamespace(run=True, config=str(marked), source_dir=str(tmp_path))

    assert ras._refuse_a_container_config_that_does_not_parse(opts) is None


def test_the_parse_check_still_refuses_a_json_config_that_does_not_parse(tmp_path):
    """Control."""
    broken = tmp_path / "ash.json"
    broken.write_text('{"project_name": ', encoding="utf-8")
    opts = SimpleNamespace(run=True, config=str(broken), source_dir=str(tmp_path))

    with pytest.raises(ras.ScanRefusedExit) as refused:
        ras._refuse_a_container_config_that_does_not_parse(opts)

    assert refused.value.code == 3


# ---------------------------------------------------------------------------
# The operator-config refusal in a workspace container scan is markup-safe
# ---------------------------------------------------------------------------


def _workspace_plan(tmp_path):
    root = tmp_path / "ws"
    (root / "api").mkdir(parents=True)
    definition = root / "dev.code-workspace"
    definition.write_text(json.dumps({"folders": [{"path": "api"}]}), encoding="utf-8")
    return resolve_workspace(definition)


def test_a_config_refusal_whose_text_reads_as_markup_still_exits(tmp_path, monkeypatch):
    """The refusal's text names a path; one holding a closing tag with no open
    tag raised MarkupError out of the handler instead of exiting."""
    from automated_security_helper.config import resolve_config

    plan = _workspace_plan(tmp_path)
    config = tmp_path / "ops" / "ash.yaml"
    config.parent.mkdir()
    config.write_text("project_name: ops\n", encoding="utf-8")

    def refuse(_config, _root):
        raise ASHConfigValidationError("the config at [/x] is in the checkout")

    monkeypatch.setattr(resolve_config, "check_operator_config", refuse)
    monkeypatch.setattr(ras, "sweep_leftovers_before_run", lambda runner: [])
    monkeypatch.setattr(ras, "sweep_env_dirs", list)
    monkeypatch.setattr(
        ras,
        "run_ash_container",
        lambda **kwargs: rac._not_started(
            create_completed_process(args=[], returncode=4)
        ),
    )
    monkeypatch.chdir(tmp_path)
    opts = ras.ScanOptions(
        source_dir=plan.workspace_root,
        output_dir=tmp_path / "out",
        mode=RunMode.container,
        workspace_plan=plan,
        config=str(config),
        build=False,
        run=True,
        progress=False,
        show_summary=False,
    )

    with pytest.raises(SystemExit) as exited:
        ras._run_container_mode(opts, MagicMock())

    assert exited.value.code == int(WorkspaceExitCode.INVALID_PROJECT_CONFIG)


def test_the_shared_printer_shows_a_markup_shaped_message_as_text(capsys):
    ras._print_invalid_config(ASHConfigValidationError("a path like [/x] here"))

    out = capsys.readouterr().out
    assert "[/x]" in out, out


def test_a_denied_field_refusal_whose_text_reads_as_markup_still_exits(
    tmp_path, monkeypatch, capsys
):
    """The third handler, in local mode: a client-delivered config's denied
    field names the field and a path; printed raw inside markup, a closing tag
    in it raised MarkupError instead of exiting 3."""
    from automated_security_helper.core import orchestrator
    from automated_security_helper.core.exceptions import ASHConfigFieldDeniedError

    # Exit 3 is every config refusal's code, so the test shows the denied-field
    # handler itself ran: the patched `create` was reached, and the refusal's text
    # was printed as text. A config the environment names would be refused before
    # `create` and share the exit code, so it is cleared.
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    reached = []

    def refuse(**kwargs):
        reached.append(True)
        raise ASHConfigFieldDeniedError("field sandbox.[/x] is denied by the policy")

    monkeypatch.setattr(orchestrator.ASHScanOrchestrator, "create", refuse)
    src = tmp_path / "src"
    src.mkdir()
    opts = ras.ScanOptions(
        source_dir=src,
        output_dir=tmp_path / "out",
        progress=False,
        show_summary=False,
    )

    with pytest.raises(SystemExit) as exited:
        ras._run_local_mode(opts, MagicMock())

    assert exited.value.code == 3
    assert reached == [True]
    captured = capsys.readouterr()
    assert "sandbox.[/x]" in captured.out + captured.err


# ---------------------------------------------------------------------------
# --min-severity counts only actionable findings as qualifying
# ---------------------------------------------------------------------------


def _finding(scanner: str, level: str, issue_severity: str) -> dict:
    return {
        "ruleId": f"{scanner.upper()}-1",
        "level": level,
        "message": {"text": "finding"},
        "properties": {"scanner_name": scanner, "issue_severity": issue_severity},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "src/app.py"},
                    "region": {"startLine": 1},
                }
            }
        ],
    }


def _results_with_two_findings(tmp_path):
    """A MEDIUM bandit finding the scanner's own CRITICAL threshold makes
    non-actionable, and a LOW semgrep finding the global LOW threshold makes
    actionable; both in the model and in the SARIF file the run left."""
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.models.asharp_model import (
        AshAggregatedResults,
        ScannerStatusInfo,
    )
    from automated_security_helper.schemas.sarif_schema_model import (
        Result,
        Run,
        SarifReport,
        Tool,
        ToolComponent,
    )

    AshConfig.model_rebuild()
    AshAggregatedResults.model_rebuild()
    findings = [
        _finding("bandit", "warning", "MEDIUM"),
        _finding("semgrep", "note", "LOW"),
    ]
    results = AshAggregatedResults()
    results.ash_config = AshConfig.model_validate(
        {
            "project_name": "min-severity",
            "global_settings": {"severity_threshold": "LOW"},
            "scanners": {"bandit": {"options": {"severity_threshold": "CRITICAL"}}},
        }
    )
    results.sarif = SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="ASH", version="1.0")),
                results=[Result.model_validate(finding) for finding in findings],
            )
        ],
    )
    results.scanner_results["bandit"] = ScannerStatusInfo()
    results.scanner_results["semgrep"] = ScannerStatusInfo()
    sarif_file = tmp_path / "out" / "reports" / "ash.sarif"
    sarif_file.parent.mkdir(parents=True, exist_ok=True)
    sarif_file.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "ASH", "version": "1.0"}},
                        "results": findings,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return results


def _opts(tmp_path, min_severity):
    return ras.ScanOptions(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        min_severity=min_severity,
    )


def test_a_non_actionable_finding_at_the_minimum_does_not_keep_exit_2(tmp_path):
    """The only actionable finding is LOW, below --min-severity medium; the
    MEDIUM finding at the minimum is one its scanner's threshold made
    non-actionable, so it was never counted and cannot hold the count open."""
    results = _results_with_two_findings(tmp_path)

    assert ras._compute_exit_code(results, _opts(tmp_path, "medium")) == 0


def test_an_actionable_finding_at_the_minimum_still_fails_the_scan(tmp_path):
    """Control: with no minimum above the actionable LOW finding, exit 2."""
    results = _results_with_two_findings(tmp_path)

    assert ras._compute_exit_code(results, _opts(tmp_path, "low")) == 2


def test_the_actionability_check_reads_the_scanners_own_threshold(tmp_path):
    results = _results_with_two_findings(tmp_path)
    bandit, semgrep = results.sarif.runs[0].results

    assert ras._actionable_under_its_scanner_threshold(bandit, results) is False
    assert ras._actionable_under_its_scanner_threshold(semgrep, results) is True


def _results_whose_scanner_is_named_by_its_run(tmp_path, run_tool_name):
    """One INFO result that carries no scanner name, in a run whose tool is
    *run_tool_name*. bandit's own threshold is ALL (INFO is actionable); the
    global one is LOW (INFO is not)."""
    from automated_security_helper.schemas.sarif_schema_model import Result

    finding = _finding("ignored", "none", "")
    del finding["properties"]
    results = _results_with_the_file_apart_from_the_model(
        tmp_path,
        in_model=[],
        in_file=[],
        scanner_thresholds={"bandit": "ALL"},
    )
    run = results.sarif.runs[0]
    run.tool.driver.name = run_tool_name
    run.results = [Result.model_validate(finding)]
    return results


def _metrics_counting_one_actionable_finding(monkeypatch):
    """The scanner metrics' count: one actionable finding, which they attribute
    to bandit from the scanner's own report rather than from the SARIF."""
    from automated_security_helper.core.unified_metrics import ScannerMetrics

    metric = ScannerMetrics(
        scanner_name="bandit",
        status="FAILED",
        actionable=1,
        targets_attempted=1,
        targets_failed=0,
    )
    monkeypatch.setattr(
        ras, "get_unified_scanner_metrics", lambda *_args, **_kwargs: [metric]
    )


def test_a_result_named_only_by_its_run_is_judged_by_that_scanners_threshold(
    tmp_path, monkeypatch
):
    """The metrics counted the finding under bandit's ALL threshold. The
    --min-severity re-check read the result's scanner from its own properties
    alone, found none, judged it by the global LOW threshold, found it
    non-actionable and zeroed the count at the default minimum: exit 0 over a
    finding the summary table lists as failing."""
    _metrics_counting_one_actionable_finding(monkeypatch)
    results = _results_whose_scanner_is_named_by_its_run(tmp_path, "bandit")
    opts = _opts(tmp_path, "low")

    assert ras._gating_actionable_count(results, opts, False) == 1
    assert (
        ras._compute_exit_code(results, opts, report_sarif_written_this_run=False) == 2
    )


def test_a_result_named_by_a_run_with_no_threshold_of_its_own_is_still_judged_globally(
    tmp_path, monkeypatch
):
    """Control: the run's tool has no threshold of its own, so the global LOW
    one applies, INFO is not actionable and nothing qualifies."""
    _metrics_counting_one_actionable_finding(monkeypatch)
    results = _results_whose_scanner_is_named_by_its_run(tmp_path, "semgrep")
    opts = _opts(tmp_path, "low")

    assert ras._gating_actionable_count(results, opts, False) == 0


def _local_scan_that_reaches_the_orchestrator(tmp_path, monkeypatch, restriction):
    """Run the local mode with *restriction*; the orchestrator's `create` is
    replaced by an exit 77, so a run that gets there ends with that code."""
    from automated_security_helper.core import orchestrator

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    reached = []

    def create(**kwargs):
        reached.append(True)
        raise SystemExit(77)

    monkeypatch.setattr(orchestrator.ASHScanOrchestrator, "create", create)
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    opts = ras.ScanOptions(
        source_dir=src,
        output_dir=tmp_path / "out",
        severity_threshold_restriction=restriction,
        progress=False,
        show_summary=False,
    )

    with pytest.raises(SystemExit) as exited:
        ras._run_local_mode(opts, MagicMock())

    return exited.value.code, reached


def test_a_severity_restriction_that_names_no_threshold_exits_3(tmp_path, monkeypatch):
    """The orchestrator refused it with an ASHValidationError, which the generic
    handler reads as a crash and exits 1 for, though it is an input ASH cannot
    use, as an invalid configuration is."""
    code, reached = _local_scan_that_reaches_the_orchestrator(
        tmp_path, monkeypatch, "EXTREME"
    )

    assert code == 3
    assert reached == []


def test_a_known_or_blank_severity_restriction_reaches_the_orchestrator(
    tmp_path, monkeypatch
):
    """Control: a ladder word, in any case, and a blank value are not refused."""
    for restriction in ("high", "HIGH", "  "):
        code, reached = _local_scan_that_reaches_the_orchestrator(
            tmp_path, monkeypatch, restriction
        )

        assert (code, reached) == (77, [True]), restriction


def _results_with_the_report_named_apart_from_ash_sarif(tmp_path, monkeypatch):
    """The metrics count nothing; the report this run wrote is reports/custom.sarif
    and holds one actionable finding. The count is taken from that file."""
    from automated_security_helper.core.unified_metrics import ScannerMetrics

    results = _results_with_the_file_apart_from_the_model(
        tmp_path, in_model=[], in_file=[_finding("semgrep", "error", "HIGH")]
    )
    results.validation_checkpoints = []
    record_reports_written(results, [("custom.sarif", "sarif")])
    reports = tmp_path / "out" / "reports"
    (reports / "ash.sarif").rename(reports / "custom.sarif")
    metric = ScannerMetrics(
        scanner_name="semgrep",
        status="PASSED",
        actionable=0,
        targets_attempted=1,
        targets_failed=0,
    )
    monkeypatch.setattr(
        ras, "get_unified_scanner_metrics", lambda *_args, **_kwargs: [metric]
    )
    return results, reports


def test_the_count_does_not_open_the_report_through_a_link(tmp_path, monkeypatch):
    """A link at the report's name points at a file beside it, so it passes the
    confinement check. The count was read before the exit code's link check
    ran, and opened the file the link names: here the finding in another run's
    report decided the count."""
    results, reports = _results_with_the_report_named_apart_from_ash_sarif(
        tmp_path, monkeypatch
    )
    (reports / "custom.sarif").rename(reports / "earlier-run.sarif")
    try:
        (reports / "custom.sarif").symlink_to("earlier-run.sarif")
    except (OSError, NotImplementedError):
        pytest.skip("this host cannot create a symlink")

    assert ras._gating_actionable_count(results, _opts(tmp_path, "low"), True) == 0


def test_the_count_still_reads_the_report_that_is_a_file(tmp_path, monkeypatch):
    """Control: the same report as a regular file decides the count."""
    results, _reports = _results_with_the_report_named_apart_from_ash_sarif(
        tmp_path, monkeypatch
    )

    assert ras._gating_actionable_count(results, _opts(tmp_path, "low"), True) == 1


# ---------------------------------------------------------------------------
# A workspace plan with --mode nix enters the shell
# ---------------------------------------------------------------------------


def _results_with_the_file_apart_from_the_model(
    tmp_path, in_model, in_file, scanner_thresholds=None
):
    """A results model holding *in_model* while the report this run wrote
    (reports/ash.sarif) holds *in_file*: the shape of a report phase over saved
    results, and of a container's or a shell's inner run writing the file.

    *scanner_thresholds* names each scanner's own ``severity_threshold``; the
    default tightens bandit to CRITICAL and leaves semgrep at the global LOW."""
    if scanner_thresholds is None:
        scanner_thresholds = {"bandit": "CRITICAL"}
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.models.asharp_model import (
        AshAggregatedResults,
        ScannerStatusInfo,
    )
    from automated_security_helper.schemas.sarif_schema_model import (
        Result,
        Run,
        SarifReport,
        Tool,
        ToolComponent,
    )

    AshConfig.model_rebuild()
    AshAggregatedResults.model_rebuild()
    results = AshAggregatedResults()
    results.ash_config = AshConfig.model_validate(
        {
            "project_name": "min-severity",
            "global_settings": {"severity_threshold": "LOW"},
            "scanners": {
                name: {"options": {"severity_threshold": level}}
                for name, level in scanner_thresholds.items()
            },
        }
    )
    results.sarif = SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="ASH", version="1.0")),
                results=[Result.model_validate(finding) for finding in in_model],
            )
        ],
    )
    results.scanner_results["bandit"] = ScannerStatusInfo()
    results.scanner_results["semgrep"] = ScannerStatusInfo()
    # The exit code reads reports/ash.sarif only when the results record it as a
    # file this run's SARIF reporter wrote (report_file_written_as); a file in
    # reports/ that nothing recorded is an earlier run's. The report phase makes
    # this record; the fixture makes it the same way.
    record_reports_written(results, [("ash.sarif", "sarif")])
    sarif_file = tmp_path / "out" / "reports" / "ash.sarif"
    sarif_file.parent.mkdir(parents=True, exist_ok=True)
    sarif_file.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "ASH", "version": "1.0"}},
                        "results": list(in_file),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return results


def test_a_count_taken_from_the_written_report_is_judged_on_that_report(tmp_path):
    """The model holds only a MEDIUM bandit finding its scanner's CRITICAL
    threshold makes non-actionable; the report this run wrote holds an
    actionable HIGH semgrep finding. The count (1) comes from the file, so the
    --min-severity question is answered on the file too: exit 2. Judging the
    model's results against the file's count read the run as having no
    qualifying finding and exited 0."""
    results = _results_with_the_file_apart_from_the_model(
        tmp_path,
        in_model=[_finding("bandit", "warning", "MEDIUM")],
        in_file=[_finding("semgrep", "error", "HIGH")],
    )

    assert (
        ras._compute_exit_code(
            results, _opts(tmp_path, "low"), report_sarif_written_this_run=True
        )
        == 2
    )


def test_a_written_report_with_no_actionable_finding_still_exits_0(tmp_path):
    """Control: the file decides, and it holds only the non-actionable finding."""
    results = _results_with_the_file_apart_from_the_model(
        tmp_path,
        in_model=[_finding("semgrep", "error", "HIGH")],
        in_file=[_finding("bandit", "warning", "MEDIUM")],
    )

    assert (
        ras._compute_exit_code(
            results, _opts(tmp_path, "low"), report_sarif_written_this_run=True
        )
        == 0
    )


def test_the_minimum_is_read_on_the_written_report_too(tmp_path):
    """The file's one actionable finding is LOW; with --min-severity medium
    nothing qualifies, as the model-side rule already read it."""
    results = _results_with_the_file_apart_from_the_model(
        tmp_path,
        in_model=[],
        in_file=[_finding("semgrep", "note", "LOW")],
    )

    assert (
        ras._compute_exit_code(
            results, _opts(tmp_path, "medium"), report_sarif_written_this_run=True
        )
        == 0
    )


def test_the_exit_code_read_asks_each_scanners_threshold_once(tmp_path, monkeypatch):
    """get_scanner_threshold_info dumps the whole scanners config on every call,
    and a --min-severity filter that asked it once per result ran that dump over
    every result at or above the minimum. One memoised lookup now serves one
    exit-code read: the filter over the model's results asks each scanner once,
    and when the count is taken from the written report, the count and the filter
    share that lookup too."""
    from automated_security_helper.core.scanner_statistics_calculator import (
        ScannerStatisticsCalculator,
    )
    from automated_security_helper.core.unified_metrics import ScannerMetrics

    findings = [
        _finding("bandit", "warning", "MEDIUM"),
        _finding("bandit", "warning", "MEDIUM"),
        _finding("bandit", "warning", "MEDIUM"),
        _finding("semgrep", "note", "LOW"),
        _finding("semgrep", "note", "LOW"),
    ]
    results = _results_with_the_file_apart_from_the_model(
        tmp_path, in_model=findings, in_file=findings
    )
    asked = []
    real = ScannerStatisticsCalculator.get_scanner_threshold_info

    def counting(model, scanner_name):
        asked.append(scanner_name)
        return real(model, scanner_name)

    monkeypatch.setattr(
        ScannerStatisticsCalculator, "get_scanner_threshold_info", counting
    )
    # The written report is not this run's, so the count comes from the model's
    # metrics (a real metrics row, not a mock whose every unset attribute reads
    # as truthy) and the filter judges the model's results: three bandit MEDIUMs
    # at the minimum, each asking bandit's threshold; the two semgrep LOWs are
    # below the minimum and never asked. One scanner, so one resolver call.
    metric = ScannerMetrics(
        scanner_name="semgrep",
        status="PASSED",
        actionable=2,
        targets_attempted=1,
        targets_failed=0,
    )
    # The product passes the model by keyword (asharp_model=...), so the stand-in
    # takes the call in either shape.
    monkeypatch.setattr(
        ras, "get_unified_scanner_metrics", lambda *_args, **_kwargs: [metric]
    )

    exit_code = ras._compute_exit_code(
        results, _opts(tmp_path, "medium"), report_sarif_written_this_run=False
    )

    assert exit_code == 0
    assert asked == ["bandit"], asked

    # The written report is this run's: the count over its five results and the
    # filter over them share the one lookup, so each of the two scanners is asked
    # once. Nothing counted is at the minimum (bandit's MEDIUMs fail its CRITICAL
    # threshold, semgrep's LOWs are below medium), so exit 0 again.
    asked.clear()

    exit_code = ras._compute_exit_code(
        results, _opts(tmp_path, "medium"), report_sarif_written_this_run=True
    )

    assert exit_code == 0
    assert sorted(asked) == ["bandit", "semgrep"], asked


@pytest.mark.parametrize(
    ("level", "fails", "exit_code"),
    [
        # The ladder reads a level-only `error` as CRITICAL, which alone meets
        # semgrep's CRITICAL threshold here: counted on the written report, read
        # as qualifying by the --min-severity critical filter, exit 2.
        pytest.param("error", True, 2, id="error-is-critical"),
        # Control: `warning` is MEDIUM, below the same threshold on both sides, so
        # a grading that read it any higher would count it and exit 2 instead.
        pytest.param("warning", False, 0, id="warning-is-medium"),
    ],
)
def test_the_count_and_the_filter_read_a_level_only_result_alike(
    tmp_path, level, fails, exit_code
):
    """A result with no issue_severity is graded by its SARIF level by both: the
    one rule is utils.severity_ladder.result_severity. The scanner's threshold
    and --min-severity are both CRITICAL, so only the CRITICAL reading of
    `error` passes on both sides, and a MEDIUM `warning` passes on neither."""
    from automated_security_helper.schemas.sarif_schema_model import Result

    level_only = _finding("semgrep", level, "")
    del level_only["properties"]["issue_severity"]
    results = _results_with_the_file_apart_from_the_model(
        tmp_path,
        in_model=[level_only],
        in_file=[level_only],
        scanner_thresholds={"bandit": "CRITICAL", "semgrep": "CRITICAL"},
    )
    threshold_for = ras._scanner_threshold_lookup(results)

    as_json = ras._result_fails_its_scanner_threshold(level_only, threshold_for)
    as_model = ras._result_fails_its_scanner_threshold(
        Result.model_validate(level_only), threshold_for
    )

    assert as_json is as_model is fails
    assert (
        ras._compute_exit_code(
            results, _opts(tmp_path, "critical"), report_sarif_written_this_run=True
        )
        == exit_code
    )


def test_a_workspace_plan_in_nix_mode_runs_inside_the_shell(tmp_path, monkeypatch):
    plan = _workspace_plan(tmp_path)
    entered = {}

    class Entered(SystemExit):
        pass

    def nix_mode(opts, logger, **kwargs):
        entered["opts"] = opts
        raise Entered(0)

    def host_workspace(opts, logger):
        raise AssertionError("the workspace scan ran on the host, outside the shell")

    monkeypatch.setattr(ras, "_run_nix_mode", nix_mode)
    monkeypatch.setattr(ras, "_run_workspace_mode", host_workspace)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)

    with pytest.raises(Entered):
        ras.run_ash_scan(
            source_dir=plan.workspace_root,
            output_dir=str(tmp_path / "out"),
            mode=RunMode.nix,
            workspace_plan=plan,
            progress=False,
            show_summary=False,
        )

    assert entered["opts"].workspace_plan is plan


def test_the_inner_nix_command_line_names_the_workspace_and_its_policy(tmp_path):
    plan = _workspace_plan(tmp_path)
    policy = tmp_path / "ops" / "policy.yaml"
    policy.parent.mkdir()
    policy.write_text("workspace:\n  max_severity_threshold: HIGH\n", encoding="utf-8")
    plan = resolve_workspace(plan.workspace_file, workspace_config=policy)
    opts = ras.ScanOptions(
        source_dir=plan.workspace_root,
        output_dir=tmp_path / "out",
        mode=RunMode.nix,
        workspace_plan=plan,
        allow_missing_projects=True,
    )

    argv = ras._nix_inner_argv(opts)

    assert argv[argv.index("--workspace") + 1] == str(plan.workspace_file)
    assert argv[argv.index("--workspace-config") + 1] == plan.workspace_config_source
    assert "--allow-missing-projects" in argv
    # Mutually exclusive with --workspace on the CLI.
    assert "--source-dir" not in argv
    assert argv[argv.index("--output-dir") + 1] == str(opts.output_dir)
