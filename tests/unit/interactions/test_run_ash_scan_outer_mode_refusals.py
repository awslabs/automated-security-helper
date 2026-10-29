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
    tmp_path, monkeypatch
):
    """The third handler, in local mode: a client-delivered config's denied
    field names the field and a path; printed raw inside markup, a closing tag
    in it raised MarkupError instead of exiting 3."""
    from automated_security_helper.core import orchestrator
    from automated_security_helper.core.exceptions import ASHConfigFieldDeniedError

    def refuse(**kwargs):
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


# ---------------------------------------------------------------------------
# A workspace plan with --mode nix enters the shell
# ---------------------------------------------------------------------------


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
