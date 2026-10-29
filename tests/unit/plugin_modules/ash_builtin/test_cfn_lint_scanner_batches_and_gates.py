"""cfn-lint: one template's fault costs that template; the operator's options hold.

Pinned here against ``CfnLintScanner`` with only ``_run_subprocess`` faked, as
``test_cfn_lint_scanner.py`` does:

* a batch cfn-lint exits on for one template's fault (a region its Metadata names
  that this cfn-lint does not know exits 32) is re-run one template at a time, so
  only that template fails and the others' findings are kept;
* after one invocation times out, the remaining batches are not started: the
  executor discards the scan after a recorded timeout, and each batch would have
  spent a fresh full scan_timeout;
* with ``honor_inline_ignores`` on, ``--merge-configs`` is passed, so an operator's
  ``ignore_checks`` no longer replaces the template's own list;
* an operator's ``.cfnlintrc`` ASH cannot read stops the scan instead of being
  handed to cfn-lint unchecked;
* ``self.errors`` is reset per ``scan()`` call;
* the last dependency fallback that finds a binary on PATH runs that binary.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    cfn_lint_scanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_lint_scanner import (
    CfnLintScanner,
    CfnLintScannerConfig,
    CfnLintScannerConfigOptions,
    _one_template_can_fail_the_run,
)
from automated_security_helper.utils.config_trust import record_provenance

pytestmark = pytest.mark.unit

TEMPLATE = "Resources:\n  Q:\n    Type: AWS::SQS::Queue\n"

SARIF_WITH_ONE_FINDING = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "cfn-lint",
                    "version": "1.57.2",
                    "rules": [{"id": "W2001", "shortDescription": {"text": "unused"}}],
                }
            },
            "results": [],
        }
    ],
}


def _scanner(repo: Path, *, operator: bool = True, **options) -> CfnLintScanner:
    config = get_default_config()
    record_provenance(
        config,
        in_tree=[] if operator else [repo / ".ash" / ".ash.yaml"],
        trusted=AshConfig(),
        config_overrides=[],
    )
    context = PluginContext(
        source_dir=repo,
        output_dir=repo / ".ash" / "ash_output",
        work_dir=repo / ".ash" / "ash_output" / "converted",
        config=config,
    )
    return CfnLintScanner(
        context=context,
        config=CfnLintScannerConfig(
            enabled=True, options=CfnLintScannerConfigOptions(**options)
        ),
    )


def _repo(ash_temp_path: Path, *names: str) -> Path:
    repo = ash_temp_path / "repo"
    repo.mkdir()
    for name in names:
        (repo / name).write_text(TEMPLATE, encoding="utf-8")
    return repo


def _finding_at(uri: str) -> dict:
    return {
        "ruleId": "W2001",
        "level": "note",
        "message": {"text": f"W2001 at {uri}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": 1},
                }
            }
        ],
    }


class RegionFaultCfnLint:
    """Exits 32 for any invocation that names ``faulty``; otherwise writes SARIF."""

    def __init__(self, faulty: str):
        self.faulty = faulty
        self.calls: list = []

    def __call__(self, command, **kwargs):
        self.calls.append(list(command))
        files = command[command.index("--") + 1 :]
        if any(f.endswith(self.faulty) for f in files):
            return {
                "stdout": "",
                "stderr": "Regions ['mars-north-1'] are unsupported.",
                "returncode": 32,
            }
        output = next(
            a.split("=", 1)[1] for a in command if a.startswith("--output-file=")
        )
        document = json.loads(json.dumps(SARIF_WITH_ONE_FINDING))
        document["runs"][0]["results"] = [_finding_at(f) for f in files]
        Path(output).write_text(json.dumps(document), encoding="utf-8")
        return {"stdout": "", "stderr": "", "returncode": 4}


def _run(scanner: CfnLintScanner, fake, repo: Path):
    with (
        patch.object(CfnLintScanner, "validate_plugin_dependencies", return_value=True),
        patch.object(CfnLintScanner, "_run_subprocess", side_effect=fake),
    ):
        return scanner.scan(target=repo, target_type="source")


def test_one_template_can_fail_the_run_is_false_for_timeouts_and_unstarted():
    assert _one_template_can_fail_the_run({"returncode": 32}) is True
    assert _one_template_can_fail_the_run({"timed_out": True}) is False
    assert _one_template_can_fail_the_run({"error": "no such file"}) is False
    assert _one_template_can_fail_the_run({}) is False


def test_a_batch_failed_by_one_template_is_rerun_one_template_at_a_time(
    ash_temp_path,
):
    """At the base both templates read as not evaluated and no finding survived."""
    repo = _repo(ash_temp_path, "good.yaml", "unknown-region.yaml")
    fake = RegionFaultCfnLint("unknown-region.yaml")
    scanner = _scanner(repo)

    report = _run(scanner, fake, repo)

    batches = [call[call.index("--") + 1 :] for call in fake.calls]
    assert [len(b) for b in batches] == [2, 1, 1], batches
    assert scanner.targets_attempted == 2
    assert scanner.targets_failed == 1
    assert [r.ruleId for r in report.runs[0].results] == ["W2001"]
    assert any("unknown-region.yaml" in e and "exited 32" in e for e in scanner.errors)


def test_a_timeout_stops_the_remaining_invocations(ash_temp_path):
    """Each template runs alone under honor_inline_ignores; the first times out."""
    repo = _repo(ash_temp_path, "a.yaml", "b.yaml", "c.yaml")
    calls: list = []

    def timing_out(command, **kwargs):
        calls.append(list(command))
        return {"stdout": "", "stderr": "", "returncode": None, "timed_out": True}

    scanner = _scanner(repo, honor_inline_ignores=True)
    _run(scanner, timing_out, repo)

    assert len(calls) == 1, "every batch after the timeout was still started"
    assert scanner.targets_attempted == 3
    assert scanner.targets_failed == 3
    assert sum("not started" in e for e in scanner.errors) == 2


def test_honored_template_ignores_merge_with_the_operators_ignore_checks(
    ash_temp_path,
):
    repo = _repo(ash_temp_path, "a.yaml")
    fake = RegionFaultCfnLint("no-such-template")
    _run(_scanner(repo, honor_inline_ignores=True, ignore_checks=["W2001"]), fake, repo)
    args = fake.calls[0]
    assert "--merge-configs" in args, args
    assert args[args.index("--ignore-checks") + 1] == "W2001"

    default = RegionFaultCfnLint("no-such-template")
    _run(_scanner(repo), default, repo)
    assert "--merge-configs" not in default.calls[0], default.calls[0]


def test_an_operators_cfnlintrc_ash_cannot_read_stops_the_scan(ash_temp_path, tmp_path):
    repo = _repo(ash_temp_path, "a.yaml")
    operator_rc = tmp_path / "operator" / ".cfnlintrc"
    operator_rc.parent.mkdir()
    operator_rc.write_text("ignore_checks: [\n", encoding="utf-8")
    scanner = _scanner(repo, config_file=str(operator_rc))
    with pytest.raises(ScannerError, match="could not read"):
        scanner._config_file_settings(operator_rc)


def test_errors_are_reset_for_each_scan_call(ash_temp_path):
    repo = ash_temp_path / "repo"
    repo.mkdir()
    scanner = _scanner(repo)
    scanner.errors = ["the source target's line"]
    with patch.object(CfnLintScanner, "_run_subprocess") as run:
        scanner.scan(target=repo, target_type="source")
    run.assert_not_called()
    assert scanner.errors == []


def test_the_last_dependency_fallback_runs_the_binary_it_found(ash_temp_path):
    repo = ash_temp_path / "repo"
    repo.mkdir()
    scanner = _scanner(repo)
    with (
        patch.object(
            CfnLintScanner, "resolve_deferred_tool_version", return_value=None
        ),
        patch.object(
            CfnLintScanner, "_validate_uv_tool_availability", return_value=True
        ),
        patch.object(
            CfnLintScanner,
            "_get_tool_installation_info",
            return_value={"available": False},
        ),
        patch.object(CfnLintScanner, "_install_uv_tool", return_value=False),
        patch.object(
            cfn_lint_scanner, "get_uv_tool_command", return_value=["/usr/bin/cfn-lint"]
        ),
    ):
        assert scanner.validate_plugin_dependencies() is True
    assert scanner.dependencies_satisfied is True
    assert scanner.use_uv_tool is False, (
        "the scan would go through uv, whose install failed"
    )
