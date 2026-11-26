# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""CredSweeper over reports a real run wrote, and what the sandbox gives it.

``tests/test_data/scanners/credsweeper/captured/`` holds the reports CredSweeper 1.19.7
wrote (see its README). The severity mapping is asserted over those, not over a
report written in this file. The sandbox rows build the policy with
``build_scanner_policy``, the function every sandboxed spawn goes through, so a
declaration the policy ignores fails here.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, List

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_credsweeper_plugins.credsweeper_scanner import (
    REDACTED,
    CredSweeperScanner,
    CredSweeperScannerConfig,
    convert_credsweeper_report,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.sandbox.policy import (
    SandboxRequirements,
    build_scanner_policy,
)

pytestmark = pytest.mark.unit

CAPTURED = (
    Path(__file__).resolve().parents[3]
    / "test_data"
    / "scanners"
    / "credsweeper"
    / "captured"
)


def _captured_text(name: str) -> str:
    return (CAPTURED / name).read_text(encoding="utf-8")


def _captured(name: str) -> Any:
    return json.loads(_captured_text(name))


@pytest.fixture
def tree(tmp_path) -> Path:
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text("print(1)\n")
    return src


# ---------------------------------------------------------------------------
# Severity over a captured report
# ---------------------------------------------------------------------------


def test_the_captured_positive_is_a_real_report():
    """The control on the fixture: it is the tool's own shape, one finding."""
    findings = _captured("positive.json")
    assert len(findings) == 1
    finding = findings[0]
    assert finding["rule"] == "Password"
    assert finding["severity"] == "high"
    assert finding["confidence"] == "moderate"
    assert finding["line_data_list"][0]["path"] == "./app.py"


def test_the_captured_positive_is_rated_by_confidence_not_rule_severity(tree):
    """The rule says severity high; the model says confidence moderate; ASH rates MEDIUM."""
    doc = convert_credsweeper_report(_captured("positive.json"), tree)
    report = SarifReport.model_validate(doc)
    results = report.get_all_results()
    assert len(results) == 1
    result = results[0]
    location = result.locations[0].physicalLocation.root
    assert result.ruleId == "Password"
    assert getattr(result.level, "value", result.level) == "warning"
    assert getattr(result.properties, "issue_severity") == "MEDIUM"
    assert location.artifactLocation.uri == "app.py"
    assert location.region.startLine == 2
    assert location.region.snippet.text == REDACTED
    assert getattr(result.properties, "credsweeper_rule_severity") == "high"


def test_no_hashed_field_of_the_capture_reaches_the_sarif(tree):
    """Even the digests the tool wrote (--hashed) stay out of the SARIF."""
    finding = _captured("positive.json")[0]["line_data_list"][0]
    text = json.dumps(convert_credsweeper_report(_captured("positive.json"), tree))
    for field in ("line", "variable", "value"):
        assert finding[field] not in text


def test_the_captured_negative_has_a_run_and_no_findings(tree):
    findings = _captured("negative.json")
    assert findings == []
    report = SarifReport.model_validate(convert_credsweeper_report(findings, tree))
    assert len(report.runs) == 1
    assert report.get_all_results() == []


def _scanner(source: Path, tmp_path: Path) -> CredSweeperScanner:
    output = tmp_path / "out"
    return CredSweeperScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=output,
            work_dir=output / "converted",
            config=get_default_config(),
        ),
        config=CredSweeperScannerConfig(enabled=True),
    )


def _serve(scanner: CredSweeperScanner, text: str, monkeypatch) -> None:
    """Stand in for the subprocess: write the captured bytes where --save-json points."""

    def run(command: List[str], **_: Any) -> dict:
        arg = next(a for a in command if a.startswith("--save-json="))
        path = Path(arg.split("=", 1)[1])
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        scanner.exit_code = 0
        return {"returncode": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(scanner, "validate_plugin_dependencies", lambda: True)
    monkeypatch.setattr(scanner, "_run_subprocess", run)


@pytest.mark.parametrize(
    "name, expected",
    [("positive.json", ["MEDIUM"]), ("negative.json", [])],
)
def test_scan_over_the_captured_bytes(tree, tmp_path, monkeypatch, name, expected):
    scanner = _scanner(tree, tmp_path)
    _serve(scanner, _captured_text(name), monkeypatch)
    report = scanner.scan(target=tree, target_type="source")
    assert isinstance(report, SarifReport)
    severities = [
        getattr(r.properties, "issue_severity", None) for r in report.get_all_results()
    ]
    assert severities == expected


# ---------------------------------------------------------------------------
# Sandbox requirements
# ---------------------------------------------------------------------------


@pytest.fixture
def layout(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    source = tmp_path / "sandbox_src"
    source.mkdir()
    output = source / ".ash" / "ash_output"
    output.mkdir(parents=True)
    return SimpleNamespace(home=home, source=source, output=output, tmp=tmp_path)


def _policy(layout, requirements):
    return build_scanner_policy(
        "credsweeper",
        requirements,
        argv0=sys.executable,
        source_dir=layout.source,
        output_dir=layout.output,
        results_dir=layout.output / "scanners" / "credsweeper",
        scan_target=layout.source,
        cwd=layout.source,
        offline=False,
        network_scanners=None,
    )


def _real(paths):
    return {p.resolve() for p in paths}


def test_credsweeper_declares_the_strict_default(layout):
    declared = CredSweeperScanner.sandbox_requirements
    assert declared == SandboxRequirements()
    policy = _policy(layout, declared)
    default = _policy(layout, SandboxRequirements())
    assert policy.network is False
    assert _real(policy.read_only) == _real(default.read_only)
    assert _real(policy.cache) == _real(default.cache)


def test_no_environment_variable_is_passed_into_the_sandbox(layout):
    """The baseline allowlist only: a CredSweeper or proxy variable does not cross."""
    policy = _policy(layout, CredSweeperScanner.sandbox_requirements)
    passed = policy.filter_env(
        {
            "CREDSWEEPER_CONFIG": "/etc/rules.json",
            "HTTPS_PROXY": "http://proxy.invalid",
            "AWS_SECRET_ACCESS_KEY": "not-a-secret",
        }
    )
    assert passed.keys() == {"HOME"} | set(policy.extra_env)
