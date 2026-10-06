# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""cfn-lint and cfn-guard, run for real by ``ash scan`` against the fixture repository.

Every scan here is a subprocess of the installed ``ash`` entry point, so config
resolution, opt-in selection, template discovery, the real tools, suppressions and the
reporters are all the code a user runs. The fixture is
``tests/test_data/scanners/cfn_lint_guard/repo``: one template with known positives for
both tools, one compliant template (which also carries a cfn-guard native suppression),
a YAML file that is not CloudFormation, and a file that is not valid YAML.

The skip is env-gated, as in ``test_cfn_nag_custom_rules.py``: a test that silently
skips when its tools are missing protects nothing. ``ASH_REQUIRE_CFN_TOOLS=1`` turns the
skip into a failure; the integration-test job installs both tools with
``ash dependencies install --tool cfn-lint --tool cfn-guard`` and sets it.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess  # nosec B404 - the CLI under test is a separate process
import sys
from pathlib import Path

import pytest
import yaml

from automated_security_helper.utils.rules_bundles import RulesBundleUnavailable
from automated_security_helper.utils.subprocess_utils import find_executable

pytestmark = [pytest.mark.integration]

FIXTURE_REPO = (
    Path(__file__).resolve().parents[2]
    / "test_data"
    / "scanners"
    / "cfn_lint_guard"
    / "repo"
)

#: (rule id, line) per tool on templates/insecure.yaml, as the unit tests' captured
#: output records them. The real tools must still produce exactly these.
CFN_LINT_EXPECTED = {("W2001", 4), ("E3002", 10), ("E2533", 14)}
CFN_GUARD_EXPECTED_RULES = {
    "LAMBDA_INSIDE_VPC",
    "S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED",
    "S3_BUCKET_LOGGING_ENABLED",
    "S3_BUCKET_PUBLIC_READ_PROHIBITED",
    "S3_BUCKET_PUBLIC_WRITE_PROHIBITED",
    "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED",
    "S3_BUCKET_VERSIONING_ENABLED",
    "S3_DEFAULT_ENCRYPTION_KMS",
}


def _required() -> bool:
    return os.environ.get("ASH_REQUIRE_CFN_TOOLS", "").strip().upper() in (
        "1",
        "YES",
        "TRUE",
    )


def _require_tools() -> None:
    from automated_security_helper.utils.rules_bundles import verify_installed_bundle
    from automated_security_helper.utils.tool_downloads import get_rules_bundle

    problems = []
    if find_executable("cfn-guard") is None:
        problems.append("cfn-guard is not on PATH or in ASH_BIN_PATH")
    try:
        verify_installed_bundle(get_rules_bundle("aws-guard-rules-registry"))
    except RulesBundleUnavailable as exc:
        problems.append(str(exc))
    if find_executable("cfn-lint") is None:
        problems.append("cfn-lint is not on PATH")
    if problems:
        message = "; ".join(problems)
        if _required():
            pytest.fail(
                f"ASH_REQUIRE_CFN_TOOLS is set but {message}. These tests must RUN "
                "where the tools are provisioned."
            )
        pytest.skip(message)


def _ash() -> str:
    ash = shutil.which("ash", path=str(Path(sys.executable).parent))
    assert ash, f"no ash entry point beside {sys.executable}"
    return ash


def _scan(tmp_path: Path, scanners: str, config: dict | None = None, env=None):
    source = tmp_path / "repo"
    if not source.exists():
        shutil.copytree(FIXTURE_REPO, source)
    output = (
        tmp_path / f"out-{scanners.replace(',', '-')}-{len(list(tmp_path.iterdir()))}"
    )
    config_path = tmp_path / "ash.yaml"
    config_path.write_text(
        yaml.safe_dump({"project_name": "cfn-tools-e2e", **(config or {})}),
        encoding="utf-8",
    )
    proc = subprocess.run(  # nosec B603 - fixed argv
        [
            _ash(),
            "scan",
            "--mode",
            "local",
            "--source-dir",
            str(source),
            "--output-dir",
            str(output),
            "--config",
            str(config_path),
            "--scanners",
            scanners,
            "--no-progress",
            "--no-fail-on-findings",
        ],
        capture_output=True,
        text=True,
        timeout=900,
        env={**os.environ, **(env or {})},
    )
    log = (
        f"exit {proc.returncode}\nSTDOUT:\n{proc.stdout[-4000:]}\n"
        f"STDERR:\n{proc.stderr[-4000:]}"
    )
    return proc, output, log


def _results(output: Path, scanner: str) -> list:
    sarif = json.loads((output / "reports" / "ash.sarif").read_text(encoding="utf-8"))
    out = []
    for run in sarif["runs"]:
        for result in run.get("results", []):
            tags = (result.get("properties") or {}).get("tags") or []
            if scanner in tags:
                out.append(result)
    return out


def _where(result) -> tuple:
    physical = result["locations"][0]["physicalLocation"]
    return physical["artifactLocation"]["uri"], physical["region"]["startLine"]


def _scanner_results(output: Path) -> dict:
    data = json.loads(
        (output / "ash_aggregated_results.json").read_text(encoding="utf-8")
    )
    return data["scanner_results"]


def test_both_scanners_report_the_known_positives_and_nothing_else(tmp_path):
    _require_tools()
    proc, output, log = _scan(tmp_path, "cfn-lint,cfn-guard")
    assert proc.returncode == 0, log

    lint = _results(output, "cfn-lint")
    assert {(r["ruleId"], _where(r)[1]) for r in lint} == CFN_LINT_EXPECTED, log
    assert {_where(r)[0] for r in lint} == {"templates/insecure.yaml"}

    guard = _results(output, "cfn-guard")
    assert {r["ruleId"] for r in guard} == CFN_GUARD_EXPECTED_RULES, log
    # compliant.yaml produces nothing, including the LogBucket whose missing access
    # logging is suppressed in the template with cfn-guard's own Metadata.
    assert {_where(r)[0] for r in guard} == {"templates/insecure.yaml"}

    statuses = _scanner_results(output)
    assert statuses["cfn-lint"]["status"] == "FAILED", statuses["cfn-lint"]
    assert statuses["cfn-guard"]["status"] == "FAILED", statuses["cfn-guard"]


def test_ash_suppressions_apply_by_rule_path_and_line(tmp_path):
    _require_tools()
    suppressions = [
        {
            "rule_id": "E2533",
            "path": "templates/insecure.yaml",
            "line_start": 14,
            "line_end": 14,
            "reason": "line-scoped: the deprecated runtime is the fixture's point",
        },
        {
            "rule_id": "LAMBDA_INSIDE_VPC",
            "path": "templates/insecure.yaml",
            "reason": "rule-and-path scoped",
        },
    ]
    proc, output, log = _scan(
        tmp_path,
        "cfn-lint,cfn-guard",
        config={"global_settings": {"suppressions": suppressions}},
    )
    assert proc.returncode == 0, log
    suppressed = {
        (r["ruleId"], _where(r)[1])
        for scanner in ("cfn-lint", "cfn-guard")
        for r in _results(output, scanner)
        if r.get("suppressions")
    }
    assert ("E2533", 14) in suppressed, log
    assert ("LAMBDA_INSIDE_VPC", 13) in suppressed, log
    # The same file's other findings stay visible: the entries are narrow.
    assert ("E3002", 10) not in suppressed
    assert not any(rule.startswith("S3_") for rule, _ in suppressed)


def test_offline_mode_gives_the_same_findings(tmp_path):
    _require_tools()
    _, online, log_online = _scan(tmp_path, "cfn-lint,cfn-guard")
    proc, offline, log = _scan(
        tmp_path, "cfn-lint,cfn-guard", env={"ASH_OFFLINE": "true"}
    )
    assert proc.returncode == 0, log
    for scanner in ("cfn-lint", "cfn-guard"):
        assert sorted(
            (r["ruleId"], _where(r)) for r in _results(offline, scanner)
        ) == sorted((r["ruleId"], _where(r)) for r in _results(online, scanner)), log


def test_missing_rules_are_missing_and_the_scan_is_incomplete(tmp_path):
    _require_tools()
    empty = tmp_path / "no-rules"
    empty.mkdir()
    proc, output, log = _scan(
        tmp_path, "cfn-guard", env={"ASH_CFN_GUARD_RULES_DIR": str(empty)}
    )
    assert proc.returncode == 1, log
    assert _scanner_results(output)["cfn-guard"]["status"] == "MISSING", log
    assert "rules are not installed" in (output / "ash.log").read_text(
        encoding="utf-8", errors="replace"
    )


def test_unselected_opt_in_scanners_leave_no_trace(tmp_path):
    """Named nowhere and not enabled: not run, not SKIPPED, not MISSING, absent."""
    proc, output, log = _scan(tmp_path, "cfn-nag")
    assert (output / "ash_aggregated_results.json").exists(), log
    results = _scanner_results(output)
    assert "cfn-lint" not in results and "cfn-guard" not in results, sorted(results)
