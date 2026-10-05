# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The shared e2e contract: scripts/e2e/assert_outcome.py, the fixtures, the CLI name.

Every e2e channel judges its scans with assert_outcome.py, so a defect there is a
defect in every channel at once. These tests run its planted-output self-test, check
it against outputs shaped like real ones, and hold the fixtures and the CLI-name
sources to each other.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "e2e" / "assert_outcome.py"
CASES = REPO_ROOT / "tests" / "e2e" / "fixtures" / "cases.json"


def _load():
    spec = importlib.util.spec_from_file_location("ash_e2e_assert_outcome", SCRIPT)
    assert spec is not None and spec.loader is not None, SCRIPT
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ao = _load()


def _write(root: Path, results, statuses, actionable=None):
    return ao._write_output(root, results, statuses, actionable=actionable)


def test_self_test_passes(capsys):
    assert ao.self_test() == 0
    assert "self-test passed" in capsys.readouterr().out


def test_cli_findings_case_accepts_a_matching_output(tmp_path):
    out = _write(
        tmp_path, [ao._sarif_result("detect-secrets")] * 3, {"detect-secrets": "FAILED"}
    )
    assert ao.main(["--case", "findings", "--output-dir", str(out), "--rc", "2"]) == 0


def test_cli_rejects_the_wrong_exit_code(tmp_path):
    out = _write(
        tmp_path, [ao._sarif_result("detect-secrets")] * 3, {"detect-secrets": "FAILED"}
    )
    assert ao.main(["--case", "findings", "--output-dir", str(out), "--rc", "0"]) == 1


def test_cli_incomplete_case_requires_the_named_scanner(tmp_path):
    out = _write(
        tmp_path,
        [ao._sarif_result("detect-secrets")] * 3,
        {"detect-secrets": "FAILED", "opengrep": "PASSED"},
    )
    assert ao.main(["--case", "incomplete", "--output-dir", str(out), "--rc", "1"]) == 1


def test_cli_refuses_exit_one_without_a_named_scanner(tmp_path):
    out = _write(tmp_path, [], {"detect-secrets": "PASSED"})
    rc = ao.main(
        [
            "--output-dir",
            str(out),
            "--rc",
            "1",
            "--expect-rc",
            "1",
            "--findings",
            "0",
            "--selected",
            "detect-secrets",
        ]
    )
    assert rc == 3


def test_flags_override_the_case(tmp_path):
    out = _write(
        tmp_path, [ao._sarif_result("detect-secrets")] * 2, {"detect-secrets": "FAILED"}
    )
    assert (
        ao.main(
            [
                "--case",
                "findings",
                "--findings",
                "2",
                "--output-dir",
                str(out),
                "--rc",
                "2",
            ]
        )
        == 0
    )


def test_no_sarif_fallback(tmp_path):
    out = ao._write_output(
        tmp_path,
        [ao._sarif_result("detect-secrets")] * 3,
        {"detect-secrets": "FAILED"},
        sarif_at=Path("ash.sarif"),
    )
    problems = ao.check_outcome(
        out, 2, ao.Expectation(2, findings=3, selected=["detect-secrets"])
    )
    assert any("no SARIF report at" in p for p in problems)


@pytest.mark.parametrize("name", ["findings", "clean", "incomplete"])
def test_every_case_is_well_formed(name):
    case = ao.load_case(CASES, name)
    expectation = ao.Expectation(
        expect_rc=case["expect_rc"],
        findings=case.get("findings"),
        min_findings=case.get("min_findings"),
        require_scanner=case.get("require_scanner"),
        selected=case["scanners"],
        incomplete_scanner=case.get("incomplete_scanner"),
    )
    assert expectation.usage_problems() == []
    source = CASES.parent / case["source"]
    assert source.is_dir() and any(source.iterdir()), source
    assert isinstance(case.get("env"), dict)


def test_the_cases_cover_all_three_exit_codes():
    cases = json.loads(CASES.read_text(encoding="utf-8"))["cases"]
    assert sorted(c["expect_rc"] for c in cases.values()) == [0, 1, 2]


def test_incomplete_trigger_blanks_the_rule_cache():
    # The trigger measured in tests/e2e/README.md: offline opengrep with no rule cache.
    # The cache variable must be set to empty, not left out, so an image that carries a
    # populated cache cannot turn the trigger off.
    env = ao.load_case(CASES, "incomplete")["env"]
    assert env == {"ASH_OFFLINE": "YES", "OPENGREP_RULES_CACHE_DIR": ""}


def test_findings_fixture_plants_the_published_example_key():
    text = (CASES.parent / "findings" / "leak.py").read_text(encoding="utf-8")
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" in text


def test_cli_name_sources_agree():
    shell = (REPO_ROOT / "packaging" / "cli-name.sh").read_text(encoding="utf-8")
    match = re.search(r"^ASH_CLI_NAME=([a-z0-9+.-]+)$", shell, re.MULTILINE)
    assert match, "ASH_CLI_NAME not found in packaging/cli-name.sh"
    json_name = json.loads(
        (REPO_ROOT / "scripts" / "e2e" / "cli_name.json").read_text(encoding="utf-8")
    )["cli_name"]
    assert json_name == match.group(1)
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert re.search(rf'^{re.escape(json_name)} = "', pyproject, re.MULTILINE), (
        f"{json_name} is not a [project.scripts] entry"
    )
