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
RUN_CASE = REPO_ROOT / "scripts" / "e2e" / "run_case.py"
CASES = REPO_ROOT / "tests" / "e2e" / "fixtures" / "cases.json"


def _load(path=SCRIPT, name="ash_e2e_assert_outcome"):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None, path
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
        tmp_path,
        [ao._sarif_result("detect-secrets")] * 3,
        {"detect-secrets": "FAILED"},  # pragma: allowlist secret
    )
    assert ao.main(["--case", "findings", "--output-dir", str(out), "--rc", "2"]) == 0


def test_cli_rejects_the_wrong_exit_code(tmp_path):
    out = _write(
        tmp_path,
        [ao._sarif_result("detect-secrets")] * 3,
        {"detect-secrets": "FAILED"},  # pragma: allowlist secret
    )
    assert ao.main(["--case", "findings", "--output-dir", str(out), "--rc", "0"]) == 1


def _findings_output(tmp_path):
    return _write(
        tmp_path,
        [ao._sarif_result("detect-secrets")] * 3,
        {"detect-secrets": "FAILED"},  # pragma: allowlist secret
    )


def _annotations(text):
    return [line for line in text.splitlines() if line.lstrip().startswith("::error::")]


def test_a_real_rejection_is_an_error_annotation(tmp_path, capsys):
    # The control for the next test: without --expect-reject, every problem is an
    # annotation, so a real failure still shows on the run summary.
    out = _findings_output(tmp_path)
    rc = ao.main(["--case", "findings", "--output-dir", str(out), "--rc", "0"])
    printed = capsys.readouterr().out
    assert rc == 1
    assert _annotations(printed)
    assert "exit code 0 (nothing actionable), expected exactly 2" in printed
    assert "FAIL:" in printed


def test_an_expected_rejection_prints_no_annotation(tmp_path, capsys):
    out = _findings_output(tmp_path)
    rc = ao.main(
        ["--case", "findings", "--output-dir", str(out), "--rc", "0", "--expect-reject"]
    )
    printed = capsys.readouterr().out
    assert rc == 1, "the flag must not change the verdict"
    assert _annotations(printed) == []
    # The reason is still printed, so a caller can check the control fired for it.
    assert (
        f"{ao.EXPECTED_REJECTION}[findings] exit code 0 (nothing actionable), "
        "expected exactly 2" in printed
    )
    assert "REJECTED, as the caller expected" in printed


def test_an_expected_rejection_that_matched_is_annotated(tmp_path, capsys):
    # The negative control failing: it asked for a rejection and the outcome matched.
    out = _findings_output(tmp_path)
    rc = ao.main(
        ["--case", "findings", "--output-dir", str(out), "--rc", "2", "--expect-reject"]
    )
    printed = capsys.readouterr().out
    assert rc == 0
    assert len(_annotations(printed)) == 1
    assert "rejected nothing" in printed


def _fake_scan(run_case, monkeypatch, rc, write_output):
    class _Done:
        returncode = rc

    def fake_run(command, **kwargs):
        if write_output is not None:
            write_output(Path(command[command.index("--output-dir") + 1]))
        return _Done()

    monkeypatch.setattr(run_case.subprocess, "run", fake_run)


@pytest.mark.parametrize("expect_reject", [False, True])
def test_run_case_annotates_only_unexpected_rejections(
    tmp_path, monkeypatch, capsys, expect_reject
):
    run_case = _load(RUN_CASE, "ash_e2e_run_case")
    cli = tmp_path / "fake-ashx"
    cli.write_text("", encoding="utf-8")
    # A findings scan that exited 0, the shape of the --no-fail-on-findings control.
    _fake_scan(
        run_case,
        monkeypatch,
        0,
        lambda out: _write(
            out,
            [ao._sarif_result("detect-secrets")] * 3,
            {"detect-secrets": "FAILED"},  # pragma: allowlist secret
        ),
    )
    argv = ["--cli", str(cli), "--case", "findings", "--work", str(tmp_path / "w")]
    if expect_reject:
        argv.append("--expect-reject")
    rc = run_case.main(argv)
    printed = capsys.readouterr().out
    assert rc == 1
    assert "exit code 0 (nothing actionable), expected exactly 2" in printed
    assert bool(_annotations(printed)) is not expect_reject


def test_run_case_annotates_an_expected_rejection_that_matched(
    tmp_path, monkeypatch, capsys
):
    run_case = _load(RUN_CASE, "ash_e2e_run_case")
    cli = tmp_path / "fake-ashx"
    cli.write_text("", encoding="utf-8")
    _fake_scan(
        run_case,
        monkeypatch,
        2,
        lambda out: _write(
            out,
            [ao._sarif_result("detect-secrets")] * 3,
            {"detect-secrets": "FAILED"},  # pragma: allowlist secret
        ),
    )
    rc = run_case.main(
        [
            "--cli",
            str(cli),
            "--case",
            "findings",
            "--work",
            str(tmp_path / "w"),
            "--expect-reject",
        ]
    )
    printed = capsys.readouterr().out
    assert rc == 0
    assert len(_annotations(printed)) == 1


WINDOWS_LEGS = {
    "msix": REPO_ROOT / "packaging" / "msix" / "verify-on-windows.ps1",
    "chocolatey": REPO_ROOT / "packaging" / "chocolatey" / "verify-on-windows.ps1",
    "winget": REPO_ROOT / "packaging" / "winget" / "verify-on-windows.ps1",
}


def _asks_for_rejection(line):
    # The flag itself, or the -ExpectReject switch of the scripts' Invoke-Case helper.
    return "--expect-reject" in line or "-ExpectReject" in line


@pytest.mark.parametrize("leg", sorted(WINDOWS_LEGS))
def test_windows_negative_controls_ask_for_their_rejection(leg):
    # Each deliberate negative on the shared verdict passes --expect-reject, and no
    # positive case does. Counted per call: a control that dropped the flag would
    # annotate a green run again, and a positive case that gained it would turn a real
    # failure into a plain line.
    text = WINDOWS_LEGS[leg].read_text(encoding="utf-8")
    negatives = re.findall(r"^.*negative-no-fail-on-findings.*$", text, re.MULTILINE)
    calls = [line for line in negatives if "--no-fail-on-findings" in line]
    assert calls, f"{leg}: no --no-fail-on-findings control found"
    for line in calls:
        assert _asks_for_rejection(line), f"{leg}: {line.strip()}"
    flagged = [
        line
        for line in text.splitlines()
        if _asks_for_rejection(line)
        and not line.lstrip().startswith("#")
        # The Invoke-Case helper turning its switch into the flag.
        and "$arguments" not in line
    ]
    # The only other flagged call is the clean-output-as-findings control, which runs
    # assert_outcome.py with --expect-rc 2 on the clean case's output.
    for line in flagged:
        assert "negative" in line or "--expect-rc" in line or "'--expect-rc'" in line, (
            f"{leg}: --expect-reject on a line that is not a negative control: "
            f"{line.strip()}"
        )


def test_cli_incomplete_case_requires_the_named_scanner(tmp_path):
    out = _write(
        tmp_path,
        [ao._sarif_result("detect-secrets")] * 3,
        {"detect-secrets": "FAILED", "opengrep": "PASSED"},  # pragma: allowlist secret
    )
    assert ao.main(["--case", "incomplete", "--output-dir", str(out), "--rc", "1"]) == 1


def test_cli_refuses_exit_one_without_a_named_scanner(tmp_path):
    out = _write(tmp_path, [], {"detect-secrets": "PASSED"})  # pragma: allowlist secret
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
        tmp_path,
        [ao._sarif_result("detect-secrets")] * 2,
        {"detect-secrets": "FAILED"},  # pragma: allowlist secret
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
        {"detect-secrets": "FAILED"},  # pragma: allowlist secret
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
    assert isinstance(case.get("args"), list)
    assert all(isinstance(a, str) for a in case["args"])


def test_the_cases_cover_all_three_exit_codes():
    cases = json.loads(CASES.read_text(encoding="utf-8"))["cases"]
    assert sorted(c["expect_rc"] for c in cases.values()) == [0, 1, 2]


def test_incomplete_trigger_blanks_the_rule_cache():
    # The trigger measured in tests/e2e/README.md: offline opengrep with no rule cache.
    # The cache variable must be set to empty, not left out, so an image that carries a
    # populated cache cannot turn the trigger off.
    env = ao.load_case(CASES, "incomplete")["env"]
    assert env == {"ASH_OFFLINE": "YES", "OPENGREP_RULES_CACHE_DIR": ""}


def test_incomplete_trigger_turns_opengrep_on():
    # opengrep's config is disabled by default on Windows
    # (OpengrepScannerConfig.enabled), and a config-disabled scanner is recorded
    # SKIPPED even when --scanners names it, so without this override the windows
    # legs exit 2 instead of 1. See the Windows rows in tests/e2e/README.md.
    args = ao.load_case(CASES, "incomplete")["args"]
    assert args == ["--config-overrides", "scanners.opengrep.enabled=true"]


def test_run_case_passes_the_case_args_to_the_scan(tmp_path, monkeypatch):
    # Every channel that runs a case through run_case.py gets the case's args, ahead of
    # any extra arguments the caller adds.
    run_case = _load(RUN_CASE, "ash_e2e_run_case")
    cli = tmp_path / "fake-ashx"
    cli.write_text("", encoding="utf-8")
    seen = []

    class _Done:
        returncode = 1

    def fake_run(command, **kwargs):
        seen.append(list(command))
        return _Done()

    monkeypatch.setattr(run_case.subprocess, "run", fake_run)
    rc = run_case.main(
        [
            "--cli",
            str(cli),
            "--case",
            "incomplete",
            "--work",
            str(tmp_path / "work"),
            "--",
            "--extra-flag",
        ]
    )
    assert rc == 1  # the fake scan wrote no reports
    assert len(seen) == 1
    command = seen[0]
    scanners_at = command.index("--scanners")
    assert command[scanners_at + 1] == "detect-secrets,opengrep"
    assert command[scanners_at + 2 :] == [
        "--config-overrides",
        "scanners.opengrep.enabled=true",
        "--extra-flag",
    ]


def test_findings_fixture_plants_the_published_example_key():
    text = (CASES.parent / "findings" / "leak.py").read_text(encoding="utf-8")
    planted = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # pragma: allowlist secret
    assert planted in text


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
