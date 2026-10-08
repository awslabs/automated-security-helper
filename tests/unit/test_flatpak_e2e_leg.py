# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The Flatpak e2e leg: packaging/flatpak/verify-in-container.sh and its CI job.

The leg itself needs a host where bwrap can create a user namespace, so it runs in CI
(ash-package.yml `flatpak`, on the runner host) and in a privileged container, never
in the unit suite. These tests hold the parts that can drift without that host noticing:

- the script runs every case in tests/e2e/fixtures/cases.json through
  scripts/e2e/run_case.py, and has no private SARIF reader to fall back on;
- its exit-code negative control greps run_case.py's output for a line that
  assert_outcome.py really prints, so a reworded message cannot turn the control into
  one that can never pass;
- the CI job feeds the upgrade leg an N-1 wheel, and the push caller rebuilds the
  packages when ASH's own code or the e2e contract changes.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "packaging" / "flatpak" / "verify-in-container.sh"
RUN_CASE = REPO_ROOT / "scripts" / "e2e" / "run_case.py"
CASES = REPO_ROOT / "tests" / "e2e" / "fixtures" / "cases.json"
PACKAGE_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ash-package.yml"
FORMATS_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ash-package-formats.yml"


def _load(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None, path
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _script() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def test_every_case_runs_through_run_case() -> None:
    match = re.search(r"^for case_name in ([a-z ]+); do$", _script(), re.MULTILINE)
    assert match, "the loop over the e2e cases is gone from the Flatpak script"
    looped = set(match.group(1).split())
    cases = set(json.loads(CASES.read_text(encoding="utf-8"))["cases"])
    assert looped == cases
    assert 'run_case --cli "$SHIM" --case "$case_name"' in _script()


def test_no_private_report_reader_is_left() -> None:
    # The defects this leg replaced: an exit code captured and never compared, and a
    # SARIF lookup that took any *.sarif when reports/ash.sarif was missing. The last
    # *.sarif walk was step 7's sandbox control, which read rc=1 with no report as
    # "0 findings" and passed; it is gone too.
    text = _script()
    assert "SCAN_RC=" not in text
    assert "rglob(" not in text
    assert '.sarif")' not in text


def _step(number: str) -> str:
    text = _script()
    start = text.index(f'echo "== {number}. ')
    nxt = re.compile(r'^echo "== [0-9]+[a-z]?\. ', re.MULTILINE)
    match = nxt.search(text, start + 1)
    return text[start : match.start() if match else len(text)]


def test_the_sandbox_control_asserts_its_exit_code_message_and_report_paths() -> None:
    step = _step("7")
    assert 'if [ "$NEG_RC" -ne 1 ]; then' in step
    # The refusal ASH prints for a missing --source-dir, naming this fixture's path.
    assert 'grep -qF "Source directory does not exist: $FIX_UNREACHABLE"' in step
    source = (REPO_ROOT / "automated_security_helper" / "cli" / "scan.py").read_text(
        encoding="utf-8"
    )
    assert 'f"Source directory does not exist: {source_dir}. "' in source, (
        "the message step 7 requires is no longer what ASH prints"
    )
    # Both reports, at their exact paths, under an output dir the sandbox can write.
    assert "for report in reports/ash.sarif ash_aggregated_results.json; do" in step
    assert "NEG_OUT=/srv/" in step
    assert '--output-dir "$NEG_OUT"' in step
    assert "exit 1" in step


def _run_version_check(reported: str, expected: str) -> int:
    import subprocess

    text = _script()
    start = text.index("assert_reports_version() {")
    end = text.index("\n}\n", start) + 3
    script = text[start:end] + f'assert_reports_version "{reported}" "{expected}"\n'
    return subprocess.run(["bash", "-c", script], capture_output=True).returncode


@pytest.mark.parametrize(
    ("reported", "expected", "rc"),
    [
        ("awslabs/automated-security-helper v4.0.0", "4.0.0", 0),
        ("awslabs/automated-security-helper v3.0.0", "4.0.0", 1),
        ("awslabs/automated-security-helper v14.0.0", "4.0.0", 1),
        ("awslabs/automated-security-helper v4.0.01", "4.0.0", 1),
        ("", "4.0.0", 1),
    ],
)
def test_the_version_check_requires_the_exact_version(
    reported: str, expected: str, rc: int
) -> None:
    assert _run_version_check(reported, expected) == rc


def test_every_version_the_app_reports_is_compared() -> None:
    text = _script()
    # step 5's --version and -V, and step 12's N-1 and N.
    assert text.count('assert_reports_version "$REPORTED" "$VERSION"') == 2
    assert 'assert_reports_version "$PREV_REPORTED" "$PREV_VERSION"' in text
    assert 'assert_reports_version "$NEW_REPORTED" "$VERSION"' in text
    assert 'flatpak run "$APP_ID" --version\nflatpak' not in text


def test_exit_code_control_matches_what_run_case_prints(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    pattern = re.search(r"grep -Eq '(\^::error::\\\[neg-no-fail\\\][^']*)'", _script())
    assert pattern, "the --no-fail-on-findings control's grep is gone"
    regex = re.compile(pattern.group(1))

    ao = _load(REPO_ROOT / "scripts" / "e2e" / "assert_outcome.py", "flatpak_e2e_ao")
    run_case = _load(RUN_CASE, "flatpak_e2e_run_case")
    cli = tmp_path / "ashx"
    cli.write_text("", encoding="utf-8")

    class _Done:
        returncode = 0

    def fake_run(command: List[str], **kwargs: Any) -> _Done:
        # What `scan --no-fail-on-findings` produces on the findings fixture: the same
        # three detect-secrets results, and exit 0.
        out = Path(command[command.index("--output-dir") + 1])
        ao._write_output(
            out,
            [ao._sarif_result("detect-secrets")] * 3,
            {"detect-secrets": "FAILED"},  # pragma: allowlist secret
        )
        return _Done()

    monkeypatch.setattr(run_case.subprocess, "run", fake_run)
    rc = run_case.main(
        [
            "--cli",
            str(cli),
            "--case",
            "findings",
            "--work",
            str(tmp_path / "work"),
            "--label",
            "neg-no-fail",
            "--",
            "--no-fail-on-findings",
        ]
    )
    printed = capsys.readouterr().out.splitlines()
    assert rc == 1
    assert [line for line in printed if regex.search(line)], printed


def _flatpak_steps() -> List[Dict[str, Any]]:
    jobs = yaml.safe_load(PACKAGE_WORKFLOW.read_text(encoding="utf-8"))["jobs"]
    steps: List[Dict[str, Any]] = jobs["flatpak"]["steps"]
    return steps


def test_the_ci_job_builds_and_passes_the_n_minus_1_wheel() -> None:
    steps = _flatpak_steps()
    builds = [s for s in steps if "build-test-wheels.sh" in str(s.get("run", ""))]
    assert len(builds) == 1, "the flatpak job no longer builds the N-1 wheel"
    out_dir = builds[0]["run"].split()[-1].strip('"')
    verify = [s for s in steps if "verify-in-container.sh" in str(s.get("run", ""))]
    assert len(verify) == 1
    env = verify[0]["env"]
    assert env["PREV_DIST"].endswith("/flatpak-wheels/dist-prev")
    assert out_dir == "$RUNNER_TEMP/flatpak-wheels"
    assert "--preserve-env=REPO,DIST,PREV_DIST" in verify[0]["run"]


def test_the_push_caller_rebuilds_on_product_and_contract_changes() -> None:
    on = yaml.safe_load(FORMATS_WORKFLOW.read_text(encoding="utf-8"))[True]
    push = on["push"]
    assert push["branches"] == ["**"]
    for path in (
        "automated_security_helper/**",
        "scripts/e2e/**",
        "tests/e2e/**",
        "packaging/**",
    ):
        assert path in push["paths"], path


def _function(name: str) -> str:
    text = _script()
    start = text.index(f"{name}() {{")
    return text[start : text.index("\n}\n", start) + 3]


def test_the_runtime_is_pinned_by_a_full_commit_and_read_back() -> None:
    text = _script()
    match = re.search(r'^RUNTIME_COMMIT_X86_64="([0-9a-f]+)"$', text, re.MULTILINE)
    assert match, "the x86_64 runtime commit pin is gone or not a literal"
    assert len(match.group(1)) == 64, "an OSTree commit is 64 hex digits"
    assert '--commit="$RUNTIME_COMMIT"' in text
    assert 'assert_runtime_commit "$RUNTIME_COMMIT"' in text
    # The pin is applied before anything is built against the runtime.
    assert text.index('assert_runtime_commit "$RUNTIME_COMMIT"') < text.index(
        "== 2. build the N and N-1 bundles"
    )


@pytest.mark.parametrize(
    ("installed", "pinned", "rc"),
    [("a" * 64, "a" * 64, 0), ("b" * 64, "a" * 64, 1), ("", "a" * 64, 1)],
)
def test_the_runtime_commit_check_rejects_any_other_commit(
    tmp_path: Path, installed: str, pinned: str, rc: int
) -> None:
    import subprocess

    stub = tmp_path / "flatpak"
    stub.write_text(f"#!/bin/sh\nprintf '%s\\n' '{installed}'\n", encoding="utf-8")
    stub.chmod(0o755)
    script = (
        "RUNTIME_VERSION=24.08\n"
        + _function("assert_runtime_commit")
        + f'assert_runtime_commit "{pinned}"\n'
    )
    result = subprocess.run(
        ["bash", "-c", script],
        env={"PATH": f"{tmp_path}:/usr/bin:/bin"},
        capture_output=True,
        text=True,
    )
    assert result.returncode == rc, result.stderr


def test_n_minus_1_is_built_with_its_own_packaging() -> None:
    text = _script()
    assert 'PREV_BUNDLE="$("$PREV_SRC/packaging/flatpak/build.sh" "$PREV_WHEEL"' in text
    assert '"$REPO/packaging/flatpak/build.sh" "$PREV_WHEEL"' not in text
    assert '[ "$N1_SHA" != "$N1_HEAD" ]' in text
