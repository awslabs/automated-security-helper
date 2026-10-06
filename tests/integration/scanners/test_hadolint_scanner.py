# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""hadolint, run for real: the pinned binary, through `ash scan`, on the fixtures.

The unit tests in tests/unit/plugin_modules/ash_builtin/test_hadolint_scanner_behavior.py
read SARIF captured from hadolint 2.15.1. These tests run the binary itself, so
they also prove the captured files are what that binary writes today.

The skip is env-gated for the reason test_cfn_nag_custom_rules.py gives: a test
that silently skips when its tool is missing protects nothing.
``ASH_REQUIRE_HADOLINT=1`` turns the skip into a failure, and the integration-test
job in .github/workflows/ash-unified-ci.yml installs the pinned binary and sets it.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess  # nosec B404 - the tool under test is a separate process
import sys
from pathlib import Path

import pytest

from automated_security_helper.utils.subprocess_utils import find_executable
from automated_security_helper.utils.tool_downloads import TOOL_VERSIONS

pytestmark = pytest.mark.integration

FIXTURES = Path(__file__).resolve().parents[2] / "test_data" / "scanners" / "hadolint"


def _hadolint() -> str:
    found = find_executable("hadolint")
    if found:
        return str(found)
    if os.environ.get("ASH_REQUIRE_HADOLINT", "").strip().lower() in (
        "1",
        "yes",
        "true",
    ):
        pytest.fail(
            "ASH_REQUIRE_HADOLINT is set but hadolint is not on PATH. These are the "
            "only tests that run the real hadolint binary."
        )
    pytest.skip("hadolint is not installed on this machine")


def _ash_scan(
    source: Path, output: Path, *extra: str, env: dict | None = None
) -> subprocess.CompletedProcess:
    return subprocess.run(  # nosec B603 - fixed argv, no shell
        [
            sys.executable,
            "-c",
            "from automated_security_helper.cli.entrypoint import main; main()",
            "scan",
            "--source-dir",
            source.as_posix(),
            "--output-dir",
            output.as_posix(),
            "--no-progress",
            "--simple",
            *extra,
        ],
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
        env=env,
    )


def _results(output: Path) -> dict:
    return json.loads(
        (output / "ash_aggregated_results.json").read_text(encoding="utf-8")
    )


@pytest.fixture
def fixture_copy(tmp_path):
    def copy(name: str) -> Path:
        dest = tmp_path / name
        shutil.copytree(FIXTURES / name, dest)
        return dest

    return copy


def test_the_binary_is_the_pinned_version():
    out = subprocess.run(  # nosec B603 - fixed argv
        [_hadolint(), "--version"], capture_output=True, text=True, check=True
    )
    assert TOOL_VERSIONS["hadolint"].lstrip("v") in out.stdout


@pytest.mark.parametrize(
    ("fixture", "files", "captured"),
    [
        (
            "positive",
            ["Dockerfile", "services/Dockerfile.broken", "services/api.Dockerfile"],
            "positive",
        ),
        ("negative", ["Containerfile"], "negative"),
    ],
)
def test_the_captured_reports_are_what_the_binary_writes(fixture, files, captured):
    """Re-run the argv the scanner builds and compare with the committed capture."""
    hadolint = _hadolint()
    for fmt, suffix in (("sarif", "sarif"), ("json", "json")):
        capture = FIXTURES / "captured" / f"{captured}.{suffix}"
        if not capture.exists():
            continue
        out = subprocess.run(  # nosec B603 - fixed argv
            [hadolint, "--no-fail", "--no-color", "--format", fmt, "--", *files],
            cwd=FIXTURES / fixture,
            capture_output=True,
            text=True,
            check=True,
        )
        assert json.loads(out.stdout) == json.loads(capture.read_text()), capture.name


def test_a_scan_reports_every_hadolint_level(fixture_copy, tmp_path):
    _hadolint()
    source = fixture_copy("positive")
    output = tmp_path / "out"
    proc = _ash_scan(source, output, "--scanners", "hadolint")
    assert proc.returncode == 2, proc.stdout + proc.stderr
    row = _results(output)["scanner_results"]["hadolint"]
    assert row["status"] == "FAILED"
    counts = row["severity_counts"]
    assert (counts["critical"], counts["high"], counts["medium"]) == (0, 2, 6)
    assert (counts["low"], counts["info"]) == (4, 1)


def test_a_clean_dockerfile_passes(fixture_copy, tmp_path):
    _hadolint()
    source = fixture_copy("negative")
    output = tmp_path / "out"
    proc = _ash_scan(source, output, "--scanners", "hadolint")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    row = _results(output)["scanner_results"]["hadolint"]
    assert row["status"] == "PASSED"
    assert row["finding_count"] == 0


def test_enabling_in_the_project_config_runs_it_without_a_selection(
    fixture_copy, tmp_path
):
    """No --scanners at all: the project config alone turns hadolint on.

    Every other scanner is switched off in the same file so the run does not
    depend on which other tools this machine has.
    """
    _hadolint()
    from automated_security_helper.config.default_config import get_default_config

    source = fixture_copy("negative")
    others = [
        name
        for name in get_default_config().scanners.model_dump(by_alias=True)
        if name != "hadolint"
    ]
    lines = ["scanners:"]
    lines += [f"  {name}:\n    enabled: false" for name in others]
    lines += ["  hadolint:\n    enabled: true"]
    (source / ".ash").mkdir()
    (source / ".ash" / ".ash.yaml").write_text("\n".join(lines) + "\n")
    output = tmp_path / "out"
    proc = _ash_scan(source, output)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert _results(output)["scanner_results"]["hadolint"]["status"] == "PASSED"


def test_the_projects_hadolint_yaml_is_honored(fixture_copy, tmp_path):
    _hadolint()
    source = fixture_copy("configured")
    output = tmp_path / "out"
    _ash_scan(source, output, "--scanners", "hadolint")
    sarif = json.loads((output / "reports" / "ash.sarif").read_text())
    by_rule = {
        r["ruleId"]: r for run in sarif["runs"] for r in run.get("results") or []
    }
    assert "DL3007" not in by_rule, "ignored in .hadolint.yaml"
    assert by_rule["DL3008"]["properties"]["issue_severity"] == "INFO"


def test_an_unparseable_config_is_an_error_not_a_silent_default(fixture_copy, tmp_path):
    _hadolint()
    source = fixture_copy("configured")
    (source / ".hadolint.yaml").write_text("ignored: [\n")
    output = tmp_path / "out"
    proc = _ash_scan(source, output, "--scanners", "hadolint")
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert _results(output)["scanner_results"]["hadolint"]["status"] == "ERROR"


def test_not_enabled_it_leaves_no_trace(fixture_copy, tmp_path):
    """The binary is present and there are Dockerfiles, but nobody asked for it."""
    _hadolint()
    source = fixture_copy("positive")
    output = tmp_path / "out"
    _ash_scan(source, output, "--scanners", "detect-secrets")
    results = _results(output)
    assert "hadolint" not in results["scanner_results"]
    assert "hadolint" not in (results["metadata"].get("expected_scanners") or [])


def test_an_ash_line_suppression_suppresses_exactly_that_finding(
    fixture_copy, tmp_path
):
    _hadolint()
    source = fixture_copy("positive")
    (source / ".ash").mkdir()
    (source / ".ash" / ".ash.yaml").write_text(
        "global_settings:\n"
        "  suppressions:\n"
        "    - rule_id: DL3008\n"
        "      path: Dockerfile\n"
        "      line_start: 3\n"
        "      line_end: 3\n"
        "      reason: fixture\n"
    )
    output = tmp_path / "out"
    _ash_scan(source, output, "--scanners", "hadolint")
    counts = _results(output)["scanner_results"]["hadolint"]["severity_counts"]
    assert counts["suppressed"] == 1
    assert counts["medium"] == 5


def test_offline_mode_runs_it_unchanged(fixture_copy, tmp_path):
    """hadolint needs no network, so --offline changes nothing about its result."""
    _hadolint()
    source = fixture_copy("positive")
    output = tmp_path / "out"
    proc = _ash_scan(source, output, "--scanners", "hadolint", "--offline")
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert _results(output)["scanner_results"]["hadolint"]["finding_count"] == 13


def test_enabled_but_not_installed_is_missing_and_fails_the_scan(
    fixture_copy, tmp_path
):
    """The #640 contract: an enabled scanner without its tool is MISSING, exit 1.

    PATH is reduced to the interpreter's own directory and ASH_BIN_PATH points at
    an empty directory, so no hadolint is reachable. The integration job installs
    hadolint into its own directory, which this PATH leaves out.
    """
    hadolint = Path(_hadolint()).resolve()
    interpreter_dir = Path(sys.executable).parent
    if hadolint.parent == interpreter_dir.resolve():
        pytest.skip("hadolint shares the interpreter's directory here")
    empty_bin = tmp_path / "empty-bin"
    empty_bin.mkdir()
    env = {
        **os.environ,
        "PATH": str(interpreter_dir),
        "ASH_BIN_PATH": str(empty_bin),
    }
    source = fixture_copy("negative")
    output = tmp_path / "out"
    proc = _ash_scan(source, output, "--scanners", "hadolint", env=env)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert _results(output)["scanner_results"]["hadolint"]["status"] == "MISSING"


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
def test_a_config_symlinked_out_of_the_tree_is_not_applied(fixture_copy, tmp_path):
    """hadolint reads ./.hadolint.yaml itself; ASH must stop it following the link."""
    _hadolint()
    source = fixture_copy("negative")
    (source / "Dockerfile").write_text("FROM ubuntu:latest\n")
    outside = tmp_path / "outside.yaml"
    outside.write_text("ignored:\n  - DL3007\n")
    (source / ".hadolint.yaml").symlink_to(outside)
    output = tmp_path / "out"
    proc = _ash_scan(source, output, "--scanners", "hadolint")
    assert proc.returncode == 2, proc.stdout + proc.stderr
    sarif = json.loads((output / "reports" / "ash.sarif").read_text())
    rules = {r["ruleId"] for run in sarif["runs"] for r in run.get("results") or []}
    assert "DL3007" in rules
