# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""actionlint end to end, with the real binary.

The unit tests in ``tests/unit/plugin_modules/ash_builtin/test_actionlint_scanner.py``
replace the subprocess with output captured from actionlint 1.7.12. These run the
installed binary, so a version whose output drifts from the capture, or an argv the
binary rejects, fails here.

CI installs the pinned binary with ``ash dependencies install --tool actionlint`` and
sets ``ASH_REQUIRE_ACTIONLINT=1``, which turns the skip below into a failure: this
file must run in CI, not skip.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess  # nosec B404 - runs the real ash CLI under test
import sys
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners.actionlint_scanner import (
    ActionlintScanner,
    ActionlintScannerConfig,
    ActionlintScannerConfigOptions,
)
from automated_security_helper.utils.subprocess_utils import find_executable

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[3]
FIXTURE_REPO = REPO_ROOT / "tests" / "test_data" / "scanners" / "actionlint" / "repo"

#: (ruleId, SARIF level, ASH severity, startLine) for the fixture, in order.
EXPECTED = [
    ("credentials", "error", "HIGH", 17),
    ("expression", "error", "HIGH", 20),
    ("deprecated-commands", "note", "LOW", 22),
    ("deprecated-commands", "warning", "MEDIUM", 24),
    ("if-cond", "warning", "MEDIUM", 26),
    ("job-needs", "note", "LOW", 28),
    ("runner-label", "note", "LOW", 36),
    ("syntax-check", "note", "LOW", 37),
]


def _require_actionlint() -> str:
    found = find_executable("actionlint")
    if found:
        return found
    if os.environ.get("ASH_REQUIRE_ACTIONLINT", "").strip().upper() in (
        "1",
        "YES",
        "TRUE",
    ):
        pytest.fail(
            "ASH_REQUIRE_ACTIONLINT is set but actionlint is not installed. "
            "This test must run in CI, not skip."
        )
    pytest.skip("actionlint is not installed")


@pytest.fixture
def repo(tmp_path) -> Path:
    target = tmp_path / "repo"
    shutil.copytree(FIXTURE_REPO, target)
    # A git root: actionlint discovers a project only at an ancestor that holds
    # both .github/workflows and .git, and the fixture tree is committed without
    # one. Without it actionlint never finds the repository, so it never reads
    # the repository's own actionlint.yaml and the config cases below would pass
    # whatever -config-file did.
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    subprocess.run(  # nosec B603 B607 - initializes the copied fixture, fixed argv
        ["git", "init", "-q", str(target)], check=True, capture_output=True
    )
    return target


def _ash(
    *args: str, env: dict | None = None, cwd: Path | None = None
) -> subprocess.CompletedProcess:
    return subprocess.run(  # nosec B603 - starts the real ash CLI under test, fixed argv
        [sys.executable, "-m", "automated_security_helper.cli.main", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=600,
        env=env,
        cwd=cwd,
    )


def test_the_real_binary_reports_the_fixture_findings(repo, tmp_path):
    _require_actionlint()
    scanner = ActionlintScanner(
        context=PluginContext(
            source_dir=repo,
            output_dir=tmp_path / "out",
            config=get_default_config(),
        ),
        config=ActionlintScannerConfig(
            enabled=True, options=ActionlintScannerConfigOptions()
        ),
    )

    report = scanner.scan(target=repo, target_type="source")

    rows = [
        (
            r.ruleId,
            getattr(r.level, "value", r.level),
            r.properties.issue_severity,
            r.locations[0].physicalLocation.root.region.startLine,
        )
        for r in report.runs[0].results
    ]
    assert rows == EXPECTED
    assert {
        r.locations[0].physicalLocation.root.artifactLocation.uri
        for r in report.runs[0].results
    } == {".github/workflows/vulnerable.yml"}
    assert scanner.exit_code == 1
    assert report.runs[0].tool.driver.version.startswith("1.")


@pytest.mark.parametrize("shape", ["malformed", "linked-out"])
def test_the_scanned_trees_actionlint_config_does_not_change_the_run(
    repo, tmp_path, shape, caplog
):
    """ASH passes -config-file on every run, so the repository's own
    .github/actionlint.yaml must not change the findings. A malformed one must
    not turn the run into exit 3: actionlint parses it while it looks for the
    project root (the fixture is a git root), whatever the flag names, so ASH
    lints such a tree from a copy outside it and says so. One that is a link out
    of the tree must not have the outside file quoted into actionlint's stderr.
    Measured with the real binary; the unit tests replace the subprocess."""
    _require_actionlint()
    config = repo / ".github" / "actionlint.yaml"
    if shape == "malformed":
        config.write_text("paths: [\n")
    else:
        if sys.platform == "win32":
            pytest.skip("symlinks")
        outside = tmp_path / "outside.yaml"
        outside.write_text("self-hosted-runner:\n  labels: [OUTSIDE-MARKER-LABEL]\n")
        config.symlink_to(outside)
    output = tmp_path / "out"
    scanner = ActionlintScanner(
        context=PluginContext(
            source_dir=repo, output_dir=output, config=get_default_config()
        ),
        config=ActionlintScannerConfig(enabled=True),
    )

    with caplog.at_level(logging.WARNING):
        report = scanner.scan(target=repo, target_type="source")

    rows = [
        (
            r.ruleId,
            getattr(r.level, "value", r.level),
            r.properties.issue_severity,
            r.locations[0].physicalLocation.root.region.startLine,
        )
        for r in report.runs[0].results
    ]
    assert rows == EXPECTED
    assert scanner.exit_code == 1
    note = ".github/actionlint.yaml in the scanned tree cannot be read as YAML"
    if shape == "malformed":
        assert note in caplog.text
    else:
        assert note not in caplog.text
    stderr_log = Path(scanner.results_dir) / "source" / "ActionlintScanner.stderr.log"
    if stderr_log.exists():
        assert "OUTSIDE-MARKER-LABEL" not in stderr_log.read_text(
            encoding="utf-8", errors="replace"
        )


def test_a_full_scan_with_actionlint_selected(repo, tmp_path):
    """``--scanners actionlint`` runs it, offline, and fails on the HIGH findings."""
    _require_actionlint()
    output = tmp_path / "out"
    env = {**os.environ, "ASH_OFFLINE": "true"}

    result = _ash(
        "scan",
        "--mode",
        "local",
        "--source-dir",
        str(repo),
        "--output-dir",
        str(output),
        "--scanners",
        "actionlint",
        "--no-progress",
        env=env,
    )

    assert result.returncode == 2, result.stdout[-3000:] + result.stderr[-3000:]
    aggregated = json.loads(
        (output / "ash_aggregated_results.json").read_text(encoding="utf-8")
    )
    status = aggregated["scanner_results"]["actionlint"]
    assert status["status"] == "FAILED", status
    sarif = json.loads((output / "reports" / "ash.sarif").read_text(encoding="utf-8"))
    levels = sorted(
        r["level"]
        for run in sarif["runs"]
        for r in run["results"]
        if r["ruleId"] in {"credentials", "expression"}
    )
    assert levels == ["error", "error"]


def test_enabled_but_missing_is_missing_and_exits_one(repo, tmp_path):
    """An enabled opt-in scanner without its binary fails the completeness gate."""
    if Path("/usr/local/bin/actionlint").exists():
        pytest.skip("/usr/local/bin/actionlint exists and is always searched")
    empty_bin = tmp_path / "empty-bin"
    empty_bin.mkdir()
    output = tmp_path / "out"
    env = {
        **os.environ,
        "PATH": os.pathsep.join([str(Path(sys.executable).parent)]),
        "ASH_BIN_PATH": str(empty_bin),
    }

    result = _ash(
        "scan",
        "--mode",
        "local",
        "--source-dir",
        str(repo),
        "--output-dir",
        str(output),
        "--scanners",
        "actionlint",
        "--no-progress",
        env=env,
    )

    assert result.returncode == 1, result.stdout[-3000:] + result.stderr[-3000:]
    aggregated = json.loads(
        (output / "ash_aggregated_results.json").read_text(encoding="utf-8")
    )
    assert aggregated["scanner_results"]["actionlint"]["status"] == "MISSING"


# --------------------------------------------------------------------------- #
# The scanned tree's config cannot choose the program actionlint pipes run:
# scripts to. actionlint runs it as `<program> --norc -f json -x --shell bash
# ... -` from the scan root, so `shellcheck: bash` makes bash execute a file
# named `json` that the repository committed. Each case plants a program that
# leaves a marker when run; the operator case is the control that proves a
# planted program does run when it is allowed to.
# --------------------------------------------------------------------------- #


def _marker_program(path: Path, marker: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"#!/bin/sh\ntouch '{marker}'\necho '[]'\n")
    path.chmod(0o755)
    return path


def _repo_config(repo: Path, **options: str) -> None:
    lines = [
        "scanners:",
        "  actionlint:",
        "    options:",
        *(f"      {name}: {json.dumps(value)}" for name, value in options.items()),
    ]
    (repo / ".ash").mkdir(exist_ok=True)
    (repo / ".ash" / ".ash.yaml").write_text("\n".join(lines) + "\n")


def _scan(
    repo: Path, output: Path, *extra: str, cwd: Path | None = None
) -> subprocess.CompletedProcess:
    return _ash(
        "scan",
        "--mode",
        "local",
        "--source-dir",
        str(repo),
        "--output-dir",
        str(output),
        "--scanners",
        "actionlint",
        "--no-progress",
        # An on/off flag: `--fail-on-findings false` is refused, since `ash scan`
        # takes no extra arguments.
        "--no-fail-on-findings",
        *extra,
        env={**os.environ, "ASH_OFFLINE": "true"},
        cwd=cwd,
    )


def _actionlint_sarif(output: Path) -> str:
    found = sorted((output / "scanners" / "actionlint").rglob("actionlint.sarif"))
    assert found, f"actionlint wrote no SARIF under {output}"
    return found[0].read_text(encoding="utf-8")


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX shell and execute bit")
def test_shellcheck_bash_from_the_scanned_tree_never_runs_its_json(repo, tmp_path):
    _require_actionlint()
    if not shutil.which("bash"):
        pytest.skip("bash is not installed")
    marker = tmp_path / "json-ran"
    _marker_program(repo / "json", marker)
    _repo_config(repo, shellcheck="bash")
    output = tmp_path / "out"

    result = _scan(repo, output)

    assert not marker.exists(), "actionlint ran bash on the repository's json file"
    log = (output / "ash.log").read_text(encoding="utf-8", errors="replace")
    assert "Ignoring scanners.actionlint.options.shellcheck" in log, (
        result.stdout[-3000:] + result.stderr[-3000:]
    )
    assert "-shellcheck=bash" not in _actionlint_sarif(output)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX shell and execute bit")
@pytest.mark.parametrize("flag", ["shellcheck", "pyflakes"])
def test_a_program_planted_in_the_scanned_tree_never_runs(repo, tmp_path, flag):
    _require_actionlint()
    marker = tmp_path / "planted-ran"
    planted = _marker_program(repo / "tools" / "planted", marker)
    _repo_config(repo, **{flag: planted.as_posix()})
    output = tmp_path / "out"

    _scan(repo, output)

    assert not marker.exists()
    assert planted.as_posix() not in _actionlint_sarif(output)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX shell and execute bit")
def test_the_operator_can_name_a_program_outside_the_tree(repo, tmp_path):
    """The control: the same kind of program does run when the operator names it."""
    _require_actionlint()
    marker = tmp_path / "operator-ran"
    program = _marker_program(tmp_path / "operator-bin" / "shellcheck", marker)
    _repo_config(repo, shellcheck="bash")
    output = tmp_path / "out"

    _scan(
        repo,
        output,
        "--config-overrides",
        f"scanners.actionlint.options.shellcheck={program.as_posix()}",
    )

    assert marker.exists(), "the operator's shellcheck never ran"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX shell and symlinks")
def test_an_operator_path_in_the_tree_that_links_out_never_runs(repo, tmp_path):
    """The operator names tools/shellcheck in the tree; the tree's link there
    decides which program that is. Before, actionlint ran the program the link
    pointed at on every run: script; now shellcheck stays off. The operator test
    above is the control: the same program runs when named outside the tree."""
    _require_actionlint()
    marker = tmp_path / "linked-ran"
    program = _marker_program(tmp_path / "elsewhere" / "program", marker)
    (repo / "tools").mkdir()
    (repo / "tools" / "shellcheck").symlink_to(program)
    output = tmp_path / "out"

    result = _scan(
        repo,
        output,
        "--config-overrides",
        "scanners.actionlint.options.shellcheck=tools/shellcheck",
    )

    assert not marker.exists(), "actionlint ran the program the tree's link chose"
    log = (output / "ash.log").read_text(encoding="utf-8", errors="replace")
    assert "Ignoring scanners.actionlint.options.shellcheck" in log, (
        result.stdout[-3000:] + result.stderr[-3000:]
    )
    assert program.as_posix() not in _actionlint_sarif(output)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks")
def test_a_local_reference_out_of_the_tree_is_never_read(repo, tmp_path):
    """actionlint reads the action a ``uses: ./...`` names and lists its inputs in the
    finding. One linked out of the tree is not linted; one in the tree still is, which
    shows the real binary does resolve local references in this layout."""
    _require_actionlint()
    outside = tmp_path / "outside" / "action"
    outside.mkdir(parents=True)
    metadata = (
        "name: {name}\ndescription: x\ninputs:\n  {name}_input:\n    description: x\n"
        "runs:\n  using: composite\n  steps: []\n"
    )
    (outside / "action.yml").write_text(metadata.format(name="outside"))
    actions = repo / ".github" / "actions"
    (actions / "inside").mkdir(parents=True)
    (actions / "inside" / "action.yml").write_text(metadata.format(name="inside"))
    (actions / "linked").symlink_to(outside)
    workflows = repo / ".github" / "workflows"
    for name, spec in (
        ("out.yml", "./.github/actions/linked"),
        ("in.yml", "./.github/actions/inside"),
    ):
        (workflows / name).write_text(
            "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
            f"      - uses: {spec}\n        with:\n          bogus: x\n"
        )
    scanner = ActionlintScanner(
        context=PluginContext(
            source_dir=repo, output_dir=tmp_path / "out", config=get_default_config()
        ),
        config=ActionlintScannerConfig(enabled=True),
    )

    report = scanner.scan(target=repo, target_type="source")

    messages = {
        (
            r.locations[0].physicalLocation.root.artifactLocation.uri,
            r.message.root.text,
        )
        for r in report.runs[0].results
    }
    assert any(
        uri == ".github/workflows/in.yml" and "inside_input" in text
        for uri, text in messages
    ), messages
    assert not any("outside" in text for _, text in messages), messages
    assert not any(uri == ".github/workflows/out.yml" for uri, _ in messages)


#: Text of a file outside the scanned tree. actionlint quotes the first seven
#: characters of a value it cannot unmarshal, so the marker is in those.
_OUTSIDE_MARKER = "QZXJWVK"


def _files_mentioning(output: Path, text: str) -> list:
    return sorted(
        str(path.relative_to(output))
        for path in output.rglob("*")
        if path.is_file() and text in path.read_text(encoding="utf-8", errors="replace")
    )


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks")
@pytest.mark.parametrize(
    "content",
    [
        # Parses; ASH logs the ignore pattern.
        f"paths:\n  '**':\n    ignore:\n      - {_OUTSIDE_MARKER}-pattern\n",
        # Does not unmarshal; actionlint quotes the start of the value.
        f"self-hosted-runner:\n  labels: {_OUTSIDE_MARKER}-label\n",
    ],
    ids=["ignore-pattern", "unparseable"],
)
def test_an_operator_config_file_in_the_tree_that_links_out_is_not_read(
    repo, tmp_path, content
):
    """Before, actionlint read the file a link in the tree pointed at, and its text
    reached ash.log, the aggregated results and the console. Now actionlint is not
    run, the scanner is ERROR, and nothing of that file is in the output."""
    _require_actionlint()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "creds").write_text(content, encoding="utf-8")
    (repo / "ci").mkdir()
    (repo / "ci" / "actionlint.yaml").symlink_to(outside / "creds")
    output = tmp_path / "out"

    # Run from the repository: a relative override is taken from the working
    # directory, so this names the tree's ci/actionlint.yaml.
    result = _scan(
        repo,
        output,
        "--config-overrides",
        "scanners.actionlint.options.config_file=ci/actionlint.yaml",
        cwd=repo,
    )

    console = result.stdout + result.stderr
    assert _files_mentioning(output, _OUTSIDE_MARKER) == [], console[-3000:]
    assert _OUTSIDE_MARKER not in console
    aggregated = json.loads(
        (output / "ash_aggregated_results.json").read_text(encoding="utf-8")
    )
    assert aggregated["scanner_results"]["actionlint"]["status"] == "ERROR"
    log = (output / "ash.log").read_text(encoding="utf-8", errors="replace")
    assert "through a symbolic link" in log, console[-3000:]
