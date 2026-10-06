# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The actionlint scanner: argv, parsing, severity mapping and failure handling.

The parser tests read output captured from the pinned actionlint (1.7.12) running
over ``tests/test_data/scanners/actionlint/repo``:

* ``actionlint-1.7.12-default.json`` -- the argv ASH uses (shellcheck and pyflakes
  disabled), over ``clean.yml`` and ``vulnerable.yml``.
* ``actionlint-1.7.12-shellcheck.json`` -- the same with ``-shellcheck=<path>``
  (shellcheck 0.11.0), which adds one SC2086 finding.
* ``actionlint-1.7.12-clean.json`` -- ``clean.yml`` alone, exit 0.

The repository's pretty-format-json hook re-indents the captures; the content is the
binary's output unchanged.

To recapture after a version bump, run from the fixture repo::

    actionlint -no-color -shellcheck= -pyflakes= -config-file <empty file> \\
      -format '<ACTIONLINT_FORMAT>' -- .github/workflows/clean.yml \\
      .github/workflows/vulnerable.yml > ../actionlint-<version>-default.json

The subprocess is replaced in these tests; the real binary runs in
``tests/integration/scanners/test_actionlint_real_binary.py``.
"""

from __future__ import annotations

import copy
import json
import logging
import os
import shutil
import sys
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.core.scanner_opt_in import (
    is_opt_in,
    opt_in_scanner_enabled,
)
from automated_security_helper.models.core import AshSuppression, IgnorePathWithReason
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    actionlint_scanner as module,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.actionlint_scanner import (
    ACTIONLINT_FORMAT,
    KIND_SEVERITY,
    ActionlintScanner,
    ActionlintScannerConfig,
    ActionlintScannerConfigOptions,
    build_sarif,
    config_ignore_patterns,
    is_workflow_file,
    severity_for,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.sarif_utils import apply_suppressions_to_sarif

FIXTURES = Path(__file__).resolve().parents[3] / "test_data" / "scanners" / "actionlint"
FIXTURE_REPO = FIXTURES / "repo"
FAKE_ACTIONLINT = "/opt/fake/bin/actionlint"

#: What ASH must report for the captured default run, in actionlint's order:
#: (ruleId, SARIF level, ASH severity, uri, startLine, startColumn).
EXPECTED_DEFAULT = [
    ("credentials", "error", "HIGH", ".github/workflows/vulnerable.yml", 17, 21),
    ("expression", "error", "HIGH", ".github/workflows/vulnerable.yml", 20, 24),
    ("deprecated-commands", "note", "LOW", ".github/workflows/vulnerable.yml", 22, 14),
    (
        "deprecated-commands",
        "warning",
        "MEDIUM",
        ".github/workflows/vulnerable.yml",
        24,
        14,
    ),
    ("if-cond", "warning", "MEDIUM", ".github/workflows/vulnerable.yml", 26, 13),
    ("job-needs", "note", "LOW", ".github/workflows/vulnerable.yml", 28, 3),
    ("runner-label", "note", "LOW", ".github/workflows/vulnerable.yml", 36, 14),
    ("syntax-check", "note", "LOW", ".github/workflows/vulnerable.yml", 37, 5),
]


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _summary(sarif: dict) -> list:
    rows = []
    for result in sarif["runs"][0]["results"]:
        location = result["locations"][0]["physicalLocation"]
        rows.append(
            (
                result["ruleId"],
                result["level"],
                result["properties"]["issue_severity"],
                location["artifactLocation"]["uri"],
                location["region"]["startLine"],
                location["region"].get("startColumn"),
            )
        )
    return rows


def _assert_matches_default(sarif: dict) -> None:
    assert _summary(sarif) == EXPECTED_DEFAULT


@pytest.fixture
def repo(tmp_path) -> Path:
    target = tmp_path / "repo"
    shutil.copytree(FIXTURE_REPO, target)
    return target


def _scanner(source: Path, output: Path | None = None, **options) -> ActionlintScanner:
    output = output or source.parent / "ash_output"
    return ActionlintScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=output,
            work_dir=output / "converted",
            config=get_default_config(),
        ),
        config=ActionlintScannerConfig(
            enabled=True, options=ActionlintScannerConfigOptions(**options)
        ),
    )


class FakeRun:
    """Stands in for ``_run_subprocess`` and records the argv it was given."""

    def __init__(self, scanner, stdout: str = "", returncode: int = 0, **extra):
        self.scanner = scanner
        self.stdout = stdout
        self.returncode = returncode
        self.extra = extra
        self.calls: list = []

    def __call__(self, command, **kwargs):
        self.calls.append((list(command), kwargs))
        self.scanner.exit_code = self.returncode
        return {"returncode": self.returncode, "stdout": self.stdout, **self.extra}


@pytest.fixture
def on_path(monkeypatch):
    """actionlint (and nothing else) is installed."""
    monkeypatch.setattr(
        module,
        "find_executable",
        lambda name: FAKE_ACTIONLINT if name == "actionlint" else None,
    )


def _run(scanner, monkeypatch, stdout, returncode, **extra) -> FakeRun:
    fake = FakeRun(scanner, stdout=stdout, returncode=returncode, **extra)
    monkeypatch.setattr(scanner, "_run_subprocess", fake)
    return fake


# --------------------------------------------------------------------------- #
# Opt-in contract
# --------------------------------------------------------------------------- #


def test_the_scanner_is_opt_in_and_off_by_default():
    assert is_opt_in(ActionlintScanner)
    assert ActionlintScannerConfig().enabled is False
    assert not opt_in_scanner_enabled(ActionlintScanner, None, [])
    assert opt_in_scanner_enabled(ActionlintScanner, None, [" ActionLint "])
    assert opt_in_scanner_enabled(ActionlintScanner, {"enabled": True}, [])


# --------------------------------------------------------------------------- #
# Parsing real output
# --------------------------------------------------------------------------- #


def test_captured_default_output_maps_to_the_expected_findings():
    sarif = build_sarif(_load("actionlint-1.7.12-default.json"), exit_code=1)

    _assert_matches_default(sarif)
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "actionlint"
    assert sarif["runs"][0]["tool"]["driver"]["version"] == "1.7.12"
    # It is valid SARIF as ASH's model reads it.
    SarifReport.model_validate(sarif)


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda e: e.update(kind="syntax-check"), id="rule-id"),
        pytest.param(lambda e: e.update(line=e["line"] + 1), id="line"),
        pytest.param(lambda e: e.update(column=e["column"] + 1), id="column"),
        pytest.param(
            lambda e: e.update(filepath=".github/workflows/other.yml"), id="path"
        ),
        pytest.param(
            lambda e: e.update(message=e["message"].replace("potentially ", "")),
            id="level",
        ),
    ],
)
def test_negative_control_a_mutated_finding_fails_the_expectation(mutate):
    """The expectation above bites: change any field of one finding and it fails."""
    payload = _load("actionlint-1.7.12-default.json")
    expression = next(e for e in payload["errors"] if e["kind"] == "expression")
    mutate(expression)

    with pytest.raises(AssertionError):
        _assert_matches_default(build_sarif(payload, exit_code=1))


def test_region_carries_snippet_and_exclusive_end_column():
    sarif = build_sarif(_load("actionlint-1.7.12-default.json"), exit_code=1)
    region = sarif["runs"][0]["results"][1]["locations"][0]["physicalLocation"][
        "region"
    ]
    # actionlint reports end_column 47, inclusive; SARIF's endColumn is exclusive.
    assert region == {
        "startLine": 20,
        "endLine": 20,
        "startColumn": 24,
        "endColumn": 48,
        "snippet": {
            "text": '        run: echo "${{ github.event.issue.title }}"\n'
            "                       ^~~~~~~~~~~~~~~~~~~~~~~~"
        },
    }


def test_rules_list_each_kind_once_with_its_default_level():
    sarif = build_sarif(_load("actionlint-1.7.12-default.json"), exit_code=1)
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    assert [r["id"] for r in rules] == sorted({row[0] for row in EXPECTED_DEFAULT})
    by_id = {r["id"]: r["defaultConfiguration"]["level"] for r in rules}
    assert by_id["credentials"] == "error"
    assert by_id["expression"] == "note"


def test_captured_shellcheck_output_reports_shellcheck_as_low():
    sarif = build_sarif(_load("actionlint-1.7.12-shellcheck.json"), exit_code=1)
    shellcheck = [row for row in _summary(sarif) if row[0] == "shellcheck"]
    assert shellcheck == [
        ("shellcheck", "note", "LOW", ".github/workflows/vulnerable.yml", 34, 9)
    ]


def test_captured_clean_output_is_zero_findings():
    sarif = build_sarif(_load("actionlint-1.7.12-clean.json"), exit_code=0)
    assert sarif["runs"][0]["results"] == []


# --------------------------------------------------------------------------- #
# Severity mapping
# --------------------------------------------------------------------------- #


def test_every_kind_of_the_pinned_version_has_a_deliberate_severity():
    """The 18 kinds ``allKinds`` lists in 1.7.12, each mapped explicitly."""
    assert sorted(KIND_SEVERITY) == [
        "action",
        "credentials",
        "deprecated-commands",
        "env-var",
        "events",
        "expression",
        "glob",
        "id",
        "if-cond",
        "job-needs",
        "matrix",
        "permissions",
        "pyflakes",
        "runner-label",
        "shell-name",
        "shellcheck",
        "syntax-check",
        "workflow-call",
    ]


@pytest.mark.parametrize(
    ("kind", "message", "expected"),
    [
        (
            "expression",
            '"github.event.issue.title" is potentially untrusted. avoid using it',
            "HIGH",
        ),
        (
            "expression",
            (
                "object filter extracts potentially untrusted properties "
                '"github.event.commits.*.message"'
            ),
            "HIGH",
        ),
        ("expression", 'property "foo" is not defined in object type {}', "LOW"),
        ("credentials", '"password" section in "db" service ...', "HIGH"),
        ("deprecated-commands", 'workflow command "set-env" was deprecated', "MEDIUM"),
        ("deprecated-commands", 'workflow command "add-path" was deprecated', "MEDIUM"),
        ("deprecated-commands", 'workflow command "set-output" was deprecated', "LOW"),
        ("deprecated-commands", 'workflow command "save-state" was deprecated', "LOW"),
        ("if-cond", "is always evaluated to true", "MEDIUM"),
        ("permissions", 'unknown permission scope "issue"', "MEDIUM"),
        ("syntax-check", 'unexpected key "timeout-minute"', "LOW"),
        ("shellcheck", "SC2086", "LOW"),
        ("brand-new-kind", "anything", "LOW"),
    ],
)
def test_severity_for(kind, message, expected):
    assert severity_for(kind, message) == expected


def test_an_unknown_kind_is_reported_low_and_logged_once(caplog):
    payload = {
        "version": "9.9.9",
        "errors": [
            {"kind": "brand-new-kind", "message": "m", "filepath": "a.yml", "line": 1},
            {"kind": "brand-new-kind", "message": "m", "filepath": "a.yml", "line": 2},
        ],
    }
    with caplog.at_level(logging.WARNING):
        sarif = build_sarif(payload, exit_code=1)
    assert [r["level"] for r in sarif["runs"][0]["results"]] == ["note", "note"]
    assert sum("brand-new-kind" in r.getMessage() for r in caplog.records) == 1


# --------------------------------------------------------------------------- #
# Malformed or contradictory output fails closed
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("payload", "exit_code", "match"),
    [
        ([], 0, "expected JSON object"),
        ({"version": "1"}, 0, "expected JSON object"),
        ({"errors": {}}, 0, "not a JSON array"),
        ({"errors": []}, 1, "exited 1"),
        (
            {"errors": [{"kind": "id", "message": "m", "filepath": "a", "line": 1}]},
            0,
            "exited 0",
        ),
        ({"errors": ["text"]}, 1, "not a JSON object"),
        ({"errors": [{"kind": "id", "message": "m", "line": 1}]}, 1, "missing"),
        (
            {"errors": [{"kind": "id", "message": "m", "filepath": "a", "line": 0}]},
            1,
            "missing",
        ),
        (
            {"errors": [{"kind": "id", "message": "m", "filepath": "a", "line": True}]},
            1,
            "missing",
        ),
    ],
)
def test_malformed_output_raises(payload, exit_code, match):
    with pytest.raises(ScannerError, match=match):
        build_sarif(payload, exit_code)


def test_null_errors_with_exit_zero_is_clean():
    assert build_sarif({"version": "1", "errors": None}, 0)["runs"][0]["results"] == []


# --------------------------------------------------------------------------- #
# Workflow discovery
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        (".github/workflows/ci.yml", True),
        (".github/workflows/ci.YAML", True),
        ("svc/.github/workflows/ci.yaml", True),
        (".github\\workflows\\ci.yml", True),
        (".github/workflows/sub/ci.yml", False),
        (".github/workflows/README.md", False),
        (".github/actionlint.yaml", False),
        ("github/workflows/ci.yml", False),
        ("config/not-a-workflow.yml", False),
    ],
)
def test_is_workflow_file(path, expected):
    assert is_workflow_file(path) is expected


# --------------------------------------------------------------------------- #
# Running the scanner (subprocess replaced)
# --------------------------------------------------------------------------- #


def test_argv_disables_shellcheck_and_pyflakes_and_passes_workflows_explicitly(
    repo, monkeypatch, on_path
):
    """Determinism: the integrations stay off even with shellcheck on PATH.

    ``find_executable`` here answers for shellcheck and pyflakes too, so the only
    reason they are absent from the argv is that ASH disabled them.
    """
    monkeypatch.setattr(module, "find_executable", lambda name: f"/usr/bin/{name}")
    scanner = _scanner(repo)
    stdout = (FIXTURES / "actionlint-1.7.12-default.json").read_text()
    fake = _run(scanner, monkeypatch, stdout, 1)

    report = scanner.scan(target=repo, target_type="source")

    ((argv, kwargs),) = fake.calls
    separator = argv.index("--")
    assert argv[0] == "actionlint"
    assert "-shellcheck=" in argv[:separator]
    assert "-pyflakes=" in argv[:separator]
    assert argv[argv.index("-format") + 1] == ACTIONLINT_FORMAT
    assert argv[separator + 1 :] == [
        ".github/workflows/clean.yml",
        ".github/workflows/vulnerable.yml",
    ]
    assert kwargs["cwd"] == repo
    assert kwargs["timeout"] == 1800
    assert isinstance(report, SarifReport)
    assert scanner.targets_attempted == 2
    assert scanner.targets_failed == 0
    assert len(report.runs[0].results) == len(EXPECTED_DEFAULT)
    assert report.runs[0].invocations[0].executionSuccessful is True


def test_configured_shellcheck_is_passed_by_resolved_path(repo, monkeypatch):
    monkeypatch.setattr(module, "find_executable", lambda name: f"/opt/bin/{name}")
    scanner = _scanner(repo, shellcheck="shellcheck")
    fake = _run(scanner, monkeypatch, '{"version":"1.7.12","errors":[]}', 0)

    scanner.scan(target=repo, target_type="source")

    ((argv, _),) = fake.calls
    assert "-shellcheck=/opt/bin/shellcheck" in argv
    assert "-pyflakes=" in argv


def test_configured_shellcheck_that_is_absent_is_missing_not_skipped(
    repo, monkeypatch, on_path
):
    scanner = _scanner(repo, shellcheck="shellcheck")
    fake = _run(scanner, monkeypatch, "", 0)

    assert scanner.scan(target=repo, target_type="source") is False
    assert fake.calls == []
    assert "shellcheck" in scanner.dependency_unavailable_reason


def test_configured_pyflakes_path_that_does_not_exist_is_missing(
    repo, monkeypatch, on_path, tmp_path
):
    scanner = _scanner(repo, pyflakes=str(tmp_path / "nope" / "pyflakes"))
    assert scanner.validate_plugin_dependencies() is False
    assert "pyflakes" in scanner.dependency_unavailable_reason


def test_missing_actionlint_is_missing(repo, monkeypatch):
    monkeypatch.setattr(module, "find_executable", lambda name: None)
    scanner = _scanner(repo)
    fake = _run(scanner, monkeypatch, "", 0)

    assert scanner.scan(target=repo, target_type="source") is False
    assert fake.calls == []


def test_non_workflow_yaml_and_ash_output_are_not_passed(repo, monkeypatch, on_path):
    output = repo / ".ash" / "ash_output"
    stale = output / "copy" / ".github" / "workflows"
    stale.mkdir(parents=True)
    (stale / "old.yml").write_text("name: x\n")
    scanner = _scanner(repo, output=output)
    fake = _run(scanner, monkeypatch, '{"version":"1","errors":[]}', 0)

    scanner.scan(target=repo, target_type="source")

    ((argv, _),) = fake.calls
    files = argv[argv.index("--") + 1 :]
    assert "config/not-a-workflow.yml" not in files
    assert not any(".ash/" in f for f in files)


def test_global_ignore_paths_are_respected(repo, monkeypatch, on_path):
    scanner = _scanner(repo)
    fake = _run(scanner, monkeypatch, '{"version":"1","errors":[]}', 0)

    scanner.scan(
        target=repo,
        target_type="source",
        global_ignore_paths=[
            IgnorePathWithReason(path=".github/workflows/vulnerable.yml", reason="t")
        ],
    )

    ((argv, _),) = fake.calls
    assert argv[argv.index("--") + 1 :] == [".github/workflows/clean.yml"]


def test_gitignore_is_respected(repo, monkeypatch, on_path):
    (repo / ".gitignore").write_text(".github/workflows/vulnerable.yml\n")
    scanner = _scanner(repo)
    fake = _run(scanner, monkeypatch, '{"version":"1","errors":[]}', 0)

    scanner.scan(target=repo, target_type="source")

    ((argv, _),) = fake.calls
    assert argv[argv.index("--") + 1 :] == [".github/workflows/clean.yml"]


def test_a_workflow_path_starting_with_a_dash_is_after_the_separator(
    tmp_path, monkeypatch, on_path
):
    source = tmp_path / "src"
    workflows = source / "-svc" / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text("on: push\n")
    scanner = _scanner(source)
    fake = _run(scanner, monkeypatch, '{"version":"1","errors":[]}', 0)

    scanner.scan(target=source, target_type="source")

    ((argv, _),) = fake.calls
    assert argv[argv.index("--") + 1 :] == ["-svc/.github/workflows/ci.yml"]


def test_no_workflows_does_not_run_actionlint_and_evaluates_nothing(
    tmp_path, monkeypatch, on_path
):
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("print(1)\n")
    scanner = _scanner(source)
    fake = _run(scanner, monkeypatch, "", 0)

    report = scanner.scan(target=source, target_type="source")

    assert fake.calls == []
    assert isinstance(report, SarifReport) and report.runs == []
    assert scanner.targets_attempted == 0


def test_without_a_config_an_empty_one_is_passed_from_the_results_dir(
    repo, monkeypatch, on_path
):
    scanner = _scanner(repo)
    fake = _run(scanner, monkeypatch, '{"version":"1","errors":[]}', 0)

    scanner.scan(target=repo, target_type="source")

    ((argv, _),) = fake.calls
    config = Path(argv[argv.index("-config-file") + 1])
    assert config.is_relative_to(Path(scanner.results_dir))
    assert config.read_text().startswith("#")


@pytest.mark.parametrize("name", ["actionlint.yaml", "actionlint.yml"])
def test_a_config_in_the_scan_root_is_passed(repo, monkeypatch, on_path, name):
    (repo / ".github" / name).write_text("self-hosted-runner:\n  labels: [x]\n")
    scanner = _scanner(repo)
    fake = _run(scanner, monkeypatch, '{"version":"1","errors":[]}', 0)

    scanner.scan(target=repo, target_type="source")

    ((argv, _),) = fake.calls
    assert argv[argv.index("-config-file") + 1] == (repo / ".github" / name).as_posix()


def test_a_configured_config_file_that_does_not_exist_is_an_error(
    repo, monkeypatch, on_path
):
    scanner = _scanner(repo, config_file="ci/actionlint.yaml")
    fake = _run(scanner, monkeypatch, "", 0)

    with pytest.raises(ScannerError, match="does not exist"):
        scanner.scan(target=repo, target_type="source")
    assert fake.calls == []
    assert scanner.targets_failed == scanner.targets_attempted == 2


def test_a_config_that_ignores_findings_is_warned_about(
    repo, monkeypatch, on_path, caplog
):
    (repo / ".github" / "actionlint.yaml").write_text(
        "paths:\n  .github/workflows/**/*.yml:\n    ignore:\n"
        "      - 'potentially untrusted'\n"
    )
    scanner = _scanner(repo)
    _run(scanner, monkeypatch, '{"version":"1","errors":[]}', 0)

    with caplog.at_level(logging.WARNING):
        scanner.scan(target=repo, target_type="source")

    assert any("'potentially untrusted'" in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("paths:\n  a/**:\n    ignore: [x, y]\n  b:\n    ignore: [x]\n", ["x", "y"]),
        ("self-hosted-runner:\n  labels: [a]\n", []),
        ("paths: [1]\n", []),
        (": : :\n", []),
        ("", []),
    ],
)
def test_config_ignore_patterns(tmp_path, body, expected):
    config = tmp_path / "actionlint.yaml"
    config.write_text(body)
    assert config_ignore_patterns(config) == expected


@pytest.mark.parametrize(
    ("returncode", "stdout"),
    [
        (2, ""),
        (3, 'could not read "x.yml"'),
        (1, "not json"),
        (1, '{"version":"1","errors":[]}'),
    ],
)
def test_tool_errors_raise_rather_than_report_clean(
    repo, monkeypatch, on_path, returncode, stdout
):
    scanner = _scanner(repo)
    _run(scanner, monkeypatch, stdout, returncode)

    with pytest.raises(ScannerError):
        scanner.scan(target=repo, target_type="source")
    assert scanner.targets_failed == scanner.targets_attempted == 2


def test_a_timeout_says_timed_out(repo, monkeypatch, on_path):
    scanner = _scanner(repo)
    _run(scanner, monkeypatch, "", 124, timed_out=True)

    with pytest.raises(ScannerError, match="timed out"):
        scanner.scan(target=repo, target_type="source")


def test_the_raw_output_and_sarif_are_kept_in_the_results_dir(
    repo, monkeypatch, on_path
):
    scanner = _scanner(repo)
    stdout = (FIXTURES / "actionlint-1.7.12-default.json").read_text()
    _run(scanner, monkeypatch, stdout, 1)

    scanner.scan(target=repo, target_type="source")

    results = Path(scanner.results_dir) / "source"
    kept = json.loads((results / "actionlint.json").read_text())
    original = json.loads(stdout)
    assert len(kept["errors"]) == len(original["errors"])
    assert "hunter2" in stdout and "hunter2" not in json.dumps(kept)
    # Only the credentials snippet is dropped.
    assert [e for e in kept["errors"] if e["kind"] != "credentials"] == [
        e for e in original["errors"] if e["kind"] != "credentials"
    ]
    _assert_matches_default(
        json.loads((results / "actionlint.sarif").read_text(encoding="utf-8"))
    )


# --------------------------------------------------------------------------- #
# Suppressions
# --------------------------------------------------------------------------- #


def _suppressed_rules(report: SarifReport, suppressions, source: Path) -> list:
    config = get_default_config()
    config.global_settings.suppressions = suppressions
    context = PluginContext(
        source_dir=source, output_dir=source.parent / "out", config=config
    )
    report = apply_suppressions_to_sarif(copy.deepcopy(report), context)
    return [
        (r.ruleId, r.locations[0].physicalLocation.root.region.startLine)
        for r in report.runs[0].results
        if r.suppressions
    ]


@pytest.fixture
def default_report() -> SarifReport:
    return SarifReport.model_validate(
        build_sarif(_load("actionlint-1.7.12-default.json"), exit_code=1)
    )


def test_rule_suppression(default_report, tmp_path):
    suppressed = _suppressed_rules(
        default_report,
        [AshSuppression(rule_id="credentials", path="**", reason="test")],
        tmp_path,
    )
    assert suppressed == [("credentials", 17)]


def test_path_and_line_suppression(default_report, tmp_path):
    suppressed = _suppressed_rules(
        default_report,
        [
            AshSuppression(
                rule_id="deprecated-commands",
                path=".github/workflows/vulnerable.yml",
                line_start=24,
                line_end=24,
                reason="test",
            )
        ],
        tmp_path,
    )
    assert suppressed == [("deprecated-commands", 24)]


def test_path_suppression_for_another_file_suppresses_nothing(default_report, tmp_path):
    assert (
        _suppressed_rules(
            default_report,
            [AshSuppression(path=".github/workflows/clean.yml", reason="test")],
            tmp_path,
        )
        == []
    )


# --------------------------------------------------------------------------- #
# Review findings: confinement, integrations, exit codes, secrets, versions
# --------------------------------------------------------------------------- #


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges")
def test_a_workflow_symlinked_outside_the_root_is_not_passed(
    repo, tmp_path, monkeypatch, on_path
):
    outside = tmp_path / "outside.yml"
    outside.write_text("on: push\n")
    (repo / ".github" / "workflows" / "leak.yml").symlink_to(outside)
    scanner = _scanner(repo)
    fake = _run(scanner, monkeypatch, '{"version":"1.7.12","errors":[]}', 0)

    scanner.scan(target=repo, target_type="source")

    ((argv, _),) = fake.calls
    files = argv[argv.index("--") + 1 :]
    assert ".github/workflows/leak.yml" not in files
    assert files == [".github/workflows/clean.yml", ".github/workflows/vulnerable.yml"]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX execute bit")
def test_a_relative_integration_path_is_resolved_against_the_source_dir(
    repo, monkeypatch, on_path
):
    tool = repo / "tools" / "shellcheck"
    tool.parent.mkdir()
    tool.write_text("#!/bin/sh\n")
    tool.chmod(0o755)
    scanner = _scanner(repo, shellcheck="tools/shellcheck")
    fake = _run(scanner, monkeypatch, '{"version":"1.7.12","errors":[]}', 0)

    scanner.scan(target=repo, target_type="source")

    ((argv, _),) = fake.calls
    assert f"-shellcheck={tool.absolute().as_posix()}" in argv


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX execute bit")
def test_a_non_executable_integration_path_is_missing(repo, monkeypatch, on_path):
    tool = repo / "tools" / "shellcheck"
    tool.parent.mkdir()
    tool.write_text("not executable\n")
    tool.chmod(0o644)
    assert not os.access(tool, os.X_OK)
    scanner = _scanner(repo, shellcheck=tool.as_posix())

    assert scanner.validate_plugin_dependencies() is False
    assert "shellcheck" in scanner.dependency_unavailable_reason


@pytest.mark.parametrize("returncode", [2, 3])
def test_a_failing_exit_code_raises_even_with_valid_json(
    repo, monkeypatch, on_path, returncode
):
    scanner = _scanner(repo)
    _run(scanner, monkeypatch, '{"version":"1.7.12","errors":[]}', returncode)

    with pytest.raises(ScannerError, match=f"exited {returncode}"):
        scanner.scan(target=repo, target_type="source")


def test_a_credentials_finding_does_not_copy_the_password_into_the_report():
    sarif = build_sarif(_load("actionlint-1.7.12-default.json"), exit_code=1)
    credentials = sarif["runs"][0]["results"][0]
    assert credentials["ruleId"] == "credentials"
    region = credentials["locations"][0]["physicalLocation"]["region"]
    assert "snippet" not in region
    assert "hunter2" not in json.dumps(sarif)


def test_a_version_other_than_the_pin_is_warned_about(
    repo, monkeypatch, on_path, caplog
):
    scanner = _scanner(repo)
    _run(scanner, monkeypatch, '{"version":"1.6.0","errors":[]}', 0)

    with caplog.at_level(logging.WARNING):
        scanner.scan(target=repo, target_type="source")

    assert any("not the pinned v1.7.12" in r.getMessage() for r in caplog.records)


def test_the_pinned_version_is_not_warned_about(repo, monkeypatch, on_path, caplog):
    scanner = _scanner(repo)
    _run(scanner, monkeypatch, '{"version":"1.7.12","errors":[]}', 0)

    with caplog.at_level(logging.WARNING):
        scanner.scan(target=repo, target_type="source")

    assert not any("not the pinned" in r.getMessage() for r in caplog.records)


def test_a_scan_set_path_outside_the_target_is_not_passed(
    repo, tmp_path, monkeypatch, on_path
):
    outside = tmp_path / "elsewhere" / ".github" / "workflows" / "ci.yml"
    outside.parent.mkdir(parents=True)
    outside.write_text("on: push\n")
    inside = repo / ".github" / "workflows" / "clean.yml"
    monkeypatch.setattr(
        module, "scan_set", lambda **kwargs: [str(outside), str(inside)]
    )
    scanner = _scanner(repo)
    fake = _run(scanner, monkeypatch, '{"version":"1.7.12","errors":[]}', 0)

    scanner.scan(target=repo, target_type="source")

    ((argv, _),) = fake.calls
    assert argv[argv.index("--") + 1 :] == [".github/workflows/clean.yml"]
