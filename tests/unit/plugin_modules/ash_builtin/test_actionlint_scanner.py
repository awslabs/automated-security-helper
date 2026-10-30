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

import codecs
import copy
import json
import logging
import os
import shutil
import sys
from pathlib import Path

import pytest
from unittest.mock import MagicMock

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.interactions.run_ash_scan import (
    _INCOMPLETE_SCANNER_STATUSES,
)
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
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
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.utils.config_trust import record_provenance
from automated_security_helper.utils.sarif_utils import apply_suppressions_to_sarif
from automated_security_helper.utils.scan_output_dirs import mark_converted_results
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import COULD_NOT_STOP_REASON
from automated_security_helper.utils.tool_config_dir import TOOL_CONFIG_DIR_PREFIX

FIXTURES = Path(__file__).resolve().parents[3] / "test_data" / "scanners" / "actionlint"


def _ashs_own(config: Path, repo: Path) -> bool:
    """Whether ``config`` is the empty config ASH writes for this run's actionlint.

    ``config/tool_config_trust.empty_tool_config`` writes it in a directory of the
    scanner run's own, outside the scanned tree.
    """
    return not config.resolve().is_relative_to(repo.resolve()) and any(
        parent.name.startswith(TOOL_CONFIG_DIR_PREFIX) for parent in config.parents
    )


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


def _scanner(
    source: Path,
    output: Path | None = None,
    *,
    operator: bool = False,
    overrides: tuple = (),
    **options,
) -> ActionlintScanner:
    """A scanner whose config came from the scanned tree, or from the operator.

    ``operator=True`` records a config file outside the tree; ``overrides`` records
    --config-overrides keys. Otherwise the config is the tree's own .ash/.ash.yaml.
    """
    output = output or source.parent / "ash_output"
    config = get_default_config()
    # operator=True: built from no file in the scanned tree. Otherwise from the
    # tree's .ash/.ash.yaml, judged against the defaults plus ``overrides``.
    record_provenance(
        config,
        in_tree=[] if operator else [source / ".ash" / ".ash.yaml"],
        trusted=AshConfig(),
        config_overrides=list(overrides),
    )
    return ActionlintScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=output,
            work_dir=output / "converted",
            config=config,
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
        "find_absolute_executable",
        lambda name: FAKE_ACTIONLINT if name == "actionlint" else None,
    )


def _run(scanner, monkeypatch, stdout, returncode, **extra) -> FakeRun:
    fake = FakeRun(scanner, stdout=stdout, returncode=returncode, **extra)
    monkeypatch.setattr(scanner, "_run_subprocess", fake)
    return fake


# --------------------------------------------------------------------------- #
# A builtin scanner, on by default
# --------------------------------------------------------------------------- #


@pytest.mark.unit
def test_the_scanner_is_on_by_default():
    assert ActionlintScannerConfig().enabled is True
    assert ActionlintScannerConfig().name == "actionlint"


# --------------------------------------------------------------------------- #
# Parsing real output
# --------------------------------------------------------------------------- #


@pytest.mark.unit
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
@pytest.mark.unit
def test_negative_control_a_mutated_finding_fails_the_expectation(mutate):
    """The expectation above bites: change any field of one finding and it fails."""
    payload = _load("actionlint-1.7.12-default.json")
    expression = next(e for e in payload["errors"] if e["kind"] == "expression")
    mutate(expression)

    with pytest.raises(AssertionError):
        _assert_matches_default(build_sarif(payload, exit_code=1))


@pytest.mark.unit
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


@pytest.mark.unit
def test_rules_list_each_kind_once_with_its_default_level():
    sarif = build_sarif(_load("actionlint-1.7.12-default.json"), exit_code=1)
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    assert [r["id"] for r in rules] == sorted({row[0] for row in EXPECTED_DEFAULT})
    by_id = {r["id"]: r["defaultConfiguration"]["level"] for r in rules}
    assert by_id["credentials"] == "error"
    assert by_id["expression"] == "note"


@pytest.mark.unit
def test_captured_shellcheck_output_reports_shellcheck_as_low():
    sarif = build_sarif(_load("actionlint-1.7.12-shellcheck.json"), exit_code=1)
    shellcheck = [row for row in _summary(sarif) if row[0] == "shellcheck"]
    assert shellcheck == [
        ("shellcheck", "note", "LOW", ".github/workflows/vulnerable.yml", 34, 9)
    ]


@pytest.mark.unit
def test_captured_clean_output_is_zero_findings():
    sarif = build_sarif(_load("actionlint-1.7.12-clean.json"), exit_code=0)
    assert sarif["runs"][0]["results"] == []


# --------------------------------------------------------------------------- #
# Severity mapping
# --------------------------------------------------------------------------- #


@pytest.mark.unit
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
        # The same finding with its message cut after the first sentence, as a
        # record that quotes only the head of actionlint's text does.
        ("expression", '"github.event.issue.title" is potentially untrusted', "HIGH"),
        # A type error quoting workflow-authored text that holds the marker's
        # words is still a type error, not script injection.
        (
            "expression",
            (
                'property "x is potentially untrusted. avoid using it" is not '
                "defined in object type {}"
            ),
            "LOW",
        ),
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
@pytest.mark.unit
def test_severity_for(kind, message, expected):
    assert severity_for(kind, message) == expected


@pytest.mark.unit
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


@pytest.mark.unit
def test_an_untrusted_input_message_in_an_unknown_shape_is_logged_once(caplog):
    """The anchored shape keeps workflow-authored text from raising a finding to
    HIGH; its other side is a reworded actionlint message quietly becoming LOW.
    The severity stays what the shape decides, and the drift is logged once."""
    payload = {
        "version": "1.7.13",
        "errors": [
            {
                "kind": "expression",
                "message": 'note: "github.event.issue.title" is potentially untrusted.',
                "filepath": "a.yml",
                "line": 1,
            },
            {
                "kind": "expression",
                "message": 'note: "github.event.issue.body" is potentially untrusted.',
                "filepath": "a.yml",
                "line": 2,
            },
            {
                "kind": "expression",
                "message": '"github.event.issue.title" is potentially untrusted.',
                "filepath": "a.yml",
                "line": 3,
            },
        ],
    }
    with caplog.at_level(logging.WARNING):
        sarif = build_sarif(payload, exit_code=1)
    severities = [
        r["properties"]["issue_severity"] for r in sarif["runs"][0]["results"]
    ]
    assert severities == ["LOW", "LOW", "HIGH"]
    drift = [r for r in caplog.records if "potentially untrusted" in r.getMessage()]
    assert len(drift) == 1
    assert "not HIGH" in drift[0].getMessage()


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
        # The template writes an integer line for every error. Anything else is
        # the output format having changed; read as "no position" it would drop
        # every region silently, so it is ERROR (decision 5).
        (
            {"errors": [{"kind": "id", "message": "m", "filepath": "a", "line": True}]},
            1,
            "no integer line",
        ),
        (
            {"errors": [{"kind": "id", "message": "m", "filepath": "a", "line": None}]},
            1,
            "no integer line",
        ),
        (
            {"errors": [{"kind": "id", "message": "m", "filepath": "a", "line": "3"}]},
            1,
            "no integer line",
        ),
        (
            {"errors": [{"kind": "id", "message": "m", "filepath": "a"}]},
            1,
            "no integer line",
        ),
    ],
)
@pytest.mark.unit
def test_malformed_output_raises(payload, exit_code, match):
    with pytest.raises(ScannerError, match=match):
        build_sarif(payload, exit_code)


@pytest.mark.parametrize("line", [-1, -7], ids=["minus-one", "minus-seven"])
@pytest.mark.unit
def test_a_negative_line_is_not_read_as_no_position(line):
    """Only the integer 0 is "no position": actionlint never writes a negative
    line, so one means the output format changed, and giving it the line-0
    treatment would silently drop the region (line-scoped suppressions,
    line-keyed masking)."""
    payload = {
        "version": "1.7.12",
        "errors": [
            {
                "kind": "syntax-check",
                "message": "m",
                "filepath": ".github/workflows/a.yml",
                "line": line,
                "column": 1,
            }
        ],
    }
    with pytest.raises(ScannerError, match="negative line"):
        build_sarif(payload, exit_code=1)


@pytest.mark.parametrize("line", [0], ids=["zero"])
@pytest.mark.unit
def test_an_error_at_line_zero_is_kept_without_a_region(line):
    """actionlint reports line 0 for an error with no position (an empty workflow,
    invalid UTF-8, a YAML error before the first line). The finding stays, without
    a region, and the other workflow's finding is not dropped with it. Only the
    integer 0 is read that way; test_malformed_output_raises holds the rest."""
    payload = {
        "version": "1.7.12",
        "errors": [
            {
                "kind": "syntax-check",
                "message": "empty",
                "filepath": ".github/workflows/empty.yml",
                "line": line,
                "column": 0,
            },
            {
                "kind": "expression",
                # actionlint's wording, which severity_for matches by its shape.
                "message": '"github.event.issue.title" is potentially untrusted. '
                "avoid using it directly in inline scripts",
                "filepath": ".github/workflows/vulnerable.yml",
                "line": 20,
                "column": 24,
            },
        ],
    }

    results = build_sarif(payload, exit_code=1)["runs"][0]["results"]

    assert [result["ruleId"] for result in results] == ["syntax-check", "expression"]
    first = results[0]["locations"][0]["physicalLocation"]
    assert first["artifactLocation"]["uri"] == ".github/workflows/empty.yml"
    assert "region" not in first
    assert results[1]["locations"][0]["physicalLocation"]["region"] == {
        "startLine": 20,
        "endLine": 20,
        "startColumn": 24,
    }
    assert results[1]["properties"]["issue_severity"] == "HIGH"


@pytest.mark.unit
def test_null_errors_with_exit_zero_is_clean():
    assert build_sarif({"version": "1", "errors": None}, 0)["runs"][0]["results"] == []


# --------------------------------------------------------------------------- #
# Workflow discovery
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        (".github/workflows/ci.yml", True),
        # As spelled: GitHub, actionlint and zizmor read .yml and .yaml only.
        (".github/workflows/ci.YAML", False),
        ("svc/.github/workflows/ci.yaml", True),
        # A backslash separates on Windows and is a name character on POSIX,
        # where a root-level file so named is not a workflow and a workflow
        # whose name holds one still is.
        (".github\\workflows\\ci.yml", os.sep == "\\"),
        (".github/workflows/odd\\name.yml", os.sep != "\\"),
        (".github/workflows/sub/ci.yml", False),
        (".github/workflows/README.md", False),
        (".github/actionlint.yaml", False),
        ("github/workflows/ci.yml", False),
        ("config/not-a-workflow.yml", False),
    ],
)
@pytest.mark.unit
def test_is_workflow_file(path, expected):
    assert is_workflow_file(path) is expected


# --------------------------------------------------------------------------- #
# Running the scanner (subprocess replaced)
# --------------------------------------------------------------------------- #


@pytest.mark.unit
def test_argv_disables_shellcheck_and_pyflakes_and_passes_workflows_explicitly(
    repo, monkeypatch, on_path
):
    """Determinism: the integrations stay off even with shellcheck on PATH.

    ``find_absolute_executable`` here answers for shellcheck and pyflakes too, so the only
    reason they are absent from the argv is that ASH disabled them.
    """
    monkeypatch.setattr(
        module, "find_absolute_executable", lambda name: f"/usr/bin/{name}"
    )
    scanner = _scanner(repo)
    stdout = (FIXTURES / "actionlint-1.7.12-default.json").read_text()
    fake = _run(scanner, monkeypatch, stdout, 1)

    report = scanner.scan(target=repo, target_type="source")

    ((argv, kwargs),) = fake.calls
    separator = argv.index("--")
    assert argv[0] == "/usr/bin/actionlint"
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


@pytest.mark.unit
def test_configured_shellcheck_is_passed_by_resolved_path(repo, monkeypatch):
    monkeypatch.setattr(
        module, "find_absolute_executable", lambda name: f"/opt/bin/{name}"
    )
    scanner = _scanner(repo, shellcheck="shellcheck")
    fake = _run(scanner, monkeypatch, '{"version":"1.7.12","errors":[]}', 0)

    scanner.scan(target=repo, target_type="source")

    ((argv, _),) = fake.calls
    assert "-shellcheck=/opt/bin/shellcheck" in argv
    assert "-pyflakes=" in argv


@pytest.mark.unit
def test_configured_shellcheck_that_is_absent_is_missing_not_skipped(
    repo, monkeypatch, on_path
):
    scanner = _scanner(repo, shellcheck="shellcheck")
    fake = _run(scanner, monkeypatch, "", 0)

    assert scanner.scan(target=repo, target_type="source") is False
    assert fake.calls == []
    assert "shellcheck" in scanner.dependency_unavailable_reason


@pytest.mark.unit
def test_configured_pyflakes_path_that_does_not_exist_is_missing(
    repo, monkeypatch, on_path, tmp_path
):
    scanner = _scanner(
        repo, operator=True, pyflakes=str(tmp_path / "nope" / "pyflakes")
    )
    assert scanner.validate_plugin_dependencies() is False
    assert "pyflakes" in scanner.dependency_unavailable_reason


@pytest.mark.unit
def test_missing_actionlint_is_missing(repo, monkeypatch):
    monkeypatch.setattr(module, "find_absolute_executable", lambda name: None)
    scanner = _scanner(repo)
    fake = _run(scanner, monkeypatch, "", 0)

    assert scanner.scan(target=repo, target_type="source") is False
    assert fake.calls == []


@pytest.mark.unit
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


@pytest.mark.unit
def test_the_workspace_output_directory_is_named_to_the_scan_set(
    repo, monkeypatch, on_path
):
    """In a workspace scan the workspace's output directory holds every project's
    output. The scan set leaves it out only when it is named; a project at the
    workspace root otherwise lints other projects' output as its own source."""
    seen: list = []
    monkeypatch.setattr(module, "scan_set", lambda **kwargs: seen.append(kwargs) or [])
    workspace_output = repo.parent / "workspace-out"
    scanner = ActionlintScanner(
        context=PluginContext(
            source_dir=repo,
            output_dir=workspace_output / "repo",
            work_dir=workspace_output / "repo" / "converted",
            workspace_output_dir=workspace_output,
            config=get_default_config(),
        ),
        config=ActionlintScannerConfig(),
    )

    scanner._workflow_files(repo, "source", [])

    assert [call["workspace_output_dir"] for call in seen] == [str(workspace_output)]


@pytest.mark.unit
def test_a_workflow_git_tracks_under_the_output_directory_is_linted(
    repo, monkeypatch, on_path
):
    """The scan set leaves ASH's output directory out but keeps the files git
    tracks there, since a repository can commit files at that path. The scanner
    must not drop them a second time."""
    output = repo / ".ash" / "ash_output"
    committed = output / "sample" / ".github" / "workflows" / "committed.yml"
    committed.parent.mkdir(parents=True)
    committed.write_text("on: push\n")
    kept_by_the_scan_set = [
        str(repo / ".github" / "workflows" / "clean.yml"),
        str(committed),
    ]
    monkeypatch.setattr(module, "scan_set", lambda **_: list(kept_by_the_scan_set))
    scanner = _scanner(repo, output=output)

    workflows = scanner._workflow_files(repo, "source", [])

    assert workflows == [
        ".ash/ash_output/sample/.github/workflows/committed.yml",
        ".github/workflows/clean.yml",
    ]


@pytest.mark.unit
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


@pytest.mark.parametrize("pattern", [".github/workflows/", "**/.github/"])
@pytest.mark.unit
def test_an_ignore_path_ending_in_a_slash_leaves_out_what_is_inside(repo, pattern):
    """An ignore path ending in ``/`` names what is inside that directory, as every
    other place ASH matches an ignore path reads it (``ignore_path_matches``)."""
    scanner = _scanner(repo)
    ignores = [IgnorePathWithReason(path=pattern, reason="t")]

    assert scanner._workflow_files(repo, "source", []) == [
        ".github/workflows/clean.yml",
        ".github/workflows/vulnerable.yml",
    ]
    assert scanner._workflow_files(repo, "source", ignores) == []


@pytest.mark.unit
def test_an_ignore_path_ending_in_a_slash_keeps_a_file_of_that_name(repo):
    """``clean.yml/`` names a directory, so the workflow file clean.yml is kept."""
    scanner = _scanner(repo)
    ignores = [IgnorePathWithReason(path=".github/workflows/clean.yml/", reason="t")]

    assert scanner._workflow_files(repo, "source", ignores) == [
        ".github/workflows/clean.yml",
        ".github/workflows/vulnerable.yml",
    ]


@pytest.mark.unit
def test_gitignore_is_respected(repo, monkeypatch, on_path):
    (repo / ".gitignore").write_text(".github/workflows/vulnerable.yml\n")
    scanner = _scanner(repo)
    fake = _run(scanner, monkeypatch, '{"version":"1","errors":[]}', 0)

    scanner.scan(target=repo, target_type="source")

    ((argv, _),) = fake.calls
    assert argv[argv.index("--") + 1 :] == [".github/workflows/clean.yml"]


@pytest.mark.parametrize("honor", [True, False])
@pytest.mark.unit
def test_the_gitignore_applies_as_the_config_says(tmp_path, repo, honor):
    """A scan set actionlint computes itself follows ``honor_ignore_files``."""
    (repo / ".gitignore").write_text(".github/workflows/vulnerable.yml\n")
    scanner = _scanner(repo, output=tmp_path / f"out-{honor}")
    scanner.context.config.honor_ignore_files = honor

    linted = scanner._workflow_files(repo, "source", [])

    assert (".github/workflows/vulnerable.yml" in linted) is not honor
    assert ".github/workflows/clean.yml" in linted


@pytest.mark.parametrize("honor", [True, False])
@pytest.mark.unit
def test_an_untracked_workflow_under_the_output_directory_is_not_linted(repo, honor):
    """The scanner adds no filter of its own for ASH's output directory and relies
    on the scan set to leave it out (keeping only what git tracks there). That
    premise is read through the real scan set here, in both honor_ignore_files
    modes and on a source that is no git checkout: a converted archive's workflow
    under output/converted/ is not this project's source and is not linted."""
    output = repo / ".ash" / "ash_output"
    converted = output / "converted" / "sample.zip" / ".github" / "workflows"
    converted.mkdir(parents=True)
    (converted / "inside-archive.yml").write_text("on: push\n")
    scanner = _scanner(repo, output=output)
    scanner.context.config.honor_ignore_files = honor

    linted = scanner._workflow_files(repo, "source", [])

    assert ".github/workflows/clean.yml" in linted
    assert not [path for path in linted if path.startswith(".ash/ash_output/")]


@pytest.mark.unit
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


@pytest.mark.unit
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
    # True with no target attempted is what the executor grades as SKIPPED, as
    # zizmor returns on the same tree. A SARIF report with no run is refused as
    # "nothing to grade" and reads as ERROR, which failed the Nix validation leg
    # on a fixture that has no workflow.
    assert report is True
    assert scanner.targets_attempted == 0


def _executor_row(scanner: ActionlintScanner, source: Path):
    """The row ScannerExecutor builds for ``scanner`` over ``source``.

    The executor is the real one: it applies the refusal of a SARIF log with no
    run and the status grading the exit code reads.
    """
    executor = ScannerExecutor(
        plugin_context=scanner.context,
        progress_display=MagicMock(),
        scanner_tasks=[],
    )
    (row,) = executor._execute_scanner(
        "actionlint", scanner, [{"path": source, "type": "source"}]
    )
    return row


@pytest.mark.unit
def test_a_tree_with_no_workflows_is_skipped_not_incomplete_through_the_executor(
    tmp_path, monkeypatch, on_path
):
    """The composed path: actionlint's empty-tree result, then the executor's refusal.

    Each half is pinned alone (the scanner returns no workflows to lint, the executor
    refuses a log with no run). A repository with no .github/workflows crosses both,
    and must not stop ``ash scan`` with an incomplete-scanner exit.
    """
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("print(1)\n")
    scanner = _scanner(source, severity_threshold="MEDIUM")
    fake = _run(scanner, monkeypatch, "", 0)

    row = _executor_row(scanner, source)

    assert fake.calls == []
    assert row.status == ScannerStatus.SKIPPED, (row.status, row.errors)
    assert row.status.value not in _INCOMPLETE_SCANNER_STATUSES
    assert not any("no SARIF run" in str(error) for error in row.errors), row.errors


@pytest.mark.unit
def test_a_tree_with_a_flagged_workflow_still_reports_its_finding_through_the_executor(
    repo, monkeypatch, on_path
):
    scanner = _scanner(repo, severity_threshold="MEDIUM")
    _run(
        scanner,
        monkeypatch,
        (FIXTURES / "actionlint-1.7.12-default.json").read_text(),
        1,
    )

    row = _executor_row(scanner, repo)

    assert row.status == ScannerStatus.FAILED, (row.status, row.errors)
    assert row.finding_count == len(EXPECTED_DEFAULT)


@pytest.mark.unit
def test_an_actionlint_that_failed_still_reads_error_through_the_executor(
    repo, monkeypatch, on_path
):
    scanner = _scanner(repo, severity_threshold="MEDIUM")
    _run(scanner, monkeypatch, 'could not read "x.yml"', 3)

    row = _executor_row(scanner, repo)

    assert row.status == ScannerStatus.ERROR, (row.status, row.errors)
    assert row.status.value in _INCOMPLETE_SCANNER_STATUSES


@pytest.mark.unit
def test_without_a_config_an_empty_one_is_passed_from_outside_the_tree(
    repo, monkeypatch, on_path
):
    scanner = _scanner(repo)
    fake = _run(scanner, monkeypatch, '{"version":"1","errors":[]}', 0)

    scanner.scan(target=repo, target_type="source")

    ((argv, _),) = fake.calls
    config = Path(argv[argv.index("-config-file") + 1])
    assert _ashs_own(config, repo)
    assert config.read_text().startswith("#")


@pytest.mark.parametrize("name", ["actionlint.yaml", "actionlint.yml"])
@pytest.mark.unit
def test_the_scanned_trees_actionlint_config_is_not_read(
    repo, monkeypatch, on_path, caplog, name
):
    """Its ``paths.ignore`` would drop findings neither reported nor suppressed."""
    (repo / ".github" / name).write_text(
        "paths:\n  .github/workflows/**/*.yml:\n    ignore:\n      - '.*'\n"
    )
    scanner = _scanner(repo)
    fake = _run(scanner, monkeypatch, '{"version":"1","errors":[]}', 0)

    with caplog.at_level(logging.INFO):
        scanner.scan(target=repo, target_type="source")

    ((argv, kwargs),) = fake.calls
    config = Path(argv[argv.index("-config-file") + 1])
    assert _ashs_own(config, repo)
    assert config.read_text().startswith("#")
    assert f".github/{name} in the scanned tree is not read" in caplog.text
    assert kwargs["cwd"] == repo


@pytest.mark.parametrize("name", ["actionlint.yaml", "actionlint.yml"])
@pytest.mark.unit
def test_a_tree_config_that_does_not_parse_moves_the_run_to_a_copy_outside_the_tree(
    repo, monkeypatch, on_path, caplog, name
):
    """actionlint reads the tree's config while it looks for the project root,
    whatever -config-file names, and exits 3 on one it cannot parse; the run
    moves to a copy of the workflows that holds no project root."""
    (repo / ".github" / name).write_text("paths: [\n")
    scanner = _scanner(repo)
    fake = _run(scanner, monkeypatch, '{"version":"1","errors":[]}', 0)

    with caplog.at_level(logging.WARNING):
        scanner.scan(target=repo, target_type="source")

    ((argv, kwargs),) = fake.calls
    run_root = Path(kwargs["cwd"])
    assert not run_root.resolve().is_relative_to(repo.resolve())
    assert not (run_root / ".git").exists()
    workflows = argv[argv.index("--") + 1 :]
    assert workflows
    for rel in workflows:
        assert (run_root / rel).read_bytes() == (repo / rel).read_bytes()
    config = Path(argv[argv.index("-config-file") + 1])
    assert _ashs_own(config, repo)
    assert f".github/{name} in the scanned tree cannot be read as YAML" in caplog.text
    assert "local `uses: ./...` references are not resolved" in caplog.text


@pytest.mark.unit
def test_a_tree_config_that_parses_keeps_the_run_in_the_tree(
    repo, monkeypatch, on_path, caplog
):
    """Aliases, which actionlint and PyYAML's safe loader both accept, are not a
    reason to leave the tree; only a file actionlint would refuse is."""
    (repo / ".github" / "actionlint.yaml").write_text(
        "self-hosted-runner:\n  labels: &l [x]\nconfig-variables: *l\n"
    )
    scanner = _scanner(repo)
    fake = _run(scanner, monkeypatch, '{"version":"1","errors":[]}', 0)

    with caplog.at_level(logging.WARNING):
        scanner.scan(target=repo, target_type="source")

    ((_, kwargs),) = fake.calls
    assert kwargs["cwd"] == repo
    assert "cannot be read as YAML" not in caplog.text


@pytest.mark.parametrize("body", ["paths: [\n", ": : :\n"])
@pytest.mark.unit
def test_tree_config_problem_names_the_first_candidate_and_its_problem(tmp_path, body):
    """actionlint reads ``actionlint.yaml`` before ``actionlint.yml`` and takes
    the first that exists, so the parseable ``.yml`` beside it changes nothing."""
    (tmp_path / ".github").mkdir()
    (tmp_path / ".github" / "actionlint.yaml").write_text(body)
    (tmp_path / ".github" / "actionlint.yml").write_text("paths: {}\n")

    problem = module.tree_config_problem(tmp_path)

    assert problem is not None
    name, text = problem
    assert name == ".github/actionlint.yaml"
    assert text


@pytest.mark.unit
def test_tree_config_problem_is_none_without_a_config_or_with_a_parseable_one(
    tmp_path,
):
    (tmp_path / ".github").mkdir()
    assert module.tree_config_problem(tmp_path) is None
    (tmp_path / ".github" / "actionlint.yml").write_text("paths: {}\n")
    assert module.tree_config_problem(tmp_path) is None


@pytest.mark.unit
def test_tree_config_problem_reads_at_most_its_bound_and_never_parses_past_it(
    tmp_path, monkeypatch
):
    """A large file in a scanned tree costs ASH one bounded read, not a parse:
    the bound is monkeypatched small so the test writes a few bytes, and the
    loader is replaced by one that fails the test if it is ever called."""
    (tmp_path / ".github").mkdir()
    (tmp_path / ".github" / "actionlint.yaml").write_text("paths: {}\n" * 4)
    monkeypatch.setattr(module, "TREE_CONFIG_READ_BOUND", 16)

    def never(_text):
        raise AssertionError("a file past the bound must not be parsed")

    monkeypatch.setattr(module.yaml, "safe_load", never)

    problem = module.tree_config_problem(tmp_path)

    assert problem is not None
    assert problem[0] == ".github/actionlint.yaml"
    assert "longer than 16 bytes" in problem[1]


@pytest.mark.parametrize(
    ("body", "fragment"),
    [
        (b"\xef\xbb\xbfpaths: [\n", "line"),
        ('key: "\\UFFFFFFFF"\n'.encode(), ""),
    ],
)
@pytest.mark.unit
def test_tree_config_problem_answers_a_bom_prefixed_or_escape_broken_file(
    tmp_path, body, fragment
):
    """Read by its byte-order mark as actionlint reads it, and an escape outside
    Unicode (which PyYAML's scanner lets chr() raise on) is an answer, never an
    exception out of the check."""
    (tmp_path / ".github").mkdir()
    (tmp_path / ".github" / "actionlint.yaml").write_bytes(body)

    problem = module.tree_config_problem(tmp_path)

    assert problem is not None
    assert problem[0] == ".github/actionlint.yaml"
    assert fragment in problem[1]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks")
@pytest.mark.unit
def test_tree_config_problem_follows_a_link_as_actionlint_does(tmp_path):
    """actionlint's os.ReadFile follows a linked config, so a link to a malformed
    file is a problem and a link to a parseable one is not."""
    (tmp_path / ".github").mkdir()
    bad = tmp_path / "bad.yaml"
    bad.write_text("paths: [\n")
    good = tmp_path / "good.yaml"
    good.write_text("paths: {}\n")
    link = tmp_path / ".github" / "actionlint.yaml"
    link.symlink_to(bad)
    assert module.tree_config_problem(tmp_path) is not None
    link.unlink()
    link.symlink_to(good)
    assert module.tree_config_problem(tmp_path) is None


@pytest.mark.parametrize("operator", [True, False])
@pytest.mark.unit
def test_config_file_is_passed_only_when_the_operator_set_it(
    repo, monkeypatch, on_path, caplog, operator
):
    (repo / "ci").mkdir()
    (repo / "ci" / "actionlint.yaml").write_text("self-hosted-runner:\n  labels: [x]\n")
    scanner = _scanner(repo, operator=operator, config_file="ci/actionlint.yaml")
    fake = _run(scanner, monkeypatch, '{"version":"1","errors":[]}', 0)

    with caplog.at_level(logging.WARNING):
        scanner.scan(target=repo, target_type="source")

    ((argv, _),) = fake.calls
    config = Path(argv[argv.index("-config-file") + 1])
    if operator:
        assert config == (repo / "ci" / "actionlint.yaml").absolute()
        assert "Ignoring scanners.actionlint.options.config_file" not in caplog.text
    else:
        assert _ashs_own(config, repo)
        assert "Ignoring scanners.actionlint.options.config_file" in caplog.text


@pytest.mark.unit
def test_an_operator_config_file_that_does_not_exist_is_an_error(
    repo, monkeypatch, on_path
):
    scanner = _scanner(repo, operator=True, config_file="ci/actionlint.yaml")
    fake = _run(scanner, monkeypatch, "", 0)

    with pytest.raises(ScannerError, match="does not exist"):
        scanner.scan(target=repo, target_type="source")
    assert fake.calls == []
    assert scanner.targets_failed == scanner.targets_attempted == 2


_OUTSIDE_PATTERN = "pattern-from-a-file-outside-the-tree"


def _config_linked_out(repo: Path, shape: str) -> str:
    """A config_file value in the tree that leads to a file outside it, an
    actionlint config whose ``ignore`` pattern ASH would log."""
    outside = repo.parent / "outside"
    outside.mkdir()
    (outside / "creds").write_text(
        f"paths:\n  '**':\n    ignore:\n      - {_OUTSIDE_PATTERN}\n"
    )
    link = repo / "ci" / "actionlint.yaml"
    if shape in ("file", "chain", "dangling"):
        link.parent.mkdir()
    if shape == "file":
        link.symlink_to(outside / "creds")
    elif shape == "chain":
        (repo / "ci" / "second.yaml").symlink_to(outside / "creds")
        link.symlink_to("second.yaml")
    elif shape == "dangling":
        link.symlink_to(outside / "missing.yaml")
    elif shape == "directory":
        (repo / "ci").symlink_to(outside, target_is_directory=True)
        return "ci/creds"
    else:
        (repo / "ci").mkdir()
        (repo / "ci" / "up").symlink_to(outside, target_is_directory=True)
        return "ci/up/creds"
    return "ci/actionlint.yaml"


@pytest.mark.skipif(os.name == "nt", reason="symlinks")
@pytest.mark.parametrize(
    "shape", ["file", "chain", "dangling", "directory", "nested directory"]
)
@pytest.mark.unit
def test_an_operator_config_file_in_the_tree_cannot_link_out_of_it(
    repo, monkeypatch, on_path, caplog, shape
):
    """The operator may name a config inside the scanned tree, but the tree decides
    what is at that path. actionlint quotes the start of a value it cannot parse,
    and ASH logs a config's ignore patterns, so a link there to a file outside the
    tree put that file's text into ash.log. actionlint is not run, and the scan is
    an error."""
    value = _config_linked_out(repo, shape)
    scanner = _scanner(repo, operator=True, config_file=value)
    fake = _run(scanner, monkeypatch, '{"version":"1","errors":[]}', 0)

    with caplog.at_level(logging.DEBUG), pytest.raises(ScannerError) as excinfo:
        scanner.scan(target=repo, target_type="source")
    assert fake.calls == []
    message = str(excinfo.value)
    assert "scanners.actionlint.options.config_file" in message
    assert "symbolic link" in message and "actionlint is not run" in message
    assert _OUTSIDE_PATTERN not in message + caplog.text
    assert (repo.parent / "outside").as_posix() not in message


@pytest.mark.skipif(os.name == "nt", reason="symlinks")
@pytest.mark.unit
def test_an_operator_config_file_in_the_tree_may_link_inside_it(
    repo, monkeypatch, on_path
):
    (repo / "ci").mkdir()
    (repo / "ci" / "real.yaml").write_text("self-hosted-runner:\n  labels: [x]\n")
    (repo / "ci" / "actionlint.yaml").symlink_to("real.yaml")
    scanner = _scanner(repo, operator=True, config_file="ci/actionlint.yaml")
    fake = _run(scanner, monkeypatch, '{"version":"1","errors":[]}', 0)
    scanner.scan(target=repo, target_type="source")
    ((argv, _),) = fake.calls
    config = Path(argv[argv.index("-config-file") + 1])
    assert config == (repo / "ci" / "real.yaml").resolve()


@pytest.mark.skipif(os.name == "nt", reason="symlinks")
@pytest.mark.unit
def test_an_operator_config_file_outside_the_tree_may_be_a_link(
    repo, monkeypatch, on_path
):
    """Outside the tree the operator controls both the path and the link."""
    shared = repo.parent / "shared"
    shared.mkdir()
    (shared / "actionlint.yaml").write_text("self-hosted-runner:\n  labels: [x]\n")
    (repo.parent / "actionlint.yaml").symlink_to(shared / "actionlint.yaml")
    scanner = _scanner(repo, operator=True, config_file="../actionlint.yaml")
    fake = _run(scanner, monkeypatch, '{"version":"1","errors":[]}', 0)
    scanner.scan(target=repo, target_type="source")
    ((argv, _),) = fake.calls
    config = Path(argv[argv.index("-config-file") + 1])
    assert config == (shared / "actionlint.yaml").resolve()


@pytest.mark.unit
def test_an_operator_config_that_ignores_findings_is_warned_about(
    repo, monkeypatch, on_path, caplog
):
    (repo / "ci").mkdir()
    (repo / "ci" / "actionlint.yaml").write_text(
        "paths:\n  .github/workflows/**/*.yml:\n    ignore:\n"
        "      - 'potentially untrusted'\n"
    )
    scanner = _scanner(repo, operator=True, config_file="ci/actionlint.yaml")
    _run(scanner, monkeypatch, '{"version":"1","errors":[]}', 0)

    with caplog.at_level(logging.WARNING):
        scanner.scan(target=repo, target_type="source")

    assert any("'potentially untrusted'" in r.getMessage() for r in caplog.records)


ALIASED_IGNORES = (
    "paths:\n  .github/workflows/a.yml:\n    ignore: &ignored\n"
    "      - 'potentially untrusted'\n"
    "  .github/workflows/b.yml:\n    ignore: *ignored\n"
)


@pytest.mark.unit
def test_an_operator_config_whose_ignores_cannot_be_listed_is_warned_about(
    repo, monkeypatch, on_path, caplog
):
    """ASH reads the config with YAML aliases refused, and actionlint reads them.

    So ASH cannot list what an aliased config ignores, while actionlint still
    drops those findings; the warning says so instead of staying silent.
    """
    (repo / "ci").mkdir()
    (repo / "ci" / "actionlint.yaml").write_text(ALIASED_IGNORES)
    scanner = _scanner(repo, operator=True, config_file="ci/actionlint.yaml")
    _run(scanner, monkeypatch, '{"version":"1","errors":[]}', 0)

    with caplog.at_level(logging.WARNING):
        scanner.scan(target=repo, target_type="source")

    warnings = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert any(
        "could not list" in message and "alias" in message for message in warnings
    ), warnings


@pytest.mark.unit
def test_an_aliased_config_is_not_read_for_its_ignore_patterns(tmp_path):
    config = tmp_path / "actionlint.yaml"
    config.write_text(ALIASED_IGNORES)
    with pytest.raises(module.IgnorePatternsUnlisted, match="alias"):
        config_ignore_patterns(config)


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("paths:\n  a/**:\n    ignore: [x, y]\n  b:\n    ignore: [x]\n", ["x", "y"]),
        ("self-hosted-runner:\n  labels: [a]\n", []),
        ("paths: [1]\n", []),
        ("", []),
        # go-yaml reads a null as "" and every other scalar as its source text,
        # and actionlint compiles each as a regular expression: "" drops every
        # finding, which is the entry the log most needs to show.
        ("paths:\n  '**':\n    ignore: ['', ~, 0, false]\n", ["", "0", "false"]),
        # A null on its own: read as "", not dropped (the row above cannot tell
        # the two apart, since '' is in it too).
        ("paths:\n  '**':\n    ignore: [~]\n", [""]),
        ("paths:\n  '**':\n    ignore: [null]\n", [""]),
        # Spellings PyYAML's constructor would turn into True, True, False and
        # 31; go-yaml hands actionlint the text as written.
        (
            "paths:\n  '**':\n    ignore: [yes, on, False, 0x1F, 1e3]\n",
            ["0x1F", "1e3", "False", "on", "yes"],
        ),
        # A quoted scalar is its text without the quotes, as go-yaml reads it.
        ("paths:\n  '**':\n    ignore: ['false', \"0x1F\"]\n", ["0x1F", "false"]),
        # An entry that is not a scalar is left out; actionlint refuses it.
        ("paths:\n  '**':\n    ignore: [[a], {b: c}, x]\n", ["x"]),
    ],
)
@pytest.mark.unit
def test_config_ignore_patterns(tmp_path, body, expected):
    config = tmp_path / "actionlint.yaml"
    config.write_text(body)
    assert config_ignore_patterns(config) == expected


@pytest.mark.parametrize(
    ("body", "cause"),
    [
        pytest.param(": : :\n", "line", id="syntax-error"),
        pytest.param("[" * 3000 + "]" * 3000 + "\n", "recursion", id="too-deep"),
        pytest.param(
            "paths:\n  x:\n    ignore: [2001-13-45]\n", "month", id="bad-date"
        ),
    ],
)
@pytest.mark.unit
def test_a_config_ash_cannot_read_is_reported_rather_than_listed_as_empty(
    tmp_path, body, cause
):
    """actionlint's go-yaml reads what PyYAML refuses (a date its constructor
    rejects, nesting past its recursion limit), so "no patterns" would be a
    guess; the caller is told instead."""
    config = tmp_path / "actionlint.yaml"
    config.write_text(body)
    with pytest.raises(module.IgnorePatternsUnlisted, match=cause):
        config_ignore_patterns(config)


@pytest.mark.unit
def test_a_refusal_on_the_second_read_is_reported_rather_than_raised(
    tmp_path, monkeypatch
):
    """The patterns are listed from a second read of the text (the composed
    node tree) after the document parsed. A YAML error from that read is
    reported the way the first read's is, so the caller warns and the scan
    goes on; before, it escaped config_ignore_patterns as the raw exception."""
    config = tmp_path / "actionlint.yaml"
    config.write_text("paths:\n  '**':\n    ignore: [x]\n")

    def refuse(text):
        raise module.yaml.composer.ComposerError(
            None, None, "refused on the second read", None
        )

    monkeypatch.setattr(module, "_ignore_pattern_texts", refuse)

    with pytest.raises(module.IgnorePatternsUnlisted, match="second read"):
        config_ignore_patterns(config)


@pytest.mark.unit
def test_a_utf16_config_is_read_by_its_byte_order_mark(tmp_path):
    config = tmp_path / "actionlint.yaml"
    body = "paths:\n  '**':\n    ignore: [x]\n"
    config.write_bytes(codecs.BOM_UTF16_LE + body.encode("utf-16-le"))
    assert config_ignore_patterns(config) == ["x"]


@pytest.mark.unit
def test_a_config_ash_cannot_parse_is_warned_about_in_the_scan(
    repo, monkeypatch, on_path, caplog
):
    (repo / "ci").mkdir()
    (repo / "ci" / "actionlint.yaml").write_text(": : :\n")
    scanner = _scanner(repo, operator=True, config_file="ci/actionlint.yaml")
    _run(scanner, monkeypatch, '{"version":"1","errors":[]}', 0)

    with caplog.at_level(logging.WARNING):
        scanner.scan(target=repo, target_type="source")

    warnings = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert any("could not list" in message for message in warnings), warnings


@pytest.mark.parametrize(
    ("returncode", "stdout"),
    [
        (2, ""),
        (3, 'could not read "x.yml"'),
        (1, "not json"),
        (1, '{"version":"1","errors":[]}'),
    ],
)
@pytest.mark.unit
def test_tool_errors_raise_rather_than_report_clean(
    repo, monkeypatch, on_path, returncode, stdout
):
    scanner = _scanner(repo)
    _run(scanner, monkeypatch, stdout, returncode)

    with pytest.raises(ScannerError):
        scanner.scan(target=repo, target_type="source")
    assert scanner.targets_failed == scanner.targets_attempted == 2


@pytest.mark.unit
def test_a_timeout_says_timed_out(repo, monkeypatch, on_path):
    scanner = _scanner(repo)
    _run(scanner, monkeypatch, "", 124, timed_out=True)

    with pytest.raises(ScannerError, match="timed out"):
        scanner.scan(target=repo, target_type="source")


@pytest.mark.unit
def test_a_timeout_prints_the_limit_as_the_shared_token(repo, monkeypatch, on_path):
    """The limit goes through the base class's token (a quoted whole number, or
    the option's name when the environment wrote it), never the raw float."""
    scanner = _scanner(repo, scan_timeout=7)
    _run(scanner, monkeypatch, "", 124, timed_out=True)

    with pytest.raises(ScannerError) as caught:
        scanner.scan(target=repo, target_type="source")

    assert "timed out after '7' s and was killed" in str(caught.value)
    assert "7.0s" not in str(caught.value)


@pytest.mark.unit
def test_a_timeout_whose_stop_failed_does_not_say_the_tool_was_killed(
    repo, monkeypatch, on_path
):
    """Driven through the base class with the response shape it reads for this
    ending (a timeout carrying the could-not-stop record), so the marker the
    scanner consults is set the way a real run sets it, not by hand."""
    scanner = _scanner(repo, scan_timeout=7)
    _through_the_base_class(
        monkeypatch,
        [
            {
                "returncode": 124,
                "stdout": "",
                "timed_out": True,
                "could_not_stop": True,
                "could_not_stop_pid": 4242,
                "error": "the tool could not be stopped",
            }
        ],
    )

    with pytest.raises(ScannerError) as caught:
        scanner.scan(target=repo, target_type="source")

    assert scanner.scan_could_not_stop is not None
    message = str(caught.value)
    assert "timed out after '7' s" in message
    assert "was killed" not in message
    assert COULD_NOT_STOP_REASON in message


@pytest.mark.unit
def test_output_that_is_not_json_is_not_kept(repo, monkeypatch, on_path):
    """Output that does not parse cannot be redacted, and a credentials
    finding's snippet (the password) may be in it, so nothing of it is written
    to the output directory or kept in the plugin's record lines.

    Driven through the base class, which copies the run's stdout into the
    record lines; a stand-in for the whole subprocess step skipped that copy,
    so the record-lines check could only have caught the scanner echoing the
    output itself."""
    scanner = _scanner(repo)
    _through_the_base_class(
        monkeypatch, [{"returncode": 1, "stdout": "not json: password hunter2"}]
    )

    with pytest.raises(ScannerError, match="not JSON"):
        scanner.scan(target=repo, target_type="source")

    assert not (Path(scanner.results_dir) / "source" / "actionlint.json").exists()
    record = "\n".join(scanner.output)
    assert "hunter2" not in record
    assert "not kept" in record


@pytest.mark.unit
def test_a_failure_before_actionlint_starts_is_described_as_not_started(
    repo, monkeypatch, on_path
):
    scanner = _scanner(repo, operator=True, config_file="ci/missing.yaml")
    fake = _run(scanner, monkeypatch, _EMPTY_RUN, 0)

    with pytest.raises(ScannerError) as caught:
        scanner.scan(target=repo, target_type="source")

    assert fake.calls == []
    assert "was not started" in str(caught.value)
    assert "exit code 0" not in str(caught.value)


@pytest.mark.unit
def test_workflow_batches_split_by_the_argv_budget():
    assert module.workflow_batches([], 10) == []
    assert module.workflow_batches(["a.yml", "b.yml", "c.yml"], 12) == [
        ["a.yml", "b.yml"],
        ["c.yml"],
    ]
    long_name = "x" * 30
    assert module.workflow_batches([long_name, "a.yml"], 12) == [
        [long_name],
        ["a.yml"],
    ]
    assert module.workflow_batches(["a.yml", "b.yml"]) == [["a.yml", "b.yml"]]


@pytest.mark.unit
def test_many_workflows_are_linted_in_several_runs_and_one_report(
    repo, monkeypatch, on_path
):
    """A tree with more workflows than one command line holds is linted in
    several runs, each judged by its own exit code, and reported once.

    Driven through the base class, whose exit-code accumulation keeps the worst
    code across calls: the first run exits 1 with findings and the second exits
    0 with none, so a scanner that judged the second run by the accumulated 1
    would fail it as "exited 1 but reported none". The runs' findings are the
    fixtures' and are not tied to the workflow each run was given."""
    monkeypatch.setattr(module, "_WORKFLOW_ARGV_BUDGET", 30)
    scanner = _scanner(repo)
    with_findings = (FIXTURES / "actionlint-1.7.12-default.json").read_text()
    clean = (FIXTURES / "actionlint-1.7.12-clean.json").read_text()
    calls = _through_the_base_class(
        monkeypatch,
        [
            {"returncode": 1, "stdout": with_findings},
            {"returncode": 0, "stdout": clean},
        ],
    )

    report = scanner.scan(target=repo, target_type="source")

    argvs = [call["command"] for call in calls]
    assert [argv[argv.index("--") + 1 :] for argv in argvs] == [
        [".github/workflows/clean.yml"],
        [".github/workflows/vulnerable.yml"],
    ]
    assert len(report.runs[0].results) == len(EXPECTED_DEFAULT)
    assert scanner.targets_attempted == 2
    kept = json.loads(
        (Path(scanner.results_dir) / "source" / "actionlint.json").read_text()
    )
    assert len(kept["errors"]) == len(EXPECTED_DEFAULT)
    assert "hunter2" not in json.dumps(kept)
    # The one invocation describes the whole target: the worst code any run
    # returned (1, the first run's) and every workflow the runs were given, not
    # the last run's clean 0 and its one file.
    assert scanner.exit_code == 1
    invocation = report.runs[0].invocations[0]
    assert invocation.exitCode == 1
    recorded = " ".join(invocation.arguments or [])
    assert ".github/workflows/clean.yml" in recorded
    assert ".github/workflows/vulnerable.yml" in recorded


@pytest.mark.unit
def test_scan_timeout_bounds_the_target_not_each_batch(repo, monkeypatch, on_path):
    """scan_timeout is the limit for one target. With two batches, the first is
    given the whole limit; when it has used it all (the clock here jumps past
    the deadline between the runs), the second never starts and the scan ends
    as a timeout, instead of each batch getting the whole limit again."""
    monkeypatch.setattr(module, "_WORKFLOW_ARGV_BUDGET", 30)
    # The clock is read once when the deadline is set and once before the
    # second batch (the first batch gets the limit as given, with no read).
    readings = [0.0, 10.0]

    def monotonic():
        return readings.pop(0) if len(readings) > 1 else readings[0]

    monkeypatch.setattr(module.time, "monotonic", monotonic)
    scanner = _scanner(repo, scan_timeout=7)
    calls = _through_the_base_class(
        monkeypatch,
        [
            {"returncode": 0, "stdout": _EMPTY_RUN},
            {"returncode": 0, "stdout": _EMPTY_RUN},
        ],
    )

    with pytest.raises(ScannerError, match="timed out after '7' s"):
        scanner.scan(target=repo, target_type="source")

    assert len(calls) == 1
    assert calls[0]["timeout"] == 7.0


@pytest.mark.unit
def test_an_earlier_batchs_raw_output_is_not_kept_when_a_later_batch_fails(
    repo, monkeypatch, on_path
):
    """The first run's stdout, password snippet included, became record lines;
    the second run fails before the redacted payload would replace them. The
    failed scan's records must hold a note, not the raw stdout."""
    monkeypatch.setattr(module, "_WORKFLOW_ARGV_BUDGET", 30)
    stdout = (FIXTURES / "actionlint-1.7.12-default.json").read_text()
    assert "hunter2" in stdout
    scanner = _scanner(repo)
    _through_the_base_class(
        monkeypatch,
        [{"returncode": 1, "stdout": stdout}, {"returncode": 2, "stdout": ""}],
    )

    with pytest.raises(ScannerError):
        scanner.scan(target=repo, target_type="source")

    record = "\n".join(scanner.output)
    assert "hunter2" not in record
    assert "not kept" in record


@pytest.mark.unit
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


@pytest.mark.unit
def test_rule_suppression(default_report, tmp_path):
    suppressed = _suppressed_rules(
        default_report,
        [AshSuppression(rule_id="credentials", path="**", reason="test")],
        tmp_path,
    )
    assert suppressed == [("credentials", 17)]


@pytest.mark.unit
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


@pytest.mark.unit
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
@pytest.mark.unit
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


@pytest.mark.parametrize("kind", ["dangling", "loop"])
@pytest.mark.unit
def test_a_workflow_link_that_resolves_to_no_file_is_skipped_with_a_warning(
    repo, monkeypatch, on_path, caplog, kind
):
    """actionlint exits 3 on a file it cannot open, failing the whole run.

    So a broken or looping link is skipped with a warning, as a link pointing
    outside the scan root is, and the other workflows are still linted.
    """
    workflows = repo / ".github" / "workflows"
    if kind == "dangling":
        (workflows / "broken.yml").symlink_to("missing.yml")
    else:
        (workflows / "broken.yml").symlink_to("loop.yml")
        (workflows / "loop.yml").symlink_to("broken.yml")
    scanner = _scanner(repo)
    fake = _run(scanner, monkeypatch, '{"version":"1.7.12","errors":[]}', 0)

    with caplog.at_level(logging.WARNING):
        scanner.scan(target=repo, target_type="source")

    ((argv, _),) = fake.calls
    files = argv[argv.index("--") + 1 :]
    assert files == [".github/workflows/clean.yml", ".github/workflows/vulnerable.yml"]
    assert "Not linting .github/workflows/broken.yml" in caplog.text


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX named pipes")
@pytest.mark.unit
def test_a_named_pipe_named_like_a_workflow_is_skipped_without_blocking(repo, caplog):
    """Reading a FIFO blocks until a writer appears, outside any scan timeout.
    Only a regular file is a workflow. The writer thread makes a read that does
    happen return "on: push" instead of hanging the test: a tree that reads the
    pipe then lists it as a workflow, which the assertion catches."""
    import threading

    pipe = repo / ".github" / "workflows" / "pipe.yml"
    os.mkfifo(pipe)

    def feed():
        with open(pipe, "w") as writer:
            writer.write("on: push\n")

    writer_thread = threading.Thread(target=feed, daemon=True)
    writer_thread.start()
    try:
        scanner = _scanner(repo)

        with caplog.at_level(logging.WARNING):
            workflows = scanner._workflow_files(repo, "source", [])

        assert workflows == [
            ".github/workflows/clean.yml",
            ".github/workflows/vulnerable.yml",
        ]
        assert "Not linting .github/workflows/pipe.yml" in caplog.text
        assert "not a regular file" in caplog.text
    finally:
        # A scanner that behaves never opens the pipe, which would leave the
        # writer blocked in open() for the rest of the session: open the read
        # end so its open() and write return, and let it finish.
        reader = os.open(pipe, os.O_RDONLY | os.O_NONBLOCK)
        try:
            writer_thread.join(timeout=5)
        finally:
            os.close(reader)
        assert not writer_thread.is_alive()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX execute bit")
@pytest.mark.unit
def test_a_non_executable_integration_path_is_missing(
    repo, monkeypatch, on_path, tmp_path
):
    tool = tmp_path / "operator-bin" / "shellcheck"
    tool.parent.mkdir()
    tool.write_text("not executable\n")
    tool.chmod(0o644)
    assert not os.access(tool, os.X_OK)
    scanner = _scanner(repo, operator=True, shellcheck=tool.as_posix())

    assert scanner.validate_plugin_dependencies() is False
    assert "shellcheck" in scanner.dependency_unavailable_reason


@pytest.mark.parametrize("returncode", [2, 3])
@pytest.mark.unit
def test_a_failing_exit_code_raises_even_with_valid_json(
    repo, monkeypatch, on_path, returncode
):
    scanner = _scanner(repo)
    _run(scanner, monkeypatch, '{"version":"1.7.12","errors":[]}', returncode)

    with pytest.raises(ScannerError, match=f"exited {returncode}"):
        scanner.scan(target=repo, target_type="source")


def _through_the_base_class(monkeypatch, responses: list) -> list:
    """Replace only the process call, one response per run; returns the recorded
    calls (their keyword arguments, ``command`` among them).

    ``_run_subprocess`` and the base class's exit-code accumulation (it keeps the
    worst code across calls) run for real, which ``FakeRun`` bypasses.
    """
    remaining = iter(responses)
    calls: list = []

    def run(**kwargs):
        calls.append(kwargs)
        return next(remaining)

    monkeypatch.setattr(
        "automated_security_helper.utils.subprocess_utils."
        "run_command_with_output_handling",
        run,
    )
    return calls


def _converted_target(output: Path, workflow: Path | None) -> Path:
    """``work_dir`` as the archive converter leaves it, holding *workflow* or not."""
    work_dir = output / "converted"
    extracted = work_dir / "archive.zip"
    extracted.mkdir(parents=True)
    if workflow is None:
        (extracted / "app.py").write_text("print(1)\n")
    else:
        destination = extracted / ".github" / "workflows"
        destination.mkdir(parents=True)
        shutil.copy(workflow, destination / workflow.name)
    return work_dir


@pytest.mark.parametrize("target_type", ["source", "converted"])
@pytest.mark.unit
def test_a_relative_source_or_work_directory_names_existing_workflows(
    repo, tmp_path, monkeypatch, target_type
):
    """ASH is often run with relative directories. The scan set spells its paths
    from the source directory as given, so joining them to the target a second
    time named workflows that do not exist, and actionlint was handed those."""
    output = repo.parent / "ash_output"
    work_dir = _converted_target(output, repo / ".github" / "workflows" / "clean.yml")
    monkeypatch.chdir(tmp_path)
    scanner = _scanner(Path("repo"), output=Path("ash_output"))
    target = Path("repo") if target_type == "source" else Path("ash_output/converted")

    workflows = scanner._workflow_files(target, target_type, [])

    expected = (
        [".github/workflows/clean.yml", ".github/workflows/vulnerable.yml"]
        if target_type == "source"
        else ["archive.zip/.github/workflows/clean.yml"]
    )
    assert workflows == expected
    assert all((target / relative).is_file() for relative in workflows)
    assert work_dir.is_dir()


@pytest.mark.unit
def test_a_converted_finding_carries_an_absolute_uri_under_the_work_dir(
    repo, monkeypatch, on_path
):
    """actionlint runs in the target, so its paths are relative to it. The scan
    reads a relative URI as relative to the source directory, so a converted
    workflow's finding was reported at a source path that does not exist and
    was never marked as converted; a converted file's URI is absolute, names
    the file where it is under the work directory, and that is what marks the
    finding as converted."""
    output = repo.parent / "ash_output"
    work_dir = _converted_target(
        output, repo / ".github" / "workflows" / "vulnerable.yml"
    )
    scanner = _scanner(repo, output=output)
    # actionlint runs in the converted tree, where the extracted archive holds
    # the workflow, so it prints the path the file has there.
    where = "archive.zip/.github/workflows/vulnerable.yml"
    stdout = (FIXTURES / "actionlint-1.7.12-default.json").read_text()
    stdout = stdout.replace('".github/workflows/vulnerable.yml"', f'"{where}"')
    assert where in stdout
    _through_the_base_class(monkeypatch, [{"returncode": 1, "stdout": stdout}])

    converted = scanner.scan(target=work_dir, target_type="converted")

    results = converted.runs[0].results
    uris = {
        result.locations[0].physicalLocation.root.artifactLocation.uri
        for result in results
    }
    expected = work_dir.absolute() / where
    assert uris == {expected.as_posix()}
    assert expected.is_file()
    assert all(Path(uri).is_absolute() and Path(uri).is_file() for uri in uris)
    # The mark the scan output step puts on a finding under the work directory.
    assert mark_converted_results(converted, scanner.context) == len(results) > 0
    assert {getattr(r.properties, "converted_path") for r in results} == {where}


@pytest.mark.parametrize("converted_has_workflows", [True, False])
@pytest.mark.unit
def test_each_target_starts_from_a_clean_exit_code(
    repo, monkeypatch, on_path, converted_has_workflows
):
    """ScannerExecutor runs one instance over the source, then the converted target.

    A source with findings exits 1. A clean converted target after it must report
    its own exit 0, not fail as "exited 1 but reported none".
    """
    output = repo.parent / "ash_output"
    work_dir = _converted_target(
        output,
        repo / ".github" / "workflows" / "clean.yml"
        if converted_has_workflows
        else None,
    )
    scanner = _scanner(repo, output=output)
    _through_the_base_class(
        monkeypatch,
        [
            {
                "returncode": 1,
                "stdout": (FIXTURES / "actionlint-1.7.12-default.json").read_text(),
            },
            {
                "returncode": 0,
                "stdout": (FIXTURES / "actionlint-1.7.12-clean.json").read_text(),
            },
        ],
    )

    source = scanner.scan(target=repo, target_type="source")
    assert len(source.runs[0].results) == len(EXPECTED_DEFAULT)
    assert scanner.exit_code == 1

    converted = scanner.scan(target=work_dir, target_type="converted")

    assert scanner.exit_code == 0
    assert scanner.targets_failed == 0
    if converted_has_workflows:
        assert converted.runs[0].results == []
        assert converted.runs[0].invocations[0].exitCode == 0
    else:
        assert converted is True


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks")
@pytest.mark.unit
def test_an_early_return_does_not_keep_the_previous_targets_not_scanned_inputs(
    repo, tmp_path, monkeypatch, on_path
):
    """One instance scans the source target and then the converted one. The
    source run refused a workflow (a link out of the tree) and recorded it as
    an input not scanned; the converted run returns before it selects any
    workflow (an empty work directory), and must not carry the source's refused
    workflow into its own record."""
    outside = tmp_path / "outside.yml"
    outside.write_text("on: push\n")
    (repo / ".github" / "workflows" / "leak.yml").symlink_to(outside)
    scanner = _scanner(repo)
    _run(scanner, monkeypatch, _EMPTY_RUN, 0)

    scanner.scan(target=repo, target_type="source")
    assert [entry["path"] for entry in scanner.inputs_not_scanned] == [
        ".github/workflows/leak.yml"
    ]

    empty = tmp_path / "empty-work-dir"
    empty.mkdir()
    assert scanner.scan(target=empty, target_type="converted") is True

    assert scanner.inputs_not_scanned == []


@pytest.mark.unit
def test_a_failure_after_the_redaction_keeps_the_redacted_output(
    repo, monkeypatch, on_path
):
    """The redacted payload replaces the raw record lines once every run is
    parsed. A failure after that (here the invocation record) must leave it in
    place, not overwrite it with a note saying the scan failed before the output
    could be redacted, which would be false and would lose the output."""
    scanner = _scanner(repo)
    stdout = (FIXTURES / "actionlint-1.7.12-default.json").read_text()
    assert "hunter2" in stdout
    _through_the_base_class(monkeypatch, [{"returncode": 1, "stdout": stdout}])

    def fail(*_args, **_kwargs):
        raise RuntimeError("the invocation record could not be built")

    monkeypatch.setattr(scanner, "_inject_invocation", fail)

    with pytest.raises(ScannerError):
        scanner.scan(target=repo, target_type="source")

    record = "\n".join(scanner.output)
    assert "hunter2" not in record
    assert "before the output could be redacted" not in record
    assert any('"errors"' in line for line in scanner.output)


@pytest.mark.unit
def test_a_credentials_finding_does_not_copy_the_password_into_the_report():
    sarif = build_sarif(_load("actionlint-1.7.12-default.json"), exit_code=1)
    credentials = sarif["runs"][0]["results"][0]
    assert credentials["ruleId"] == "credentials"
    region = credentials["locations"][0]["physicalLocation"]["region"]
    assert "snippet" not in region
    assert "hunter2" not in json.dumps(sarif)


@pytest.mark.unit
def test_the_password_never_stays_in_the_plugins_record_lines(
    repo, monkeypatch, on_path
):
    """The run's stdout becomes the plugin's record lines, which are persisted
    with the results when a later scan of this scanner fails. The lines must hold
    the redacted payload, as actionlint.json does, not the raw stdout with the
    hard-coded password a credentials finding quotes."""
    stdout = (FIXTURES / "actionlint-1.7.12-default.json").read_text()
    assert "hunter2" in stdout
    scanner = _scanner(repo)
    _through_the_base_class(monkeypatch, [{"returncode": 1, "stdout": stdout}])

    report = scanner.scan(target=repo, target_type="source")

    assert len(report.runs[0].results) == len(EXPECTED_DEFAULT)
    record = "\n".join(scanner.output)
    assert "hunter2" not in record
    assert '"kind": "credentials"' in record


@pytest.mark.unit
def test_a_credentials_finding_is_a_secret_finding_for_masking():
    """The finding reports a password on that line, so ASH's masking has to treat
    it as a secret finding: another scanner's snippet of the same line is then
    masked. Decided by the tags on the result and its rule, as for trivy's."""
    from automated_security_helper.utils.secret_masking import (
        is_secret_finding,
        secret_rule_ids,
    )

    report = SarifReport.model_validate(
        build_sarif(_load("actionlint-1.7.12-default.json"), exit_code=1)
    )
    credentials, *others = report.runs[0].results

    assert credentials.ruleId == "credentials"
    assert is_secret_finding(credentials) is True
    assert secret_rule_ids(report) == {"credentials"}
    assert all(is_secret_finding(result) is False for result in others)


@pytest.mark.unit
def test_a_version_other_than_the_pin_is_warned_about(
    repo, monkeypatch, on_path, caplog
):
    scanner = _scanner(repo)
    _run(scanner, monkeypatch, '{"version":"1.6.0","errors":[]}', 0)

    with caplog.at_level(logging.WARNING):
        scanner.scan(target=repo, target_type="source")

    assert any("not the pinned v1.7.12" in r.getMessage() for r in caplog.records)


@pytest.mark.unit
def test_the_pinned_version_is_not_warned_about(repo, monkeypatch, on_path, caplog):
    scanner = _scanner(repo)
    _run(scanner, monkeypatch, '{"version":"1.7.12","errors":[]}', 0)

    with caplog.at_level(logging.WARNING):
        scanner.scan(target=repo, target_type="source")

    assert not any("not the pinned" in r.getMessage() for r in caplog.records)


@pytest.mark.unit
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


# --------------------------------------------------------------------------- #
# shellcheck and pyflakes name the program actionlint pipes run: scripts to.
# The scanned tree's config may only turn them on by their own names.
# --------------------------------------------------------------------------- #

_EMPTY_RUN = '{"version":"1.7.12","errors":[]}'


def _plant(directory: Path, name: str = "planted") -> Path:
    """An executable that would leave a marker beside itself if anything ran it."""
    directory.mkdir(parents=True, exist_ok=True)
    tool = directory / name
    tool.write_text(f"#!/bin/sh\ntouch '{directory / (name + '.ran')}'\n")
    tool.chmod(0o755)
    return tool


def _argv(scanner, monkeypatch, repo) -> list:
    fake = _run(scanner, monkeypatch, _EMPTY_RUN, 0)
    scanner.scan(target=repo, target_type="source")
    ((argv, _),) = fake.calls
    return argv


@pytest.mark.parametrize("flag", ["shellcheck", "pyflakes"])
@pytest.mark.parametrize("value", ["sh", "bash", "python3", "env"])
@pytest.mark.unit
def test_the_scanned_tree_cannot_choose_another_program_by_name(
    repo, monkeypatch, caplog, flag, value
):
    looked_up = []

    def find(name):
        looked_up.append(name)
        return FAKE_ACTIONLINT if name == "actionlint" else f"/usr/bin/{name}"

    monkeypatch.setattr(module, "find_absolute_executable", find)
    scanner = _scanner(repo, **{flag: value})

    with caplog.at_level(logging.WARNING):
        argv = _argv(scanner, monkeypatch, repo)

    assert [arg for arg in argv if arg.startswith(f"-{flag}=")] == [f"-{flag}="]
    assert f"/usr/bin/{value}" not in " ".join(argv)
    assert value not in looked_up
    assert f"scanners.actionlint.options.{flag}" in caplog.text


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX execute bit")
@pytest.mark.parametrize("spelling", ["absolute", "relative", "dot-relative"])
@pytest.mark.unit
def test_the_scanned_tree_cannot_point_an_integration_at_its_own_file(
    repo, monkeypatch, on_path, spelling
):
    tool = _plant(repo / "tools")
    value = {
        "absolute": tool.as_posix(),
        "relative": "tools/planted",
        "dot-relative": "./tools/planted",
    }[spelling]
    scanner = _scanner(repo, shellcheck=value)

    argv = _argv(scanner, monkeypatch, repo)

    assert "-shellcheck=" in argv
    assert not any("planted" in arg for arg in argv)
    assert not (repo / "tools" / "planted.ran").exists()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX execute bit")
@pytest.mark.unit
def test_the_operator_cannot_point_an_integration_inside_the_scanned_tree(
    repo, monkeypatch, on_path
):
    tool = _plant(repo / "tools")
    scanner = _scanner(repo, operator=True, shellcheck=tool.as_posix())

    argv = _argv(scanner, monkeypatch, repo)

    assert "-shellcheck=" in argv
    assert not any("planted" in arg for arg in argv)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX execute bit and symlinks")
@pytest.mark.parametrize("flag", ["shellcheck", "pyflakes"])
@pytest.mark.parametrize("shape", ["file", "directory"])
@pytest.mark.unit
def test_the_operator_cannot_name_a_path_in_the_tree_that_links_out_of_it(
    repo, monkeypatch, on_path, caplog, flag, shape
):
    """A path written inside the scanned tree goes where the tree's links send it,
    so the tree would choose the program actionlint pipes every run: script to
    (a link to /bin/sh would execute them). The integration stays off."""
    tool = _plant(repo.parent / "outside")
    if shape == "file":
        (repo / "tools").mkdir()
        (repo / "tools" / flag).symlink_to(tool)
        value = f"tools/{flag}"
    else:
        (repo / "tools").symlink_to(tool.parent, target_is_directory=True)
        value = f"tools/{tool.name}"
    scanner = _scanner(repo, operator=True, **{flag: value})

    with caplog.at_level(logging.WARNING):
        argv = _argv(scanner, monkeypatch, repo)

    assert f"-{flag}=" in argv
    assert tool.as_posix() not in " ".join(argv)
    assert f"Ignoring scanners.actionlint.options.{flag}" in caplog.text
    assert "symbolic link" in caplog.text


@pytest.mark.unit
def test_a_name_that_resolves_inside_the_scanned_tree_is_refused(repo, monkeypatch):
    # A relative PATH entry such as "." finds a file the repository committed.
    inside = (repo / "shellcheck").as_posix()
    monkeypatch.setattr(
        module,
        "find_absolute_executable",
        lambda name: FAKE_ACTIONLINT if name == "actionlint" else inside,
    )
    scanner = _scanner(repo, shellcheck="shellcheck")

    argv = _argv(scanner, monkeypatch, repo)

    assert "-shellcheck=" in argv
    assert inside not in " ".join(argv)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX execute bit and symlinks")
@pytest.mark.unit
def test_a_name_found_through_a_link_in_the_scanned_tree_is_refused(repo, monkeypatch):
    """An absolute PATH entry inside the tree that is a link out of it: the name
    is found at <tree>/bin/shellcheck, which resolves outside the tree, but the
    tree's link chose the program."""
    tool = _plant(repo.parent / "elsewhere", "shellcheck")
    (repo / "bin").symlink_to(tool.parent, target_is_directory=True)
    found = (repo / "bin" / "shellcheck").as_posix()
    monkeypatch.setattr(
        module,
        "find_absolute_executable",
        lambda name: FAKE_ACTIONLINT if name == "actionlint" else found,
    )
    scanner = _scanner(repo, shellcheck="shellcheck")

    argv = _argv(scanner, monkeypatch, repo)

    assert "-shellcheck=" in argv
    assert found not in " ".join(argv) and tool.as_posix() not in " ".join(argv)


def _only_path(monkeypatch, *entries) -> None:
    """PATH is exactly ``entries``, nothing is cached and ASH's bin dirs are empty."""
    monkeypatch.setenv("PATH", os.pathsep.join(str(entry) for entry in entries))
    monkeypatch.setattr(subprocess_utils, "_find_executable_cache", {})
    monkeypatch.setattr(subprocess_utils, "path_independent_dirs", list)
    monkeypatch.setattr(module, "path_independent_dirs", list, raising=False)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX execute bit")
@pytest.mark.parametrize("flag", ["shellcheck", "pyflakes"])
@pytest.mark.unit
def test_a_relative_path_entry_never_chooses_an_integration(
    repo, tmp_path, monkeypatch, flag
):
    """A relative PATH entry is relative to the working directory: ASH's when it
    looks, the scan target when actionlint starts the program. So it is skipped,
    and actionlint is handed the absolute path ASH checked."""
    elsewhere = tmp_path / "elsewhere"
    _plant(elsewhere / "bin", flag)
    _plant(repo / "bin", flag)
    absolute = _plant(tmp_path / "abs-bin", flag)
    _plant(tmp_path / "abs-bin", "actionlint")
    monkeypatch.chdir(elsewhere)
    _only_path(monkeypatch, "bin", tmp_path / "abs-bin")
    scanner = _scanner(repo, **{flag: flag})

    argv = _argv(scanner, monkeypatch, repo)

    assert f"-{flag}={absolute.as_posix()}" in argv


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX execute bit")
@pytest.mark.parametrize("name", ["actionlint", "shellcheck"])
@pytest.mark.unit
def test_a_copy_inside_the_scanned_tree_is_passed_over_for_the_next_one(
    repo, tmp_path, monkeypatch, name
):
    """An in-repo bin directory first on PATH (a .venv/bin under `uv run`, a
    committed tools directory) must not be the copy ASH checks: the spawn guard
    refuses it and the scan would read ERROR although a usable copy exists later
    on PATH. The lookup is ASH's own, which passes over the tree's copy."""
    _plant(repo / "bin", name)
    usable = _plant(tmp_path / "abs-bin", name)
    _only_path(monkeypatch, repo / "bin", tmp_path / "abs-bin")

    with subprocess_utils.scanning_tree(repo):
        found = module.find_absolute_executable(name)

    assert found == usable.as_posix()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX execute bit")
@pytest.mark.unit
def test_actionlint_found_only_inside_the_scanned_tree_is_missing(
    repo, tmp_path, monkeypatch
):
    """With no copy anywhere else, the tree's copy is not used either: the scanner
    reports MISSING, as the spawn guard would have refused the copy."""
    _plant(repo / "bin", "actionlint")
    _only_path(monkeypatch, repo / "bin")
    scanner = _scanner(repo)

    with subprocess_utils.scanning_tree(repo):
        satisfied = scanner.validate_plugin_dependencies()

    assert satisfied is False
    assert scanner._executable is None


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX execute bit")
@pytest.mark.unit
def test_an_integration_reachable_only_through_a_relative_path_entry_is_missing(
    repo, tmp_path, monkeypatch
):
    elsewhere = tmp_path / "elsewhere"
    _plant(elsewhere / "bin", "shellcheck")
    _plant(tmp_path / "abs-bin", "actionlint")
    monkeypatch.chdir(elsewhere)
    _only_path(monkeypatch, "bin", tmp_path / "abs-bin")
    scanner = _scanner(repo, shellcheck="shellcheck")

    assert scanner.validate_plugin_dependencies() is False
    assert "shellcheck" in scanner.dependency_unavailable_reason


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX shebang scripts")
@pytest.mark.integration
def test_actionlint_itself_is_started_by_its_absolute_path(repo, tmp_path, monkeypatch):
    """actionlint runs from the scan target. Started by a path a relative PATH entry
    produced, it would be the repository's own ``bin/actionlint``."""
    elsewhere = tmp_path / "elsewhere"
    _plant(elsewhere / "bin", "actionlint")
    marker = repo / "bin" / "actionlint.ran"
    planted = repo / "bin" / "actionlint"
    planted.parent.mkdir()
    # A shell builtin, so the script works with a PATH that has no /usr/bin.
    planted.write_text(f"#!/bin/sh\n: > '{marker}'\n")
    planted.chmod(0o755)
    real = tmp_path / "abs-bin" / "actionlint"
    real.parent.mkdir()
    real.write_text(f"#!/bin/sh\necho '{_EMPTY_RUN}'\n")
    real.chmod(0o755)
    monkeypatch.chdir(elsewhere)
    _only_path(monkeypatch, "bin", tmp_path / "abs-bin")
    scanner = _scanner(repo)

    report = scanner.scan(target=repo, target_type="source")

    assert not marker.exists()
    assert report.runs[0].invocations[0].executionSuccessful is True


@pytest.mark.unit
def test_the_scanned_tree_may_turn_shellcheck_on_by_its_own_name(repo, monkeypatch):
    monkeypatch.setattr(
        module, "find_absolute_executable", lambda name: f"/opt/bin/{name}"
    )
    scanner = _scanner(repo, shellcheck="shellcheck", pyflakes="pyflakes")

    argv = _argv(scanner, monkeypatch, repo)

    assert "-shellcheck=/opt/bin/shellcheck" in argv
    assert "-pyflakes=/opt/bin/pyflakes" in argv


@pytest.mark.unit
def test_an_operator_override_may_name_another_program(repo, monkeypatch):
    monkeypatch.setattr(
        module, "find_absolute_executable", lambda name: f"/opt/bin/{name}"
    )
    scanner = _scanner(
        repo,
        overrides=("scanners.actionlint.options.shellcheck=shellcheck-0.10",),
        shellcheck="shellcheck-0.10",
    )

    argv = _argv(scanner, monkeypatch, repo)

    assert "-shellcheck=/opt/bin/shellcheck-0.10" in argv


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX execute bit")
@pytest.mark.unit
def test_an_operator_config_may_name_an_absolute_path_outside_the_tree(
    repo, monkeypatch, on_path, tmp_path
):
    tool = _plant(tmp_path / "operator-bin", "shellcheck")
    scanner = _scanner(repo, operator=True, shellcheck=tool.as_posix())

    argv = _argv(scanner, monkeypatch, repo)

    assert f"-shellcheck={tool.as_posix()}" in argv


@pytest.mark.unit
def test_an_override_of_another_option_does_not_vouch_for_shellcheck(
    repo, monkeypatch, on_path
):
    scanner = _scanner(
        repo,
        overrides=("scanners.actionlint.options.pyflakes=pyflakes",),
        shellcheck="sh",
    )

    argv = _argv(scanner, monkeypatch, repo)

    assert "-shellcheck=" in argv


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX execute bit")
@pytest.mark.unit
def test_the_scanned_tree_cannot_name_an_absolute_program_outside_it(
    repo, monkeypatch, on_path, tmp_path
):
    """The operator rule on its own: outside the tree, but the tree's config chose it."""
    tool = _plant(tmp_path / "elsewhere", "shellcheck")
    scanner = _scanner(repo, shellcheck=tool.as_posix())

    argv = _argv(scanner, monkeypatch, repo)

    assert "-shellcheck=" in argv
    assert tool.as_posix() not in " ".join(argv)


# --------------------------------------------------------------------------- #
# Which files: the workflows zizmor audits, no more and no fewer
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "vendored", ["node_modules/pkg", "web/node_modules/pkg", ".venv/lib", "venv"]
)
@pytest.mark.unit
def test_workflows_under_vendored_directories_are_not_passed(
    repo, monkeypatch, on_path, vendored
):
    """KNOWN_IGNORE_PATHS, as zizmor applies it: the repository does not own these."""
    nested = repo / vendored / ".github" / "workflows"
    nested.mkdir(parents=True)
    shutil.copy(repo / ".github" / "workflows" / "vulnerable.yml", nested / "v.yml")
    scanner = _scanner(repo)
    fake = _run(scanner, monkeypatch, _EMPTY_RUN, 0)

    scanner.scan(target=repo, target_type="source")

    ((argv, _),) = fake.calls
    assert argv[argv.index("--") + 1 :] == [
        ".github/workflows/clean.yml",
        ".github/workflows/vulnerable.yml",
    ]


@pytest.mark.parametrize("source_dir", [".github", ".github/workflows"])
@pytest.mark.unit
def test_a_source_dir_that_is_a_github_or_workflows_dir_is_linted(
    repo, monkeypatch, on_path, source_dir
):
    """``<source>/workflows/ci.yml`` with the source dir ``.github`` is a file whose
    parent directory is ``.github/workflows``, which is what the scanner lints."""
    source = repo / source_dir
    scanner = _scanner(source, output=repo.parent / "ash_output")
    fake = _run(scanner, monkeypatch, _EMPTY_RUN, 0)

    scanner.scan(target=source, target_type="source")

    ((argv, kwargs),) = fake.calls
    prefix = "workflows/" if source_dir == ".github" else ""
    assert argv[argv.index("--") + 1 :] == [
        f"{prefix}clean.yml",
        f"{prefix}vulnerable.yml",
    ]
    assert kwargs["cwd"] == source


@pytest.mark.parametrize(
    ("relative", "scan_root", "expected"),
    [
        ("workflows/ci.yml", "/r/.github", True),
        ("ci.yml", "/r/.github/workflows", True),
        ("sub/ci.yml", "/r/.github/workflows", False),
        ("workflows/ci.yml", "/r/github", False),
        ("ci.yml", "/r/.github", False),
        ("workflows/ci.yml", None, False),
        (".github/workflows/ci.yml", "/r/anything", True),
    ],
)
@pytest.mark.unit
def test_is_workflow_file_counts_the_scan_roots_own_name(relative, scan_root, expected):
    root = None if scan_root is None else Path(scan_root)
    assert is_workflow_file(relative, scan_root=root) is expected


_PARITY_LAYOUT = [
    ".github/workflows/ci.yml",
    ".github/workflows/release.YAML",
    ".github/workflows/sub/nested.yml",
    "svc/.github/workflows/deploy.yaml",
    "node_modules/pkg/.github/workflows/v.yml",
    "web/node_modules/pkg/.github/workflows/v.yml",
    ".venv/lib/.github/workflows/v.yml",
    "venv/.github/workflows/v.yml",
    "ignored/.github/workflows/v.yml",
    "config/not-a-workflow.yml",
    "actions/greet/action.yml",
]


@pytest.mark.parametrize(
    ("target_name", "expected"),
    [
        (
            "source",
            [".github/workflows/ci.yml", "svc/.github/workflows/deploy.yaml"],
        ),
        ("source/.github", ["workflows/ci.yml"]),
        ("source/.github/workflows", ["ci.yml"]),
        (
            "converted",
            [
                "archive.zip/.github/workflows/ci.yml",
                "archive.zip/ignored/.github/workflows/v.yml",
                "archive.zip/svc/.github/workflows/deploy.yaml",
            ],
        ),
    ],
)
@pytest.mark.unit
def test_actionlint_lints_exactly_the_workflows_zizmor_audits(
    tmp_path, monkeypatch, on_path, target_name, expected
):
    """Both scanners select workflows from the same tree the same way.

    zizmor also audits composite actions, which actionlint does not lint, so its
    ``action.yml`` inputs are left out of the comparison. ``ignored/`` is in the
    source's ``.gitignore``, which the converted files (not from the scan set) do
    not read. ``release.YAML`` is in the layout and selected by neither: both tools
    and GitHub read the suffix as spelled.
    """
    from automated_security_helper.plugin_modules.ash_builtin.scanners.zizmor_scanner import (
        ZizmorScanner,
        ZizmorScannerConfig,
    )

    monkeypatch.setattr(
        ZizmorScanner, "_get_uv_tool_version", lambda self, *_: "1.30.1"
    )
    repo_root = tmp_path / "source"
    output = tmp_path / "ash_output"
    work_dir = output / "converted"
    for base in (repo_root, work_dir / "archive.zip"):
        for relative in _PARITY_LAYOUT:
            (base / relative).parent.mkdir(parents=True, exist_ok=True)
            (base / relative).write_text("on: push\n")
    (repo_root / ".gitignore").write_text("ignored/\n")
    if target_name == "converted":
        target, target_type, source = work_dir, "converted", repo_root
    else:
        target = tmp_path / target_name
        target_type, source = "source", target
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=work_dir,
        config=get_default_config(),
    )
    actionlint = ActionlintScanner(context=context, config=ActionlintScannerConfig())
    zizmor = ZizmorScanner(context=context, config=ZizmorScannerConfig())

    linted = actionlint._workflow_files(target, target_type, [])
    audited = [
        path.relative_to(target.absolute()).as_posix()
        for path in zizmor._collect_inputs(target, target_type, [])
        if path.name.lower() not in ("action.yml", "action.yaml")
    ]

    assert linted == expected
    assert sorted(audited) == linted


# --------------------------------------------------------------------------- #
# Local ``uses: ./...`` references: actionlint reads the action metadata or the
# reusable workflow they name, from the project root, and puts what it read (the
# action's name, its input names) into its findings.
# --------------------------------------------------------------------------- #

_OUTSIDE_ACTION = (
    "name: outside\ndescription: x\ninputs:\n  leaked:\n    description: x\n"
    "runs:\n  using: composite\n  steps: []\n"
)
_OUTSIDE_REUSABLE = (
    "on:\n  workflow_call:\n    inputs:\n      leaked:\n        type: string\n"
    "jobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
)


def _step_uses(spec: str) -> str:
    return (
        "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
        f"      - uses: {spec}\n"
    )


def _job_uses(spec: str) -> str:
    return f"on: push\njobs:\n  a:\n    uses: {spec}\n"


def _local_reference_layout(repo: Path, outside: Path, case: str) -> None:
    """``.github/workflows/refs.yml`` naming a file outside the tree, by ``case``."""
    (repo / ".git").mkdir()
    (outside / "action").mkdir(parents=True)
    (outside / "action" / "action.yml").write_text(_OUTSIDE_ACTION)
    (outside / "reusable.yml").write_text(_OUTSIDE_REUSABLE)
    actions = repo / ".github" / "actions"
    actions.mkdir()
    workflows = repo / ".github" / "workflows"
    if case == "linked-action-dir":
        (actions / "linked").symlink_to(outside / "action")
        body = _step_uses("./.github/actions/linked")
    elif case == "linked-action-file":
        (actions / "linked").mkdir()
        (actions / "linked" / "action.yml").symlink_to(
            outside / "action" / "action.yml"
        )
        body = _step_uses("./.github/actions/linked")
    elif case == "dot-dot-action":
        body = _step_uses("./../outside/action")
    elif case == "linked-reusable":
        (workflows / "linked.yml").symlink_to(outside / "reusable.yml")
        body = _job_uses("./.github/workflows/linked.yml")
    elif case == "dot-dot-reusable":
        body = _job_uses("./../outside/reusable.yml")
    elif case == "flow-mapping":
        body = (
            "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
            '    steps: [{"uses": "./../outside/action"}]\n'
        )
    else:
        raise AssertionError(case)
    (workflows / "refs.yml").write_text(body)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks")
@pytest.mark.parametrize(
    "case",
    [
        "linked-action-dir",
        "linked-action-file",
        "dot-dot-action",
        "linked-reusable",
        "dot-dot-reusable",
        "flow-mapping",
    ],
)
@pytest.mark.unit
def test_a_workflow_whose_local_reference_leaves_the_tree_is_not_linted(
    repo, tmp_path, monkeypatch, on_path, caplog, case
):
    _local_reference_layout(repo, tmp_path / "outside", case)
    scanner = _scanner(repo)
    fake = _run(scanner, monkeypatch, _EMPTY_RUN, 0)

    with caplog.at_level(logging.WARNING):
        scanner.scan(target=repo, target_type="source")

    ((argv, _),) = fake.calls
    assert argv[argv.index("--") + 1 :] == [
        ".github/workflows/clean.yml",
        ".github/workflows/vulnerable.yml",
    ]
    assert "Not linting .github/workflows/refs.yml" in caplog.text
    assert "outside the scanned tree" in caplog.text


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks")
@pytest.mark.parametrize(
    ("link_target", "spec", "linted"),
    [
        # The link points inside the tree; ".." after it leaves the tree
        # lexically, which is where actionlint reads.
        ("inside", "./.github/actions/linked/../../../../outside/action", False),
        # The link points outside the tree; ".." after it comes back inside
        # lexically, so actionlint reads a file of the tree.
        ("outside", "./.github/actions/linked/../inside", True),
    ],
    ids=["link-in-dotdot-out", "link-out-dotdot-in"],
)
@pytest.mark.unit
def test_a_reference_through_a_link_is_judged_where_actionlint_reads_it(
    repo, tmp_path, monkeypatch, on_path, link_target, spec, linted
):
    """actionlint joins "uses: ./..." to its root lexically, so ".." is taken
    before any link is followed. Resolving the link first judged the wrong file:
    inside when actionlint reads outside, and the reverse."""
    (repo / ".git").mkdir()
    outside = tmp_path / "outside" / "action"
    outside.mkdir(parents=True)
    (outside / "action.yml").write_text(_OUTSIDE_ACTION)
    # What following the outside link first and then taking ".." reaches: a
    # real action outside the tree, so a scanner that resolved the link first
    # would refuse the workflow instead of reading a reference that names
    # nothing as harmless, and the two readings give different answers.
    (tmp_path / "outside" / "inside").mkdir()
    (tmp_path / "outside" / "inside" / "action.yml").write_text(_OUTSIDE_ACTION)
    actions = repo / ".github" / "actions"
    for name in ("inside", "deep/real"):
        (actions / name).mkdir(parents=True)
        (actions / name / "action.yml").write_text(_OUTSIDE_ACTION)
    (actions / "linked").symlink_to(
        actions / "deep" / "real" if link_target == "inside" else outside
    )
    (repo / ".github" / "workflows" / "refs.yml").write_text(_step_uses(spec))
    scanner = _scanner(repo)
    fake = _run(scanner, monkeypatch, _EMPTY_RUN, 0)

    scanner.scan(target=repo, target_type="source")

    ((argv, _),) = fake.calls
    assert (".github/workflows/refs.yml" in argv[argv.index("--") + 1 :]) is linted


@pytest.mark.unit
def test_a_local_reference_holding_a_nul_does_not_fail_the_scan(
    repo, monkeypatch, on_path
):
    """A YAML escape can put a NUL into a "uses:" value. No operating system
    opens such a path, so it names no file; os.path.realpath raises ValueError
    on it, which used to escape the workflow selection and fail the whole scan
    before actionlint ran."""
    (repo / ".git").mkdir()
    (repo / ".github" / "workflows" / "refs.yml").write_text(
        "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
        '      - uses: "./.github/actions/a\\0b"\n'
    )
    scanner = _scanner(repo)
    fake = _run(scanner, monkeypatch, _EMPTY_RUN, 0)

    scanner.scan(target=repo, target_type="source")

    ((argv, _),) = fake.calls
    assert ".github/workflows/refs.yml" in argv[argv.index("--") + 1 :]


@pytest.mark.unit
def test_a_local_reference_holding_a_lone_surrogate_does_not_fail_the_scan(
    repo, monkeypatch, on_path
):
    """A "\\ud800" escape puts a lone surrogate into the value. The operating
    system takes no path from it (the encoder refuses it), so os.path.realpath
    raises a ValueError that is no OSError; the first candidate has no exists()
    guard in front of it, so the error escaped the workflow selection and failed
    the whole scan. The value names no file, so the workflow is linted."""
    (repo / ".git").mkdir()
    (repo / ".github" / "workflows" / "refs.yml").write_text(
        "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
        '      - uses: "./.github/actions/\\ud800"\n'
    )
    scanner = _scanner(repo)
    fake = _run(scanner, monkeypatch, _EMPTY_RUN, 0)

    scanner.scan(target=repo, target_type="source")

    ((argv, _),) = fake.calls
    assert ".github/workflows/refs.yml" in argv[argv.index("--") + 1 :]


@pytest.mark.parametrize("encoding", ["utf-16", "utf-16-be", "utf-8-sig"])
@pytest.mark.unit
def test_a_workflow_with_a_byte_order_mark_is_read_as_actionlint_reads_it(
    repo, tmp_path, monkeypatch, on_path, caplog, encoding
):
    """actionlint's YAML parser decodes a UTF-16 file by its byte-order mark and
    follows the local reference it holds; read as UTF-8 the file held no
    reference at all and was linted unchecked."""
    _local_reference_layout(repo, tmp_path / "outside", "dot-dot-action")
    refs = repo / ".github" / "workflows" / "refs.yml"
    body = refs.read_text()
    # "utf-16" and "utf-8-sig" write their mark; "utf-16-be" does not.
    mark = codecs.BOM_UTF16_BE if encoding == "utf-16-be" else b""
    refs.write_bytes(mark + body.encode(encoding))
    assert module.decode_workflow(refs.read_bytes()) == body
    scanner = _scanner(repo)
    fake = _run(scanner, monkeypatch, _EMPTY_RUN, 0)

    with caplog.at_level(logging.WARNING):
        scanner.scan(target=repo, target_type="source")

    ((argv, _),) = fake.calls
    assert ".github/workflows/refs.yml" not in argv
    assert "Not linting .github/workflows/refs.yml" in caplog.text


@pytest.mark.parametrize(
    "body",
    [
        _step_uses("./.github/actions/inside"),
        _step_uses("./"),
        _job_uses("./.github/workflows/clean.yml"),
        _step_uses("actions/checkout@v4"),
        _step_uses("./${{ matrix.dir }}"),
    ],
    ids=["in-tree-action", "root-action", "in-tree-reusable", "remote", "expression"],
)
@pytest.mark.unit
def test_a_workflow_whose_local_references_stay_in_the_tree_is_linted(
    repo, monkeypatch, on_path, body
):
    (repo / ".git").mkdir()
    inside = repo / ".github" / "actions" / "inside"
    inside.mkdir(parents=True)
    (inside / "action.yml").write_text(_OUTSIDE_ACTION)
    (repo / ".github" / "workflows" / "refs.yml").write_text(body)
    scanner = _scanner(repo)
    fake = _run(scanner, monkeypatch, _EMPTY_RUN, 0)

    scanner.scan(target=repo, target_type="source")

    ((argv, _),) = fake.calls
    assert ".github/workflows/refs.yml" in argv[argv.index("--") + 1 :]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("jobs:\n  a:\n    steps:\n      - uses: ./a\n", {"./a"}),
        ('steps:\n  - "uses": "./b"\n', {"./b"}),
        ('steps: [{uses: ./c}, {"uses": "./d"}]\n', {"./c", "./d"}),
        ("steps:\n  - uses: >-\n      ./e\n", {"./e"}),
        ("x: &A ./f\nsteps:\n  - uses: *A\n", {"./f"}),
        ("base: &B {uses: ./g}\nsteps:\n  - <<: *B\n", {"./g"}),
        ("steps:\n  - uses: ./h\n  bad: [\n", {"./h"}),
        ("steps:\n  - uses: ./i # a comment\n", {"./i"}),
        ("steps:\n  - uses: actions/checkout@v4\n", set()),
        ("steps:\n  - uses: ./${{ matrix.dir }}\n", set()),
        ("steps:\n  - run: ./build.sh\n", set()),
        # The line scan is the fallback when PyYAML cannot read the file at all,
        # so it has to read a quoted value whole and decode its escapes, as
        # actionlint's parser does: a space, a comma, a bracket or a "#" inside
        # the quotes does not end the value.
        ('steps:\n  - uses: "./my action/x" # c\n  bad: [\n', {"./my action/x"}),
        ("steps:\n  - uses: './b, c]#d'\n  bad: [\n", {"./b, c]#d"}),
        ('steps:\n  - uses: "./a\\u0041\\x42"\n  bad: [\n', {"./aAB"}),
        ("steps:\n  - uses: 'it''s/../x'\n  bad: [\n", set()),
        # actionlint reads workflow keys case-insensitively.
        ("steps:\n  - Uses: ./k\n  bad: [\n", {"./k"}),
        ("x: &A ./f\nsteps:\n  - USES: *A\n", {"./f"}),
        # A later document that fails to compose must not lose the ones before
        # it; the folded value is found by the walk alone.
        ("steps:\n  - uses: >-\n      ./n\n---\nbad: [\n", {"./n"}),
        # An escape outside Unicode: PyYAML's scanner lets chr() raise, not a
        # YAMLError, on both the composed walk and the line scan's decode (an
        # OverflowError here, past the C int; a ValueError past 0x10FFFF). go-yaml
        # rejects the escape too, so actionlint reads nothing through it.
        ('steps:\n  - uses: "./\\UFFFFFFFF"\n', set()),
        ('steps:\n  - uses: "./\\UFFFFFFFF"\n  bad: [\n', set()),
        # Three more shapes actionlint's parser reads that the line scan has to
        # read too when PyYAML cannot compose the file: an escaped line break in
        # a double-quoted value joins the lines; a plain value in block style
        # runs to the comment or the end of the line, spaces included (the cut
        # at the space is kept as a second candidate, since the scan cannot tell
        # block from flow); a single-quoted value may span lines, folded.
        ('steps:\n  - uses: "./a\\\n      b"\n  bad: [\n', {"./ab"}),
        ("steps:\n  - uses: ./my dir/act\n  bad: [\n", {"./my", "./my dir/act"}),
        ("steps:\n  - uses: './a\n      b'\n  bad: [\n", {"./a b"}),
        # With the walk gone (the document does not compose), the line scan
        # reads a value on the line after its key, and one behind a tag.
        ("steps:\n  - uses:\n      ./m\n  bad: [\n", {"./m"}),
        ("steps:\n  - uses: !!str ./t\n  bad: [\n", {"./t"}),
        # With the walk gone, two keys on one flow line are both read: the plain
        # value is cut at the separator, so the scan goes on to the next key.
        ('steps: [{uses: ./c}, {"uses": "./d"}]\nbad: [\n', {"./c", "./d"}),
        # A next-line value under a flow opener on the line ABOVE is judged by its
        # own line, so the block-style reading (to the end of the line) applies.
        (
            "x: [1]\nsteps:\n  - uses:\n      ./my dir/act\n  bad: [\n",
            {"./my", "./my dir/act"},
        ),
    ],
    ids=[
        "block",
        "quoted-key",
        "flow",
        "folded",
        "alias",
        "merge-key",
        "invalid-yaml",
        "comment",
        "remote",
        "expression",
        "not-uses",
        "double-quoted-space",
        "single-quoted-punctuation",
        "double-quoted-escapes",
        "single-quoted-not-local",
        "capitalized-key",
        "upper-key-alias",
        "later-document-fails",
        "escape-outside-unicode",
        "escape-outside-unicode-line-scan",
        "double-quoted-escaped-break",
        "plain-with-space",
        "single-quoted-multi-line",
        "next-line-value-without-the-walk",
        "tagged-value-without-the-walk",
        "flow-two-keys-without-the-walk",
        "next-line-value-after-a-flow-line",
    ],
)
@pytest.mark.unit
def test_local_uses_references(text, expected):
    """Every form actionlint's parser could read a local ``uses`` from."""
    assert module.local_uses_references(text) == expected


# --------------------------------------------------------------------------- #
# The password line, the integrations at scan time, and what the lint left out
# --------------------------------------------------------------------------- #


@pytest.mark.unit
def test_the_password_line_is_dropped_from_every_finding_on_it():
    """actionlint quotes the line in the snippet of every finding on it, so a
    second finding on the credentials line carries the password too."""
    payload = {
        "version": "1.7.12",
        "errors": [
            {
                "kind": "credentials",
                "filepath": "w.yml",
                "line": 17,
                "column": 21,
                "message": "m",
                "snippet": "password: hunter2",
            },
            {
                "kind": "syntax-check",
                "filepath": "w.yml",
                "line": 17,
                "column": 1,
                "message": "m",
                "snippet": "password: hunter2\n^",
            },
            {
                "kind": "syntax-check",
                "filepath": "w.yml",
                "line": 18,
                "column": 1,
                "message": "m",
                "snippet": "safe line",
            },
        ],
    }

    redacted = module.redact_credentials(payload)
    assert "hunter2" not in json.dumps(redacted)
    assert redacted["errors"][2]["snippet"] == "safe line"
    # The redaction is a copy, so the builder below gets input the password is
    # still in and its own redaction is what the second half measures.
    assert "hunter2" in json.dumps(payload)

    sarif = build_sarif(copy.deepcopy(payload), exit_code=1)
    assert "hunter2" not in json.dumps(sarif)
    regions = [
        result["locations"][0]["physicalLocation"]["region"]
        for result in sarif["runs"][0]["results"]
    ]
    assert "snippet" not in regions[1]
    assert regions[2]["snippet"] == {"text": "safe line"}


@pytest.mark.unit
def test_an_integration_that_no_longer_resolves_at_scan_time_is_missing(
    repo, monkeypatch
):
    """The dependency check found shellcheck; by the time scan() resolves it
    again it is gone. An enabled integration is never run quietly off: the
    scan is MISSING, as the dependency check would have made it.

    The lookups are counted: the explicit dependency check and the one scan()
    runs before its own resolution both find shellcheck, and the lookup after
    them, the scan's own, is the one that finds nothing. Without the count, a
    check that failed or ran twice would pass this test with no scan-time
    resolution at all."""
    answers = ["/usr/bin/shellcheck", "/usr/bin/shellcheck"]
    looked_up: list = []

    def find(name):
        if name == "actionlint":
            return FAKE_ACTIONLINT
        if name == "shellcheck":
            looked_up.append(name)
            return answers.pop(0) if answers else None
        return None

    monkeypatch.setattr(module, "find_absolute_executable", find)
    scanner = _scanner(repo, shellcheck="shellcheck")
    fake = _run(scanner, monkeypatch, _EMPTY_RUN, 0)

    assert scanner.validate_plugin_dependencies() is True
    assert looked_up == ["shellcheck"]

    assert scanner.scan(target=repo, target_type="source") is False

    assert fake.calls == []
    assert looked_up == ["shellcheck"] * 3
    assert answers == []
    assert "shellcheck" in scanner.dependency_unavailable_reason
    assert scanner.dependencies_satisfied is False


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX execute bit")
@pytest.mark.unit
def test_an_integration_path_holding_a_space_is_quoted_for_actionlint(
    repo, tmp_path, monkeypatch, on_path
):
    """actionlint reads the value as a command line split on whitespace, so a
    path with a space is passed quoted, or it names a program that does not
    exist and the integration drops."""
    tool = _plant(tmp_path / "my tools", "shellcheck")
    scanner = _scanner(repo, operator=True, shellcheck=tool.as_posix())

    argv = _argv(scanner, monkeypatch, repo)

    assert f'-shellcheck="{tool.as_posix()}"' in argv


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX execute bit")
@pytest.mark.unit
def test_an_integration_path_holding_a_quote_or_a_backslash_is_escaped(
    repo, tmp_path, monkeypatch, on_path
):
    """Inside the double quotes actionlint's shell-style splitting honors, a
    quote would end the value early and a backslash would swallow the next
    character, so both are escaped; plain wrapping would name a program that
    does not exist and the integration would quietly drop."""
    tool = _plant(tmp_path / 'my "tools"' / "back\\slash", "shellcheck")
    scanner = _scanner(repo, operator=True, shellcheck=tool.as_posix())

    argv = _argv(scanner, monkeypatch, repo)

    escaped = tool.as_posix().replace("\\", "\\\\").replace('"', '\\"')
    assert escaped != tool.as_posix()
    assert f'-shellcheck="{escaped}"' in argv


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks")
@pytest.mark.unit
def test_workflows_left_out_of_the_lint_are_named_not_called_absent(
    repo, tmp_path, monkeypatch, on_path
):
    """When the only workflow files were refused (here a link out of the tree),
    the scan records them as inputs it did not scan and the nothing-to-scan
    reason names them, rather than saying the tree holds no workflow file."""
    workflows = repo / ".github" / "workflows"
    for name in ("clean.yml", "vulnerable.yml"):
        (workflows / name).unlink()
    outside = tmp_path / "outside.yml"
    outside.write_text("on: push\n")
    (workflows / "leak.yml").symlink_to(outside)
    scanner = _scanner(repo)
    fake = _run(scanner, monkeypatch, _EMPTY_RUN, 0)

    reason = scanner.nothing_to_scan_reason()
    assert reason != module.NO_WORKFLOW_FILE
    assert "left out of the lint" in reason
    assert ".github/workflows/leak.yml" in reason

    assert scanner.scan(target=repo, target_type="source") is True
    assert fake.calls == []
    assert scanner.inputs_not_scanned == [
        {
            "path": ".github/workflows/leak.yml",
            "reason": "it resolves outside the scan root",
        }
    ]


@pytest.mark.unit
def test_a_reference_that_names_nothing_under_an_ancestor_is_not_a_leak(
    repo, tmp_path, on_path
):
    """An ancestor holding .github/workflows is a candidate project root, but a
    reference that names nothing there is one actionlint reads no file through,
    so an ordinary local action does not exempt the workflow from the lint."""
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    local = repo / ".github" / "actions" / "local"
    local.mkdir(parents=True)
    (local / "action.yml").write_text(_OUTSIDE_ACTION)
    (repo / ".github" / "workflows" / "refs.yml").write_text(
        _step_uses("./.github/actions/local")
    )
    scanner = _scanner(repo)

    workflows = scanner._workflow_files(repo, "source", [])

    assert ".github/workflows/refs.yml" in workflows


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks")
@pytest.mark.unit
def test_the_real_paths_ancestors_are_candidate_roots_under_a_linked_scan_root(
    tmp_path,
):
    """actionlint computes its project root from the physical working directory,
    so under a scan root that is a symbolic link the roots it may pick are the
    real path's ancestors; a reference an ancestor of the real path resolves
    outside the tree is judged there."""
    real = tmp_path / "real"
    (real / ".github" / "workflows").mkdir(parents=True)
    (real / "sibling").mkdir()
    (real / "sibling" / "action.yml").write_text(_OUTSIDE_ACTION)
    project = real / "proj"
    (project / ".github" / "workflows").mkdir(parents=True)
    workflow = project / ".github" / "workflows" / "w.yml"
    workflow.write_text(_step_uses("./sibling"))
    link = tmp_path / "link"
    link.symlink_to(project, target_is_directory=True)
    scanner = _scanner(link)

    spec = scanner._reference_outside_the_tree(
        link / ".github" / "workflows" / "w.yml", link.resolve()
    )

    assert spec == "./sibling"


@pytest.mark.unit
def test_an_ancestor_whose_stat_is_refused_does_not_fail_the_reference_check(
    repo, tmp_path, monkeypatch
):
    """Before Python 3.13 Path.is_dir() raises the stat's PermissionError for a
    path under an unsearchable directory; an ancestor the scan does not own
    must not fail the whole scan."""
    local = repo / ".github" / "actions" / "local"
    local.mkdir(parents=True)
    (local / "action.yml").write_text(_OUTSIDE_ACTION)
    workflow = repo / ".github" / "workflows" / "refs.yml"
    workflow.write_text(_step_uses("./.github/actions/local"))
    denied = tmp_path / ".github" / "workflows"
    original = Path.is_dir
    probed: list = []

    def is_dir(self, *args, **kwargs):
        probed.append(self)
        if self == denied:
            raise PermissionError(13, "Permission denied", str(self))
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "is_dir", is_dir)
    scanner = _scanner(repo)

    assert scanner._reference_outside_the_tree(workflow, repo.resolve()) is None
    # The refusal fired: the check asked about the denied ancestor through the
    # patched method, so the answer above was reached past it, not around it.
    assert denied in probed
