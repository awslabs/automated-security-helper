# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""`ash config lint`: every kind of lint issue, the fixes, and the file left behind.

The fixtures between them trigger every ``LintCategory``. Which categories exist is
read from the enum itself, not copied here, so adding a lint rule without a fixture
(and so without a snapshot) that exercises it fails
``test_fixtures_exercise_every_lint_category``.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from automated_security_helper.config.config_linter import (
    ConfigLinter,
    LintCategory,
)
from tests.snapshot.support.cli import run_cli
from tests.snapshot.support.fixture_model import pin_clock

pytestmark = pytest.mark.unit

# Everything except a parse failure and an unused suppression, which need their own
# fixtures: a parse failure stops the lint, and unused suppressions need a report.
EVERY_ISSUE = """\
fail_on_findings: true
fail_on_incomplete_scanners: sometimes
build:
  build_mode: ONLINE
legacy_option: 1
scanners:
  bandit:
    name: bandit
    enabled: true
  cdk_nag:
    enabled: true
  npm-audit:
    enabled: true
  npm_audit:
    enabled: false
  trivy-repo:
    enabled: true
reporters:
  html:
    extension: html
converters:
  archive:
    install_timeout: 10
global_settings:
  ignore_paths:
    - path: vendor
      reason: third party code
  suppressions:
    - path: src/app.py
      rule_id: B101
      line_start: 10
      reason: |
        Asserts are stripped in production builds,
        so this check never runs there.
    - path: src/app.py
      rule_id: B105
      expiration: "2020-01-31"
      reason: Temporary test credential
    - path: src/app.py
      rule_id: B106
      symbol: "handler(request)"
      reason: Not a qualified name
    - path: src/app.py
      rule_id: B107
      expiration: "31/01/2099"
      reason: Wrong date format
    - path: src/app.rb
      rule_id: B108
      symbol: Handler.run
      reason: A file type with no symbol grammar
fail_on_findings: false
"""

BROKEN = "project_name: [unclosed\n"

CLEAN = """\
project_name: snapshot-demo
global_settings:
  suppressions:
    - path: src/app.py
      rule_id: B101
      line_start: 10
      line_end: 12
      reason: Reviewed
"""

WITH_UNUSED = """\
project_name: snapshot-demo
global_settings:
  suppressions:
    - path: src/app.py
      rule_id: B101
      line_start: 10
      line_end: 12
      reason: Still matches a finding
    - path: src/old.py
      rule_id: B105
      reason: The file was deleted
"""

# `extends` names a base config that does not exist, so resolving it fails.
BAD_EXTENDS = """\
extends: base-that-does-not-exist.yaml
project_name: snapshot-demo
"""

UNUSED_REPORT = {
    "unused_suppressions": [
        {"path": "src/old.py", "rule_id": "B105", "reason": "The file was deleted"}
    ]
}


@pytest.fixture
def project_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    project = tmp_path / "demo-project"
    (project / ".ash").mkdir(parents=True)
    (project / "vendor").mkdir()
    (project / "src").mkdir()
    (project / ".ash" / ".ash.yaml").write_text(EVERY_ISSUE, encoding="utf-8")
    (project / "broken.yaml").write_text(BROKEN, encoding="utf-8")
    (project / "clean.yaml").write_text(CLEAN, encoding="utf-8")
    (project / "unused.yaml").write_text(WITH_UNUSED, encoding="utf-8")
    (project / "extends.yaml").write_text(BAD_EXTENDS, encoding="utf-8")
    report = project / "out" / "reports" / "ash.unused-suppressions.json"
    report.parent.mkdir(parents=True)
    report.write_text(json.dumps(UNUSED_REPORT), encoding="utf-8")
    # The symbols extra installed, as if: whether this host has it is not the
    # output under test, and without it a valid symbol adds a warning of its own.
    from automated_security_helper.utils import symbol_spans

    monkeypatch.setattr(symbol_spans, "symbols_extra_available", lambda: True)
    # Fresh, so the "report is N hours old" warning (a wall-clock value) never fires.
    now = time.time()
    os.utime(report, (now, now))
    # --fix-unused stamps each commented-out line "[ash-lint <today>]" from the local
    # clock: measured, 2026-10-05 under one TZ and 2026-10-06 under Pacific/Kiritimati.
    # Pinned, the stamp is the fixture's date. The pinned "now" is earlier than the
    # report's real mtime, so the report's age stays below the warning threshold.
    pin_clock(
        monkeypatch, extra_modules=("automated_security_helper.config.config_linter",)
    )
    monkeypatch.chdir(project)
    return project


def _issues(result) -> list[dict]:
    return [
        {
            "severity": issue.severity.value,
            "category": issue.category.value,
            "path": issue.path,
            "fixable": issue.fixable,
            "message": issue.message,
            "fix_description": issue.fix_description,
        }
        for issue in result.issues
    ]


def test_fixtures_exercise_every_lint_category(project_dir, snapshot):
    results = {
        "every-issue": ConfigLinter.lint(project_dir / ".ash" / ".ash.yaml"),
        "broken": ConfigLinter.lint(project_dir / "broken.yaml"),
        "unused": ConfigLinter.lint(
            project_dir / "unused.yaml",
            output_dir=project_dir / "out",
            check_unused=True,
        ),
        "bad-extends": ConfigLinter.lint(project_dir / "extends.yaml"),
    }

    seen = {issue.category for r in results.values() for issue in r.issues}
    # OTHER is the category of a validator warning in words lint has no category
    # for; no config file written for a snapshot reads as one, so its unit test
    # (tests/unit/config/test_config_linter_low_severity_fixes.py) builds the check
    # by hand.
    missing = sorted(c.value for c in set(LintCategory) - seen - {LintCategory.OTHER})
    assert not missing, (
        f"No fixture triggers {missing}. Add one to this module so the new rule's "
        "output is snapshotted."
    )
    assert {name: _issues(r) for name, r in results.items()} == snapshot


# EVERY_ISSUE, BROKEN and BAD_EXTENDS are configs a scan refuses (a value the model
# refuses, a parse error, a base that does not exist), so lint exits 3 as the scan
# does, even after declining --fix.
@pytest.mark.parametrize(
    "args, stdin, exit_code",
    [
        pytest.param(["config", "lint"], None, 3, id="every-issue"),
        pytest.param(["config", "lint", "-c", "broken.yaml"], None, 3, id="broken"),
        pytest.param(["config", "lint", "-c", "clean.yaml"], None, 0, id="clean"),
        pytest.param(["config", "lint", "-c", "missing.yaml"], None, 3, id="missing"),
        pytest.param(
            ["config", "lint", "-c", "extends.yaml"], None, 3, id="bad-extends"
        ),
        pytest.param(["config", "lint", "--fix"], "n\n", 3, id="fix-declined"),
    ],
)
def test_config_lint(args, stdin, exit_code, project_dir, text_snapshot):
    run = run_cli(args, stdin=stdin)

    assert run.exit_code == exit_code, run.output
    assert (project_dir / ".ash" / ".ash.yaml").read_text(
        encoding="utf-8"
    ) == EVERY_ISSUE
    assert text_snapshot("txt") == run.document


def test_config_lint_fix_rewrites_config(project_dir, text_snapshot):
    run = run_cli(["config", "lint", "--fix", "--non-interactive"])

    # The fixes are applied, and the exit code describes the file they leave:
    # its symbol, expiration and fail_on_incomplete_scanners values are still
    # ones the model refuses.
    assert run.exit_code == 3, run.output
    assert text_snapshot("txt")(name="stdout") == run.document
    assert text_snapshot("yaml")(name="fixed") == (
        project_dir / ".ash" / ".ash.yaml"
    ).read_text(encoding="utf-8")


def test_config_lint_fix_unused_comments_out(project_dir, text_snapshot):
    run = run_cli(
        [
            "config",
            "lint",
            "-c",
            "unused.yaml",
            "-o",
            "out",
            "--fix-unused",
            "--non-interactive",
        ]
    )

    assert run.exit_code == 0, run.output
    assert text_snapshot("txt")(name="stdout") == run.document
    assert text_snapshot("yaml")(name="fixed") == (
        project_dir / "unused.yaml"
    ).read_text(encoding="utf-8")


def test_config_lint_fix_unused_without_report(project_dir, text_snapshot):
    run = run_cli(
        ["config", "lint", "-c", "clean.yaml", "--fix-unused", "--non-interactive"]
    )

    assert run.exit_code == 0, run.output
    assert text_snapshot("txt") == run.document
