# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""How a grep-family scan that scanned no file is graded.

``_post_process_sarif`` reads the tool's ``paths.scanned`` and ``paths.skipped``.
Nothing scanned is one of three outcomes:

- every file the tool found was left out by ASH's own exclusions: the global
  ignore paths, the ASH output directories inside the target, or the tools' own
  default ignore list (``tests/``, ``vendor/``, ``node_modules/``, ``*.min.js``,
  ...) that ASH re-passes as ``--exclude`` because ``--x-ignore-semgrepignore-files``
  drops it. The tools graded such a target SKIPPED on their own, and ASH grades it
  SKIPPED (``targets_attempted`` 0). It used to raise: the re-passed defaults were
  read as the operator's patterns.
- every file the tool found was left out by the operator's ``exclude`` patterns:
  a scanner error, as before, since the scan says nothing about them and the
  operator can change the patterns.
- the tool found a file in a covered language and did not read it (too large,
  unreadable, a parse failure): a scanner error. It used to be graded SKIPPED as
  "no file in a covered language", which it is not.

The grading is driven directly, with a paths file written the way the tools write
it; no tool starts here.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
    SemgrepScanner,
    SemgrepScannerConfig,
    SemgrepScannerConfigOptions,
)

pytestmark = pytest.mark.unit


_SARIF: dict = {
    "version": "2.1.0",
    "runs": [{"tool": {"driver": {"name": "semgrep"}}, "results": []}],
}


def _scanner(test_plugin_context, monkeypatch, exclude=None) -> SemgrepScanner:
    monkeypatch.delenv("SEMGREP_RULES_CACHE_DIR", raising=False)
    monkeypatch.setattr(SemgrepScanner, "_scanner_offline", lambda self: False)
    options = (
        SemgrepScannerConfigOptions(offline=False, exclude=exclude)
        if exclude is not None
        else SemgrepScannerConfigOptions(offline=False)
    )
    return SemgrepScanner(
        context=test_plugin_context, config=SemgrepScannerConfig(options=options)
    )


def _grade(scanner, tmp_path: Path, skipped: list, scanned: list | None = None):
    """Run the grading over a paths file holding *scanned* and *skipped*."""
    paths_file = tmp_path / "paths.json"
    paths_file.write_text(
        json.dumps({"paths": {"scanned": list(scanned or []), "skipped": skipped}}),
        encoding="utf-8",
    )
    scanner.targets_attempted = None
    scanner._post_process_sarif(
        _SARIF, [f"--json-output={paths_file.as_posix()}"], tmp_path / "src"
    )
    return scanner.targets_attempted


def _excluded(*paths: str) -> list:
    return [{"path": path, "reason": "cli_exclude_flags_match"} for path in paths]


@pytest.mark.parametrize(
    "paths",
    [
        pytest.param(["tests/test_app.py", "tests/unit/test_x.py"], id="tests"),
        pytest.param(["test/app_test.py"], id="test"),
        pytest.param(["vendor/lib/x.py"], id="vendor"),
        pytest.param(["node_modules/pkg/index.js"], id="node_modules"),
        pytest.param(["build/out.py", "dist/out.js"], id="build-dist"),
        pytest.param(["static/app.min.js"], id="min-js"),
        pytest.param(["pkg/handler_test.go"], id="go-test"),
        pytest.param(["/abs/repo/tests/test_app.py"], id="absolute"),
    ],
)
def test_files_the_tools_default_ignore_list_left_out_grade_skipped(
    test_plugin_context, monkeypatch, tmp_path, paths
):
    """A target whose files all sit on the tools' own default ignore list is
    SKIPPED, as the tools graded it before ASH re-passed that list as --exclude.

    Fails at the base with ScannerError ("its --exclude patterns left out all N
    files it found"): every ``cli_exclude_flags_match`` entry outside the global
    ignore names counted as the operator's.
    """
    scanner = _scanner(test_plugin_context, monkeypatch)

    assert _grade(scanner, tmp_path, _excluded(*paths)) == 0


def test_files_in_an_ash_output_directory_grade_skipped(
    test_plugin_context, monkeypatch, tmp_path
):
    """The ASH output directories the command excluded are ASH's own exclusions."""
    scanner = _scanner(test_plugin_context, monkeypatch)
    scanner._output_dir_excluded = [Path(".ash/ash_output")]

    skipped = _excluded(
        ".ash/ash_output/reports/report.py",
        "/abs/repo/.ash/ash_output/scanners/semgrep/x.py",
    )
    assert _grade(scanner, tmp_path, skipped) == 0


def test_files_the_operators_patterns_left_out_are_a_scanner_error(
    test_plugin_context, monkeypatch, tmp_path
):
    """The control: an operator pattern that excludes every file is still refused."""
    scanner = _scanner(test_plugin_context, monkeypatch, exclude=["*.py"])

    with pytest.raises(ScannerError, match="--exclude patterns left out all 2 files"):
        _grade(scanner, tmp_path, _excluded("src/app.py", "src/lib.py"))


def test_one_operator_excluded_file_among_default_ignored_ones_is_a_scanner_error(
    test_plugin_context, monkeypatch, tmp_path
):
    """One file outside ASH's own exclusions is enough: the scan says nothing
    about it."""
    scanner = _scanner(test_plugin_context, monkeypatch, exclude=["*.py"])

    with pytest.raises(ScannerError, match="--exclude patterns left out"):
        _grade(scanner, tmp_path, _excluded("tests/test_app.py", "src/app.py"))


def test_a_directory_named_like_a_default_ignore_as_the_file_is_not_one(
    test_plugin_context, monkeypatch, tmp_path
):
    """The default list names directories; a file named ``tests`` with no
    directory above it is not on it."""
    scanner = _scanner(test_plugin_context, monkeypatch, exclude=["tests"])

    with pytest.raises(ScannerError, match="--exclude patterns left out"):
        _grade(scanner, tmp_path, _excluded("tests"))


@pytest.mark.parametrize(
    "reason",
    [
        "exceeded_size_limit",
        "too_big",
        "analysis_failed_parser_or_internal_error",
        "insufficient_permissions",
    ],
)
def test_a_file_the_tool_found_and_did_not_read_is_a_scanner_error(
    test_plugin_context, monkeypatch, tmp_path, reason
):
    """Nothing scanned while a covered file was skipped unread is refused.

    Fails at the base: ``targets_attempted`` was set to 0 and the target graded
    SKIPPED, "none is in a language its rules cover", for a file that is.
    """
    scanner = _scanner(test_plugin_context, monkeypatch)

    with pytest.raises(ScannerError, match="did not read them"):
        _grade(scanner, tmp_path, [{"path": "src/big.py", "reason": reason}])


def test_unread_files_beside_uncovered_ones_are_still_a_scanner_error(
    test_plugin_context, monkeypatch, tmp_path
):
    scanner = _scanner(test_plugin_context, monkeypatch)
    skipped = [
        {"path": "README.md", "reason": "wrong_language"},
        {"path": "src/big.py", "reason": "too_big"},
    ]

    with pytest.raises(ScannerError, match="1 file\\(s\\)"):
        _grade(scanner, tmp_path, skipped)


def test_only_uncovered_files_grade_skipped(test_plugin_context, monkeypatch, tmp_path):
    """The control: nothing in a covered language is SKIPPED, as before."""
    scanner = _scanner(test_plugin_context, monkeypatch)
    skipped = [
        {"path": "README.md", "reason": "wrong_language"},
        {"path": "image.png", "reason": "binary"},
        {"path": "app.min.js", "reason": "minified"},
    ]

    assert _grade(scanner, tmp_path, skipped) == 0


def test_a_scanned_file_counts_whatever_was_skipped(
    test_plugin_context, monkeypatch, tmp_path
):
    """The control: with a file scanned the count is the scanned count, and the
    skipped entries, unread ones included, change nothing."""
    scanner = _scanner(test_plugin_context, monkeypatch)
    skipped = [{"path": "src/big.py", "reason": "too_big"}]

    assert _grade(scanner, tmp_path, skipped, scanned=["src/app.py"]) == 1


def test_the_output_directories_the_command_excluded_are_recorded(
    tmp_path, monkeypatch
):
    """``_output_dir_exclude_patterns`` records the directories it excluded, so
    the grading can tell their files apart from the operator's patterns."""
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.default_config import get_default_config

    source = tmp_path / "repo"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    output = source / ".ash" / "ash_output"
    output.mkdir(parents=True)
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=get_default_config(),
    )
    monkeypatch.delenv("SEMGREP_RULES_CACHE_DIR", raising=False)
    monkeypatch.setattr(SemgrepScanner, "_scanner_offline", lambda self: False)
    scanner = SemgrepScanner(
        context=context,
        config=SemgrepScannerConfig(options=SemgrepScannerConfigOptions(offline=False)),
    )

    patterns = scanner._output_dir_exclude_patterns(source)

    assert patterns, "premise: the output directory inside the target is excluded"
    assert Path(".ash/ash_output") in scanner._output_dir_excluded
