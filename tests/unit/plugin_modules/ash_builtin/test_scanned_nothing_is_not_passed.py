# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scanner that scanned no file does not report PASSED.

semgrep, opengrep and bandit can say how many files they scanned. With
``--exclude proj`` for a target named proj, semgrep scanned none and ASH reported
PASSED with no finding. Now the count is read after each run:

- semgrep and opengrep write ``paths.scanned`` and, with ``--verbose``,
  ``paths.skipped`` (each with its reason) to ``--json-output`` (measured with
  semgrep 1.180.0 and opengrep 1.30.2). None scanned while files were skipped by
  ``--exclude`` (reason ``cli_exclude_flags_match``) is ERROR, naming the count;
  none scanned and none skipped that way is SKIPPED (``targets_attempted`` 0):
  nothing below the target was in a language the rules cover.
- bandit lists every file it scanned under ``run.properties.metrics`` in its SARIF
  (next to ``_totals``). None scanned while the target holds ``.py`` or ``.pyw``
  files is ERROR; none scanned and none there is SKIPPED.
- Otherwise ``targets_attempted`` is the number scanned. It is reset for each
  target, so a later target cannot inherit an earlier one's count.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.exceptions import ScannerError

PluginContext.model_rebuild()

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(sys.platform == "win32", reason="the fixtures use POSIX paths"),
]

EMPTY_SARIF = {
    "version": "2.1.0",
    "runs": [{"tool": {"driver": {"name": "tool"}}, "results": []}],
}


def _context(source: Path, base: Path) -> PluginContext:
    output = base / "ash-output"
    output.mkdir(exist_ok=True)
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=AshConfig(),
    )


def _source(base: Path, files: dict[str, str]) -> Path:
    source = base / "source"
    for rel, text in files.items():
        (source / rel).parent.mkdir(parents=True, exist_ok=True)
        (source / rel).write_text(text, encoding="utf-8")
    source.mkdir(exist_ok=True)
    return source


def _flag_value(argv: list[str], flag: str) -> str | None:
    for arg in argv:
        if str(arg).startswith(f"{flag}="):
            return str(arg)[len(flag) + 1 :]
    return None


def _results_path(argv: list[str], output_flag: str) -> Path:
    index = argv.index(output_flag)
    return Path(argv[index + 1])


# ---------------------------------------------------------------------------
# semgrep and opengrep
# ---------------------------------------------------------------------------


@pytest.fixture(params=["semgrep", "opengrep"])
def grep_scanner(request, tmp_path, monkeypatch):
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    if request.param == "semgrep":
        from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
            SemgrepScanner as scanner_class,
            SemgrepScannerConfig as config_class,
        )
    else:
        from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
            OpengrepScanner as scanner_class,
            OpengrepScannerConfig as config_class,
        )
    source = _source(tmp_path, {"a.py": "x = 1\n", "b.py": "y = 2\n"})
    scanner = scanner_class(context=_context(source, tmp_path), config=config_class())
    scanner.dependencies_satisfied = True
    scanner.results_dir = tmp_path / "ash-output" / "scanners" / request.param
    return scanner, source


def _run_grep(scanner, source: Path, paths: dict):
    """scan() with a tool run that writes an empty SARIF and ``paths``."""
    seen: dict = {}

    def _fake_run(*args, **kwargs):
        argv = list(kwargs.get("command") or args[0])
        seen["argv"] = argv
        _results_path(argv, "--sarif-output").write_text(json.dumps(EMPTY_SARIF))
        json_output = _flag_value(argv, "--json-output")
        if json_output is not None:
            Path(json_output).write_text(json.dumps({"results": [], "paths": paths}))
        return {"stdout": "", "stderr": "", "returncode": 0}

    with (
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_post_scan"),
        patch.object(scanner, "_run_subprocess", side_effect=_fake_run),
    ):
        result = scanner.scan(target=source, target_type="source")
    return result, seen.get("argv", [])


def test_a_grep_scanner_asks_for_the_scanned_and_skipped_paths(grep_scanner):
    scanner, source = grep_scanner

    _, argv = _run_grep(scanner, source, {"scanned": [str(source / "a.py")]})

    assert _flag_value(argv, "--json-output") is not None
    assert "--verbose" in argv


def test_every_file_left_out_by_exclude_is_an_error(grep_scanner):
    scanner, source = grep_scanner
    skipped = [
        {"path": str(source / name), "reason": "cli_exclude_flags_match"}
        for name in ("a.py", "b.py")
    ]

    with pytest.raises(ScannerError) as refused:
        _run_grep(scanner, source, {"scanned": [], "skipped": skipped})

    assert "scanned no file" in str(refused.value)
    assert "--exclude" in str(refused.value)
    assert "2" in str(refused.value)


def test_no_file_in_a_covered_language_is_skipped(grep_scanner):
    scanner, source = grep_scanner

    _run_grep(scanner, source, {"scanned": [], "skipped": []})

    assert scanner.targets_attempted == 0


def test_the_scanned_count_is_recorded(grep_scanner):
    scanner, source = grep_scanner

    _run_grep(
        scanner,
        source,
        {"scanned": [str(source / "a.py"), str(source / "b.py")], "skipped": []},
    )

    assert scanner.targets_attempted == 2


def test_the_count_is_reset_for_each_target(grep_scanner, tmp_path):
    scanner, source = grep_scanner
    _run_grep(scanner, source, {"scanned": [str(source / "a.py")], "skipped": []})
    assert scanner.targets_attempted == 1
    empty = tmp_path / "empty-converted"
    empty.mkdir()

    scanner.scan(target=empty, target_type="converted")

    assert scanner.targets_attempted is None


# ---------------------------------------------------------------------------
# detect-secrets
# ---------------------------------------------------------------------------


def test_detect_secrets_with_nothing_to_scan_is_skipped(tmp_path):
    """detect-secrets reads the scan set; with every file ignored it scanned none."""
    from automated_security_helper.models.core import IgnorePathWithReason
    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        DetectSecretsScanner,
        DetectSecretsScannerConfig,
    )

    source = _source(tmp_path, {"vendor/a.yml": "key: value\n"})
    scanner = DetectSecretsScanner(
        context=_context(source, tmp_path), config=DetectSecretsScannerConfig()
    )
    scanner.dependencies_satisfied = True
    scanner.results_dir = tmp_path / "ash-output" / "scanners" / "detect-secrets"

    with (
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_post_scan"),
    ):
        scanner.scan(
            target=source,
            target_type="source",
            global_ignore_paths=[
                IgnorePathWithReason(path="vendor/**", reason="vendored")
            ],
        )

    assert scanner.targets_attempted == 0


# ---------------------------------------------------------------------------
# bandit
# ---------------------------------------------------------------------------


def _bandit(tmp_path: Path, files: dict[str, str]):
    from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
        BanditScanner,
        BanditScannerConfig,
    )

    source = _source(tmp_path, files)
    scanner = BanditScanner(
        context=_context(source, tmp_path), config=BanditScannerConfig()
    )
    scanner.dependencies_satisfied = True
    scanner.results_dir = tmp_path / "ash-output" / "scanners" / "bandit"
    return scanner, source


def _run_bandit(scanner, source: Path, scanned: list[str]):
    metrics = {"_totals": {"loc": 0}}
    metrics.update({path: {"loc": 1} for path in scanned})
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "Bandit"}},
                "results": [],
                "properties": {"metrics": metrics},
            }
        ],
    }

    def _fake_run(*args, **kwargs):
        argv = list(kwargs.get("command") or args[0])
        _results_path(argv, "--output").write_text(json.dumps(sarif))
        return {"stdout": "", "stderr": "", "returncode": 0}

    with (
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_post_scan"),
        patch.object(scanner, "_run_subprocess", side_effect=_fake_run),
    ):
        return scanner.scan(target=source, target_type="source")


def test_bandit_scanning_none_of_the_python_files_is_an_error(tmp_path):
    scanner, source = _bandit(tmp_path, {"a.py": "x = 1\n", "b.pyw": "y = 2\n"})

    with pytest.raises(ScannerError) as refused:
        _run_bandit(scanner, source, [])

    assert "scanned no file" in str(refused.value)
    assert "2 Python files" in str(refused.value)


def test_bandit_with_no_python_file_is_skipped(tmp_path):
    scanner, source = _bandit(tmp_path, {"README.md": "# hi\n"})

    _run_bandit(scanner, source, [])

    assert scanner.targets_attempted == 0


def test_bandit_records_the_scanned_count(tmp_path):
    scanner, source = _bandit(tmp_path, {"a.py": "x = 1\n", "b.py": "y = 2\n"})

    _run_bandit(scanner, source, [f"{source}/a.py", f"{source}/b.py"])

    assert scanner.targets_attempted == 2
