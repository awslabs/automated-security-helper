# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Edges of the gitleaks scanner's ``.gitleaksignore`` re-scan and its reports.

Each test pins one behavior the scanner lacked:

* a ``.gitleaksignore`` that is a dangling symlink, or a symlink to a directory,
  stopped the scan, though gitleaks reads no line through either;
* a rule id holding ``:`` put the wrong file part into the re-scan, so the file
  the ignore file hid was never re-scanned;
* the report path was passed as given, so a relative results directory sent
  gitleaks' report to its working directory, where ASH does not read it;
* the count of names the re-scan skipped, and a re-scan's failure, were not
  reset per target, and the recorded end time left the re-scan out;
* ``.gitleaksignore`` was read once before gitleaks ran and never compared with
  what gitleaks itself read;
* a failure description printed an exit code for a tool ASH could not stop, and
  described a failed re-scan by the first run's accepted exit code and log;
* a timed-out re-scan recorded its share of the deadline as the limit;
* the re-scan root was a lexical normalization, so a baseline inside a source
  directory reached through a symlink was copied and re-scanned;
* the copies had no byte budget and ran outside the deadline;
* the size pre-filter was stricter than gitleaks' whole-megabyte test;
* a backslash in a URI was read as a separator on POSIX, and only this run's
  output directory was dropped, not an earlier run's ``.ash/ash_output``;
* an empty re-scan report, or one without a run, was read as no findings.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    gitleaks_scanner as module,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.gitleaks_scanner import (
    GitleaksScanner,
    GitleaksScannerConfig,
    GitleaksScannerConfigOptions,
    gitleaksignore_files,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.config_trust import record_provenance
from tests.unit.plugin_modules.ash_builtin.test_gitleaks_scanner import (
    _add_back,
    _report,
    _rescan_harness,
    _result,
    _scanner,
    _write,
)
from tests.utils.git_isolation import isolate_git_at

pytestmark = pytest.mark.unit

PluginContext.model_rebuild()

symlinks = pytest.mark.skipif(sys.platform == "win32", reason="symlinks")
posix_names = pytest.mark.skipif(sys.platform == "win32", reason="POSIX file names")


def _scanner_at(source: Path, output: Path, *, operator: bool = False, **options):
    """A scanner over ``source`` with its output at ``output``."""
    output.mkdir(parents=True, exist_ok=True)
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=AshConfig(),
    )
    if operator:
        record_provenance(context.config, in_tree=[], trusted=AshConfig())
    return GitleaksScanner(
        context=context,
        config=GitleaksScannerConfig(
            enabled=True, options=GitleaksScannerConfigOptions(**options)
        ),
    )


# --------------------------------------------------------------------------- #
# .gitleaksignore shapes gitleaks reads nothing through
# --------------------------------------------------------------------------- #


@symlinks
def test_a_dangling_gitleaksignore_symlink_is_no_ignore_file(tmp_path):
    """gitleaks' stat of the name fails, so it applies nothing; ASH stopped."""
    scanner = _scanner(tmp_path)
    source = Path(scanner.context.source_dir)
    _write(source, "app/x.py")
    (source / ".gitleaksignore").symlink_to(source / "nowhere")
    assert scanner._read_tree_ignore_file(source) == b""
    final_args, _, _ = scanner._execute_scan(source, "source", [])
    assert final_args[-2:] == ["--", "."]


@symlinks
def test_a_gitleaksignore_symlink_to_a_directory_is_no_ignore_file(tmp_path):
    """gitleaks opens the directory and reads no line from it."""
    scanner = _scanner(tmp_path)
    source = Path(scanner.context.source_dir)
    _write(source, "app/x.py")
    (source / ".gitleaksignore").symlink_to(source / "app")
    assert scanner._read_tree_ignore_file(source) == b""


# --------------------------------------------------------------------------- #
# A rule id can hold ":"
# --------------------------------------------------------------------------- #


def test_every_file_part_a_colon_rule_id_allows_is_a_candidate():
    """``app/x.py:my:rule:4`` hides a finding of rule ``my:rule`` in ``app/x.py``;
    reading the file as everything before the last two colons gave ``app/x.py:my``,
    which names no file, so the hidden finding was never re-scanned."""
    assert "app/x.py" in gitleaksignore_files(b"app/x.py:my:rule:4\n")


def test_a_plain_entry_still_names_its_file_once():
    assert gitleaksignore_files(b"app/x.py:github-pat:4\n") == ["app/x.py"]


def test_a_two_part_line_hides_nothing():
    assert gitleaksignore_files(b"app/x.py:4\n") == []


def test_a_colon_rule_id_entry_is_re_scanned(tmp_path, monkeypatch):
    hidden = _result("app/x.py", "my:rule", 4, column=3)
    scanner, calls = _rescan_harness(tmp_path, monkeypatch, {"app/x.py": [hidden]})
    source = Path(scanner.context.source_dir)
    _write(source, "app/x.py")
    (source / ".gitleaksignore").write_text("app/x.py:my:rule:4\n")
    assert _add_back(scanner, source, _report(), tmp_path) == [
        ("app/x.py", "my:rule", 4, 3)
    ]
    assert [call["files"] for call in calls] == [["app/x.py"]]


# --------------------------------------------------------------------------- #
# The on-disk spelling lookup reads each directory once and keeps its names in a set
# --------------------------------------------------------------------------- #


def test_each_directory_is_listed_once_and_kept_as_a_set_over_many_entries(
    tmp_path, monkeypatch
):
    """An ignore file can name thousands of entries under one directory; each
    lookup reads the directory's listing from the cache, as a set of names,
    never as a list to scan."""
    for index in range(200):
        _write(tmp_path, f"app/f{index}.py")
    _write(tmp_path, "top.py")
    scanned = []
    real_scandir = os.scandir

    def counting_scandir(path):
        scanned.append(Path(path))
        return real_scandir(path)

    monkeypatch.setattr(module.os, "scandir", counting_scandir)
    listings: dict = {}
    spelled = [
        GitleaksScanner._on_disk_spelling(tmp_path, f"app/f{index}.py", listings)
        for index in range(200)
    ]
    spelled.append(GitleaksScanner._on_disk_spelling(tmp_path, "top.py", listings))
    spelled.append(
        GitleaksScanner._on_disk_spelling(tmp_path, "app/missing.py", listings)
    )

    assert spelled[:200] == [f"app/f{index}.py" for index in range(200)]
    assert spelled[200:] == ["top.py", None]
    # One listing per directory touched: the root and app.
    assert sorted(scanned) == sorted([tmp_path, tmp_path / "app"])
    names = listings[tmp_path / "app"]
    assert isinstance(names, set) and len(names) == 200
    assert "f7.py" in names


# --------------------------------------------------------------------------- #
# Per-target state and paths
# --------------------------------------------------------------------------- #


def test_the_report_path_is_absolute_whatever_the_results_dir(tmp_path, monkeypatch):
    """gitleaks runs with its working directory at the source directory, so a
    relative report path would land there."""
    monkeypatch.chdir(tmp_path)
    scanner = _scanner(tmp_path)
    scanner.results_dir = Path("relative-results")
    source = Path(scanner.context.source_dir)
    _write(source, "app/x.py")
    final_args, results_file, _ = scanner._execute_scan(source, "source", [])
    assert results_file.is_absolute()
    (report,) = [a for a in final_args if a.startswith("--report-path=")]
    assert Path(report.split("=", 1)[1]).is_absolute()


def test_the_skipped_count_and_rescan_failure_are_reset_per_target(tmp_path):
    scanner = _scanner(tmp_path)
    source = Path(scanner.context.source_dir)
    _write(source, "app/x.py")
    scanner._rescan_skipped = 5
    scanner._rescan_failure_log = tmp_path / "old.log"
    scanner._execute_scan(source, "source", [])
    assert scanner._rescan_skipped == 0
    assert scanner._rescan_failure_log is None


def _pending(scanner, source: Path, results_file: Path, ignore_data: bytes):
    results_file.parent.mkdir(parents=True, exist_ok=True)
    results_file.write_text(json.dumps(_report()))
    args = scanner._build_arguments(source, results_file)
    scanner._pending_run = (source, args, ignore_data)
    scanner.exit_code = 0


def test_the_end_time_covers_the_re_scan(tmp_path, monkeypatch):
    scanner = _scanner(tmp_path)
    source = Path(scanner.context.source_dir)
    _write(source, "app/x.py")
    (source / ".gitleaksignore").write_text("app/x.py:github-pat:1\n")
    results_file = scanner.results_dir / "source" / "gitleaks.sarif"
    _pending(scanner, source, results_file, b"app/x.py:github-pat:1\n")
    monkeypatch.setattr(scanner, "_add_back_gitleaksignore_drops", lambda *a, **k: None)
    before = datetime.now(timezone.utc) - timedelta(hours=1)
    scanner.end_time = before
    scanner._read_results_file(results_file)
    assert scanner.end_time > before


def test_a_gitleaksignore_that_changed_while_gitleaks_ran_fails_the_scan(
    tmp_path, monkeypatch
):
    """The re-scan would cover entries other than the ones gitleaks applied."""
    scanner = _scanner(tmp_path)
    source = Path(scanner.context.source_dir)
    _write(source, "app/x.py")
    (source / ".gitleaksignore").write_text("app/x.py:github-pat:1\n")
    results_file = scanner.results_dir / "source" / "gitleaks.sarif"
    _pending(scanner, source, results_file, b"other.py:github-pat:1\n")
    monkeypatch.setattr(
        scanner, "_run_subprocess", lambda *a, **k: pytest.fail("re-scan ran")
    )
    with pytest.raises(ScannerError, match="changed while gitleaks ran"):
        scanner._read_results_file(results_file)


# --------------------------------------------------------------------------- #
# Failure descriptions
# --------------------------------------------------------------------------- #


def test_a_tool_ash_could_not_stop_is_described_without_an_exit_code(tmp_path):
    scanner = _scanner(tmp_path)
    results_file = scanner.results_dir / "source" / "gitleaks.sarif"
    results_file.parent.mkdir(parents=True)
    scanner.exit_code = 124
    scanner._scan_could_not_stop = "ASH could not stop the tool"
    message = scanner._describe_scan_failure(ScannerError("timed out"), results_file)
    assert "no exit code" in message
    assert "exit code 124" not in message
    assert "accepted exit code" not in message


def _failing_rescan(tmp_path, monkeypatch, response: dict):
    scanner, calls = _rescan_harness(tmp_path, monkeypatch, {}, scan_timeout=100)
    source = Path(scanner.context.source_dir)
    _write(source, "app/x.py")
    (source / ".gitleaksignore").write_text("app/x.py:github-pat:1\n")

    def failing(command, results_dir=None, timeout=None, cwd=None, **kwargs):
        return dict(response)

    monkeypatch.setattr(scanner, "_run_subprocess", failing)
    results_file = tmp_path / "res" / "gitleaks.sarif"
    results_file.parent.mkdir()
    args = scanner._build_arguments(source, results_file)
    scanner.exit_code = module.LEAKS_EXIT_CODE
    with pytest.raises(ScannerError) as excinfo:
        scanner._add_back_gitleaksignore_drops(_report(), source, args, results_file)
    return scanner, results_file, excinfo.value


def test_a_timed_out_re_scan_says_so_and_records_the_whole_limit(tmp_path, monkeypatch):
    scanner, _, error = _failing_rescan(
        tmp_path, monkeypatch, {"returncode": None, "timed_out": True}
    )
    assert "timed out" in str(error)
    assert "exit None" not in str(error)
    assert scanner.scan_timed_out_after == 100


def test_a_re_scan_that_could_not_start_says_so(tmp_path, monkeypatch):
    _, _, error = _failing_rescan(
        tmp_path, monkeypatch, {"returncode": 127, "spawn_failed": True}
    )
    assert "could not be started" in str(error)


def test_a_failed_re_scan_is_described_by_its_own_log(tmp_path, monkeypatch):
    """The first run exited 2, an accepted code, so that code alone read as a
    success; the re-scan's log is in its own directory."""
    scanner, results_file, error = _failing_rescan(
        tmp_path, monkeypatch, {"returncode": 1}
    )
    message = scanner._describe_scan_failure(error, results_file)
    assert "re-scan" in message
    assert "gitleaksignore-rescan" in message
    assert "an accepted exit code" not in message


# --------------------------------------------------------------------------- #
# The re-scan root is the directory gitleaks walked
# --------------------------------------------------------------------------- #


@symlinks
def test_the_baseline_inside_a_linked_source_dir_is_not_re_scanned(
    tmp_path, monkeypatch
):
    """The operator's baseline path is resolved; the root compared with it was
    not, so under a linked source directory the baseline, which gitleaks does not
    scan, was copied and its contents reported as findings."""
    real = tmp_path / "real" / "src"
    real.mkdir(parents=True)
    (tmp_path / "link").symlink_to(tmp_path / "real")
    source = tmp_path / "link" / "src"
    _write(source, "app/x.py")
    (source / "baseline.json").write_text("[]")
    (source / ".gitleaksignore").write_text(
        "app/x.py:github-pat:1\nbaseline.json:github-pat:1\n"
    )
    scanner = _scanner_at(
        source, tmp_path / "out", operator=True, baseline_path="baseline.json"
    )
    calls = []

    def fake_run(command, results_dir=None, timeout=None, cwd=None, **kwargs):
        root = Path(cwd)
        calls.append(
            sorted(
                p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()
            )
        )
        report = next(
            a.split("=", 1)[1] for a in command if a.startswith("--report-path=")
        )
        Path(report).write_text(json.dumps(_report()))
        return {"returncode": 0}

    monkeypatch.setattr(scanner, "_run_subprocess", fake_run)
    results_file = tmp_path / "res" / "gitleaks.sarif"
    results_file.parent.mkdir()
    args = scanner._build_arguments(source, results_file)
    assert any(a.startswith("--baseline-path=") for a in args)
    scanner._add_back_gitleaksignore_drops(_report(), source, args, results_file)
    assert calls == [["app/x.py"]]


# --------------------------------------------------------------------------- #
# The copies are bounded in bytes and by the deadline
# --------------------------------------------------------------------------- #


def test_the_copies_stop_at_the_byte_budget_and_report_the_rest(
    tmp_path, monkeypatch, caplog
):
    monkeypatch.setattr(module, "MAX_RESCAN_BYTES", 5)
    scanner, calls = _rescan_harness(tmp_path, monkeypatch, {})
    source = Path(scanner.context.source_dir)
    _write(source, "app/a.py", "aaa")
    _write(source, "app/b.py", "bbb")
    _write(source, "app/c.py", "ccc")
    (source / ".gitleaksignore").write_text(
        "app/a.py:github-pat:1\napp/b.py:github-pat:1\napp/c.py:github-pat:1\n"
    )
    with caplog.at_level("WARNING"):
        _add_back(scanner, source, _report(), tmp_path)
    assert [call["files"] for call in calls] == [["app/a.py"]]
    assert scanner._rescan_skipped == 2
    assert "2 file(s) the scanned tree's .gitleaksignore names were not" in caplog.text


def test_no_copy_is_made_once_the_deadline_has_passed(tmp_path, monkeypatch):
    """The copies ran before the first deadline check, outside scan_timeout."""
    clock = iter([0.0, 1000.0, 1000.0, 1000.0])
    monkeypatch.setattr(module, "_monotonic", lambda: next(clock))
    writes = []

    def recording_copy(source, destination):
        writes.append(destination)

    monkeypatch.setattr(module, "_write_private_copy", recording_copy)
    scanner, calls = _rescan_harness(tmp_path, monkeypatch, {}, scan_timeout=1)
    source = Path(scanner.context.source_dir)
    _write(source, "app/x.py")
    (source / ".gitleaksignore").write_text("app/x.py:github-pat:1\n")
    with pytest.raises(ScannerError, match="timed out re-scanning"):
        _add_back(scanner, source, _report(), tmp_path)
    assert writes == [] and calls == []


def test_a_file_just_over_the_megabyte_limit_is_still_re_scanned(tmp_path, monkeypatch):
    """gitleaks skips a file when size / 1,000,000 (whole megabytes) is over the
    limit, so 1,000,001 bytes under --max-target-megabytes=1 is scanned."""
    scanner, calls = _rescan_harness(
        tmp_path, monkeypatch, {}, operator=True, max_target_megabytes=1
    )
    source = Path(scanner.context.source_dir)
    _write(source, "app/edge.py", "x" * 1_000_001)
    _write(source, "app/big.py", "x" * 2_000_000)
    (source / ".gitleaksignore").write_text(
        "app/edge.py:github-pat:1\napp/big.py:github-pat:1\n"
    )
    _add_back(scanner, source, _report(), tmp_path)
    assert [call["files"] for call in calls] == [["app/edge.py"]]


# --------------------------------------------------------------------------- #
# Dropping results under ASH's output directories
# --------------------------------------------------------------------------- #


def _dropped(scanner, target: Path, *uris: str) -> list:
    report = SarifReport.model_validate(
        _report(*(_result(uri, "github-pat", 1) for uri in uris))
    )
    scanner._drop_results_under_output_dir(report, target)
    return [
        r.locations[0].physicalLocation.root.artifactLocation.uri
        for r in report.runs[0].results
    ]


@posix_names
def test_a_backslash_in_a_posix_file_name_is_not_a_separator(tmp_path):
    """Read as one, a file named like the output directory's path was dropped."""
    scanner = _scanner(tmp_path)
    source = Path(scanner.context.source_dir)
    _write(source, ".ash\\ash_output\\x.py")
    assert _dropped(scanner, source, ".ash\\ash_output\\x.py") == [
        ".ash\\ash_output\\x.py"
    ]


def _tree_with_an_earlier_report(tmp_path) -> Path:
    """A source tree holding ``app/x.py`` and an earlier run's report under the
    default ``.ash/ash_output``."""
    source = tmp_path / "src"
    source.mkdir()
    _write(source, "app/x.py")
    _write(source, ".ash/ash_output/reports/old.json", "{}")
    return source


def _repository_at(directory: Path) -> None:
    """Make ``directory`` a repository with ``app/x.py`` committed, so git can
    say which of the files below it the repository holds."""
    environ = {
        key: value
        for key, value in os.environ.items()
        if key not in ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE")
    }

    def git(*args: str) -> None:
        subprocess.run(
            ["git", *args], cwd=directory, env=environ, check=True, capture_output=True
        )

    git("init", "-q")
    git("add", "app/x.py")
    git(
        "-c",
        "user.name=ash-test",
        "-c",
        "user.email=ash-test@example.com",
        "commit",
        "-q",
        "-m",
        "committed",
    )


def test_an_earlier_runs_default_output_dir_is_dropped_too(tmp_path, monkeypatch):
    """Every other directory-walking scanner skips the default .ash/ash_output an
    earlier run left in the tree; gitleaks dropped only this run's.

    The directory is ASH's only where git can say which of its files are
    committed (``scan_output_dirs.classified_output_dirs``), so the tree is a
    repository and the earlier report is untracked in it. The first cut of this
    test built a plain directory and read the designed scan of it as a miss."""
    isolate_git_at(tmp_path, monkeypatch)
    source = _tree_with_an_earlier_report(tmp_path)
    _repository_at(source)
    scanner = _scanner_at(source, tmp_path / "out")
    assert _dropped(
        scanner, source, ".ash/ash_output/reports/old.json", "app/x.py"
    ) == ["app/x.py"]


def test_an_earlier_runs_output_dir_outside_a_checkout_is_kept(tmp_path, monkeypatch):
    """Outside a checkout nothing tells the repository's files in .ash/ash_output
    from ASH's, so the directory is scanned like the rest of the tree and its
    findings stay; the scan set warns about it instead."""
    isolate_git_at(tmp_path, monkeypatch)
    source = _tree_with_an_earlier_report(tmp_path)
    scanner = _scanner_at(source, tmp_path / "out")
    assert _dropped(
        scanner, source, ".ash/ash_output/reports/old.json", "app/x.py"
    ) == [".ash/ash_output/reports/old.json", "app/x.py"]


# --------------------------------------------------------------------------- #
# An empty re-scan report is not a clean re-scan
# --------------------------------------------------------------------------- #


def _rescan_writing(tmp_path, monkeypatch, text: str):
    scanner, _ = _rescan_harness(tmp_path, monkeypatch, {})
    source = Path(scanner.context.source_dir)
    _write(source, "app/x.py")
    (source / ".gitleaksignore").write_text("app/x.py:github-pat:1\n")

    def writing(command, results_dir=None, timeout=None, cwd=None, **kwargs):
        report = next(
            a.split("=", 1)[1] for a in command if a.startswith("--report-path=")
        )
        Path(report).write_text(text)
        return {"returncode": 0}

    monkeypatch.setattr(scanner, "_run_subprocess", writing)
    return scanner, source


def test_an_empty_re_scan_report_fails_the_scan(tmp_path, monkeypatch):
    scanner, source = _rescan_writing(tmp_path, monkeypatch, "")
    with pytest.raises(ScannerError, match="empty report"):
        _add_back(scanner, source, _report(), tmp_path)


def test_a_re_scan_report_without_a_run_fails_the_scan(tmp_path, monkeypatch):
    scanner, source = _rescan_writing(tmp_path, monkeypatch, '{"version": "2.1.0"}')
    with pytest.raises(ScannerError, match="no SARIF run"):
        _add_back(scanner, source, _report(), tmp_path)
