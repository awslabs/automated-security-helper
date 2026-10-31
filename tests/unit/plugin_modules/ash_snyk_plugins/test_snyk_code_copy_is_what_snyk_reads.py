# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""snyk-code judges, copies and grades by the files snyk is given, not the tree.

The source target is tested as a copy of the scan set, so what counts is what the
copy holds. Six readings that went wrong before:

- With ``honor_ignore_files: false`` the ``.gitignore`` files copied into the
  snyk copy still made snyk skip the files they name, which ASH itself scans. A
  ``.gitignore`` is now left out of the copy then, and for the converted target,
  tested in place, it counts as an exclusion file.
- The exclusion-file check walked the whole original tree, so a ``.dcignore`` in a
  directory the scan set leaves out refused a scan snyk would never have read it
  in. The source target is now checked on its copy.
- ``_sweep_abandoned_copies`` removed any of this user's directories under TMPDIR
  whose name starts like a copy's, the scanned source or the output directory
  included. The scan's own directories are never removed.
- A source whose scan set holds nothing returned True with no claim, so the row
  read PASSED with exit code 0 for a tool that never ran. It now records that
  nothing was evaluated, which grades SKIPPED.
- The copy was built without the workspace's output directory, so a scan set
  built when the run's list is not read back took the files there along.
- A file snyk-code could not copy was logged and nothing more, so a partial scan
  graded PASSED. Each such file is now an unevaluated target, which grades ERROR
  naming it.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import List
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.plugin_modules.ash_snyk_plugins import snyk_code_scanner
from automated_security_helper.plugin_modules.ash_snyk_plugins.snyk_code_scanner import (
    SnykCodeScanner,
    SnykCodeScannerConfig,
    tree_exclusion_files,
)

pytestmark = pytest.mark.unit

SARIF = json.dumps(
    {
        "version": "2.1.0",
        "runs": [
            {"tool": {"driver": {"name": "SnykCode", "rules": []}}, "results": []}
        ],
    }
)
OUTPUT_FLAG = "--sarif-file-output="


@pytest.fixture(autouse=True)
def snyk_on_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    binary = tmp_path / "bin" / "snyk"
    binary.parent.mkdir(parents=True)
    binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    monkeypatch.setattr(snyk_code_scanner, "find_executable", lambda name: str(binary))
    monkeypatch.setenv("SNYK_TOKEN", "placeholder-token")
    monkeypatch.delenv("ASH_OFFLINE", raising=False)


def _context(
    tmp_path: Path, *, honor_ignore_files: bool = True, **extra
) -> PluginContext:
    config = get_default_config()
    if not honor_ignore_files:
        config = config.model_copy(update={"honor_ignore_files": False})
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=config,
        **extra,
    )
    for path in (context.source_dir, context.output_dir, context.work_dir):
        path.mkdir(parents=True, exist_ok=True)
    return context


def _write(root: Path, name: str, text: str = "const a = 1;\n") -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


@pytest.fixture
def tested() -> dict:
    """What snyk was given: the directory and the files below it, by relative path."""
    seen: dict = {}

    def run(self, command, **kwargs):
        destination = next(
            a.split("=", 1)[1] for a in command if a.startswith(OUTPUT_FLAG)
        )
        directory = Path(
            next(a for a in command[3:] if not a.startswith("-") and a != destination)
        )
        seen["directory"] = directory
        seen["files"] = sorted(
            p.relative_to(directory).as_posix()
            for p in directory.rglob("*")
            if p.is_file()
        )
        seen.setdefault("runs", 0)
        seen["runs"] += 1
        Path(destination).write_text(SARIF, encoding="utf-8")
        return {"stdout": "", "stderr": "", "returncode": 0}

    with patch.object(SnykCodeScanner, "_run_subprocess", autospec=True) as double:
        double.side_effect = run
        yield seen


def _scan(context: PluginContext, target_type: str = "source", **options):
    scanner = SnykCodeScanner(
        context=context, config=SnykCodeScannerConfig(options=options)
    )
    target = Path(context.source_dir if target_type == "source" else context.work_dir)
    return scanner, scanner.scan(target=target, target_type=target_type)


# --- .gitignore under honor_ignore_files: false -----------------------------------


def test_with_ignore_files_not_honored_the_copy_holds_no_gitignore(tmp_path, tested):
    context = _context(tmp_path, honor_ignore_files=False)
    _write(context.source_dir, "app.js")
    _write(context.source_dir, ".gitignore", "app.js\n")

    _scan(context)

    assert tested["files"] == ["app.js"], tested


def test_control_with_ignore_files_honored_the_copy_keeps_the_gitignore(
    tmp_path, tested
):
    """The scan set left out what the .gitignore names, so copying it changes
    nothing snyk tests."""
    context = _context(tmp_path, honor_ignore_files=True)
    _write(context.source_dir, "app.js")
    _write(context.source_dir, "kept.js")
    _write(context.source_dir, ".gitignore", "app.js\n")

    _scan(context)

    assert tested["files"] == [".gitignore", "kept.js"], tested


def test_with_ignore_files_not_honored_a_gitignore_in_the_converted_target_refuses(
    tmp_path, tested
):
    context = _context(tmp_path, honor_ignore_files=False)
    _write(context.work_dir, "notebook.py")
    _write(context.work_dir, ".gitignore", "notebook.py\n")

    with pytest.raises(ScannerError, match=r"\.gitignore"):
        _scan(context, target_type="converted")

    assert tested.get("runs", 0) == 0


def test_a_gitignore_counts_as_an_exclusion_file_only_when_asked(tmp_path):
    root = tmp_path / "tree"
    _write(root, ".gitignore", "app.js\n")
    _write(root, "app.js")

    assert tree_exclusion_files(root) == []
    assert tree_exclusion_files(root, gitignore_excludes=True) == [root / ".gitignore"]


# --- exclusion files outside the scan set -----------------------------------------


def test_an_exclusion_file_outside_the_scan_set_does_not_refuse_the_source(
    tmp_path, tested
):
    """A .dcignore under a gitignored directory never reaches snyk, since the copy
    holds the scan set only; refusing on it stopped a scan snyk could run."""
    context = _context(tmp_path)
    _write(context.source_dir, "app.js")
    _write(context.source_dir, ".gitignore", "vendor/\n")
    _write(context.source_dir, "vendor/.dcignore", "app.js\n")
    _write(context.source_dir, "vendor/lib.js")

    _scan(context)

    assert tested["runs"] == 1
    assert "vendor/.dcignore" not in tested["files"]


def test_control_an_exclusion_file_in_the_copy_still_refuses_the_source(
    tmp_path, tested
):
    context = _context(tmp_path)
    _write(context.source_dir, "app.js")
    _write(context.source_dir, ".dcignore", "app.js\n")

    with pytest.raises(ScannerError, match=r"\.dcignore") as raised:
        _scan(context)

    assert "honor_tree_exclusions" in str(raised.value)
    assert tested.get("runs", 0) == 0


# --- the sweep and the scan's own directories -------------------------------------


@pytest.mark.skipif(
    sys.platform == "win32", reason="the liveness check uses flock, which is POSIX"
)
def test_the_sweep_never_removes_the_scanned_source_or_the_output_directory(
    tmp_path, tested, monkeypatch
):
    temp_root = tmp_path / "tmp"
    temp_root.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(temp_root))
    source = temp_root / "ash-snyk-code-project"
    output = temp_root / "ash-snyk-code-out"
    _write(source, "app.js")
    # Every directory the scan touches exists before the backdate, so nothing the
    # scan creates refreshes a mtime the sweep reads. The default scan timeout
    # (1800 s, base/options.py) is the sweep's age bound; 7200 s is past it.
    (output / "converted").mkdir(parents=True)
    then = time.time() - 7200
    os.utime(source, (then, then))
    os.utime(output, (then, then))
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=get_default_config(),
    )

    _scan(context)

    assert (source / "app.js").exists(), "the sweep removed the scanned source"
    assert output.is_dir(), "the sweep removed the output directory"
    assert tested["runs"] == 1


@pytest.mark.skipif(
    sys.platform == "win32", reason="the liveness check uses flock, which is POSIX"
)
def test_the_sweep_keeps_only_the_directories_it_is_told_to_keep(tmp_path):
    """``keep`` is what protects the scan's directories, not their age or name.

    Three aged directories named like copies: with the scan's two in ``keep`` only
    the third is removed; the control without ``keep`` removes the two as well,
    which is what the scan-level test above cannot show (the output directory's
    mtime is refreshed by whatever the scan creates under it).
    """
    temp_root = tmp_path / "tmp"
    temp_root.mkdir()
    source = temp_root / "ash-snyk-code-project"
    output = temp_root / "ash-snyk-code-out"
    abandoned = temp_root / "ash-snyk-code-abandoned"
    _write(source, "app.js")
    output.mkdir()
    abandoned.mkdir()
    then = time.time() - 7200
    for directory in (source, output, abandoned):
        os.utime(directory, (then, then))

    snyk_code_scanner._sweep_abandoned_copies(
        temp_root, older_than=60, keep=(source, output)
    )

    assert (source / "app.js").exists(), "the sweep removed a kept directory"
    assert output.is_dir(), "the sweep removed a kept directory"
    assert not abandoned.exists(), "the sweep left the abandoned copy"

    # The control: the same two directories, no longer kept, are removed too.
    snyk_code_scanner._sweep_abandoned_copies(temp_root, older_than=60)

    assert not source.exists(), "without keep the source would have stayed anyway"
    assert not output.exists(), "without keep the output would have stayed anyway"


# --- nothing to send ---------------------------------------------------------------


def test_a_scan_set_with_no_file_records_that_nothing_was_evaluated(tmp_path, tested):
    context = _context(tmp_path)
    (context.source_dir / "empty-dir").mkdir()

    scanner, result = _scan(context)

    assert result is True
    assert scanner.targets_attempted == 0
    assert tested.get("runs", 0) == 0


def test_a_scan_set_with_no_file_is_graded_skipped(tmp_path, tested):
    context = _context(tmp_path)
    (context.source_dir / "empty-dir").mkdir()
    executor = ScannerExecutor(
        plugin_context=context, progress_display=MagicMock(), scanner_tasks=[]
    )

    (container,) = executor._execute_scanner(
        "snyk-code",
        SnykCodeScanner(context=context, config=SnykCodeScannerConfig()),
        [{"path": context.source_dir, "type": "source"}],
    )

    assert container.status == ScannerStatus.SKIPPED, container.raw_results


# --- the copy is built under the run's rules ---------------------------------------


def test_the_workspace_output_directory_is_left_out_of_the_copy(tmp_path, tested):
    context = _context(tmp_path)
    workspace_output = context.source_dir / "workspace-out"
    _write(context.source_dir, "app.js")
    _write(workspace_output, "report.js")
    context.workspace_output_dir = workspace_output

    _scan(context)

    assert tested["files"] == ["app.js"], tested


# --- files that could not be copied ------------------------------------------------


@pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)
def test_a_file_that_could_not_be_copied_is_an_unevaluated_target(tmp_path, tested):
    """An in-tree link passes the leaving-links refusal and is not copied (a link
    is never followed into the copy). Its target is a file the scan set leaves out
    (named by the .gitignore), so its content is tested under no name: snyk never
    evaluates it, and the run says so."""
    context = _context(tmp_path)
    _write(context.source_dir, "app.js")
    _write(context.source_dir, ".gitignore", "lib.js\n")
    _write(context.source_dir, "vendor/lib.js")
    (context.source_dir / "alias.js").symlink_to(
        context.source_dir / "vendor" / "lib.js"
    )

    scanner, _ = _scan(context)

    assert tested["files"] == [".gitignore", "app.js"], tested
    assert scanner.unevaluated_targets == ["alias.js"]


@pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)
def test_a_link_to_a_file_the_scan_set_holds_is_tested_under_that_name(
    tmp_path, tested
):
    """A link to a file the scan set holds is not copied either, but snyk evaluates
    its content under the target's own name, so it is not an unevaluated target: a
    tree holding ``CLAUDE.md -> AGENTS.md`` must not grade ERROR on every run."""
    context = _context(tmp_path)
    _write(context.source_dir, "app.js")
    _write(context.source_dir, "AGENTS.md", "# agents\n")
    (context.source_dir / "CLAUDE.md").symlink_to(context.source_dir / "AGENTS.md")

    scanner, _ = _scan(context)

    assert tested["files"] == ["AGENTS.md", "app.js"], tested
    assert scanner.unevaluated_targets == []


@pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)
def test_a_link_to_a_file_an_ignore_path_keeps_out_of_the_copy_is_unevaluated(
    tmp_path, tested, monkeypatch
):
    """The target is in the scan set, but the operator's ignore path keeps it out
    of the copy, so the link's content is tested under no name: recorded, as a
    link to a file outside the set is. Judged against what the copy holds, not
    against the set.

    ``scan()`` refuses a source holding an ignored file before it copies anything
    (``_refuse_ignored_files``, pinned by its own tests); the copy's ignore skip
    is the second guard, which this test reaches by setting the first aside."""
    from automated_security_helper.models.core import IgnorePathWithReason

    monkeypatch.setattr(
        SnykCodeScanner, "_refuse_ignored_files", lambda self, *a, **k: None
    )
    context = _context(tmp_path)
    _write(context.source_dir, "app.js")
    _write(context.source_dir, "vendor/lib.js")
    (context.source_dir / "alias.js").symlink_to(
        context.source_dir / "vendor" / "lib.js"
    )
    scanner = SnykCodeScanner(context=context, config=SnykCodeScannerConfig())

    scanner.scan(
        target=Path(context.source_dir),
        target_type="source",
        global_ignore_paths=[IgnorePathWithReason(path="vendor/lib.js", reason="t")],
    )

    assert tested["files"] == ["app.js"], tested
    assert scanner.unevaluated_targets == ["alias.js"]


@pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)
def test_a_link_to_the_gitignore_the_copy_leaves_out_is_unevaluated(tmp_path, tested):
    """With ``honor_ignore_files: false`` the ``.gitignore`` is in the scan set but
    left out of the copy (the first test of this module). A link to it is then
    tested under no name, and unlike an ignore path this route needs no guard set
    aside: scan() refuses nothing here, so it is the shape a real run can reach."""
    context = _context(tmp_path, honor_ignore_files=False)
    _write(context.source_dir, "app.js")
    _write(context.source_dir, ".gitignore", "node_modules\n")
    (context.source_dir / "rules.txt").symlink_to(context.source_dir / ".gitignore")

    scanner, _ = _scan(context)

    assert tested["files"] == ["app.js"], tested
    assert scanner.unevaluated_targets == ["rules.txt"]


@pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)
def test_a_run_with_an_in_tree_link_to_a_copied_file_is_graded_passed(tmp_path, tested):
    context = _context(tmp_path)
    _write(context.source_dir, "app.js")
    _write(context.source_dir, "AGENTS.md", "# agents\n")
    (context.source_dir / "CLAUDE.md").symlink_to(context.source_dir / "AGENTS.md")
    executor = ScannerExecutor(
        plugin_context=context, progress_display=MagicMock(), scanner_tasks=[]
    )

    (container,) = executor._execute_scanner(
        "snyk-code",
        SnykCodeScanner(context=context, config=SnykCodeScannerConfig()),
        [{"path": context.source_dir, "type": "source"}],
    )

    assert container.status == ScannerStatus.PASSED, (
        container.status,
        container.errors,
    )


@pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)
def test_a_run_with_an_uncopied_file_is_not_graded_passed(tmp_path, tested):
    context = _context(tmp_path)
    _write(context.source_dir, "app.js")
    _write(context.source_dir, ".gitignore", "lib.js\n")
    _write(context.source_dir, "vendor/lib.js")
    (context.source_dir / "alias.js").symlink_to(
        context.source_dir / "vendor" / "lib.js"
    )
    executor = ScannerExecutor(
        plugin_context=context, progress_display=MagicMock(), scanner_tasks=[]
    )

    (container,) = executor._execute_scanner(
        "snyk-code",
        SnykCodeScanner(context=context, config=SnykCodeScannerConfig()),
        [{"path": context.source_dir, "type": "source"}],
    )

    # ERROR, as the module docstring says: SKIPPED is the grade of a scan set that
    # held nothing, and FAILED of findings, so neither stands in for a file that
    # could not be copied.
    assert container.status == ScannerStatus.ERROR, container.status
    errors: List[str] = [str(error) for error in container.errors or []]
    assert any("alias.js" in error for error in errors), errors
