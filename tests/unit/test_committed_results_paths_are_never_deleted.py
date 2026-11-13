# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ASH never deletes or overwrites a file git tracks in its output directory.

Before it starts, a scan clears its output directory of the previous run's output:
``ash_aggregated_results.json``, ``ash-ignore-report.txt`` and
``ash-scan-set-files-list.txt`` at its root, and the working directories
``analysis``, ``reports``, ``scanners`` and ``converted``, which it then fills again.
Done whatever git says, that would have a repository that committed a file to one of
those places, with the default output directory ``.ash/ash_output``, see it deleted
from the working tree by every scan.

A file git tracks at one of those paths stops the scan before anything is
deleted, with exit 3 and a message naming the file. The alternative, writing this
run's results under a name of its own, was rejected: ``ash report``, ``--use-existing``,
container mode, the MCP progress readers and the scan registry all read
``ash_aggregated_results.json`` at its fixed path, so a run-specific name would have
left each of them reading the committed file as this run's results. Refusing keeps
that path meaning one thing. A file git tracks anywhere else in the output directory
is not touched.

Every test here runs against a git repository under ``tmp_path``. The red run of
these tests executed the deletion they guard against, so each one checks first that
the directories the scan is given lie inside ``tmp_path``.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.exceptions import ASHConfigValidationError
from automated_security_helper.core.orchestrator import ASHScanOrchestrator
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils.scan_output_dirs import tracked_files_in
from tests.unit.workspace.test_execution import _git

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

#: A tree built without ``git init`` is outside git wherever tmp_path is
#: (tests/unit/conftest.py).
pytestmark = pytest.mark.usefixtures("no_checkout_above_tmp_path")

#: Paths, relative to the output directory, that a scan deletes and writes again.
RESULTS_PATHS = (
    "ash_aggregated_results.json",
    "ash-ignore-report.txt",
    "ash-scan-set-files-list.txt",
    "ash-scan-set-run.json",
    "reports/ash.sarif",
    "scanners/bandit/source/bandit.sarif",
    "converted/jupyter/notebook.py",
    "analysis/notes.json",
    # Where an MCP scan sets the previous results aside, and the marker a restore
    # leaves: a scan removes both when it starts (core/previous_results.py).
    ".ash_previous_results/reports/ash.sarif",
    ".ash_previous_results.partial/ash_aggregated_results.json",
    ".ash_previous_results_restored",
)

#: Files a previous run left, not in git.
LEFTOVERS = ("reports/old.html", "scanners/grype/source/results_sarif.sarif")


def _results_json(project_name: str) -> str:
    model = AshAggregatedResults()
    model.metadata.project_name = project_name
    return model.model_dump_json(by_alias=True)


def _repo(tmp_path: Path, committed: str) -> tuple[Path, Path, Path]:
    """A git repository whose default output directory holds *committed*, in git."""
    source = tmp_path / "repo"
    output = source / ".ash" / "ash_output"
    (source / "app.py").parent.mkdir(parents=True, exist_ok=True)
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    for relative in (committed, *LEFTOVERS):
        path = output / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        text = (
            _results_json("committed-results")
            if relative == "ash_aggregated_results.json"
            else f"committed {relative}\n"
        )
        path.write_text(text, encoding="utf-8")
    _git(source, "init", "-q")
    _git(source, "add", "app.py", f".ash/ash_output/{committed}")
    tracked = output / committed
    # A control: the fixture has to give git something to say.
    assert tracked in (tracked_files_in(output) or []), "git does not track it"
    return source, output, tracked


def _confined(tmp_path: Path, *paths: Path) -> None:
    """Stop before the scan when a directory it is given lies outside tmp_path."""
    root = tmp_path.resolve()
    for path in paths:
        assert Path(path).resolve().is_relative_to(root), path


def _snapshot(output: Path) -> dict[str, bytes]:
    return {
        p.relative_to(output).as_posix(): p.read_bytes()
        for p in sorted(output.rglob("*"))
        if p.is_file()
    }


class _EngineStub:
    def __init__(self):
        self._asharp_model = AshAggregatedResults()

    def execute_phases(self, phases=None):
        raise AssertionError("the scan went on to its phases")


def _orchestrator(source: Path, output: Path, **overrides) -> ASHScanOrchestrator:
    return ASHScanOrchestrator(
        source_dir=source,
        output_dir=output,
        config_path=None,
        config_overrides=None,
        no_cleanup=False,
        metadata=None,
        ash_plugin_modules=[],
        **overrides,
    )


def _initialize(orchestrator: ASHScanOrchestrator) -> None:
    with (
        patch(
            "automated_security_helper.core.orchestrator.resolve_config",
            return_value=AshConfig(project_name="test"),
        ),
        patch(
            "automated_security_helper.core.orchestrator.ScanExecutionEngine",
            return_value=_EngineStub(),
        ),
    ):
        orchestrator.initialize()


@pytest.mark.integration
@pytest.mark.parametrize("keep_previous_results", [False, True])
@pytest.mark.parametrize("committed", RESULTS_PATHS)
def test_a_committed_file_where_a_scan_writes_stops_it_before_anything_is_deleted(
    tmp_path, monkeypatch, committed, keep_previous_results
):
    """With keep_previous_results, as an MCP scan runs, the previous results are
    set aside rather than deleted, which moves them: the scan stops before that
    too."""
    source, output, tracked = _repo(tmp_path, committed)
    monkeypatch.chdir(tmp_path)
    orchestrator = _orchestrator(
        source, output, keep_previous_results=keep_previous_results
    )
    _confined(tmp_path, orchestrator.source_dir, orchestrator.output_dir)
    before = _snapshot(output)

    with pytest.raises(ASHConfigValidationError) as refused:
        _initialize(orchestrator)

    message = str(refused.value)
    assert committed in message, message
    assert "--output-dir" in message, message
    assert type(refused.value).__name__ == "CommittedOutputFilesError"
    # Nothing was deleted or rewritten: not the committed file, and not the untracked
    # files a previous run left, since the scan stopped before clearing anything.
    assert _snapshot(output) == before


@pytest.mark.integration
def test_a_committed_file_elsewhere_in_the_output_dir_is_kept_and_the_scan_goes_on(
    tmp_path, monkeypatch
):
    """A scan deletes and writes only its own paths, so a committed file anywhere
    else in the output directory neither stops it nor is touched. The files a
    previous run left at its own paths are removed."""
    source, output, tracked = _repo(tmp_path, "hidden/app.py")
    stale = output / "ash_aggregated_results.json"
    stale.write_text(_results_json("previous-run"), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    orchestrator = _orchestrator(source, output)
    _confined(tmp_path, orchestrator.source_dir, orchestrator.output_dir)

    _initialize(orchestrator)

    assert tracked.read_text(encoding="utf-8") == "committed hidden/app.py\n"
    assert not stale.exists()
    for leftover in LEFTOVERS:
        assert not (output / leftover).exists(), leftover


@pytest.mark.unit
def test_outside_git_a_previous_runs_files_are_removed(tmp_path, monkeypatch):
    source = tmp_path / "plain"
    output = source / ".ash" / "ash_output"
    for relative in RESULTS_PATHS:
        path = output / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("previous run\n", encoding="utf-8")
    assert tracked_files_in(output) is None
    monkeypatch.chdir(tmp_path)
    orchestrator = _orchestrator(source, output)
    _confined(tmp_path, orchestrator.source_dir, orchestrator.output_dir)

    _initialize(orchestrator)

    for relative in RESULTS_PATHS:
        assert not (output / relative).exists(), relative


@pytest.mark.integration
def test_the_scan_exits_3_and_leaves_the_committed_results_file_as_it_was(
    tmp_path, monkeypatch, capsys
):
    """Through the local run, as ``ash scan`` reaches it. The scan itself is stubbed
    to fail, so that if the refusal is missing no scanner runs."""
    from automated_security_helper.interactions.run_ash_scan import (
        ScanOptions,
        _run_local_mode,
    )

    source, output, tracked = _repo(tmp_path, "ash_aggregated_results.json")
    committed = tracked.read_bytes()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        ASHScanOrchestrator,
        "execute_scan",
        lambda self, *a, **k: (_ for _ in ()).throw(AssertionError("scanned")),
    )
    opts = ScanOptions(source_dir=source, output_dir=output)
    _confined(tmp_path, opts.source_dir, opts.output_dir)

    with pytest.raises(SystemExit) as exited:
        _run_local_mode(opts, logging.getLogger("test-committed-results"))

    assert exited.value.code == 3
    printed = capsys.readouterr().out
    assert "ash_aggregated_results.json" in printed, printed
    assert tracked.read_bytes() == committed


@pytest.mark.integration
def test_ash_report_reads_the_results_file_at_its_fixed_path_after_the_refusal(
    tmp_path, monkeypatch, capsys
):
    """``ash report`` writes nothing and reads ``ash_aggregated_results.json`` where
    every reader looks for it. The refused scan left that file as it was and wrote no
    results under another name, so ``ash report`` shows the file that is there."""
    from automated_security_helper.cli.report import report_command

    source, output, tracked = _repo(tmp_path, "ash_aggregated_results.json")
    monkeypatch.chdir(tmp_path)
    orchestrator = _orchestrator(source, output)
    _confined(tmp_path, orchestrator.source_dir, orchestrator.output_dir)
    with pytest.raises(ASHConfigValidationError):
        _initialize(orchestrator)
    capsys.readouterr()

    report_command(report_format="text", output_dir=str(output), color=False)

    rendered = capsys.readouterr().out
    assert (
        json.loads(tracked.read_text(encoding="utf-8"))["metadata"]["project_name"]
        == "committed-results"
    )
    assert "committed-results" in rendered, rendered
    assert sorted(p.name for p in output.glob("ash_aggregated_results*")) == [
        "ash_aggregated_results.json"
    ]


@pytest.mark.unit
def test_setting_the_previous_results_aside_moves_the_scan_set_record_with_them(
    tmp_path,
):
    """The record of the run that wrote the scan-set lists goes where the lists go,
    so the lists an MCP scan puts back are never taken for the new run's."""
    from automated_security_helper.core.previous_results import (
        HELD_DIR_NAME,
        PreviousResults,
    )

    output = tmp_path / "out"
    output.mkdir()
    for name in (
        "ash-ignore-report.txt",
        "ash-scan-set-files-list.txt",
        "ash-scan-set-run.json",
    ):
        (output / name).write_text("previous\n", encoding="utf-8")

    PreviousResults(output).set_aside()

    assert not (output / "ash-scan-set-run.json").exists()
    assert (output / HELD_DIR_NAME / "ash-scan-set-run.json").is_file()


def _entries(output: Path) -> dict[str, tuple[str, str]]:
    """Every entry under *output* as it is on disk, links read and not followed."""
    found: dict[str, tuple[str, str]] = {}
    for root, dirs, files in os.walk(output):
        for name in [*dirs, *files]:
            path = Path(root) / name
            relative = path.relative_to(output).as_posix()
            if path.is_symlink():
                found[relative] = ("link", os.readlink(path))
            elif path.is_file():
                found[relative] = ("file", path.read_bytes().hex())
            else:
                found[relative] = ("dir", "")
    return found


#: Directories a scan clears whole, committed as links to a directory.
DIRECTORY_LINKS = ("reports", ".ash_previous_results")

#: A committed link at any results path stops a scan, as a committed file does; the
#: directories a scan clears whole are among them.
LINKED_RESULTS_PATHS = (*RESULTS_PATHS, *DIRECTORY_LINKS)


@pytest.mark.integration
@pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)
@pytest.mark.parametrize("keep_previous_results", [False, True])
@pytest.mark.parametrize("committed", LINKED_RESULTS_PATHS)
def test_a_committed_link_where_a_scan_writes_stops_it_before_anything_is_deleted(
    tmp_path, monkeypatch, committed, keep_previous_results
):
    """Whatever kind of entry git tracks there, a link included, the scan stops: it
    would remove the entry from the working tree, or move it when an MCP scan sets
    the previous results aside. The link's target, outside the repository, is left
    as it was too."""
    outside = tmp_path / "outside"
    target = outside / "target"
    if committed in DIRECTORY_LINKS:
        target.mkdir(parents=True)
        (target / "kept.txt").write_text("kept\n", encoding="utf-8")
    else:
        outside.mkdir()
        target.write_text("target\n", encoding="utf-8")
    source = tmp_path / "repo"
    output = source / ".ash" / "ash_output"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    link = output / committed
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(target, target_is_directory=target.is_dir())
    _git(source, "init", "-q")
    _git(source, "add", "app.py", f".ash/ash_output/{committed}")
    staged = _git(source, "ls-files", "-s", f".ash/ash_output/{committed}").stdout
    # A control: git tracks the link itself.
    assert staged.startswith("120000 "), staged
    monkeypatch.chdir(tmp_path)
    orchestrator = _orchestrator(
        source, output, keep_previous_results=keep_previous_results
    )
    _confined(tmp_path, orchestrator.source_dir, orchestrator.output_dir, target)
    before = _entries(output)
    outside_before = _entries(outside)

    with pytest.raises(ASHConfigValidationError) as refused:
        _initialize(orchestrator)

    assert committed in str(refused.value), refused.value
    assert _entries(output) == before
    assert _entries(outside) == outside_before


@pytest.mark.integration
def test_a_repository_layout_in_the_output_dir_does_not_hide_its_committed_files(
    tmp_path, monkeypatch
):
    """Committed files can make the output directory read, to git's own search from
    inside it, as a repository of its own with an empty index. A committed results
    file beside them still stops the scan."""
    from tests.unit.test_committed_output_entries_are_regular_files import (
        _plant_repository_layout,
    )

    source = tmp_path / "repo"
    output = source / ".ash" / "ash_output"
    output.mkdir(parents=True)
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    results = output / "ash_aggregated_results.json"
    results.write_text(_results_json("committed-results"), encoding="utf-8")
    _plant_repository_layout(output, tmp_path / "elsewhere")
    _git(source, "init", "-q")
    _git(source, "add", "app.py", ".ash/ash_output")
    # A control: git run from the output directory itself lists nothing there.
    assert "ash_aggregated_results.json" not in _git(output, "ls-files").stdout
    monkeypatch.chdir(tmp_path)
    orchestrator = _orchestrator(source, output)
    _confined(tmp_path, orchestrator.source_dir, orchestrator.output_dir)
    before = _snapshot(output)

    with pytest.raises(ASHConfigValidationError) as refused:
        _initialize(orchestrator)

    assert "ash_aggregated_results.json" in str(refused.value), refused.value
    assert _snapshot(output) == before
