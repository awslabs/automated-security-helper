# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Where git cannot say what is committed, only this run's output directory is left out.

ASH names its own output directories and leaves them out of every scan: this
run's, and ``.ash/ash_output`` under the source and the working directory, where
an earlier run's output usually is. In a git checkout the files git tracks in
those are scanned anyway. Outside one, or where git gives no answer for the
repository, nothing tells a file the repository put in a ``.ash/ash_output``
from ASH's own; leaving the whole directory out would let a ``.ash/ash_output``
holding any file at all hide it from every scanner when the scan wrote its output
elsewhere.

So only this run's output directory is left out there, including, inside ASH's
container, the host's output directory as the mounted tree holds it
(``ASH_ACTUAL_SOURCE_DIR`` and ``ASH_ACTUAL_OUTPUT_DIR``). A ``.ash/ash_output``
that is not this run's is scanned like the rest of the tree. Once the ignore
files have been applied, and only while the scan set still holds files in it,
one warning names it, says how many of its files the scan set holds, and says
how to leave it out: delete it or list it in an ignore file, since
``global_settings.ignore_paths`` leaves out its findings but not the warning. The
cost is that an earlier run's reports left there are scanned too, as they were
before ASH named its output directories.

Every path here is under ``tmp_path``.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

import pytest

from automated_security_helper.utils.get_scan_set import scan_set
from automated_security_helper.utils.scan_output_dirs import (
    named_output_dirs,
    output_dirs_to_exclude,
)
from tests.unit.workspace.test_execution import _git

pytestmark = pytest.mark.usefixtures("no_checkout_above_tmp_path")


def _tree(tmp_path: Path) -> tuple[Path, Path]:
    """A tree with a source file and an earlier run's ``.ash/ash_output``."""
    source = tmp_path / "repo"
    (source / "src").mkdir(parents=True)
    (source / "src" / "ok.py").write_text("x = 1\n", encoding="utf-8")
    leftover = source / ".ash" / "ash_output"
    (leftover / "hidden").mkdir(parents=True)
    (leftover / "hidden" / "planted.py").write_text("y = 2\n", encoding="utf-8")
    (leftover / "ash_aggregated_results.json").write_text("{}\n", encoding="utf-8")
    return source, leftover


def _relative(files, source: Path) -> list[str]:
    return sorted(Path(os.path.relpath(f, source)).as_posix() for f in files)


def _leftover_warnings(caplog) -> list[str]:
    return [
        record.getMessage()
        for record in caplog.records
        if record.levelno == logging.WARNING
        and ".ash/ash_output" in record.getMessage()
        and "ignore_paths" in record.getMessage()
    ]


def _scan_set(source: Path, output: Path, caplog) -> list[str]:
    with caplog.at_level(logging.WARNING):
        return _relative(scan_set(source=str(source), output=str(output)), source)


def test_without_git_a_leftover_output_dir_is_scanned_with_one_warning(
    tmp_path, monkeypatch, caplog
):
    source, _leftover = _tree(tmp_path)
    output = tmp_path / "out"
    monkeypatch.chdir(tmp_path)

    files = _scan_set(source, output, caplog)

    assert files == [
        ".ash/ash_output/ash_aggregated_results.json",
        ".ash/ash_output/hidden/planted.py",
        "src/ok.py",
    ], files
    warnings = _leftover_warnings(caplog)
    assert len(warnings) == 1, warnings
    assert (
        "which of the 2 files the scan set holds in it are committed" in (warnings[0])
    )
    assert "so they are scanned like the rest of the tree" in warnings[0], warnings
    assert named_output_dirs(source, output) == []
    assert output_dirs_to_exclude(source, output) == []


def _suggested_ignore_paths(message: str) -> list:
    """The ignore paths the warning's --config-overrides command adds, read the
    way a POSIX shell and ASH's override parser read it."""
    import shlex

    from automated_security_helper.config.resolve_config import (
        _apply_config_override,
    )

    words = shlex.split(message.split("--config-overrides ", 1)[1].rstrip("."))
    assert len(words) == 1, words
    key, _, value = words[0].partition("=")
    config: dict = {"global_settings": {"ignore_paths": []}}
    _apply_config_override(config, key, value)
    return config["global_settings"]["ignore_paths"]


@pytest.mark.parametrize(
    "relative",
    [
        ".ash/ash_output",
        "it's/.ash/ash_output",
        'say "hi"/.ash/ash_output',
        "both ' and \"/.ash/ash_output",
        "café dir/.ash/ash_output",
    ],
)
def test_the_suggested_command_adds_exactly_that_directory(relative, caplog):
    from automated_security_helper.utils.scan_output_dirs import (
        warn_about_scanned_output_dir,
    )

    with caplog.at_level(logging.WARNING):
        warn_about_scanned_output_dir(relative, 2)

    [message] = [r.getMessage() for r in caplog.records]
    assert _suggested_ignore_paths(message) == [
        {"path": f"{relative}/", "reason": "earlier ASH output"}
    ]


@pytest.mark.parametrize("ignore_file", [".ignore", ".gitignore"])
def test_no_warning_when_an_ignore_file_leaves_the_whole_directory_out(
    tmp_path, monkeypatch, caplog, ignore_file
):
    """The warning says the directory is scanned. When a root ignore file lists
    it, none of its files is in the scan set, so there is nothing to warn about:
    .gitignore prunes it from the walk, and .ignore drops its files after it."""
    source, _leftover = _tree(tmp_path)
    (source / ignore_file).write_text(".ash/\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    files = _scan_set(source, tmp_path / "out", caplog)

    assert not [f for f in files if f.startswith(".ash/")], files
    assert _leftover_warnings(caplog) == []


def test_the_warning_counts_only_the_files_the_scan_set_keeps(
    tmp_path, monkeypatch, caplog
):
    source, _leftover = _tree(tmp_path)
    (source / ".ignore").write_text(".ash/ash_output/hidden/\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    files = _scan_set(source, tmp_path / "out", caplog)

    assert ".ash/ash_output/ash_aggregated_results.json" in files, files
    assert ".ash/ash_output/hidden/planted.py" not in files, files
    warnings = _leftover_warnings(caplog)
    assert len(warnings) == 1, warnings
    assert "whether the 1 file the scan set holds in it is committed" in warnings[0]
    assert "so it is scanned like the rest of the tree" in warnings[0], warnings
    assert "2 files" not in warnings[0], warnings


def test_the_warning_says_it_repeats_after_the_ignore_path_is_added(caplog):
    """global_settings.ignore_paths leaves the directory's findings out of the
    results, but the scan set is walked before it applies, so the warning comes
    back on the next scan."""
    from automated_security_helper.utils.scan_output_dirs import (
        warn_about_scanned_output_dir,
    )

    with caplog.at_level(logging.WARNING):
        warn_about_scanned_output_dir(".ash/ash_output", 2)

    [message] = [r.getMessage() for r in caplog.records]
    assert "until the directory is deleted or an ignore file lists it" in message, (
        message
    )


def test_without_git_this_runs_output_dir_in_the_tree_stays_out(
    tmp_path, monkeypatch, caplog
):
    source, _leftover = _tree(tmp_path)
    output = source / "out"
    output.mkdir()
    (output / "ash.log").write_text("log\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    files = _scan_set(source, output, caplog)

    assert "out/ash.log" not in files, files
    assert ".ash/ash_output/hidden/planted.py" in files, files
    assert len(_leftover_warnings(caplog)) == 1
    assert named_output_dirs(source, output) == [output]


def test_without_git_the_default_output_dir_this_run_writes_stays_out(
    tmp_path, monkeypatch, caplog
):
    """``.ash/ash_output`` is this run's own output directory: left out whole,
    with no warning."""
    source, leftover = _tree(tmp_path)
    monkeypatch.chdir(tmp_path)

    files = _scan_set(source, leftover, caplog)

    assert files == ["src/ok.py"], files
    assert _leftover_warnings(caplog) == []
    assert named_output_dirs(source, leftover) == [leftover]


def test_when_git_gives_no_answer_for_the_repository_the_leftover_is_scanned(
    tmp_path, monkeypatch, caplog
):
    source, _leftover = _tree(tmp_path)
    _git(source, "init", "-q")
    assert _git(source, "add", "src").returncode == 0
    # A repository git cannot read: it refuses an unknown format version.
    _git(source, "config", "core.repositoryformatversion", "99")
    assert _git(source, "ls-files").returncode != 0
    output = tmp_path / "out"
    monkeypatch.chdir(tmp_path)

    files = _scan_set(source, output, caplog)

    assert ".ash/ash_output/hidden/planted.py" in files, files
    assert len(_leftover_warnings(caplog)) == 1
    assert named_output_dirs(source, output) == []


def test_in_a_checkout_git_answers_for_the_leftover_keeps_its_own_files_out(
    tmp_path, monkeypatch, caplog
):
    """git says which files are committed there, so the rest stays out,
    and there is no warning about the directory being scanned."""
    source, leftover = _tree(tmp_path)
    _git(source, "init", "-q")
    added = _git(source, "add", "src", ".ash/ash_output/hidden/planted.py")
    assert added.returncode == 0, added.stderr
    output = tmp_path / "out"
    monkeypatch.chdir(tmp_path)

    files = _scan_set(source, output, caplog)

    assert files == [".ash/ash_output/hidden/planted.py", "src/ok.py"], files
    assert _leftover_warnings(caplog) == []
    assert named_output_dirs(source, output) == [leftover]


def test_in_ash_container_the_hosts_output_dir_in_the_tree_is_this_runs(
    tmp_path, monkeypatch, caplog
):
    """Inside ASH's container the scan writes to ``/out``, and the tree mounted at
    ``/src`` holds the host's output directory, the same directory, at
    ``.ash/ash_output``: it is this run's, so it is left out with no warning."""
    source, _leftover = _tree(tmp_path)
    monkeypatch.setenv("ASH_ACTUAL_SOURCE_DIR", "/home/dev/repo")
    monkeypatch.setenv("ASH_ACTUAL_OUTPUT_DIR", "/home/dev/repo/.ash/ash_output")
    output = tmp_path / "mounted-out"
    output.mkdir()
    monkeypatch.chdir(tmp_path)

    files = _scan_set(source, output, caplog)

    assert files == ["src/ok.py"], files
    assert _leftover_warnings(caplog) == []


@pytest.mark.parametrize(
    "actual_source, actual_output, relative",
    [
        ("/home/dev/repo", "/home/dev/repo/build/ash", "build/ash"),
        ("C:\\Users\\dev\\repo", "C:\\Users\\dev\\repo\\out", "out"),
        ("C:\\Users\\dev\\repo", "c:\\users\\dev\\REPO\\scans\\out", "scans/out"),
    ],
)
def test_the_hosts_output_dir_is_found_in_the_tree_from_the_host_paths(
    tmp_path, monkeypatch, actual_source, actual_output, relative
):
    source = tmp_path / "src"
    (source / relative).mkdir(parents=True)
    monkeypatch.setenv("ASH_ACTUAL_SOURCE_DIR", actual_source)
    monkeypatch.setenv("ASH_ACTUAL_OUTPUT_DIR", actual_output)

    named = named_output_dirs(source, tmp_path / "mounted-out")

    assert named == [source.joinpath(*relative.split("/"))], named


@pytest.mark.parametrize(
    "actual_source, actual_output",
    [
        ("/home/dev/repo", "/home/dev/out"),
        ("/home/dev/repo", "/home/dev/repo"),
        ("/home/dev/repo", "/home/dev/repo/../out"),
        ("relative/repo", "relative/repo/out"),
    ],
)
def test_a_host_output_dir_not_inside_the_host_source_names_nothing_in_the_tree(
    tmp_path, monkeypatch, actual_source, actual_output
):
    source = tmp_path / "src"
    (source / "out").mkdir(parents=True)
    monkeypatch.setenv("ASH_ACTUAL_SOURCE_DIR", actual_source)
    monkeypatch.setenv("ASH_ACTUAL_OUTPUT_DIR", actual_output)

    assert named_output_dirs(source, tmp_path / "mounted-out") == []
