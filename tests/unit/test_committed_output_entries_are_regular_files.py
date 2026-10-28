# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Only regular files under an output directory are taken from git's index there.

In a git checkout, ASH lists the files git tracks in its output directories and
scans them (``tracked_files_in``). Taking every index entry that is not a
directory would take a symbolic link too, wherever it pointed, and the scan set, the
scanners reading it and the drop's list of committed files would then treat the link
as a committed file. So an entry is taken only when it is a regular file, reached
without a link from the output directory, and its normalized path stays inside that
directory. Every other entry is left out, with a debug message naming it.

Every path these tests create is under ``tmp_path``. The files the links point at
are created there too, outside the repository.
"""

from __future__ import annotations

import os
import shlex
import sys
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.utils.get_scan_set import scan_set
from automated_security_helper.utils.scan_output_dirs import (
    committed_output_files,
    tracked_files_in,
)
from tests.unit.workspace.test_execution import _git

AshConfig.model_rebuild()
PluginContext.model_rebuild()

pytestmark = [
    pytest.mark.skipif(
        sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
    ),
    # The scanners built here start no tool (tests/unit/conftest.py).
    pytest.mark.usefixtures("no_tool_probes"),
]

#: The output directories under test: the default, and one inside the tree given
#: with --output-dir.
OUTPUTS = (".ash/ash_output", "out")


def _layout(tmp_path: Path, output_rel: str):
    """A repository whose output directory holds, all in git: a regular file, a link
    to a file outside the repository, and a link to a directory outside it."""
    outside = tmp_path / "outside"
    outside.mkdir()
    marker = outside / "marker.txt"
    marker.write_text("marker\n", encoding="utf-8")
    (outside / "dir").mkdir()
    (outside / "dir" / "inner.txt").write_text("inner\n", encoding="utf-8")

    source = tmp_path / "repo"
    output = source / output_rel
    hidden = output / "hidden"
    hidden.mkdir(parents=True)
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    (hidden / "regular.py").write_text("y = 2\n", encoding="utf-8")
    (hidden / "file-link.txt").symlink_to(marker)
    (hidden / "dir-link").symlink_to(outside / "dir", target_is_directory=True)
    _git(source, "init", "-q")
    added = _git(source, "add", "app.py", f"{output_rel}/hidden")
    assert added.returncode == 0, added.stderr
    listed = _git(source, "ls-files", f"{output_rel}/hidden").stdout.split()
    # A control: git indexed the two links, so the test can see what ASH does with
    # them.
    assert sorted(listed) == sorted(
        f"{output_rel}/hidden/{name}"
        for name in ("dir-link", "file-link.txt", "regular.py")
    ), listed
    return source, output, marker


@pytest.mark.parametrize("output_rel", OUTPUTS)
def test_git_index_entries_are_taken_only_as_regular_files(tmp_path, output_rel):
    source, output, _marker = _layout(tmp_path, output_rel)

    found = tracked_files_in(output)

    assert found == [output / "hidden" / "regular.py"], found


@pytest.mark.parametrize("output_rel", OUTPUTS)
def test_the_scan_set_holds_only_the_regular_file(tmp_path, monkeypatch, output_rel):
    source, output, _marker = _layout(tmp_path, output_rel)
    monkeypatch.chdir(tmp_path)

    files = scan_set(source=str(source), output=str(output))

    under_output = sorted(
        Path(f).relative_to(output).as_posix()
        for f in files
        if Path(f).is_relative_to(output)
    )
    assert under_output == ["hidden/regular.py"], files


@pytest.mark.parametrize("output_rel", OUTPUTS)
def test_detect_secrets_reads_no_linked_file(tmp_path, monkeypatch, output_rel):
    """detect-secrets reads its files in worker processes, so what it read is told
    by what it found: the same key is in the regular file and in the file outside
    the repository that the link points at."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        DetectSecretsScanner,
        DetectSecretsScannerConfig,
    )
    from tests.unit.plugin_modules.ash_builtin.test_detect_secrets_scanner_behavior import (
        PLANTED_KEY,
    )

    source, output, marker = _layout(tmp_path, output_rel)
    secret = f"AWS_ACCESS_KEY_ID = '{PLANTED_KEY}'\n"
    for path in (marker, output / "hidden" / "regular.py"):
        path.write_text(secret, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=AshConfig(),
    )
    scanner = DetectSecretsScanner(context=context, config=DetectSecretsScannerConfig())

    report = scanner.scan(target=source, target_type="source")

    uris = {
        r.locations[0].physicalLocation.root.artifactLocation.uri
        for r in report.runs[0].results
    }
    assert uris == {f"{output_rel}/hidden/regular.py"}, uris


@pytest.mark.parametrize("output_rel", OUTPUTS)
def test_a_link_in_the_scan_set_is_not_taken_as_a_committed_file(tmp_path, output_rel):
    """The drop keeps a result only in a committed file: a scan set naming a link,
    as one read back from the output directory may, keeps nothing for it."""
    source, output, _marker = _layout(tmp_path, output_rel)
    context = PluginContext(source_dir=source, output_dir=output, config=AshConfig())
    hidden = output / "hidden"
    listed = [
        str(hidden / name) for name in ("regular.py", "file-link.txt", "dir-link")
    ]

    committed = committed_output_files(context, scanned_files=listed, dirs=[output])

    assert committed == {(hidden / "regular.py").resolve()}, committed


def test_git_is_asked_with_the_repositorys_hooks_and_fsmonitor_turned_off(
    tmp_path, monkeypatch
):
    """The repository's own config names the programs these two settings run, so
    both are set on the command line, where they take precedence."""
    from automated_security_helper.utils import scan_output_dirs
    from automated_security_helper.utils import subprocess_utils

    seen = {}

    class _Result:
        returncode = 0
        stdout = b""

    def fake_spawn(command, **kwargs):
        seen["argv"] = list(command)
        return _Result()

    monkeypatch.setattr(subprocess_utils, "spawn_run", fake_spawn)
    (tmp_path / "repo" / ".git").mkdir(parents=True)
    output = tmp_path / "repo" / "out"
    output.mkdir()

    scan_output_dirs.tracked_files_in(output)

    argv = seen["argv"]
    overrides = {argv[i + 1] for i, item in enumerate(argv[:-1]) if item == "-c"}
    assert {"core.fsmonitor=false", "core.hooksPath=/dev/null"} <= overrides, argv
    assert argv[0] == "git" and "ls-files" in argv and "-z" in argv, argv


def test_git_is_asked_about_the_repository_the_directory_is_in(tmp_path, monkeypatch):
    """The repository is named on the command line, found from the directory's
    ancestors, so git's own search from inside the directory plays no part; the
    directory is the pathspec, taken literally."""
    from automated_security_helper.utils import scan_output_dirs
    from automated_security_helper.utils import subprocess_utils

    seen = {}

    class _Result:
        returncode = 0
        stdout = b""

    def fake_spawn(command, **kwargs):
        seen["argv"] = list(command)
        seen["cwd"] = kwargs.get("cwd")
        return _Result()

    monkeypatch.setattr(subprocess_utils, "spawn_run", fake_spawn)
    root = tmp_path / "repo"
    (root / ".git").mkdir(parents=True)
    output = root / ".ash" / "out[1]"
    output.mkdir(parents=True)

    scan_output_dirs.tracked_files_in(output)

    argv = seen["argv"]
    assert f"--git-dir={root / '.git'}" in argv, argv
    assert f"--work-tree={root}" in argv, argv
    assert "--literal-pathspecs" in argv, argv
    assert argv[-2:] == ["--", ".ash/out[1]"], argv
    assert Path(seen["cwd"]) == root


def test_outside_a_repository_git_is_not_asked(tmp_path, monkeypatch):
    from automated_security_helper.utils import scan_output_dirs
    from automated_security_helper.utils import subprocess_utils

    asked = []

    class _Result:
        returncode = 0
        stdout = b""

    def fake_spawn(command, **kwargs):
        asked.append(list(command))
        return _Result()

    monkeypatch.setattr(subprocess_utils, "spawn_run", fake_spawn)
    # tmp_path may sit inside a checkout; nothing above it is looked at.
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    output = tmp_path / "plain" / "out"
    output.mkdir(parents=True)

    assert scan_output_dirs.tracked_files_in(output) is None
    assert asked == []


def test_a_name_that_leaves_the_directory_is_not_taken(tmp_path, monkeypatch):
    """git does not index a name with a '..' component; one is fed to the parsing
    here directly, through a stand-in for git's output."""
    from automated_security_helper.utils import scan_output_dirs
    from automated_security_helper.utils import subprocess_utils

    root = tmp_path / "repo"
    (root / ".git").mkdir(parents=True)
    output = root / ".ash" / "ash_output"
    (output / "hidden").mkdir(parents=True)
    (output / "hidden" / "regular.py").write_text("y = 2\n", encoding="utf-8")
    (root / "escape.txt").write_text("z = 3\n", encoding="utf-8")

    class _Result:
        returncode = 0
        stdout = (
            b".ash/ash_output/hidden/regular.py\0"
            b".ash/ash_output/hidden/../../../escape.txt\0"
        )

    monkeypatch.setattr(subprocess_utils, "spawn_run", lambda *a, **k: _Result())

    found = scan_output_dirs.tracked_files_in(output)

    assert found == [output / "hidden" / "regular.py"], found


def _plant_repository_layout(directory: Path, elsewhere: Path) -> list[str]:
    """Committable files that make *directory* read, to git's own search from inside
    it, as a repository whose work tree is *elsewhere*."""
    elsewhere.mkdir(parents=True, exist_ok=True)
    files = {
        "HEAD": "ref: refs/heads/main\n",
        "config": (
            "[core]\n\trepositoryformatversion = 0\n\tbare = false\n"
            f"\tworktree = {elsewhere.as_posix()}\n"
        ),
        "objects/.keep": "",
        "refs/.keep": "",
    }
    for name, text in files.items():
        path = directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return list(files)


@pytest.mark.parametrize("output_rel", OUTPUTS)
def test_files_in_a_directory_laid_out_like_a_repository_are_still_listed(
    tmp_path, output_rel
):
    source = tmp_path / "repo"
    output = source / output_rel
    (output / "hidden").mkdir(parents=True)
    (output / "hidden" / "regular.py").write_text("y = 2\n", encoding="utf-8")
    planted = _plant_repository_layout(output, tmp_path / "elsewhere")
    _git(source, "init", "-q")
    added = _git(source, "add", output_rel)
    assert added.returncode == 0, added.stderr
    # A control: git run from the directory itself answers for the planted layout.
    inside = _git(output, "ls-files")
    assert "hidden/regular.py" not in inside.stdout, inside

    found = tracked_files_in(output)

    assert sorted(p.relative_to(output).as_posix() for p in found or []) == sorted(
        ["hidden/regular.py", *planted]
    ), found


def test_a_file_reached_through_a_linked_directory_is_not_taken(tmp_path):
    """The index lists ``hidden/regular.py``, and the working tree's ``hidden`` has
    become a link to a directory outside the repository holding a regular file of
    that name: neither the index listing nor a scan set naming it takes it."""
    source, output, _marker = _layout(tmp_path, ".ash/ash_output")
    real = tmp_path / "outside" / "real-hidden"
    real.mkdir()
    (real / "regular.py").write_text("z = 3\n", encoding="utf-8")
    (output / "hidden").rename(tmp_path / "moved-hidden")
    (output / "hidden").symlink_to(real, target_is_directory=True)
    context = PluginContext(source_dir=source, output_dir=output, config=AshConfig())

    assert tracked_files_in(output) == []
    assert (
        committed_output_files(
            context,
            scanned_files=[str(output / "hidden" / "regular.py")],
            dirs=[output],
        )
        == set()
    )


def test_the_fsmonitor_program_the_repository_names_is_not_run(tmp_path):
    """``core.fsmonitor`` in the repository's own config can name a program, which
    git runs when it reads the index, ``git ls-files`` included. Listing the files
    in an output directory runs none: the command line turns the setting off. The
    program here only leaves a marker file behind."""
    source = tmp_path / "repo"
    output = source / ".ash" / "ash_output"
    (output / "hidden").mkdir(parents=True)
    (output / "hidden" / "regular.py").write_text("y = 2\n", encoding="utf-8")
    assert _git(source, "init", "-q").returncode == 0
    added = _git(source, "add", ".ash/ash_output/hidden/regular.py")
    assert added.returncode == 0, added.stderr
    marker = tmp_path / "fsmonitor-ran"
    program = tmp_path / "fsmonitor-program"
    program.write_text(
        f"#!/bin/sh\necho ran >> {shlex.quote(str(marker))}\nexit 1\n",
        encoding="utf-8",
    )
    program.chmod(0o755)
    assert _git(source, "config", "core.fsmonitor", str(program)).returncode == 0
    # A control: git run on the repository as it is configured runs the program.
    _git(source, "ls-files")
    assert marker.exists(), "git ran no fsmonitor program, so this test cannot fail"
    marker.unlink()

    found = tracked_files_in(output)

    assert found == [output / "hidden" / "regular.py"], found
    assert not marker.exists(), "the repository's fsmonitor program ran"


def _scanned_under(files, directory: Path) -> list[str]:
    return sorted(
        Path(f).relative_to(directory).as_posix()
        for f in files
        if Path(f).is_relative_to(directory)
    )


@pytest.mark.parametrize("output_rel", OUTPUTS)
def test_a_committed_link_to_a_directory_of_the_repository_is_not_taken(
    tmp_path, monkeypatch, output_rel
):
    """A committed ``docs -> ../../docs`` in the output directory, a relative link to
    a directory of the same repository, once put that directory in the scan set. The
    link is left out, and the file it reaches is scanned once, where it is."""
    source = tmp_path / "repo"
    output = source / output_rel
    (source / "docs").mkdir(parents=True)
    (source / "docs" / "guide.py").write_text("z = 3\n", encoding="utf-8")
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    output.mkdir(parents=True)
    (output / "docs").symlink_to(
        os.path.relpath(source / "docs", output), target_is_directory=True
    )
    assert _git(source, "init", "-q").returncode == 0
    added = _git(source, "add", "app.py", "docs", f"{output_rel}/docs")
    assert added.returncode == 0, added.stderr
    staged = _git(source, "ls-files", "-s", f"{output_rel}/docs").stdout
    # A control: git tracks the link itself.
    assert staged.startswith("120000 "), staged
    monkeypatch.chdir(tmp_path)

    assert tracked_files_in(output) == []
    files = scan_set(source=str(source), output=str(output))
    assert _scanned_under(files, output) == [], files
    assert [f for f in _scanned_under(files, source) if f.endswith("guide.py")] == [
        "docs/guide.py"
    ], files


@pytest.mark.parametrize("output_rel", OUTPUTS)
def test_a_gitlink_in_the_output_directory_is_not_taken(
    tmp_path, monkeypatch, output_rel
):
    """A submodule is a gitlink in git's index, and a directory in the working tree;
    the files in that directory are in no index of this repository."""
    source = tmp_path / "repo"
    output = source / output_rel
    vendored = output / "vendored"
    vendored.mkdir(parents=True)
    (vendored / "inner.py").write_text("w = 4\n", encoding="utf-8")
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    assert _git(source, "init", "-q").returncode == 0
    assert _git(source, "add", "app.py").returncode == 0
    entry = _git(
        source,
        "update-index",
        "--add",
        "--cacheinfo",
        f"160000,{'1' * 40},{output_rel}/vendored",
    )
    assert entry.returncode == 0, entry.stderr
    staged = _git(source, "ls-files", "-s", output_rel).stdout
    # A control: the one entry under the output directory is the gitlink.
    assert staged.splitlines() == [f"160000 {'1' * 40} 0\t{output_rel}/vendored"], (
        staged
    )
    monkeypatch.chdir(tmp_path)

    assert tracked_files_in(output) == []
    files = scan_set(source=str(source), output=str(output))
    assert _scanned_under(files, output) == [], files


def test_a_committed_file_replaced_by_a_fifo_is_not_taken(tmp_path):
    """git's index lists the name as a regular file, and the working tree holds a
    FIFO there now, which a scanner opening it would wait on for a writer."""
    source, output, _marker = _layout(tmp_path, ".ash/ash_output")
    pipe = output / "hidden" / "regular.py"
    pipe.unlink()
    os.mkfifo(pipe)

    assert tracked_files_in(output) == []
