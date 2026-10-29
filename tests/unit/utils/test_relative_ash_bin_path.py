# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A relative ASH_BIN_PATH is not searched, and one warning says so.

A relative ASH_BIN_PATH names a directory under the working directory, and a scan
usually runs from the repository it scans. Were ``ASH_BIN_PATH=bin`` searched, a
repository that committed ``bin/grype`` would have that file run as grype. Tool
lookup keeps the anchored directories only (as #798's PATH filter does) and
logs one warning per process that names the value and asks for an absolute
path.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from automated_security_helper.utils import subprocess_utils
from tests.utils.helpers import checkout_env

EXE = ".exe" if sys.platform == "win32" else ""
WARNING_TEXT = "ASH_BIN_PATH is the relative path"


def _stub(path: Path, marker: Path) -> Path:
    """An executable that records that it ran, then exits 0."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f'#!/bin/sh\necho "ran: $*" >> "{marker.as_posix()}"\nexit 0\n')
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


@pytest.fixture
def lookup(tmp_path, monkeypatch):
    """A clean lookup state, with no grype on PATH."""
    empty = tmp_path / "empty-path"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    monkeypatch.setattr(subprocess_utils, "own_environment_dirs", list)
    # A fresh "warned already" record, so each test sees its own first warning.
    monkeypatch.setattr(
        subprocess_utils, "_warned_relative_bin_paths", set(), raising=False
    )
    subprocess_utils.clear_find_executable_cache()
    yield
    subprocess_utils.clear_find_executable_cache()


@pytest.mark.unit
def test_a_relative_ash_bin_path_is_not_searched(tmp_path, monkeypatch, lookup):
    repo = tmp_path / "repo"
    _stub(repo / "bin" / f"grype{EXE}", tmp_path / "ran")
    monkeypatch.chdir(repo)
    monkeypatch.setenv("ASH_BIN_PATH", "bin")
    assert subprocess_utils.find_executable("grype") is None


@pytest.mark.unit
def test_an_absolute_ash_bin_path_is_searched(tmp_path, monkeypatch, lookup):
    """Positive control: the same directory, named absolutely, is searched."""
    repo = tmp_path / "repo"
    tool = _stub(repo / "bin" / f"grype{EXE}", tmp_path / "ran")
    monkeypatch.chdir(repo)
    monkeypatch.setenv("ASH_BIN_PATH", str(repo / "bin"))
    assert subprocess_utils.find_executable("grype") == tool.as_posix()


@pytest.mark.unit
def test_one_warning_names_the_value(tmp_path, monkeypatch, lookup, caplog):
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.chdir(repo)
    monkeypatch.setenv("ASH_BIN_PATH", "bin")
    with caplog.at_level(logging.WARNING):
        for command in ("grype", "syft", "trivy"):
            subprocess_utils.find_executable(command)
    warnings = [
        r.getMessage() for r in caplog.records if WARNING_TEXT in r.getMessage()
    ]
    assert len(warnings) == 1, warnings
    assert "'bin'" in warnings[0] and "absolute" in warnings[0], warnings[0]
    # "../x" is not under the working directory; it is relative to it.
    assert "relative to the working directory" in warnings[0], warnings[0]


@pytest.mark.unit
def test_a_pinned_copy_in_a_relative_ash_bin_path_does_not_skip_the_install(
    tmp_path, monkeypatch, lookup
):
    """The skip's "every scan finds it" set leaves out a relative ASH_BIN_PATH.

    With ASH_BIN_PATH=bin and PATH=bin, find_executable finds the repository's
    bin/grype through PATH; a relative ASH_BIN_PATH is not in the skip's set, so
    a file there with the pinned digest does not count as installed and the real
    grype is installed.
    """
    import hashlib
    from unittest.mock import patch

    from automated_security_helper.utils import download_utils, tool_downloads

    payload = b"\x7fELF planted grype\n"
    repo = tmp_path / "repo"
    planted = repo / "bin" / "grype"
    planted.parent.mkdir(parents=True)
    planted.write_bytes(payload)
    planted.chmod(0o755)
    monkeypatch.chdir(repo)
    monkeypatch.setenv("ASH_BIN_PATH", "bin")
    monkeypatch.setenv("PATH", "bin")
    asset = tool_downloads._ASSET_TABLES["grype"][("linux", "amd64")]
    digests = {
        **tool_downloads._EXECUTABLE_DIGESTS,
        asset: hashlib.sha256(payload).hexdigest(),
    }
    with patch.object(tool_downloads, "_EXECUTABLE_DIGESTS", digests):
        present = download_utils.find_verified_pinned_executable(
            "grype", "linux", "amd64", tmp_path / "destination"
        )
    assert present is None, present


CONSOLE_TEXT = "Tools in ASH_BIN_PATH 'bin' were not looked for"


@pytest.mark.unit
def test_an_incomplete_scan_names_a_skipped_relative_ash_bin_path(
    monkeypatch, capsys, lookup
):
    """The warning is in ash.log; the console's MISSING advice names it too."""
    from automated_security_helper.interactions.run_ash_scan import (
        print_incompleteness_message,
    )

    monkeypatch.setenv("ASH_BIN_PATH", "bin")
    print_incompleteness_message([("grype", "MISSING")], [])
    out = " ".join(capsys.readouterr().out.split())
    assert CONSOLE_TEXT in out, out
    assert "absolute path" in out.split(CONSOLE_TEXT, 1)[1], out


@pytest.mark.unit
def test_the_note_is_one_line_whatever_the_value(monkeypatch, capsys, lookup):
    """A long value soft-wraps onto a new line that begins with text it chose.

    At 80 columns, a value of 50 x "a" + " ::error title=t::injected" that
    wrapped would put "::error ..." at a line start, which a GitHub Actions log
    reads as a workflow command, so the note stays on one line.
    """
    import rich

    from automated_security_helper.interactions.run_ash_scan import (
        print_incompleteness_message,
    )

    # _width, not the width property: the undo sets back what was read, and reading
    # width returns the measured width, so restoring it would pin the shared console
    # at that number for every later test instead of leaving it unset.
    monkeypatch.setattr(rich.get_console(), "_width", 80)
    monkeypatch.setenv("ASH_BIN_PATH", "a" * 50 + " ::error title=t::injected")
    print_incompleteness_message([("grype", "MISSING")], [])
    out = capsys.readouterr().out
    assert CONSOLE_TEXT.split("'")[0] in out, out
    assert not [line for line in out.splitlines() if line.startswith("::")], out


@pytest.mark.parametrize(
    "rows, bin_path",
    [
        pytest.param([("grype", "ERROR")], "bin", id="nothing-missing"),
        pytest.param([("grype", "MISSING")], None, id="absolute"),
    ],
)
@pytest.mark.unit
def test_no_such_line_without_both(rows, bin_path, tmp_path, monkeypatch, capsys):
    from automated_security_helper.interactions.run_ash_scan import (
        print_incompleteness_message,
    )

    monkeypatch.setenv("ASH_BIN_PATH", bin_path or str(tmp_path / "bin"))
    print_incompleteness_message(rows, [])
    assert "were not looked for" not in capsys.readouterr().out


#: Run first in the scan's child, so it finds no grype the host has. Past PATH, a
#: lookup searches ASH's own environment (the interpreter's directory and its scripts
#: directory) and /usr/local/bin, and a host with grype in one of them runs that grype:
#: the scan is not MISSING, so without this the test's answer depends on the host.
#: Only those two are taken out; the relative ASH_BIN_PATH, which is what the test is
#: about, is read and refused as everywhere else.
NO_HOST_GRYPE = """\
from pathlib import Path as _Path
from automated_security_helper.utils import subprocess_utils as _lookup
_every_dir = _lookup.path_independent_dirs
_lookup.own_environment_dirs = list
_lookup.path_independent_dirs = lambda: [
    d for d in _every_dir() if d != _Path("/usr/local/bin")
]
"""

#: ``ash`` on the tree under test (PYTHONPATH): the console script beside the
#: interpreter imports whatever ASH that environment installed, an older tree's in a
#: venv made for another checkout, and its scan did not write the reasons this test
#: reads.
ASH_CHILD = NO_HOST_GRYPE + (
    "import sys; sys.argv[0] = 'ash'; "
    "from automated_security_helper.cli.entrypoint import main; main()"
)


@pytest.mark.e2e
@pytest.mark.skipif(sys.platform == "win32", reason="the stand-ins are sh scripts")
def test_a_scan_does_not_run_a_tool_the_repository_committed(tmp_path):
    """The whole path: ``ash scan`` from the repository, ASH_BIN_PATH=bin.

    The scan finds no grype but the repository's, which it does not run, whatever
    the host has installed: the child's PATH holds only the runner guards and git,
    and ``NO_HOST_GRYPE`` takes out the places a lookup searches past PATH.
    """
    git = shutil.which("git")
    if git is None:
        pytest.skip("needs git")
    ran = tmp_path / "grype-ran"
    guard_hits = tmp_path / "oci-runner-ran"
    repo = tmp_path / "repo"
    _stub(repo / "bin" / "grype", ran)
    (repo / "app.py").write_text('print("hello")\n')
    # Guards first on PATH: no container runner may start (and none should).
    guards = tmp_path / "guards"
    for runner in ("docker", "finch", "nerdctl", "podman"):
        _stub(guards / runner, guard_hits).write_text(
            f'#!/bin/sh\necho "$0 $*" >> "{guard_hits.as_posix()}"\nexit 97\n'
        )
    home = tmp_path / "home"
    home.mkdir()
    git_env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(home),
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    for args in (
        ["init", "-q"],
        ["add", "-A"],
        [
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.invalid",
            "commit",
            "-qm",
            "x",
        ],
    ):
        subprocess.run([git, *args], cwd=repo, env=git_env, check=True)  # nosec B603
    # git, and nothing else a host keeps in a PATH directory.
    only_git = tmp_path / "git-only"
    only_git.mkdir()
    (only_git / "git").symlink_to(git)
    env = checkout_env(
        {
            "PATH": os.pathsep.join([str(guards), str(only_git)]),
            "HOME": str(home),
            "ASH_BIN_PATH": "bin",
            "UV_OFFLINE": "1",
            "ASH_OFFLINE": "YES",
            "NO_COLOR": "1",
            "COLUMNS": "300",
        }
    )
    result = subprocess.run(  # nosec B603
        [
            sys.executable,
            "-c",
            ASH_CHILD,
            "scan",
            "--scanners",
            "grype",
            "--output-dir",
            str(tmp_path / "out"),
        ],
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
    )
    out = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout + result.stderr)
    assert not ran.exists(), ran.read_text()
    assert not guard_hits.exists(), guard_hits.read_text()
    # The scan's own log has every warning; the console's live panel keeps only
    # the latest few messages.
    log = (tmp_path / "out" / "ash.log").read_text(encoding="utf-8")
    assert log.count(WARNING_TEXT) == 1, out
    flat = " ".join(out.split())
    # The exit code's reason is an ASH log message, in ash.log; the console's
    # exit-1 summary names the scanner too, with its reason.
    assert "Scan incomplete: grype (MISSING)" in log, log
    assert "grype: MISSING" in flat, out
    assert CONSOLE_TEXT in flat, out
