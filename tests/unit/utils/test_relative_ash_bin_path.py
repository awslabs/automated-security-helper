# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A relative ASH_BIN_PATH is not searched, and one warning says so.

A relative ASH_BIN_PATH names a directory under the working directory, and a scan
usually runs from the repository it scans. Were ``ASH_BIN_PATH=bin`` searched, a
repository that committed ``bin/grype`` would have that file run as grype. Tool
lookup keeps the anchored directories only (as #798's PATH filter does) and
logs one warning per process that names the value and asks for an absolute
path. The writers follow the same rule: a relative value is never installed into,
downloaded into or used to place the cfn-guard rules, since each would write into
the repository being scanned, so they use ``~/.ash/bin`` and warn once, and with no
usable home they install nothing.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import stat
import subprocess
import sys
import urllib.error
from pathlib import Path
from typing import NamedTuple

import pytest

from automated_security_helper.core import constants
from automated_security_helper.core.constants import home_bin_path
from automated_security_helper.utils import (
    download_utils,
    rules_bundles,
    subprocess_utils,
)
from tests.utils.helpers import checkout_env
from tests.utils.tool_guard import use_the_real_candidate_names

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
    # The lookup's own candidate list: on Windows the unit tests' tool guard
    # narrows "grype" to its .bat stand-in, and these cells' stubs are .exe.
    use_the_real_candidate_names(monkeypatch)
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


# ---------------------------------------------------------------------------
# The writers: nothing is installed, downloaded or placed under the working directory
# ---------------------------------------------------------------------------

#: What is logged, once per process, for the value these tests set.
RELATIVE_VALUE_WARNING = f"{WARNING_TEXT} 'rel-bin'"
#: The pinned rules bundle the rules-directory tests install.
BUNDLE = "aws-guard-rules-registry"


class RelativeSetting(NamedTuple):
    """Where a writer test runs: an empty working directory, and a home that exists."""

    cwd: Path
    home: Path


@pytest.fixture
def relative_ash_bin_path(tmp_path, monkeypatch) -> RelativeSetting:
    """ASH_BIN_PATH=rel-bin, run from an empty directory, in a home of its own.

    The rules directory variable is unset, and the record of what was warned about
    starts empty, so each test counts its own warnings.
    """
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.chdir(cwd)
    monkeypatch.setenv("HOME", str(home))
    # What Path.home() reads on Windows.
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("ASH_BIN_PATH", "rel-bin")
    monkeypatch.delenv(rules_bundles.RULES_DIR_ENV, raising=False)
    monkeypatch.setattr(subprocess_utils, "_warned_relative_bin_paths", set())
    return RelativeSetting(cwd, home)


def _names_in(directory: Path) -> list:
    """What is directly in ``directory``: empty when nothing was made there."""
    return sorted(path.name for path in directory.iterdir())


def _relative_value_warnings(caplog) -> list:
    """The logged messages that name the relative value, as they were logged."""
    messages = [record.getMessage() for record in caplog.records]
    return [message for message in messages if RELATIVE_VALUE_WARNING in message]


def _as_the_builders_write_it(directory: Path) -> str:
    """A directory as the install command builders spell it: ``/`` on Windows only."""
    text = str(directory)
    return text.replace("\\", "/") if os.name == "nt" else text


def _without_a_usable_home(monkeypatch) -> None:
    """HOME and USERPROFILE empty, so ``~/.ash/bin`` does not exist."""
    monkeypatch.setenv("HOME", "")
    monkeypatch.setenv("USERPROFILE", "")
    assert home_bin_path() is None


def _the_import_time_constant_is_relative(monkeypatch) -> None:
    """Every copy of ``ASH_BIN_PATH``, as an import under ``rel-bin`` computed it.

    ``raising=False``: a fix that stops importing the constant into a module leaves
    nothing to set there.
    """
    for module in (constants, download_utils, subprocess_utils):
        monkeypatch.setattr(module, "ASH_BIN_PATH", Path("rel-bin"), raising=False)


def _outcome(call):
    """``(what the call returned, None)``, or ``(None, what it raised)``."""
    try:
        return call(), None
    except Exception as error:
        return None, error


def _install_command(kind: str):
    """An install command built with no destination, and where its destination sits.

    The pinned-tool command carries the destination as argv[6], the URL download
    command as argv[4].
    """
    if kind == "pinned":
        command = download_utils.create_pinned_tool_install_command(
            "grype", "linux", "amd64"
        )
        return command, 6
    command = download_utils.create_url_download_command(
        "https://example.invalid/tool", rename_to="tool", expected_sha256="0" * 64
    )
    return command, 4


@pytest.fixture
def tool_already_installed(monkeypatch):
    """``install_pinned_tool`` finds its tool in place, so it downloads nothing.

    It makes its bin directory first, which is what the tests using this are about.
    """
    monkeypatch.setattr(download_utils, "_already_installed", lambda *a, **k: True)
    monkeypatch.setattr(download_utils, "_companions_verified", lambda *a, **k: True)


@pytest.fixture
def no_network(monkeypatch) -> list:
    """Every download of the rules bundle fails as when offline; each call is listed."""
    attempts: list = []

    def refuse(*args, **kwargs):
        attempts.append(args)
        raise urllib.error.URLError("no network in this test")

    monkeypatch.setattr(download_utils, "download_file", refuse)
    return attempts


@pytest.mark.unit
def test_the_tool_lookup_takes_the_default_directory_in_the_same_setting(
    relative_ash_bin_path, caplog
):
    """Control for the writer tests below, green at the base: the lookup side.

    The same setting (a relative value in the environment, an empty working
    directory, a home of its own), asked of ``_bin_path``, which already follows the
    rule. It answers ``~/.ash/bin`` for both calls and warns once, so the setting
    reaches the rule and the count of one is what a correct reader logs.
    """
    cwd, _home = relative_ash_bin_path
    with caplog.at_level(logging.WARNING):
        first = subprocess_utils._bin_path()
        second = subprocess_utils._bin_path()
    assert first == second == home_bin_path()
    assert _names_in(cwd) == []
    warnings = _relative_value_warnings(caplog)
    assert len(warnings) == 1, warnings


@pytest.mark.unit
@pytest.mark.parametrize(
    "arrives_as",
    [
        pytest.param("environment", id="environment-variable"),
        pytest.param("constant-unset", id="import-time-constant-variable-unset"),
        pytest.param("constant-blank", id="import-time-constant-variable-blank"),
    ],
)
def test_the_installers_bin_directory_is_the_default_one_for_a_relative_value(
    arrives_as, relative_ash_bin_path, monkeypatch, caplog
):
    """``current_bin_path`` is the directory every installer asks for.

    A relative ASH_BIN_PATH was made absolute against the working directory, and the
    import-time constant (what a process that started with ``rel-bin`` keeps once
    the variable is unset or blank) was returned as it was; both name a directory in
    the repository being scanned. Like the lookup (``_bin_path``), it warns once per
    value and answers ``~/.ash/bin``.

    Fails at the base on the answer: ``<working directory>/rel-bin`` or ``rel-bin``.
    """
    cwd, home = relative_ash_bin_path
    if arrives_as != "environment":
        _the_import_time_constant_is_relative(monkeypatch)
        if arrives_as == "constant-unset":
            monkeypatch.delenv("ASH_BIN_PATH")
        else:
            monkeypatch.setenv("ASH_BIN_PATH", " ")
    expected = home_bin_path()
    assert expected == home / ".ash" / "bin"
    with caplog.at_level(logging.WARNING):
        first = download_utils.current_bin_path()
        second = download_utils.current_bin_path()
    assert first == second == expected
    assert _names_in(cwd) == []
    warnings = _relative_value_warnings(caplog)
    assert len(warnings) == 1, warnings


@pytest.mark.unit
def test_the_installers_bin_directory_is_none_for_a_relative_value_without_a_home(
    relative_ash_bin_path, monkeypatch
):
    """With no usable home ``~/.ash/bin`` does not exist, so there is no directory.

    ``current_bin_path`` answers None, as documented, and each installer then
    refuses (``NO_BIN_DIRECTORY``). It answered ``<working directory>/rel-bin``.
    """
    cwd, _home = relative_ash_bin_path
    _without_a_usable_home(monkeypatch)
    directory = download_utils.current_bin_path()
    assert directory is None, directory
    assert _names_in(cwd) == []


@pytest.mark.unit
def test_a_direct_install_goes_to_the_default_directory_for_a_relative_value(
    relative_ash_bin_path, tool_already_installed, caplog
):
    """``install_pinned_tool`` with no destination makes its bin directory first.

    With ASH_BIN_PATH=rel-bin it made ``rel-bin`` in the working directory, then
    installed there (stubbed here to find the tool in place, so nothing is
    downloaded). It makes ``~/.ash/bin`` and warns once.

    Fails at the base on the working directory: ``rel-bin`` is in it.
    """
    cwd, home = relative_ash_bin_path
    with caplog.at_level(logging.WARNING):
        first = download_utils.install_pinned_tool("grype", "linux", "amd64")
        second = download_utils.install_pinned_tool("grype", "linux", "amd64")
    assert _names_in(cwd) == []
    assert first.parent == second.parent == home_bin_path()
    assert (home / ".ash" / "bin").is_dir()
    warnings = _relative_value_warnings(caplog)
    assert len(warnings) == 1, warnings


@pytest.mark.unit
def test_a_direct_install_refuses_for_a_relative_value_without_a_home(
    relative_ash_bin_path, tool_already_installed, monkeypatch
):
    """With no usable home there is no directory to install into: a RuntimeError.

    ``install_pinned_tool`` raises ``NO_BIN_DIRECTORY`` before it makes anything. It
    made ``<working directory>/rel-bin`` and installed there.

    Fails at the base on the working directory: ``rel-bin`` is in it.
    """
    cwd, _home = relative_ash_bin_path
    _without_a_usable_home(monkeypatch)
    installed, refusal = _outcome(
        lambda: download_utils.install_pinned_tool("grype", "linux", "amd64")
    )
    assert _names_in(cwd) == [], installed
    assert isinstance(refusal, RuntimeError), (installed, refusal)
    assert str(refusal) == download_utils.NO_BIN_DIRECTORY


@pytest.mark.unit
@pytest.mark.parametrize("kind", ["pinned", "url"])
def test_an_install_command_names_the_default_directory_for_a_relative_value(
    kind, relative_ash_bin_path, caplog
):
    """A command built with no destination carries the bin directory as an argument.

    ``create_pinned_tool_install_command`` and ``create_url_download_command`` build
    their argv when a plugin is constructed, a scan included, and the child that
    runs it installs into that directory. With ASH_BIN_PATH=rel-bin the argument was
    ``<working directory>/rel-bin``. It is ``~/.ash/bin``, with one warning.

    Fails at the base on the destination argument.
    """
    cwd, _home = relative_ash_bin_path
    with caplog.at_level(logging.WARNING):
        first, index = _install_command(kind)
        second, _ = _install_command(kind)
    expected = _as_the_builders_write_it(home_bin_path())
    assert first.args[index] == second.args[index] == expected
    assert _names_in(cwd) == []
    warnings = _relative_value_warnings(caplog)
    assert len(warnings) == 1, warnings


@pytest.mark.unit
@pytest.mark.parametrize("kind", ["pinned", "url"])
def test_an_install_command_only_refuses_for_a_relative_value_without_a_home(
    kind, relative_ash_bin_path, monkeypatch
):
    """With no usable home the command built is the one that says why and exits 1.

    It was an install command aimed at ``<working directory>/rel-bin``.

    Fails at the base on the command: it is the install, not the refusal.
    """
    cwd, _home = relative_ash_bin_path
    _without_a_usable_home(monkeypatch)
    command, _ = _install_command(kind)
    refusal = download_utils.refusing_install_command(download_utils.NO_BIN_DIRECTORY)
    assert command.args == refusal.args, command.args
    assert _names_in(cwd) == []


@pytest.mark.unit
def test_the_rules_directory_is_beside_the_default_bin_directory_for_a_relative_value(
    relative_ash_bin_path, caplog
):
    """With ``ASH_CFN_GUARD_RULES_DIR`` unset the rules go beside the bin directory.

    ``rules_root`` is ``<bin directory>/../share/cfn-guard-rules``, so with
    ASH_BIN_PATH=rel-bin it named ``share`` directly in the working directory. It is
    ``~/.ash/share/cfn-guard-rules``, with one warning.

    Fails at the base on the answer: ``<working directory>/share/cfn-guard-rules``.
    """
    cwd, _home = relative_ash_bin_path
    expected = home_bin_path().parent / "share" / "cfn-guard-rules"
    with caplog.at_level(logging.WARNING):
        first = rules_bundles.rules_root()
        second = rules_bundles.rules_root()
    assert first == second == expected
    assert _names_in(cwd) == []
    warnings = _relative_value_warnings(caplog)
    assert len(warnings) == 1, warnings


@pytest.mark.unit
def test_installing_the_rules_bundle_writes_nothing_under_the_working_directory(
    relative_ash_bin_path, no_network, caplog
):
    """``install_rules_bundle`` makes the rules root and its lock before it downloads.

    The download is refused as it is offline, after those are made, so what the
    install wrote is what is left. With ASH_BIN_PATH=rel-bin it wrote ``share`` in
    the working directory; it writes under ``~/.ash/share/cfn-guard-rules``, and
    warns once.

    Fails at the base on the working directory: ``share`` is in it.
    """
    cwd, home = relative_ash_bin_path
    with caplog.at_level(logging.WARNING):
        for _ in range(2):
            with pytest.raises(rules_bundles.RulesBundleUnavailable):
                rules_bundles.install_rules_bundle(BUNDLE)
    assert _names_in(cwd) == []
    assert (home / ".ash" / "share" / "cfn-guard-rules").is_dir()
    assert len(no_network) == 2, no_network
    warnings = _relative_value_warnings(caplog)
    assert len(warnings) == 1, warnings


@pytest.mark.unit
@pytest.mark.parametrize("entry", ["rules_root", "install_rules_bundle"])
def test_the_rules_bundle_has_no_directory_for_a_relative_value_without_a_home(
    entry, relative_ash_bin_path, no_network, monkeypatch
):
    """With no usable home there is nowhere to put the rules: a refusal.

    Both the resolver and the installer refuse with ``NO_BIN_DIRECTORY``, before
    anything is made or downloaded. They resolved
    ``<working directory>/share/cfn-guard-rules`` and, for the installer, wrote it.

    Fails at the base on the working directory (the installer) or on the missing
    refusal (the resolver, which returned that path).
    """
    cwd, _home = relative_ash_bin_path
    _without_a_usable_home(monkeypatch)
    calls = {
        "rules_root": rules_bundles.rules_root,
        "install_rules_bundle": lambda: rules_bundles.install_rules_bundle(BUNDLE),
    }
    returned, refusal = _outcome(calls[entry])
    assert _names_in(cwd) == [], returned
    assert isinstance(refusal, rules_bundles.RulesBundleUnavailable), (
        returned,
        refusal,
    )
    assert download_utils.NO_BIN_DIRECTORY in str(refusal)
    assert no_network == []


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
