# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A HOME that is empty or relative gives ASH no home directory.

On POSIX, Path.home() and expanduser read HOME as it is set. An empty HOME makes ``~``
the filesystem root (Path.home() is ``/``, measured on Python 3.14), and a relative one
names a directory under the working directory, which is usually the repository being
scanned. So with either one there is no home: nothing is installed or written under
``~``, nothing lands under the working directory, and no home is handed to a child.

These are the sites of ASH's own code that read the home outside the paths it shares
with the HOME helpers in core/constants.py: the install command, its hint about where
later scans look for tools, and the environment of a sandbox probe.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests.utils.helpers import importing_this_checkout

#: ``ash dependencies install`` as a child, so ASH_BIN_PATH is computed from the HOME
#: it is started with. ``--config`` names a file ASH refuses, which stops a run that
#: got past choosing its bin directory before it loads a plugin or installs a tool.
#: The child imports ASH from this checkout (``importing_this_checkout``).
_INSTALL = (
    "import sys\n"
    "from typer.testing import CliRunner\n"
    "from automated_security_helper.cli.main import app\n"
    "result = CliRunner().invoke(\n"
    "    app, ['dependencies', 'install', '--config', sys.argv[1]], prog_name='ash'\n"
    ")\n"
    "print(result.output, end='')\n"
    "if result.exception is not None and not isinstance(result.exception, SystemExit):\n"
    "    print(repr(result.exception))\n"
    "raise SystemExit(result.exit_code)\n"
)


def _install_with_home(directory: Path, home: str) -> subprocess.CompletedProcess:
    config = directory / "refused.yaml"
    # A value of the wrong type: ASH refuses it (ASHConfigValidationError). An
    # unparsable file would not stop the run, because ASH falls back to defaults then.
    config.write_text("fail_on_findings: [1, 2]\n", encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if k != "ASH_BIN_PATH"}
    # Offline, so a run that gets past the config downloads nothing either.
    env.update(HOME=home, USERPROFILE=home, UV_OFFLINE="1")
    return subprocess.run(  # nosec B603 - fixed argv, the test's own interpreter
        [sys.executable, "-c", importing_this_checkout(_INSTALL), str(config)],
        cwd=directory,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
    )


def _made_under(directory: Path) -> list:
    return sorted(
        path.relative_to(directory).as_posix()
        for path in directory.rglob("*")
        if path.name != "refused.yaml"
    )


@pytest.mark.skipif(os.name == "nt", reason="HOME is not Windows' home")
@pytest.mark.parametrize(
    "home",
    [
        pytest.param("relative-home", id="relative"),
        pytest.param(
            "",
            id="empty",
            marks=pytest.mark.skipif(
                hasattr(os, "geteuid") and os.geteuid() == 0,
                reason="as root, an install that read ~ as / would write /.ash/bin",
            ),
        ),
    ],
)
def test_install_with_no_usable_home_refuses_and_writes_nothing(tmp_path, home):
    """With no --bin-path, no ASH_BIN_PATH and no usable HOME there is nowhere to
    install, so the install exits 3 before it writes anything: neither
    ``relative-home/.ash/bin`` under the working directory nor ``/.ash/bin`` for an
    empty HOME."""
    result = _install_with_home(tmp_path, home)
    output = result.stdout + result.stderr
    # The console wraps long lines, so the text is read with its whitespace joined.
    said = " ".join(output.split())

    assert result.returncode == 3, output
    # The refusal says what to set: HOME (or a bin directory) as an absolute path.
    assert "HOME" in said and "absolute path" in said, output
    assert _made_under(tmp_path) == []


@pytest.mark.skipif(os.name == "nt", reason="HOME is not Windows' home")
@pytest.mark.parametrize("home", ["relative-home", ""])
def test_the_bin_path_hint_is_given_when_there_is_no_home(monkeypatch, tmp_path, home):
    """A scan searches ``~/.ash/bin`` only when there is a home; with none, a tool
    installed into what ``~/.ash/bin`` would read as is not looked for, so the hint
    says how to point scans at it."""
    from automated_security_helper.cli.dependencies import _bin_path_hint

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", home)
    would_be = Path(os.path.abspath(os.path.join(home or "/", ".ash", "bin")))

    assert _bin_path_hint(would_be, None) is not None


@pytest.mark.skipif(os.name == "nt", reason="HOME is not Windows' home")
@pytest.mark.parametrize(
    "home,passed",
    [
        pytest.param("relative-home", False, id="relative"),
        pytest.param("", False, id="empty"),
        pytest.param("/an/absolute/home", True, id="absolute"),
    ],
)
def test_a_probe_is_given_only_a_usable_home(monkeypatch, home, passed):
    """A sandbox probe gets this process's HOME so that ``~`` in it is the operator's;
    a relative one would be read against the probe's working directory."""
    from automated_security_helper.utils.sandbox.backends import _probe_env

    monkeypatch.setenv("HOME", home)

    assert ("HOME" in _probe_env()) is passed


@pytest.mark.skipif(os.name == "nt", reason="HOME is not Windows' home")
@pytest.mark.parametrize("home", ["relative-home", ""])
def test_shown_paths_name_no_home_when_there_is_none(monkeypatch, home):
    """The control: shown text replaces only a home that is an absolute directory,
    so a root or relative HOME rewrites nothing."""
    from automated_security_helper.utils.get_shortest_name import home_as_tilde

    monkeypatch.setenv("HOME", home)
    text = "wrote /tmp/out/report.json and relative-home/x"

    assert home_as_tilde(text) == text
