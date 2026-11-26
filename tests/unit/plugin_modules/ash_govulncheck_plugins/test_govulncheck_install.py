# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The govulncheck install child: ``go install`` with GOBIN in go's environment.

``install_govulncheck`` is what the install command's ``-c`` script runs. The go
process is replaced with a recorder, so these tests run on every platform without
Go installed and start no program.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest

from automated_security_helper.plugin_modules.ash_govulncheck_plugins import (
    govulncheck_install as gi,
)
from automated_security_helper.plugin_modules.ash_govulncheck_plugins import (
    govulncheck_scanner as gs,
)

pytestmark = pytest.mark.unit

MODULE = f"{gs.GOVULNCHECK_PACKAGE}@{gs.GOVULNCHECK_VERSION}"
FAKE_GO = "/fake/go/bin/go"


class RecordedGo:
    """Stands in for subprocess.run: records each call, returns ``returncode``."""

    def __init__(self, returncode: int = 0):
        self.returncode = returncode
        self.calls: List[Dict[str, Any]] = []

    def __call__(self, argv, **kwargs):
        self.calls.append({"argv": list(argv), **kwargs})
        return subprocess.CompletedProcess(argv, self.returncode)


@pytest.fixture
def go_on_path(monkeypatch):
    monkeypatch.setattr(
        gi, "find_executable", lambda cmd: FAKE_GO if cmd == "go" else None
    )


@pytest.fixture
def recorded(monkeypatch) -> RecordedGo:
    fake = RecordedGo()
    monkeypatch.setattr(gi.subprocess, "run", fake)
    return fake


def test_gobin_is_set_in_the_environment_go_is_started_with(
    tmp_path, go_on_path, recorded, monkeypatch
):
    monkeypatch.setenv("GOPROXY", "off")
    monkeypatch.setenv("GOBIN", "/somewhere/else")
    destination = tmp_path / "bin"
    assert gi.install_govulncheck(destination, MODULE) == 0
    (call,) = recorded.calls
    assert call["argv"] == [FAKE_GO, "install", MODULE]
    assert call["env"]["GOBIN"] == str(destination)
    # The rest of the environment is the user's own, passed through as it is.
    assert call["env"]["GOPROXY"] == "off"
    # An argv handed to the program as it is: no shell is asked for.
    assert not call.get("shell")
    assert destination.is_dir()


def test_go_s_exit_status_is_the_install_s(tmp_path, go_on_path, monkeypatch):
    monkeypatch.setattr(gi.subprocess, "run", RecordedGo(returncode=3))
    assert gi.install_govulncheck(tmp_path / "bin", MODULE) == 3


def test_without_go_nothing_is_started(tmp_path, recorded, monkeypatch, capsys):
    monkeypatch.setattr(gi, "find_executable", lambda cmd: None)
    assert gi.install_govulncheck(tmp_path / "bin", MODULE) == 1
    assert recorded.calls == []
    assert gi.NO_GO_TOOLCHAIN in capsys.readouterr().err
    assert not (tmp_path / "bin").exists()


def test_a_relative_destination_is_refused(
    tmp_path, go_on_path, recorded, monkeypatch, capsys
):
    monkeypatch.chdir(tmp_path)
    assert gi.install_govulncheck(Path("bin"), MODULE) == 1
    assert recorded.calls == []
    assert "not an absolute path" in capsys.readouterr().err
    assert not (tmp_path / "bin").exists()


def test_the_command_is_the_script_and_its_two_arguments():
    assert gi.install_command_args("/ash/bin", MODULE) == [
        sys.executable,
        "-c",
        gi.INSTALL_SCRIPT,
        "/ash/bin",
        MODULE,
    ]


def test_the_script_hands_its_two_arguments_to_the_install(tmp_path, monkeypatch):
    """The ``-c`` source itself, run in this process with a recording install."""
    seen = []

    def install(destination, module):
        seen.append((destination, module))
        return 7

    monkeypatch.setattr(gi, "install_govulncheck", install)
    monkeypatch.setattr(sys, "argv", ["-c", str(tmp_path / "bin"), MODULE])
    with pytest.raises(SystemExit) as stopped:
        exec(compile(gi.INSTALL_SCRIPT, "<install-command>", "exec"), {})  # nosec B102 - the install command's own -c source
    assert stopped.value.code == 7
    assert seen == [(tmp_path / "bin", MODULE)]
