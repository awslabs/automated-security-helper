# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The pre-installed tool verdict judges the right environment and names the
right cause.

* ``find_tool_interpreter`` reads a console script's ``#!`` line for the
  interpreter that provides it; a native binary, or a script another
  interpreter owns, is no longer judged against whatever python sits in its
  directory.
* A dry run that reports no changes while uv warns that the installed version
  "does not have an extra named" the requested one is unsatisfied: the extra is
  never provided.
* An OSError while staging a Nix tool's metadata is an "unverifiable" verdict,
  not an exception out of the scanner's dependency check.
* When the bare package does not resolve in the copy's environment, no extra
  is blamed; the resolver's own cause is reported.
"""

from __future__ import annotations

import stat
import subprocess  # nosec B404
import sys
from pathlib import Path

import pytest

from automated_security_helper.utils import pre_installed_tool
from automated_security_helper.utils.pre_installed_tool import (
    _dry_run,
    _judge,
    find_tool_interpreter,
    reset_pre_installed_tool_cache,
    verify_pre_installed_tool,
)

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(sys.platform == "win32", reason="POSIX execute bits"),
]


@pytest.fixture(autouse=True)
def _fresh_verdicts():
    reset_pre_installed_tool_cache()
    yield
    reset_pre_installed_tool_cache()


def _executable(path: Path, content: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


class TestFindToolInterpreter:
    def test_a_native_binary_beside_a_python_has_no_interpreter(self, tmp_path):
        bin_dir = tmp_path / "bin"
        _executable(bin_dir / "python3", b"#!/bin/sh\nexit 0\n")
        native = _executable(bin_dir / "grype", b"\x7fELF\x02\x01\x01\x00rest")
        assert find_tool_interpreter(str(native)) is None

    def test_a_script_names_its_own_interpreter_not_its_neighbor(self, tmp_path):
        bin_dir = tmp_path / "bin"
        _executable(bin_dir / "python3", b"#!/bin/sh\nexit 0\n")
        script = _executable(
            bin_dir / "tool", f"#!{sys.executable}\nprint('1')\n".encode()
        )
        assert find_tool_interpreter(str(script)) == sys.executable

    def test_a_windows_launcher_takes_the_interpreter_beside_it(self, tmp_path):
        """The control: an .exe entry point has no readable shebang at its
        start, and its environment is the one it sits in."""
        bin_dir = tmp_path / "Scripts"
        python = _executable(bin_dir / "python.exe", b"MZ\x90\x00")
        launcher = _executable(bin_dir / "tool.exe", b"MZ\x90\x00")
        assert find_tool_interpreter(str(launcher)) == str(python)


class TestAnExtraTheInstalledVersionDoesNotDeclare:
    def test_it_is_unsatisfied_not_satisfied(self, monkeypatch):
        monkeypatch.setattr(
            pre_installed_tool,
            "_run",
            lambda command, timeout: subprocess.CompletedProcess(
                command,
                0,
                "",
                "warning: The package `bandit==1.7.0` does not have an extra "
                "named `sarif`\nWould make no changes\n",
            ),
        )
        status, _ = _dry_run("/opt/uv", sys.executable, "bandit[sarif]")
        assert status == "unsatisfied"

    def test_no_changes_without_the_warning_is_satisfied(self, monkeypatch):
        """The control."""
        monkeypatch.setattr(
            pre_installed_tool,
            "_run",
            lambda command, timeout: subprocess.CompletedProcess(
                command, 0, "", "Would make no changes\n"
            ),
        )
        assert _dry_run("/opt/uv", sys.executable, "bandit[sarif]")[0] == "satisfied"


class TestNixStaging:
    def test_a_staging_error_is_an_unverifiable_verdict(self, tmp_path, monkeypatch):
        tool = _executable(tmp_path / "bin" / "tool", b"#!/bin/sh\necho 1.0\n")
        monkeypatch.setattr(
            pre_installed_tool,
            "_run",
            lambda command, timeout: subprocess.CompletedProcess(
                command, 0, "1.0\n", ""
            ),
        )
        monkeypatch.setattr(
            pre_installed_tool,
            "find_nix_python_environment",
            lambda executable: (sys.executable, ("/nix/store/abc-site-packages",)),
        )

        def _raises(site_dirs, target):
            raise PermissionError(13, "Permission denied", str(target))

        monkeypatch.setattr(pre_installed_tool, "_stage_nix_metadata", _raises)
        verdict = verify_pre_installed_tool(
            str(tool), "bandit", ["sarif"], None, uv_executable="/opt/uv"
        )
        assert verdict.status == "unverifiable"
        assert verdict.from_nix is True
        assert "could not be staged" in verdict.detail


class TestTheCauseOfAnUnsatisfiedVerdict:
    @staticmethod
    def _probes(answers):
        calls = []

        def _dry_run_stub(uv, interpreter, requirement, target=None, no_deps=False):
            calls.append(requirement)
            return answers(requirement)

        return calls, _dry_run_stub

    def test_a_dependency_gap_blames_no_extra(self, monkeypatch):
        resolver = "No solution found when resolving dependencies: rich>=13 is missing"
        calls, stub = self._probes(lambda requirement: ("unsatisfied", resolver))
        monkeypatch.setattr(pre_installed_tool, "_dry_run", stub)
        verdict = _judge(
            "/opt/bin/bandit",
            "bandit",
            ["sarif", "toml"],
            None,
            "bandit[sarif,toml]",
            "/opt/uv",
            sys.executable,
            None,
            "its environment",
            None,
            values=(),
        )
        assert verdict.status == "unsatisfied"
        assert verdict.missing_extras == ()
        assert "missing extra" not in verdict.detail, verdict.detail
        assert "bandit" in calls, calls

    def test_an_extra_the_environment_lacks_is_still_named(self, monkeypatch):
        """The control: with the bare package resolving, the extra is blamed."""

        def _answers(requirement):
            if requirement == "bandit[sarif]":
                return ("unsatisfied", "would install sarif-om")
            if requirement == "bandit[sarif,toml]":
                return ("unsatisfied", "would install sarif-om")
            return ("satisfied", "")

        _calls, stub = self._probes(_answers)
        monkeypatch.setattr(pre_installed_tool, "_dry_run", stub)
        verdict = _judge(
            "/opt/bin/bandit",
            "bandit",
            ["sarif", "toml"],
            None,
            "bandit[sarif,toml]",
            "/opt/uv",
            sys.executable,
            None,
            "its environment",
            None,
            values=(),
        )
        assert verdict.missing_extras == ("sarif",)
