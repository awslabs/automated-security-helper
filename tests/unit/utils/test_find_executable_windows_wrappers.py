# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Regression tests: find_executable prefers a Windows wrapper over a script binstub.

Why this file exists
--------------------
Measured on ``scan (python-local, windows-latest)``: ASH invoked
``C:/Users/runneradmin/.ash/bin/cfn_nag_scan`` and got

    [WinError 193] %1 is not a valid Win32 application

on all eight templates, then logged "CFN Nag returned no stdout" for each and reported
cfn-nag ERROR with zero findings after 1m22s.

``cfn_nag_scan`` with no extension is a Ruby binstub -- a text file with a shebang --
and Windows' ``CreateProcess`` runs PE images only. RubyGems writes ``cfn_nag_scan.bat``
beside it (``Gem::Installer#generate_windows_script``, which builds
``formatted_program_filename(filename) + ".bat"``), and the wrapper is the file that can
actually be executed.

``find_executable`` searched the bare name and ``.exe`` and nothing else, so in ASH's own
bin directory -- deliberately not on PATH, see the comment on "Install trivy through ASH
for the community plugin legs" in .github/actions/run-scan-test/action.yml -- the
directory probe found the binstub and returned it. The bug was not that the wrapper was
missing; it was that the one unexecutable file was reached first.

The honest limit on these tests: they mock ``platform.system`` rather than running on
Windows, so they pin the resolution logic and not end-to-end Windows execution. That is
exactly why the POSIX control is here. A fix that resolved the ``.bat`` by simply
reordering or rewriting the candidate list for every platform would satisfy the Windows
cases alone while breaking Linux and macOS, where no ``.bat`` exists and the
extensionless binstub is the only correct answer.
"""

from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.utils.subprocess_utils import (
    _executable_candidate_names,
    clear_find_executable_cache,
    find_executable,
)


@pytest.fixture(autouse=True)
def _isolate_lookup_cache():
    """find_executable memoizes into a module-global dict.

    Cleared on both sides so a name resolved under a mocked Windows does not leak into
    a POSIX test, or into anything else sharing this xdist worker.
    """
    clear_find_executable_cache()
    yield
    clear_find_executable_cache()


@pytest.fixture
def gem_bindir(tmp_path, monkeypatch):
    """A bin directory shaped like the one RubyGems leaves on Windows.

    Both files, because both really are there: ``generate_bin_script`` writes the
    extensionless binstub and then calls ``generate_windows_script`` for the wrapper.
    A fixture with only the ``.bat`` would let a fix that just appended suffixes pass
    without ever proving the binstub stopped winning.

    ASH_BIN_PATH is set through the environment rather than by patching the module
    constant, because ``_bin_path()`` reads the environment first.
    """
    bindir = tmp_path / "ash-bin"
    bindir.mkdir()
    (bindir / "cfn_nag_scan").write_text(
        "#!/usr/bin/env ruby\n# a Ruby binstub: text, not a PE image\n",
        encoding="utf-8",
    )
    (bindir / "cfn_nag_scan.bat").write_text(
        '@ECHO OFF\n@"ruby.exe" "%~dpn0" %*\n', encoding="utf-8"
    )
    monkeypatch.setenv("ASH_BIN_PATH", str(bindir))
    return bindir


@patch(
    "automated_security_helper.utils.subprocess_utils.shutil.which", return_value=None
)
def test_windows_prefers_the_bat_wrapper_over_the_binstub(_mock_which, gem_bindir):
    """The failing case: on Windows the resolved path must be the .bat.

    ``shutil.which`` returns None because ASH's bin directory is not on PATH, which is
    what pushes the lookup onto the directory probe -- the code path that returned the
    binstub in CI.
    """
    with patch(
        "automated_security_helper.utils.subprocess_utils.platform.system",
        return_value="Windows",
    ):
        resolved = find_executable("cfn_nag_scan")

    assert resolved is not None, "the wrapper is in the bin directory and must be found"
    assert Path(resolved).name == "cfn_nag_scan.bat", (
        "resolved to the extensionless Ruby binstub, which is what CreateProcess "
        f"rejects with [WinError 193]; got {resolved}"
    )


@patch(
    "automated_security_helper.utils.subprocess_utils.shutil.which", return_value=None
)
def test_posix_still_resolves_the_extensionless_binstub(_mock_which, gem_bindir):
    """The control. Linux and macOS have no .bat and must keep using the binstub.

    cfn-nag, grype and syft were only just provisioned on Windows, so this code path is
    newly reachable there -- meaning a POSIX regression here would be new breakage
    rather than a pre-existing condition.
    """
    with patch(
        "automated_security_helper.utils.subprocess_utils.platform.system",
        return_value="Linux",
    ):
        resolved = find_executable("cfn_nag_scan")

    assert resolved is not None
    assert Path(resolved).name == "cfn_nag_scan", (
        "POSIX must resolve the extensionless binstub; a .bat is not executable there "
        f"and is not even present. Got {resolved}"
    )


@patch(
    "automated_security_helper.utils.subprocess_utils.shutil.which", return_value=None
)
def test_windows_prefers_a_real_exe_over_a_wrapper(_mock_which, gem_bindir):
    """A native PE image outranks a batch wrapper when both exist."""
    (gem_bindir / "cfn_nag_scan.exe").write_bytes(b"MZ\x90\x00")

    with patch(
        "automated_security_helper.utils.subprocess_utils.platform.system",
        return_value="Windows",
    ):
        resolved = find_executable("cfn_nag_scan")

    assert Path(resolved).name == "cfn_nag_scan.exe", (
        f"a real executable should beat a wrapper; got {resolved}"
    )


@patch(
    "automated_security_helper.utils.subprocess_utils.shutil.which", return_value=None
)
def test_windows_finds_a_cmd_wrapper(_mock_which, tmp_path, monkeypatch):
    """npm's shims are .cmd, and npm_audit_scanner resolves `npm` through this function.

    So the same defect applied to npm-audit on Windows for the same reason, and .cmd is
    in the candidate list rather than just .bat.
    """
    bindir = tmp_path / "npm-bin"
    bindir.mkdir()
    (bindir / "npm").write_text("#!/bin/sh\n", encoding="utf-8")
    (bindir / "npm.cmd").write_text("@ECHO OFF\n", encoding="utf-8")
    monkeypatch.setenv("ASH_BIN_PATH", str(bindir))

    with patch(
        "automated_security_helper.utils.subprocess_utils.platform.system",
        return_value="Windows",
    ):
        resolved = find_executable("npm")

    assert Path(resolved).name == "npm.cmd", f"got {resolved}"


class TestCandidateNames:
    """The ordering contract, asserted directly.

    Order used to come out of ``set()``, so on Windows whether the bare name or ``.exe``
    was tried first depended on set iteration order. That was harmless while every
    candidate was either present or absent, and stopped being harmless once one
    candidate is the wrong file rather than a missing one.
    """

    def test_posix_list_is_exactly_the_command(self):
        with patch(
            "automated_security_helper.utils.subprocess_utils.platform.system",
            return_value="Darwin",
        ):
            assert _executable_candidate_names("cfn_nag_scan") == ["cfn_nag_scan"]

    def test_windows_order_is_exe_bat_cmd_then_bare(self):
        with patch(
            "automated_security_helper.utils.subprocess_utils.platform.system",
            return_value="Windows",
        ):
            assert _executable_candidate_names("cfn_nag_scan") == [
                "cfn_nag_scan.exe",
                "cfn_nag_scan.bat",
                "cfn_nag_scan.cmd",
                "cfn_nag_scan",
            ]

    def test_the_bare_name_is_kept_as_a_fallback(self):
        """Not dropped, just demoted.

        ``shutil.which`` on Windows can resolve a name already carrying a non-PATHEXT
        extension, and a directory probe can find a file Windows can run. Removing the
        bare name would turn both into "not found".
        """
        with patch(
            "automated_security_helper.utils.subprocess_utils.platform.system",
            return_value="Windows",
        ):
            assert _executable_candidate_names("anything")[-1] == "anything"

    @pytest.mark.parametrize(
        "command", ["tool.exe", "tool.bat", "tool.cmd", "TOOL.EXE"]
    )
    def test_an_already_suffixed_command_is_left_alone(self, command):
        """Appending .exe to tool.bat would only add a lookup that cannot hit."""
        with patch(
            "automated_security_helper.utils.subprocess_utils.platform.system",
            return_value="Windows",
        ):
            assert _executable_candidate_names(command) == [command]
