# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scan inside the Nix shell reads its options from the argv it is given, not
from the host's environment.

An option left at its default is left off the inner command line, and the scan CLI
reads the environment for the value of such an option (``envvar=`` on its options).
So a host process holding ``ASH_SCANNERS``, ``ASH_CHANGED_FILES_ONLY``,
``ASH_WORKSPACE`` and the like decided the inner scan through the environment,
which is the defect the rebuilt argv set out to close arriving by another door.
``run_ash_nix`` given an argv removes those variables from the shell's environment;
a caller forwarding its own command line (argv None) keeps them, since that command
line was read against them already. The shell is never started here.
"""

from __future__ import annotations

import subprocess
import sys

import pytest

from automated_security_helper.interactions import run_ash_nix as nix

pytestmark = pytest.mark.unit


class _Recorder:
    def __init__(self) -> None:
        self.env = None
        self.cmd = None

    def __call__(self, cmd, env):
        self.cmd = cmd
        self.env = env
        return subprocess.CompletedProcess(cmd, 0)


@pytest.fixture
def shell(monkeypatch) -> _Recorder:
    recorder = _Recorder()
    monkeypatch.setattr(nix, "_enter_shell", recorder)
    monkeypatch.setattr(nix, "find_executable", lambda _name: "/nonexistent/nix")
    monkeypatch.delenv(nix.ASH_IN_NIX_ENV_VAR, raising=False)
    return recorder


@pytest.mark.parametrize("name", nix.INNER_SCAN_OPTION_VARIABLES)
def test_an_option_variable_of_the_host_does_not_reach_an_argv_built_scan(
    shell, monkeypatch, name
):
    monkeypatch.setenv(name, "from-the-host")

    nix.run_ash_nix(argv=["scan", "--source-dir", "src", "--output-dir", "out"])

    assert shell.env is not None
    assert name not in shell.env, (
        f"{name} reached the inner scan, which would read it as an option the "
        "call never gave"
    )


def test_a_forwarded_command_line_keeps_the_hosts_variables(shell, monkeypatch):
    """Control: with no argv the caller's own command line is forwarded, and it was
    read against this environment already."""
    monkeypatch.setenv("ASH_SCANNERS", "grype")
    monkeypatch.setattr(sys, "argv", ["ash", "scan", "--mode", "nix"])

    nix.run_ash_nix()

    assert shell.env is not None
    assert shell.env.get("ASH_SCANNERS") == "grype"


def test_the_config_variable_is_kept_for_an_argv_built_scan(shell, monkeypatch):
    """ASH_CONFIG is how the host side's own config reads find the file too, so
    inner and outer keep agreeing on it."""
    monkeypatch.setenv("ASH_CONFIG", "/elsewhere/ash.yaml")

    nix.run_ash_nix(argv=["scan", "--source-dir", "src", "--output-dir", "out"])

    assert shell.env is not None
    assert shell.env.get("ASH_CONFIG") == "/elsewhere/ash.yaml"


def test_the_shells_own_variables_are_still_set(shell):
    nix.run_ash_nix(argv=["scan", "--source-dir", "src", "--output-dir", "out"])

    assert shell.env is not None
    assert shell.env[nix.ASH_IN_NIX_ENV_VAR] == "1"
    assert shell.env["ASH_OFFLINE"] == "YES"


def test_every_option_variable_of_the_scan_cli_is_listed():
    """Drift guard: each ``envvar=`` the scan CLI declares is either removed for an
    argv-built scan or deliberately kept, by name."""
    import inspect
    import re

    from automated_security_helper.cli import scan as scan_cli

    declared = set(re.findall(r'envvar="([A-Z_]+)"', inspect.getsource(scan_cli)))
    kept_on_purpose = {
        # The host side resolves its own config reads through it (see the
        # constant's comment).
        "ASH_CONFIG",
        # Container mode's runner; the inner scan runs local.
        "OCI_RUNNER",
    }
    assert declared == set(nix.INNER_SCAN_OPTION_VARIABLES) | kept_on_purpose, (
        "a scan option gained or lost an environment variable; decide whether the "
        "inner Nix scan may read it"
    )
