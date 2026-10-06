# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What Nix mode prints around the ``nix develop`` call, and what it exits with.

The real CLI runs in-process. Only the lookup of the ``nix`` executable and the one
``subprocess.run`` that would enter the shell are replaced, so the flake reference
ASH resolves, the command it builds from the caller's argv, the messages and the
exit code are ASH's own. The fake records the command, which is part of each
snapshot: it is what an operator sees with ``--debug``, and a flag lost on the way
into the shell would show up there.
"""

from __future__ import annotations

import subprocess  # nosec B404 - only CompletedProcess is used, to fake the shell's result
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

#: Where the fake says ``nix`` is. Fixed, so the recorded command is the same everywhere.
FAKE_NIX = "/nix/var/nix/profiles/default/bin/nix"

SCAN = [
    "scan",
    "--mode",
    "nix",
    "--no-progress",
    "--source-dir",
    "src",
    "--output-dir",
    "out",
]

#: The host prints "ASH Scan Completed in <duration>" from its own wall clock.
pytestmark = pytest.mark.snapshot_masking(mask_durations=True)


class FakeNixShell:
    """Answers the ``nix develop`` call with a status, optionally leaving results."""

    def __init__(self) -> None:
        self.returncode = 0
        self.results_json: str | None = None
        self.commands: list[list[str]] = []
        self.environments: list[dict[str, str]] = []

    def run(self, cmd, env=None, check=False, text=True):
        self.commands.append(list(cmd))
        self.environments.append(dict(env or {}))
        if self.results_json is not None:
            out = Path("out")
            out.mkdir(exist_ok=True)
            out.joinpath("ash_aggregated_results.json").write_text(
                self.results_json, encoding="utf-8"
            )
        return subprocess.CompletedProcess(args=cmd, returncode=self.returncode)


@pytest.fixture(autouse=True)
def _src(in_tmp, monkeypatch):
    (in_tmp / "src").mkdir()
    # Absolute output paths in the summary would fold at a machine-dependent column.
    monkeypatch.setenv("COLUMNS", "1000")
    for name in ("ASH_IN_NIX", "ASH_NIX_FLAKE_REF"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def nix_shell(monkeypatch) -> FakeNixShell:
    from automated_security_helper.interactions import run_ash_nix

    shell = FakeNixShell()
    monkeypatch.setattr(
        run_ash_nix, "find_executable", lambda name: FAKE_NIX if name == "nix" else None
    )
    monkeypatch.setattr(run_ash_nix, "subprocess", SimpleNamespace(run=shell.run))
    return shell


@pytest.fixture
def scan(run_cli, monkeypatch):
    """Run ``ashx <args>`` with ``sys.argv`` set as a real ``ashx`` process would have it.

    Nix mode forwards the caller's argv into the shell verbatim, so in-process it
    would otherwise forward pytest's.
    """

    def _scan(args):
        monkeypatch.setattr(sys, "argv", ["ashx", *args])
        return run_cli(args)

    return _scan


def _seen(result, shell: FakeNixShell) -> dict:
    return {
        **result,
        "nix_commands": shell.commands,
        "ASH_IN_NIX": [env.get("ASH_IN_NIX") for env in shell.environments],
        "ASH_OFFLINE": [env.get("ASH_OFFLINE") for env in shell.environments],
    }


def test_nix_not_installed(scan, snapshot, monkeypatch):
    from automated_security_helper.interactions import run_ash_nix

    monkeypatch.setattr(run_ash_nix, "find_executable", lambda _name: None)
    assert scan(SCAN) == snapshot


def test_already_inside_a_nix_shell(scan, snapshot, nix_shell, monkeypatch):
    monkeypatch.setenv("ASH_IN_NIX", "1")
    assert _seen(scan(SCAN), nix_shell) == snapshot


@pytest.mark.parametrize("returncode", [0, 1])
def test_shell_left_no_results(returncode, scan, snapshot, nix_shell):
    nix_shell.returncode = returncode
    assert _seen(scan(SCAN), nix_shell) == snapshot


def test_shell_exit_with_results(scan, snapshot, nix_shell, fixture_model):
    # The inner scan found something and exited 2; the host reports the shell's
    # status as a warning and reaches its own verdict from the results.
    nix_shell.returncode = 2
    nix_shell.results_json = fixture_model.model_dump_json()
    assert (
        _seen(scan([*SCAN, "--no-fail-on-incomplete-scanners"]), nix_shell) == snapshot
    )


def test_unparseable_results(scan, snapshot, nix_shell):
    nix_shell.results_json = "{not json"
    assert _seen(scan(SCAN), nix_shell) == snapshot


def test_equals_form_of_mode_is_rewritten(scan, snapshot, nix_shell):
    # `--mode=nix` is one token; the inner invocation must still get --mode=local,
    # or it would try to enter the shell again.
    args = ["scan", "--mode=nix", *SCAN[3:]]
    nix_shell.returncode = 1
    assert _seen(scan(args), nix_shell) == snapshot
