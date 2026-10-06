# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Regression tests: ``ash scan --mode nix`` refuses with a message, not a traceback.

``run_ash_nix`` raises when ``nix`` is not on PATH and when it is called from inside
a Nix-mode run (the recursion guard). Nothing caught either, so the command ended in
an uncaught ``RuntimeError``: the operator got a traceback and whatever exit code the
interpreter chose. Both now print the message on stderr and exit 1, the code
``ash scan`` uses for its other refused invocations (see ``_fail_usage`` in
``cli/scan.py``): 2 means "actionable findings", so a refusal must not exit 2.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.interactions import run_ash_nix

USAGE_ERROR_EXIT = 1

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


@pytest.fixture
def in_project(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "src").mkdir()
    for name in ("ASH_IN_NIX", "ASH_NIX_FLAKE_REF"):
        monkeypatch.delenv(name, raising=False)
    return tmp_path


@pytest.fixture
def shell_calls(monkeypatch):
    """Record any attempt to enter the shell; a refusal must make none."""
    calls: list = []
    monkeypatch.setattr(
        run_ash_nix.subprocess, "run", lambda *a, **k: calls.append(a) or None
    )
    return calls


def _assert_refused(result, fragment):
    assert result.exit_code == USAGE_ERROR_EXIT, result.output
    # A clean exit, not an exception escaping the command.
    assert isinstance(result.exception, SystemExit), repr(result.exception)
    assert "Traceback" not in result.output
    assert fragment in result.stderr, result.stderr


def test_nix_not_on_path_is_refused_cleanly(in_project, shell_calls, monkeypatch):
    monkeypatch.setattr(run_ash_nix, "find_executable", lambda _name: None)

    result = CliRunner().invoke(app, SCAN)

    _assert_refused(result, "--mode nix requires Nix, which was not found on PATH")
    assert shell_calls == []


def test_recursion_guard_is_refused_cleanly(in_project, shell_calls, monkeypatch):
    monkeypatch.setenv("ASH_IN_NIX", "1")
    monkeypatch.setattr(run_ash_nix, "find_executable", lambda _name: "/bin/nix")

    result = CliRunner().invoke(app, SCAN)

    _assert_refused(result, "already running inside a Nix shell")
    assert shell_calls == []


def test_the_refusal_is_still_a_runtime_error_for_library_callers(monkeypatch):
    """Callers of ``run_ash_nix`` that caught ``RuntimeError`` keep working."""
    monkeypatch.delenv("ASH_IN_NIX", raising=False)
    monkeypatch.setattr(run_ash_nix, "find_executable", lambda _name: None)

    with pytest.raises(run_ash_nix.NixModeRefused) as excinfo:
        run_ash_nix.run_ash_nix(argv=["scan"])

    assert isinstance(excinfo.value, RuntimeError)
