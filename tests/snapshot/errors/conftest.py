# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Shared fixture for the CLI error-message snapshots.

Every test here records what an operator sees when a command refuses or fails:
the exit code, stdout and stderr as three separate fields, because which stream a
message lands on is part of the contract (a CI log that only keeps stderr loses
whatever went to stdout). An exception that escaped the command entirely is
recorded too, by type and message, since that is the case where the user gets a
traceback instead of a sentence.

Each test runs in its own ``tmp_path`` as the working directory and passes paths
relative to it. That is deliberate: rich wraps long lines at the console width,
and an absolute temp path differs in length between machines, so it would move
the wrap points and make the snapshot depend on where the test ran.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app


@pytest.fixture(autouse=True)
def _ruby_toolchain_present(monkeypatch: pytest.MonkeyPatch) -> None:
    """Answer cfn-nag's install probe as a machine with RubyGems and a C compiler.

    Building the scanner set runs ``CfnNagScanner._missing_gem_prerequisites``, which
    looks for ``gem`` and a compiler on PATH and logs a WARNING naming whatever is
    missing. That warning is in the scan errors' output, so without this a snapshot
    recorded whether the machine running the suite had Ruby installed. What the
    installer prints for each missing prerequisite is snapshotted on purpose, host by
    host, in tests/snapshot/dependencies.
    """
    from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_nag_scanner import (
        CfnNagScanner,
    )

    monkeypatch.setattr(CfnNagScanner, "_missing_gem_prerequisites", staticmethod(list))


@pytest.fixture
def in_tmp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Make ``tmp_path`` the working directory, so nothing reads the repo cwd."""
    monkeypatch.chdir(tmp_path)
    return tmp_path


@pytest.fixture
def run_cli(in_tmp: Path) -> Callable[..., dict[str, Any]]:
    """Invoke ``ashx`` in-process and return what the user saw."""

    def _run(args: Sequence[str], **kwargs: Any) -> dict[str, Any]:
        result = CliRunner().invoke(app, list(args), **kwargs)
        seen: dict[str, Any] = {
            "exit_code": int(result.exit_code),
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
        if result.exception is not None and not isinstance(
            result.exception, SystemExit
        ):
            seen["uncaught_exception"] = (
                f"{type(result.exception).__name__}: {result.exception}"
            )
        return seen

    return _run
