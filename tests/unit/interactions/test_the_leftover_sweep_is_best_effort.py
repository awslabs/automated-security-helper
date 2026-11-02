# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The sweep of leftover containers never ends a scan, and looks for a runtime last.

It runs ahead of the clear of the previous run's outputs, in container mode and in
nix mode. A host with nothing to sweep must not resolve a runtime, log about one or
start anything, and a failure anywhere in the step is one warning, not a scan that
stops before it clears: a malformed ``OCI_RUNNER_WRAPPER``, a record that cannot be
unlinked on a read-only mount. A cancel or an interrupt is not an ``Exception`` and
still ends the run.

Every runtime here is a shell stub under ``tmp_path`` that logs its arguments; the
nix shell is replaced by a function that stops the run.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess  # nosec B404 - cells spawn the running interpreter, fixed argv
import sys
from pathlib import Path
from typing import List
from unittest.mock import MagicMock

import pytest

from automated_security_helper.interactions import container_leftovers
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        sys.platform == "win32", reason="the runtime stub is a POSIX shell script"
    ),
]


class _Stop(Exception):
    """Ends the nix-mode path once the cells have what they measure."""


class _Records(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.records: List[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)

    def messages(self, level: int) -> List[str]:
        return [r.getMessage() for r in self.records if r.levelno == level]


@pytest.fixture
def logged():
    handler = _Records()
    previous = ASH_LOGGER.level
    ASH_LOGGER.addHandler(handler)
    ASH_LOGGER.setLevel(logging.DEBUG)
    try:
        yield handler
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(previous)


@pytest.fixture
def dead_pid() -> int:
    child = subprocess.Popen(  # nosec B603 - the running interpreter, fixed argv
        [sys.executable, "-c", "pass"], stdin=subprocess.DEVNULL
    )
    child.wait(timeout=30)
    return child.pid


def _plant(dead_pid: int) -> Path:
    state = Path(os.environ[container_leftovers.STATE_DIR_ENV])
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    name = f"ash-scan-{dead_pid}-0a1b2c3d"
    path = state / f"{name}.json"
    path.write_text(
        json.dumps(
            {
                "kind": "container",
                "host": container_leftovers.host_key(),
                "name": name,
                "creator_pid": dead_pid,
                "creator_start": None,
            }
        ),
        encoding="utf-8",
    )
    return path


def _stub(tmp_path: Path, log: Path) -> Path:
    stub = tmp_path / "order-runtime"
    stub.write_text(f'#!/bin/sh\necho "$@" >> "{log}"\nexit 0\n', encoding="utf-8")
    stub.chmod(0o755)
    return stub


def _nix_mode(tmp_path: Path, log: Path, monkeypatch, runtime: Path | None) -> None:
    """Run nix mode up to the shell, with the clear and the shell both logging."""
    from automated_security_helper.core.enums import RunMode
    from automated_security_helper.interactions import run_ash_scan

    source = tmp_path / "src"
    output = tmp_path / "out"
    source.mkdir()
    output.mkdir()

    def clear(opts, logger):
        with log.open("a", encoding="utf-8") as stream:
            stream.write("CLEAR\n")

    def nix_shell(**kwargs):
        raise _Stop

    monkeypatch.setattr(run_ash_scan, "_discard_prior_run_artifacts", clear)
    monkeypatch.setattr(run_ash_scan, "run_ash_nix", nix_shell)
    monkeypatch.setattr(run_ash_scan, "nix_preflight", lambda: None)
    opts = run_ash_scan.ScanOptions(
        source_dir=source,
        output_dir=output,
        mode=RunMode.nix,
        oci_runner=str(runtime) if runtime is not None else None,
    )
    with pytest.raises(_Stop):
        run_ash_scan._run_nix_mode(opts, MagicMock())


def _lines(log: Path) -> List[str]:
    return log.read_text(encoding="utf-8").splitlines() if log.exists() else []


def test_a_nix_run_with_nothing_to_sweep_resolves_no_runtime_and_logs_nothing(
    tmp_path, monkeypatch, logged
):
    """No record means no runtime lookup, even with a wrapper that cannot be read."""
    monkeypatch.setenv("OCI_RUNNER_WRAPPER", "sudo 'x")
    log = tmp_path / "order.log"
    runtime_log = tmp_path / "runtime.log"
    stub = _stub(tmp_path, runtime_log)

    _nix_mode(tmp_path, log, monkeypatch, runtime=stub)

    assert _lines(log) == ["CLEAR"], _lines(log)
    assert logged.messages(logging.WARNING) == [], logged.messages(logging.WARNING)
    assert not [m for m in logged.messages(logging.INFO) if "OCI_RUNNER" in m]
    assert not [m for m in logged.messages(logging.DEBUG) if "Resolved OCI" in m]
    assert _lines(runtime_log) == []


def test_a_malformed_wrapper_with_a_record_is_one_warning_and_the_clear_still_runs(
    tmp_path, monkeypatch, logged, dead_pid
):
    record = _plant(dead_pid)
    monkeypatch.setenv("OCI_RUNNER_WRAPPER", "sudo 'x")
    log = tmp_path / "order.log"
    runtime_log = tmp_path / "runtime.log"
    stub = _stub(tmp_path, runtime_log)

    _nix_mode(tmp_path, log, monkeypatch, runtime=stub)

    assert _lines(log) == ["CLEAR"], _lines(log)
    warnings = logged.messages(logging.WARNING)
    assert len(warnings) == 1 and "Could not sweep leftover containers" in warnings[0]
    assert _lines(runtime_log) == [], "the runtime was called for a wrapper that failed"
    assert record.exists()


def test_a_record_that_cannot_be_unlinked_is_a_warning_and_the_scan_goes_on(
    tmp_path, monkeypatch, logged, dead_pid
):
    record = _plant(dead_pid)
    monkeypatch.delenv("OCI_RUNNER_WRAPPER", raising=False)
    runtime_log = tmp_path / "runtime.log"
    stub = _stub(tmp_path, runtime_log)
    log = tmp_path / "order.log"

    def refuse(path, *args, **kwargs):
        raise PermissionError(30, "Read-only file system", str(path))

    with monkeypatch.context() as patch:
        patch.setattr(os, "unlink", refuse)
        _nix_mode(tmp_path, log, monkeypatch, runtime=stub)

    assert _lines(runtime_log) == [f"rm -f {record.stem}"]
    assert _lines(log) == ["CLEAR"]
    warnings = logged.messages(logging.WARNING)
    assert len(warnings) == 1 and "could not drop its record" in warnings[0], warnings
    assert record.exists()


def test_a_planted_record_and_a_working_runtime_remove_the_container_before_the_clear(
    tmp_path, monkeypatch, logged, dead_pid
):
    """The negative control: nothing fails, so the order is the plain one."""
    record = _plant(dead_pid)
    monkeypatch.delenv("OCI_RUNNER_WRAPPER", raising=False)
    log = tmp_path / "order.log"
    stub = _stub(tmp_path, log)

    _nix_mode(tmp_path, log, monkeypatch, runtime=stub)

    assert _lines(log) == [f"rm -f {record.stem}", "CLEAR"], _lines(log)
    assert logged.messages(logging.WARNING) == []
    assert not record.exists()


def test_the_sweeps_runtime_lookup_is_logged_at_debug(
    tmp_path, monkeypatch, logged, dead_pid
):
    """Container mode resolves the runtime again for the run, so the sweep's own
    lookup does not print the line a second time."""
    _plant(dead_pid)
    monkeypatch.delenv("OCI_RUNNER_WRAPPER", raising=False)
    stub = _stub(tmp_path, tmp_path / "runtime.log")
    log = tmp_path / "order.log"

    _nix_mode(tmp_path, log, monkeypatch, runtime=stub)

    assert not [m for m in logged.messages(logging.INFO) if "Resolved OCI_RUNNER" in m]
    assert [m for m in logged.messages(logging.DEBUG) if "Resolved OCI_RUNNER" in m]
