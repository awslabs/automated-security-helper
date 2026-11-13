# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The CLI's scan entry sets the process-wide last-resort gate.

A homeless record -- no live handler on the way takes it -- is shown on
stderr when its level clears the configured gate, and the gate is set once
at a process's entry point (configure_last_resort_level). The MCP server's
start already does this; the CLI's scan entry is the other entry point, and
it must set the gate at the level the one precedence rule resolves from its
flags. run_ash_scan itself never calls the gate: the MCP server hosts it
in-process for every hosted scan, so a gate set there would clobber the
server's own (the must-not-fire control is
test_a_hosted_scans_logger_setup_leaves_the_gate_alone).

Every level this entry can resolve is a name logging knows by the time the
gate is set: ERROR and INFO are stdlib names, and utils/log registers
VERBOSE (15) and TRACE (5) at import, so ``--verbose`` lands the gate at 15
exactly. configure_last_resort_level's deliberate fallback for a name
logging has not got (ASH_LOG_LEVEL, WARNING by default) is pinned in the
utils suite; it is unreachable from this entry, whose precedence rule
collapses QUIET, SIMPLE and ``--mode precommit`` to ERROR before the gate. Each cell parks the
gate at a level no arm resolves to first, so "the entry never called the
gate" and "the entry set the expected level" read differently.
"""

import logging
from pathlib import Path

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.utils import log as ash_log

pytestmark = pytest.mark.unit

#: No arm below resolves to CRITICAL, so a gate still sitting here after the
#: command ran means the entry point never configured it.
_PARKED = logging.CRITICAL


@pytest.fixture(autouse=True)
def _a_moved_gate_fails_the_cell_that_moved_it():
    """This module's cells park the gate and put it back themselves; one that
    moved it and did not is this file's own bug, and the repo-wide restore
    (tests/conftest.py) would absorb it silently -- it exists for the tests
    whose command moves the gate as the entry point's documented behavior.
    Reported here in the run-log-scope guard's idiom: restored, then failed,
    naming the levels."""
    gate_before = ash_log._LAST_RESORT.level
    yield
    gate_after = ash_log._LAST_RESORT.level
    if gate_after == gate_before:
        return
    ash_log._LAST_RESORT.setLevel(gate_before)
    pytest.fail(
        f"this cell left the last resort's gate at {gate_after} (was "
        f"{gate_before}) and it was restored here: put it back in the cell's "
        "own finally"
    )


@pytest.fixture
def recorded_scan(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, object]]:
    """The scan stubbed to a recording no-op, in an environment that names
    no level, so only the command line decides."""
    calls: list[dict[str, object]] = []

    def a_recording_no_op(**kwargs: object) -> None:
        calls.append(kwargs)

    monkeypatch.setattr(
        "automated_security_helper.cli.scan.run_ash_scan", a_recording_no_op
    )
    for name in ("ASH_LOG_LEVEL", "ASH_DEBUG", "ASH_VERBOSE"):
        monkeypatch.delenv(name, raising=False)
    return calls


@pytest.mark.parametrize(
    ("log_flags", "expected_gate"),
    [
        pytest.param(["--log-level", "ERROR"], logging.ERROR, id="asked-for-ERROR"),
        pytest.param([], logging.INFO, id="default-resolves-INFO"),
        pytest.param(
            ["--verbose"],
            ash_log.VERBOSE_LEVEL,
            id="verbose-lands-at-the-registered-VERBOSE-level",
        ),
        pytest.param(["--debug"], logging.DEBUG, id="debug-resolves-DEBUG"),
        pytest.param(["--quiet"], logging.ERROR, id="quiet-collapses-to-ERROR"),
        pytest.param(["--simple"], logging.ERROR, id="simple-collapses-to-ERROR"),
        pytest.param(
            ["--log-level", "SIMPLE"],
            logging.ERROR,
            id="log-level-SIMPLE-collapses-to-ERROR",
        ),
        pytest.param(
            ["--log-level", "QUIET"],
            logging.ERROR,
            id="log-level-QUIET-collapses-to-ERROR",
        ),
        pytest.param(
            ["--mode", "precommit"],
            logging.ERROR,
            id="precommit-mode-asks-for-minimal-output",
        ),
    ],
)
def test_the_scan_entry_sets_the_gate_at_the_resolved_level(
    recorded_scan: list[dict[str, object]],
    tmp_path: Path,
    log_flags: list[str],
    expected_gate: int,
) -> None:
    gate_before = ash_log._LAST_RESORT.level
    try:
        ash_log._LAST_RESORT.setLevel(_PARKED)
        result = CliRunner().invoke(
            app,
            ["scan", "--source-dir", str(tmp_path), *log_flags],
            catch_exceptions=False,
        )
        assert result.exit_code == 0, result.output
        assert len(recorded_scan) == 1, "the stubbed scan did not run exactly once"
        assert ash_log._LAST_RESORT.level == expected_gate, (
            "the scan entry left the last resort's gate where it was parked"
            if ash_log._LAST_RESORT.level == _PARKED
            else "the scan entry set the gate, but not at the resolved level"
        )
    finally:
        ash_log._LAST_RESORT.setLevel(gate_before)


@pytest.mark.parametrize(
    ("env_name", "log_flags", "expected_gate"),
    [
        pytest.param(
            "ASH_DEBUG", [], logging.DEBUG, id="ASH_DEBUG-alone-resolves-DEBUG"
        ),
        pytest.param(
            "ASH_VERBOSE",
            [],
            ash_log.VERBOSE_LEVEL,
            id="ASH_VERBOSE-alone-resolves-VERBOSE",
        ),
        pytest.param(
            "ASH_DEBUG",
            ["--quiet"],
            logging.ERROR,
            id="a-flag-beats-ASH_DEBUG",
        ),
    ],
)
def test_the_gate_follows_the_same_env_precedence_as_the_scan(
    recorded_scan: list[dict[str, object]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    env_name: str,
    log_flags: list[str],
    expected_gate: int,
) -> None:
    """A level that came from the environment reaches the gate below every
    CLI flag: the entry drops an env-sourced --debug/--verbose and the
    resolver reads the variable itself, so the gate and the scan follow one
    precedence rule."""
    monkeypatch.setenv(env_name, "1")
    gate_before = ash_log._LAST_RESORT.level
    try:
        ash_log._LAST_RESORT.setLevel(_PARKED)
        result = CliRunner().invoke(
            app,
            ["scan", "--source-dir", str(tmp_path), *log_flags],
            catch_exceptions=False,
        )
        assert result.exit_code == 0, result.output
        assert len(recorded_scan) == 1, "the stubbed scan did not run exactly once"
        assert ash_log._LAST_RESORT.level == expected_gate, (
            "the scan entry left the last resort's gate where it was parked"
            if ash_log._LAST_RESORT.level == _PARKED
            else "the scan entry set the gate, but not at the resolved level"
        )
    finally:
        ash_log._LAST_RESORT.setLevel(gate_before)
