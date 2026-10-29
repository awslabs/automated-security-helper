# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash scan`` sets the last resort's gate by its console rule, never by ASH_LOG_LEVEL.

The plugin guide (docs/content/plugins/write-a-scanner.md, the paragraph on
``ash scan`` in its thread-logging section) says a line no handler takes reaches
stderr at the scan's console level: its flags first, then ASH_DEBUG or
ASH_VERBOSE, then INFO, and ERROR for --quiet and --simple unless --verbose or
--debug is also given; --log-level INFO reads as the default, so it does not
override the environment; ASH_LOG_LEVEL does not change it. These cells pin each
clause, ASH_LOG_LEVEL ones included: the entry's own gate cells
(test_scan_entry_sets_the_last_resort_gate.py) delete ASH_LOG_LEVEL in their
fixture, so a gate that let it decide passed them.

Measured as that file measures it: the scan stubbed to a recording no-op, the
gate parked at CRITICAL (no arm resolves to it), then read after the command.
"""

import logging
from pathlib import Path

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.utils import log as ash_log

pytestmark = pytest.mark.unit

#: No arm below resolves to CRITICAL: a gate still here means the entry never
#: set it.
_PARKED = logging.CRITICAL

_GUIDE = (
    Path(__file__).resolve().parents[3]
    / "docs"
    / "content"
    / "plugins"
    / "write-a-scanner.md"
)


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


@pytest.mark.parametrize(
    ("flags", "env", "expected"),
    [
        pytest.param([], {}, logging.INFO, id="no-flags-info"),
        pytest.param(
            [], {"ASH_LOG_LEVEL": "ERROR"}, logging.INFO, id="ash-log-level-error"
        ),
        pytest.param(
            [], {"ASH_LOG_LEVEL": "DEBUG"}, logging.INFO, id="ash-log-level-debug"
        ),
        pytest.param([], {"ASH_DEBUG": "true"}, logging.DEBUG, id="ash-debug"),
        pytest.param(
            [], {"ASH_VERBOSE": "true"}, ash_log.VERBOSE_LEVEL, id="ash-verbose"
        ),
        pytest.param(["--quiet"], {}, logging.ERROR, id="quiet"),
        pytest.param(["--simple"], {}, logging.ERROR, id="simple"),
        pytest.param(
            ["--quiet"], {"ASH_LOG_LEVEL": "DEBUG"}, logging.ERROR, id="quiet-over-env"
        ),
        pytest.param(
            ["--quiet"], {"ASH_DEBUG": "true"}, logging.ERROR, id="flag-first"
        ),
        pytest.param(
            ["--quiet", "--verbose"],
            {},
            ash_log.VERBOSE_LEVEL,
            id="verbose-beats-quiet",
        ),
        pytest.param(
            ["--simple", "--debug"], {}, logging.DEBUG, id="debug-beats-simple"
        ),
        pytest.param(
            ["--log-level", "INFO"],
            {"ASH_DEBUG": "true"},
            logging.DEBUG,
            id="log-level-info-reads-as-default",
        ),
        pytest.param(
            ["--log-level", "DEBUG"],
            {"ASH_VERBOSE": "true"},
            logging.DEBUG,
            id="explicit-log-level-over-env",
        ),
    ],
)
def test_the_scan_gate_follows_the_console_rule(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    flags: list,
    env: dict,
    expected: int,
) -> None:
    calls: list = []
    monkeypatch.setattr(
        "automated_security_helper.cli.scan.run_ash_scan",
        lambda **kwargs: calls.append(kwargs),
    )
    for name in ("ASH_LOG_LEVEL", "ASH_DEBUG", "ASH_VERBOSE"):
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    gate_before = ash_log._LAST_RESORT.level
    try:
        ash_log._LAST_RESORT.setLevel(_PARKED)
        result = CliRunner().invoke(
            app,
            ["scan", "--source-dir", str(tmp_path), *flags],
            catch_exceptions=False,
        )
        if result.exit_code != 0 or len(calls) != 1:
            raise RuntimeError(
                (
                    "control: the stubbed scan did not run once",
                    result.exit_code,
                    result.output[-2000:],
                )
            )
        gate = ash_log._LAST_RESORT.level
    finally:
        ash_log._LAST_RESORT.setLevel(gate_before)
    if gate == _PARKED:
        raise RuntimeError("control: the scan entry never set the gate")
    assert gate == expected, (gate, expected)


#: The guide's whole rule, whitespace-normalized: pinning the full sentences,
#: not clauses, so a changed default level or a reordered precedence shows too.
_RULE = (
    "Under `ash scan`, a line no handler takes reaches stderr at the scan's"
    " console level: its flags first, then `ASH_DEBUG` or `ASH_VERBOSE`, then"
    " `INFO`, and `ERROR` for `--quiet` and `--simple` unless `--verbose` or"
    " `--debug` is also given. `--log-level INFO` reads as the default, so it"
    " does not override `ASH_DEBUG` or `ASH_VERBOSE`; every other"
    " `--log-level` does. `ASH_LOG_LEVEL` does not change it there;"
)


def test_the_guide_states_the_rule_these_cells_pin() -> None:
    """The guide's paragraph states the rule the cells above measure, so a
    change to either side shows here."""
    text = " ".join(_GUIDE.read_text(encoding="utf-8").split())
    assert _RULE in text
