# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A test sees none of the caller's terminal display variables.

tests/conftest.py's ``_clear_the_callers_display_variables`` takes
``process_env.DISPLAY_VARIABLES`` (COLUMNS, LINES, FORCE_COLOR, CLICOLOR_FORCE,
TTY_COMPATIBLE, TTY_INTERACTIVE) out of the run's environment when pytest
imports it, before any test module is imported, and leaves TERM and NO_COLOR as
they are. Under COLUMNS=10 a typer usage panel, a Rich table or a log line is
wrapped, and under FORCE_COLOR or TTY_COMPATIBLE colored, so a cell that matches
the text would fail for the terminal the suite runs in, not for ASH.

The pin runs this module's probe in a child pytest whose environment holds all
six, each set, with TERM=xterm-256color and NO_COLOR=1. The probe checks the
environment, and a Rich console this module builds when it is imported: a
console reads its width, height, color system and interactivity when it is
made, so a clear that comes any later than the import (around each test, say)
leaves that console sized and colored by the caller's terminal.
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest
from rich.console import Console

from automated_security_helper.utils.process_env import DISPLAY_VARIABLES
from tests.utils.helpers import REPO_ROOT, checkout_env

_PROBE_FLAG = "ASH_TEST_DISPLAY_PROBE"

#: Each display variable, set to a value Rich would act on.
_CALLERS_DISPLAY = {
    "COLUMNS": "10",
    "LINES": "5",
    "FORCE_COLOR": "1",
    "CLICOLOR_FORCE": "1",
    "TTY_COMPATIBLE": "1",
    "TTY_INTERACTIVE": "1",
}

#: Built when this module is imported, as the consoles some ASH modules make are.
_CONSOLE_AT_IMPORT = Console()


@pytest.mark.unit
def test_the_pin_sets_every_display_variable():
    assert sorted(_CALLERS_DISPLAY) == sorted(DISPLAY_VARIABLES)


@pytest.mark.unit
@pytest.mark.skipif(
    os.environ.get(_PROBE_FLAG) != "1", reason="the probe runs in the pin's child"
)
def test_the_probe_sees_none_of_the_callers_display_variables():
    assert [name for name in DISPLAY_VARIABLES if name in os.environ] == []
    assert (os.environ.get("TERM"), os.environ.get("NO_COLOR")) == (
        "xterm-256color",
        "1",
    )
    console = _CONSOLE_AT_IMPORT
    assert console.width != int(_CALLERS_DISPLAY["COLUMNS"]), console.width
    assert console.height != int(_CALLERS_DISPLAY["LINES"]), console.height
    assert console.color_system is None, console.color_system
    assert console.is_interactive is False


@pytest.mark.integration
def test_a_test_sees_no_display_variable_from_its_caller(tmp_path):
    env = dict(os.environ)
    env.update(
        _CALLERS_DISPLAY,
        TERM="xterm-256color",
        NO_COLOR="1",
        **{_PROBE_FLAG: "1"},
    )
    probe = f"{__file__}::test_the_probe_sees_none_of_the_callers_display_variables"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            probe,
            # The repository's addopts run every CPU and write the JUnit report CI
            # publishes; neither belongs to a child run.
            "-o",
            "addopts=",
            "-p",
            "no:cacheprovider",
            "-p",
            "no:randomly",
            "-q",
            f"--basetemp={tmp_path / 'basetemp'}",
        ],
        cwd=REPO_ROOT,
        env=checkout_env(env),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=600,
    )

    assert result.returncode == 0, result.stdout[-3000:] + result.stderr[-2000:]
    assert "1 passed" in result.stdout, result.stdout[-3000:]
