# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The one_line helper of the reusable scan workflow, as the tests run it.

A step that prints a value it has not checked passes it through one_line, which the
job's "Write the one_line helper" step writes to RUNNER_TEMP. A test that runs such a
step on its own runs that definer first, into the same RUNNER_TEMP, the way the job
does. ``command_lines`` reads output the way the runner does, so a test can count the
workflow commands a step prints.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

DEFINER_NAME = "Write the one_line helper"
HELPER_FILE = "ash-one-line.sh"
HELPER_SOURCE = '. "${RUNNER_TEMP}/' + HELPER_FILE + '"'

#: A value that would add three commands of its own if printed as it is: one after
#: a carriage return, one after a line feed, and one in the legacy `##[` form, which
#: the runner finds anywhere in a line.
COMMAND_TEXT = "v\r::warning::after-cr\n::warning::after-lf ##[warning]legacy"
#: Text one_line leaves of COMMAND_TEXT, so a test can tell the value was printed
#: rather than dropped.
COMMAND_TEXT_SHOWN = "v : :warning: :after-cr : :warning: :after-lf # #[warning]legacy"


def command_lines(output: str) -> list[str]:
    """The lines of ``output`` that the runner reads as workflow commands.

    The runner ends a line at CR, LF or CRLF, and reads a line as a command when it
    starts with `::` after leading whitespace or holds `##[` anywhere.
    """
    return [
        line
        for line in re.split(r"\r\n|\r|\n", output)
        if line.lstrip().startswith("::") or "##[" in line
    ]


def honored_commands(output: str) -> list[str]:
    """``command_lines`` minus what a stop-commands region keeps from being one.

    Between `::stop-commands::<token>` and `::<token>::` the runner reads no line as a
    command. The two marker lines are the step's own and are not counted.
    """
    honored: list[str] = []
    token = None
    for line in re.split(r"\r\n|\r|\n", output):
        if token is not None:
            if line.strip() == f"::{token}::":
                token = None
            continue
        if line.lstrip().startswith("::stop-commands::"):
            token = line.lstrip()[len("::stop-commands::") :]
            continue
        if line.lstrip().startswith("::") or "##[" in line:
            honored.append(line)
    return honored


def definers(steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [step for step in steps if step.get("name") == DEFINER_NAME]


def calls_one_line(step: dict[str, Any]) -> bool:
    """Whether a step that is not the definer calls one_line or with_commands_stopped."""
    run = str(step.get("run") or "")
    return step.get("name") != DEFINER_NAME and (
        "one_line " in run or "with_commands_stopped " in run
    )


def write_helper(steps: list[dict[str, Any]], runner_temp: Path) -> Path:
    """Run the job's definer into ``runner_temp`` and return the helper's path."""
    found = definers(steps)
    assert len(found) == 1, f"expected one {DEFINER_NAME!r} step, found {len(found)}"
    bash = shutil.which("bash")
    assert bash, "bash is required to run the step"
    runner_temp.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [bash, "-e", "-o", "pipefail", "-c", found[0]["run"]],
        env={"PATH": os.environ.get("PATH", ""), "RUNNER_TEMP": str(runner_temp)},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    helper = runner_temp / HELPER_FILE
    assert helper.is_file(), f"{DEFINER_NAME!r} wrote no {HELPER_FILE}"
    return helper
