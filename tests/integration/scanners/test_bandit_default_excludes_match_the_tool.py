# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""bandit's default exclude list is read from the bandit tool the scanner runs.

``BANDIT_DEFAULT_EXCLUDES`` is a hand-kept copy of ``bandit.core.constants.EXCLUDE``.
The unit test that compares the two imports bandit into the test interpreter, and
skips wherever bandit is provided as a separate tool (a ``uv tool`` or pipx
environment), which is how the scanner runs it, so the comparison never ran
there. This one reads the list from the interpreter of the ``bandit`` executable
on PATH, the environment that actually provides it, and names that executable
in the failure. Where no such executable is found it skips with that reason: a
skip is not a pass, and a run's record says whether this one ran.
"""

from __future__ import annotations

import json
import shutil
import subprocess

import pytest

from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
    BANDIT_DEFAULT_EXCLUDES,
)
from automated_security_helper.utils import pre_installed_tool

pytestmark = pytest.mark.integration

_READ_BANDITS_EXCLUDES = (
    "import json\n"
    "from bandit.core import constants\n"
    "print(json.dumps(sorted(constants.EXCLUDE)))\n"
)


def test_the_default_excludes_match_the_bandit_tool_environments_own_list():
    executable = shutil.which("bandit")
    if executable is None:
        pytest.skip(
            "no bandit executable is on PATH, so the environment that provides "
            "bandit cannot be read and the drift check did not run"
        )
    interpreter = pre_installed_tool.find_tool_interpreter(executable)
    if interpreter is None:
        pytest.skip(
            f"the interpreter of {executable} cannot be told from the file, so "
            "the drift check did not run"
        )

    completed = subprocess.run(
        [interpreter, "-I", "-c", _READ_BANDITS_EXCLUDES],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )

    assert completed.returncode == 0, (executable, interpreter, completed.stderr[-500:])
    installed = set(json.loads(completed.stdout))
    assert set(BANDIT_DEFAULT_EXCLUDES) == installed, (executable, interpreter)
