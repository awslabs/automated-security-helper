# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""test_plugin_system.py leaves the global plugin registry as it found it.

Its tests clear every event handler and register a converter, in the one
registry a worker shares. A later test in the same worker then ran without
ASH's built-in handlers (the snapshot tests' registry is built from what is
there), and with a converter whose module does not exist. Run here in one
pytest process: the built-ins loaded first, as an earlier test would load
them, then test_plugin_system.py, then a check of what is left. The check is
test_plugin_system.py's own registry_changes_left_behind, so the registry is
read only in the file whose tests change it.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
import defusedxml.ElementTree as ET
import pytest

from tests.utils.helpers import checkout_env

pytestmark = pytest.mark.integration

REPOSITORY = Path(__file__).resolve().parents[3]

# Shadows tests/unit/conftest.py's autouse fixture of the same name, so the
# probes behave the same wherever tmp_path lives. When a probe's directory has
# a pytest ini file anywhere in its ancestry (any basetemp under a HOME that
# holds a pyproject.toml, say), pytest applies the collected unit directory's
# autouse fixtures to the probe too; under an ini-free ancestry it does not.
# Without the shadow, the leaked guard fixture errored the probe at setup
# (its module lookup reads the test's path relative to tests/unit, which a
# probe outside the tree is not under), so the meta-test's verdict depended
# on where the run put its tmp. The shadow is autouse so both placements run
# the same no-op; the guard is for unit tests, and the probes are not ones.
_PLACEMENT_SHADOW = """\
import pytest

# tests/conftest.py refuses a test that carries no tier marker, and the
# probes run under it.
pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _unit_tool_guard():
    yield


"""

BEFORE = (
    _PLACEMENT_SHADOW
    + """\
from automated_security_helper.plugins.loader import load_internal_plugins


def test_the_built_ins_are_loaded():
    load_internal_plugins()
"""
)

# The module pytest imported test_plugin_system.py as, earlier in this process.
AFTER = (
    _PLACEMENT_SHADOW
    + """\
from test_plugin_system import registry_changes_left_behind


def test_the_registry_is_as_it_was():
    left = registry_changes_left_behind()
    assert left == [], left
"""
)


def test_the_tests_restore_the_registry(tmp_path):
    (tmp_path / "test_probe_before.py").write_text(BEFORE, encoding="utf-8")
    (tmp_path / "test_probe_after.py").write_text(AFTER, encoding="utf-8")
    report = tmp_path / "report.xml"
    run = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-p",
            "no:cacheprovider",
            "-p",
            "no:randomly",
            "-n",
            "0",
            "-q",
            "-o",
            "addopts=",
            f"--basetemp={tmp_path / 'child'}",
            f"--junitxml={report}",
            str(tmp_path / "test_probe_before.py"),
            "tests/unit/plugins/test_plugin_system.py",
            str(tmp_path / "test_probe_after.py"),
        ],
        cwd=REPOSITORY,
        env=checkout_env(),
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    cases = ET.parse(report).getroot().iter("testcase")
    outcomes = [
        (case.get("name"), case.find("failure") is None and case.find("error") is None)
        for case in cases
    ]
    # The control: all seven ran, in that order, and the six before the check
    # passed: the probe loading the built-ins and test_plugin_system's five.
    names = [name for name, _ in outcomes]
    ran = (
        len(outcomes) == 7
        and names[0] == "test_the_built_ins_are_loaded"
        and names[-1] == "test_the_registry_is_as_it_was"
        and all(passed for _, passed in outcomes[:6])
    )
    assert ran, run.stdout[-3000:]
    # What test_plugin_system.py left behind, as the check found it.
    restored = outcomes[-1][1]
    assert restored, run.stdout[-3000:]
