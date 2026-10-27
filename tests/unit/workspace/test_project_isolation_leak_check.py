# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""test_project_isolation's autouse leak check fails the test that leaked, and no other.

Checked in a separate pytest run, because the check runs in a fixture's teardown: a
test cannot observe its own teardown failing. The inner run takes the real fixture
from test_project_isolation, leaks a mock the way an unstopped patch does, and runs
one more test after it.
"""

from __future__ import annotations

import os
from pathlib import Path

pytest_plugins = ["pytester"]

REPO_ROOT = Path(__file__).resolve().parents[3]

INNER = """
from unittest.mock import MagicMock, patch

from automated_security_helper.core.phases import scan_phase
from automated_security_helper.models.scanner_validation import ScannerValidationManager
from tests.unit.workspace.test_project_isolation import _reset_recorders


def test_a_leak():
    patch(
        "automated_security_helper.core.phases.scan_phase.ScannerValidationManager",
        MagicMock(name="leaked-manager"),
    ).start()


def test_after_the_leak():
    assert scan_phase.ScannerValidationManager is ScannerValidationManager
"""


def test_a_leak_fails_the_test_that_made_it_and_no_other(pytester, monkeypatch):
    pytester.makepyfile(test_inner=INNER)
    monkeypatch.setenv(
        "PYTHONPATH",
        os.pathsep.join(p for p in (str(REPO_ROOT), os.environ.get("PYTHONPATH")) if p),
    )

    result = pytester.runpytest_subprocess("-p", "no:cacheprovider", "-n", "0")

    result.assert_outcomes(passed=2, errors=1)
    result.stdout.fnmatch_lines(["*ERROR at teardown of test_a_leak*"])
    result.stdout.fnmatch_lines(["*leaked-manager*"])
