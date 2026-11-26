# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The URL-history test file runs directly, with pytest absent, as it says it does.

Its docstring offers ``python -I -B`` on the file as an assertion driver for
environments that check the predicates without pytest, but the file imported
pytest unconditionally, so the offer failed on the first line there. ``-S`` leaves
site-packages out of the child, so pytest is genuinely not importable in it.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

TARGET = Path(__file__).resolve().parent / "test_validate_url_history.py"


def test_the_file_runs_as_a_plain_driver_when_pytest_is_not_importable():
    probe = subprocess.run(
        [sys.executable, "-I", "-B", "-S", "-c", "import pytest"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert probe.returncode != 0, "premise: pytest must be hidden in the child"

    result = subprocess.run(
        [sys.executable, "-I", "-B", "-S", str(TARGET)],
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "0 failed" in result.stdout, result.stdout
