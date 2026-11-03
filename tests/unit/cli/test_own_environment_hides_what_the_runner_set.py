# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The ``own_environment`` fixture leaves an ``ash report`` run nothing of the runner's.

``ash report`` finds its configuration from ``ASH_CONFIG`` and from a ``.ash``
file in the working directory or above, and its output directory from
``ASH_OUTPUT_DIR``. The report tests that invoke the command ask for the fixture,
so a variable the runner set, or the checkout's own ``.ash/.ash.yaml``, is not
read by them.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit


@pytest.fixture
def runner_variables(monkeypatch: pytest.MonkeyPatch) -> None:
    """What a runner can set before a test starts."""
    monkeypatch.setenv("ASH_CONFIG", "/nonexistent/runner.ash.yaml")
    monkeypatch.setenv("ASH_OUTPUT_DIR", "/nonexistent/runner-output")


def test_the_runners_variables_are_not_set_for_the_test(
    runner_variables, own_environment
):
    assert "ASH_CONFIG" not in os.environ
    assert "ASH_OUTPUT_DIR" not in os.environ


def test_the_working_directory_is_the_tests_own(
    runner_variables, own_environment, tmp_path
):
    assert Path.cwd().resolve() == tmp_path.resolve()
    assert own_environment == tmp_path
