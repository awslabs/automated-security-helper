# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A reduction that raises after the scan returned still hands over the exposed values.

A project's scan masks the secret values its findings exposed and keeps them on
its results, so the workspace can mask every other project's output with them
too. The values reached the masking set only through the reduction of the
results, which runs under the arms of ``_scan_one_project`` so that a raise from
it is recorded. The arms built the failed outcome without them, so a project
whose reduction raised after the scan returned left its values out of the
masking set: its saved reports were masked with the other projects' values and
the other projects' output was not masked with its own.

Each arm now reads the values off the results the scan returned.
"""

from __future__ import annotations

import pytest

from automated_security_helper.core.cancellation import ScanCancelled
from automated_security_helper.core.exceptions import ASHConfigValidationError
from automated_security_helper.models.workspace import ProjectRunStatus
from automated_security_helper.workspace import execution
from tests.unit.workspace.test_execution import (
    FakeOrchestrator,
    _make_workspace,
    _sarif,
    _settings,
)

pytestmark = pytest.mark.unit

SECRET = "hunter2-a-value-a-finding-exposed"


@pytest.fixture(autouse=True)
def _reset_fake():
    FakeOrchestrator.built = []
    FakeOrchestrator.behaviour = {}
    yield
    FakeOrchestrator.built = []
    FakeOrchestrator.behaviour = {}


def _scan_with_a_reduction_that_raises(tmp_path, monkeypatch, error: BaseException):
    _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
    FakeOrchestrator.behaviour["api"] = {
        "sarif": _sarif(level="warning"),
        "secret_values": [SECRET],
    }

    def a_reduction_that_raises(*args, **kwargs):
        raise error

    monkeypatch.setattr(execution, "_reduce_project_scan", a_reduction_that_raises)
    return execution._scan_one_project(
        plan.projects[0], _settings(tmp_path), FakeOrchestrator.create
    )


@pytest.mark.parametrize(
    "error",
    [
        RuntimeError("the reduction broke"),
        ASHConfigValidationError("a config the reduction refused"),
        ScanCancelled("cancelled while reducing"),
    ],
    ids=["a raise", "a config refusal", "a cancel"],
)
def test_the_values_the_scan_exposed_reach_the_masking_set(
    tmp_path, monkeypatch, error
):
    run = _scan_with_a_reduction_that_raises(tmp_path, monkeypatch, error)

    # RED at the base: the arm built its outcome without them, so this was empty.
    assert run.secret_values == {SECRET}
    assert run.output_written is True


def test_a_scan_that_raised_before_it_returned_has_no_values_to_hand_over(
    tmp_path, monkeypatch
):
    """Control, green on both sides: no results, no values, and no error."""
    _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
    FakeOrchestrator.behaviour["api"] = {"raise": RuntimeError("the tool crashed")}

    run = execution._scan_one_project(
        plan.projects[0], _settings(tmp_path), FakeOrchestrator.create
    )

    assert run.outcome.status is ProjectRunStatus.FAILED
    assert run.secret_values == set()
