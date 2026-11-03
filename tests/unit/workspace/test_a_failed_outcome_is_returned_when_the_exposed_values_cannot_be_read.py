# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A project's failed outcome is still returned when its secret values cannot be read.

The arms of ``_scan_one_project`` that run after a raise from the reduction read
the values the scan exposed off the results the scan returned, and those results
may be the very object that was malformed. The read sat unguarded in the cancel,
config-refusal and general arms, so a raise from it left the arm without its
outcome and the project was recorded as a plain failure, with none of the
re-masking the arms exist to do. The read now falls back to no values, logs the
error, and the arm returns its outcome.
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


def _scan(tmp_path, monkeypatch, error: BaseException, reader):
    _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
    FakeOrchestrator.behaviour["api"] = {
        "sarif": _sarif(level="warning"),
        "secret_values": [SECRET],
    }

    def a_reduction_that_raises(*args, **kwargs):
        raise error

    monkeypatch.setattr(execution, "_reduce_project_scan", a_reduction_that_raises)
    if reader is not None:
        monkeypatch.setattr(execution, "exposed_secret_values", reader)
    return execution._scan_one_project(
        plan.projects[0], _settings(tmp_path), FakeOrchestrator.create
    )


def _a_read_that_raises(results):
    raise TypeError("the recorded values are not iterable")


@pytest.mark.parametrize(
    "error",
    [
        RuntimeError("the reduction broke"),
        ASHConfigValidationError("a config the reduction refused"),
        ScanCancelled("cancelled while reducing"),
    ],
    ids=["a raise", "a config refusal", "a cancel"],
)
def test_the_arm_returns_its_outcome_with_no_values_when_the_read_raises(
    tmp_path, monkeypatch, error
):
    run = _scan(tmp_path, monkeypatch, error, _a_read_that_raises)

    # RED at the base: the read raised inside the arm and the call raised with it.
    assert run.secret_values == set()
    assert run.output_written is True


def test_the_general_arm_records_the_project_as_failed_when_the_read_raises(
    tmp_path, monkeypatch
):
    run = _scan(tmp_path, monkeypatch, RuntimeError("broke"), _a_read_that_raises)

    assert run.outcome.status is ProjectRunStatus.FAILED
    assert "RuntimeError" in (run.outcome.error or "")


def test_the_values_are_still_handed_over_when_the_read_works(tmp_path, monkeypatch):
    """Control, green on both sides: the guard changes nothing for a readable result."""
    run = _scan(tmp_path, monkeypatch, RuntimeError("broke"), None)

    assert run.secret_values == {SECRET}
