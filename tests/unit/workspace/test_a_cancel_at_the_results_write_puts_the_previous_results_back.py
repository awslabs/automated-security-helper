# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A project cancelled at its results-file write gets its previous results back.

With ``keep_previous_results`` a project's orchestrator sets the previous
results aside, and drops them once the scan counts as having results. A cancel
read at the orchestrator's own write of the results file ends the scan with the
previous results still set aside, and the orchestrator leaves them for its
caller to settle. The workspace is that caller, and its cancelled arm never
settled them, so the last complete results of the project stayed hidden in
``.ash_previous_results`` until the next scan in that directory.

The cancelled arm now asks the orchestrator to put them back.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, List

import pytest

from automated_security_helper.core.cancellation import ScanCancelled
from automated_security_helper.core.committed_output import RESULTS_FILE_NAME
from automated_security_helper.core.previous_results import (
    HELD_DIR_NAME,
    PreviousResults,
)
from automated_security_helper.workspace import execution
from tests.unit.workspace.test_execution import (
    FakeOrchestrator,
    _make_workspace,
    _settings,
)

pytestmark = pytest.mark.unit

PREVIOUS = '{"previous": "the last complete results"}\n'


class _CancelledAtTheWrite:
    """An orchestrator that kept the previous results and was cancelled at the write.

    Built as the real one is with ``keep_previous_results``: the results file
    that was in the output directory is set aside when it is constructed. The
    scan then ends the way a cancel read at the results-file write ends it,
    with them still set aside, and ``settle_previous_results`` is the real
    method's two outcomes.
    """

    built: List["_CancelledAtTheWrite"] = []

    def __init__(self, **kwargs: Any) -> None:
        self.output_dir = Path(kwargs["output_dir"])
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / RESULTS_FILE_NAME).write_text(PREVIOUS, encoding="utf-8")
        self._previous = PreviousResults(self.output_dir)
        self._previous.set_aside()
        _CancelledAtTheWrite.built.append(self)

    @classmethod
    def create(cls, **kwargs: Any) -> "_CancelledAtTheWrite":
        return cls(**kwargs)

    def execute_scan(self, phases: Any = None) -> Any:
        raise ScanCancelled("cancelled at the results-file write")

    def settle_previous_results(self, restore: bool) -> None:
        if restore:
            self._previous.restore()
        else:
            self._previous.discard()


@pytest.fixture(autouse=True)
def _reset():
    _CancelledAtTheWrite.built = []
    FakeOrchestrator.built = []
    FakeOrchestrator.behaviour = {}
    yield
    _CancelledAtTheWrite.built = []
    FakeOrchestrator.built = []
    FakeOrchestrator.behaviour = {}


def test_a_cancel_at_the_write_leaves_the_previous_results_in_place(tmp_path):
    _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))

    execution._scan_one_project(
        plan.projects[0], _settings(tmp_path), _CancelledAtTheWrite.create
    )

    (orchestrator,) = _CancelledAtTheWrite.built
    # RED at the base: the arm never settled them, so the file was still under
    # the held directory and the top level had no results file.
    assert (orchestrator.output_dir / RESULTS_FILE_NAME).read_text(
        encoding="utf-8"
    ) == PREVIOUS
    assert not (orchestrator.output_dir / HELD_DIR_NAME).exists()


def test_a_cancel_of_an_orchestrator_with_nothing_to_settle_still_ends_the_project(
    tmp_path,
):
    """Control, green on both sides: a stand-in with no settle method is not asked."""
    _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
    FakeOrchestrator.behaviour["api"] = {"raise": ScanCancelled("cancelled")}

    run = execution._scan_one_project(
        plan.projects[0], _settings(tmp_path), FakeOrchestrator.create
    )

    assert run.outcome.error == "cancelled"
