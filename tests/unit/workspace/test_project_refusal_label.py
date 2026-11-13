# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A workspace project refused for committed output files says so, as written.

A project whose orchestrator refuses its output directory, because git tracks a
file where the scan writes its own, raises ``CommittedOutputFilesError``, an
``ASHConfigValidationError``. Were the workspace to record every such project as
"invalid configuration: ...", a label the CLI drops for that refusal, the
summary would call a committed-output refusal a configuration problem. And were
it to log and print the message as Rich markup, a committed name like
``reports/[/x].sarif`` would break the log line and raise ``MarkupError`` out of
the workspace summary.

A refused project carries the label the single-directory CLI prints ("Scan
refused", or "Invalid configuration" for any other config error), the message is
logged as data, and the summary prints it as written.
"""

from __future__ import annotations

import logging

import pytest

from automated_security_helper.core.exceptions import (
    ASHConfigValidationError,
    CommittedOutputFilesError,
)
from automated_security_helper.utils.log import ASH_LOGGER
from tests.unit.workspace.test_execution import (
    FakeOrchestrator,
    _make_workspace,
    _run,
)

pytestmark = pytest.mark.unit

#: Rich reads both as markup: a closing tag with no opening one, and a style.
MESSAGE = "committed reports/[/x].sarif and reports/[bold]y[/bold].sarif"


@pytest.mark.parametrize(
    ("error", "label"),
    [
        (CommittedOutputFilesError(MESSAGE), "Scan refused"),
        (ASHConfigValidationError(MESSAGE), "Invalid configuration"),
    ],
)
def test_a_refused_project_carries_the_refusals_own_label(tmp_path, error, label):
    _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
    FakeOrchestrator.behaviour["api"] = {"raise": error}

    outcome = _run(tmp_path, plan)

    (entry,) = outcome.payload.projects
    assert entry.status.value == "failed"
    assert entry.invalid_config is True
    assert entry.error == f"{label}: {MESSAGE}"
    assert int(outcome.exit_code) == 3


def test_a_refused_project_is_logged_as_data_not_markup(tmp_path):
    records = []

    class _Keep(logging.Handler):
        def emit(self, record):
            records.append(record)

    keep = _Keep(level=logging.ERROR)
    ASH_LOGGER.addHandler(keep)
    try:
        _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
        FakeOrchestrator.behaviour["api"] = {
            "raise": CommittedOutputFilesError(MESSAGE)
        }
        _run(tmp_path, plan)
    finally:
        ASH_LOGGER.removeHandler(keep)

    (record,) = [r for r in records if "'api'" in r.getMessage()]
    assert MESSAGE in record.getMessage()
    assert "Scan refused" in record.getMessage()
    assert getattr(record, "markup", True) is False


def test_the_workspace_summary_prints_a_refused_project_as_written(
    tmp_path, monkeypatch, capsys
):
    """Through ``ash --workspace``: the project's own orchestrator refuses it, which
    a workspace reaches when its check before the run saw nothing, and the summary
    prints the refusal."""
    from automated_security_helper.interactions.run_ash_scan import run_ash_scan
    from automated_security_helper.workspace import execution

    root, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
    FakeOrchestrator.behaviour["api"] = {"raise": CommittedOutputFilesError(MESSAGE)}
    real = execution.execute_workspace

    def _execute(plan, settings, **_kwargs):
        return real(
            plan,
            settings,
            orchestrator_factory=FakeOrchestrator.create,
            reporter_classes=[],
        )

    monkeypatch.setattr(execution, "execute_workspace", _execute)
    monkeypatch.chdir(tmp_path)

    with pytest.raises(SystemExit) as exited:
        run_ash_scan(
            source_dir=root,
            output_dir=tmp_path / "out",
            workspace_plan=plan,
            progress=False,
            show_summary=True,
        )

    assert exited.value.code == 3
    # Whitespace normalized on both sides: Rich wraps the line at its spaces.
    printed = " ".join(capsys.readouterr().out.split())
    assert f"api: Scan refused: {MESSAGE}" in printed, printed
