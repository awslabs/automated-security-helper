# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A refusal's exit does not chain the error its handler was handling.

The run's failure handlers print an error's redacted text and then exit through
one of three helpers, from inside the ``except`` block. An exception raised
there takes the handled error as its context, and anything that formats the
exit (``traceback.format_exception``, a logged ``exc_info``) prints that
context in full: the unredacted text the handler had just redacted. The exit is
raised ``from None``, so the context is suppressed and only the exit's own
message, the redacted one, is shown.
"""

from __future__ import annotations

import logging
import traceback

import pytest

from automated_security_helper.core.exceptions import ASHConfigValidationError
from automated_security_helper.interactions import run_ash_scan
from automated_security_helper.interactions.run_ash_scan import ScanRefusedExit

pytestmark = pytest.mark.unit

CANARY = "zzhandled-secret-5082"


def _printed_refusal() -> None:
    run_ash_scan._printed_refusal(1, "Exiting due to exception during ASH scan")


def _printed_config_refusal() -> None:
    run_ash_scan._printed_config_refusal(3, ASHConfigValidationError("refused"))


def _logged_refusal() -> None:
    run_ash_scan._logged_refusal(logging.getLogger("ash.test.refusal"), 1, "refused")


@pytest.mark.parametrize(
    "refuse",
    [_printed_refusal, _printed_config_refusal, _logged_refusal],
    ids=lambda refuse: refuse.__name__.lstrip("_"),
)
def test_the_exit_shows_none_of_the_handled_errors_text(refuse):
    try:
        try:
            raise ValueError(f"cannot use {CANARY}")
        except ValueError:
            refuse()
    except ScanRefusedExit as exit_:
        shown = "".join(traceback.format_exception(exit_))
        assert exit_.__suppress_context__ is True
        assert exit_.__cause__ is None
        assert CANARY not in shown, shown
        return
    pytest.fail("the helper did not exit")


def test_the_dry_runs_exit_shows_none_of_the_handled_errors_text():
    """_fail_workspace is called from the dry run's except handlers, so its
    typer.Exit otherwise chains the error being handled, whose unredacted text
    anything formatting the exit prints."""
    import typer

    from automated_security_helper.cli.scan import _fail_workspace

    try:
        try:
            raise ValueError(f"cannot use {CANARY}")
        except ValueError:
            _fail_workspace("refused")
    except typer.Exit as exit_:
        shown = "".join(traceback.format_exception(exit_))
        assert exit_.__suppress_context__ is True
        assert exit_.__cause__ is None
        assert CANARY not in shown, shown
        return
    pytest.fail("_fail_workspace did not exit")


def test_the_workspace_definition_refusals_exit_chains_no_raw_text(monkeypatch):
    """The workspace definition arm echoes error_text(exc) and exits; the exit
    must not chain the definition error itself, whose own str a formatter
    prints raw where the described form was redacted."""
    from automated_security_helper.core.exceptions import WorkspaceDefinitionError
    from automated_security_helper.workspace import execution as workspace_execution
    from automated_security_helper.workspace.plan import WorkspacePlan

    def refuse(*args, **kwargs):
        raise WorkspaceDefinitionError(f"cannot use {CANARY}")

    monkeypatch.setattr(workspace_execution, "execute_workspace", refuse)
    monkeypatch.setattr(run_ash_scan, "build_project_scan_settings", lambda opts: None)
    plan = WorkspacePlan(
        workspace_file="dev.code-workspace",
        workspace_root=".",
        projects=[],
        allow_missing_projects=False,
    )
    opts = run_ash_scan.ScanOptions(source_dir=".", output_dir=".", workspace_plan=plan)

    try:
        run_ash_scan._run_workspace_mode(opts, logging.getLogger("ash.test.k2"))
    except ScanRefusedExit as exit_:
        shown = "".join(traceback.format_exception(exit_))
        assert exit_.__suppress_context__ is True, shown
        assert shown.count(CANARY) == 0, shown
        return
    pytest.fail("the refusal did not exit")
