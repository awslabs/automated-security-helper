# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A run whose handling raised keeps the response's error out of the record when the
values hook fails.

``_run_subprocess`` has a handler for a run that returned and whose handling by ASH
then raised. It joins the response's own error (the runner keeps it raw) with the
handling error and redacts the whole text with the plugin's values. When the values
hook raised there were no values, so the redaction changed nothing and the raw error
went into the recorded post-run error, the executor's report and the results file,
against the handler's own comment that without the values the records keep only the
error's class and a note. Now the response's error is left out when the values are
withheld, and the note stands alone. With working values the error is kept and
redacted, as before.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from tests.unit.base.test_scanner_plugin_coverage import _scanner

pytestmark = pytest.mark.unit

_RUNNER = (
    "automated_security_helper.utils.subprocess_utils.run_command_with_output_handling"
)

CANARY = "ENVCANARY-err-9c1"


@pytest.fixture
def plugin_context(tmp_path):
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    work_dir = output_dir / ASH_WORK_DIR_NAME
    work_dir.mkdir()
    return PluginContext(
        source_dir=source_dir,
        output_dir=output_dir,
        work_dir=work_dir,
        config=AshConfig(project_name="test"),
    )


def _raise(_response):
    raise RuntimeError("could not record the response")


def _run(plugin_context, tmp_path, monkeypatch, hook):
    """The response ``_run_subprocess`` returns when the runner's response carries
    an error naming the canary, handling the response raises, and the values hook
    is ``hook``."""
    scanner = _scanner(plugin_context)
    monkeypatch.setattr(type(scanner), "_values_to_redact", hook)
    answer = {
        "returncode": 1,
        "stdout": "",
        "stderr": "",
        "error": f"the tool said {CANARY}",
    }

    with (
        patch(_RUNNER, return_value=answer),
        patch.object(type(scanner), "_process_command_response", side_effect=_raise),
    ):
        response = scanner._run_subprocess(
            ["stub-tool", "scan"], results_dir=str(tmp_path / "results")
        )
    return scanner, response


def test_a_failing_hook_leaves_the_responses_error_out_of_the_record(
    plugin_context, tmp_path, monkeypatch
):
    state = {"run": False}

    def _hook(self):
        # Works until the run has returned, then raises: the first read passes and
        # the handler's read is the one that fails.
        if state["run"]:
            raise RuntimeError("hook broke")
        return ()

    def _runner(*_args, **_kwargs):
        state["run"] = True
        return {
            "returncode": 1,
            "stdout": "",
            "stderr": "",
            "error": f"the tool said {CANARY}",
        }

    scanner = _scanner(plugin_context)
    monkeypatch.setattr(type(scanner), "_values_to_redact", _hook)

    with (
        patch(_RUNNER, side_effect=_runner),
        patch.object(type(scanner), "_process_command_response", side_effect=_raise),
    ):
        response = scanner._run_subprocess(
            ["stub-tool", "scan"], results_dir=str(tmp_path / "results")
        )

    assert response["post_run_error"] is True, response
    assert "text not shown" in response["error"], response
    assert CANARY not in response["error"], response
    assert CANARY not in "\n".join(scanner.errors), scanner.errors


def test_a_working_hook_keeps_the_responses_error_redacted(
    plugin_context, tmp_path, monkeypatch
):
    """The control: with the values in hand the error is kept, with the value hidden."""
    scanner, response = _run(
        plugin_context, tmp_path, monkeypatch, lambda self: (CANARY,)
    )

    assert response["post_run_error"] is True, response
    assert "the tool said" in response["error"], response
    assert CANARY not in response["error"], response
    assert CANARY not in "\n".join(scanner.errors), scanner.errors
