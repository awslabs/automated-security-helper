# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``_run_subprocess`` reads the values hook once, guarded, before and after a run.

``_values_to_redact`` is an overridable hook. The direct-execution path passed
its bare answer to the runner, which read an unusable answer (None) as "no
values" and logged the command line and the timeout line in clear; and the
method's own exception handler read the hook bare again, so a hook that raised
there raised out of the handler that was meant to record the run's failure.

Now: an unusable or raising hook before the run refuses the run, as the uv path
does, recorded as a tool that never started and naming the hook; and the
handler's read is guarded, so a hook that raises after the run started leaves a
value-free note in the recorded failure instead of escaping.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.utils.subprocess_utils import SPAWN_FAILURE_RETURNCODE
from tests.unit.base.test_scanner_plugin_coverage import _scanner

pytestmark = pytest.mark.unit

_RUNNER = (
    "automated_security_helper.utils.subprocess_utils.run_command_with_output_handling"
)


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


def test_an_unusable_hook_answer_refuses_the_run(plugin_context, tmp_path, monkeypatch):
    scanner = _scanner(plugin_context)
    monkeypatch.setattr(type(scanner), "_values_to_redact", lambda self: None)

    with patch(_RUNNER) as runner:
        response = scanner._run_subprocess(
            ["stub-tool", "scan"], results_dir=str(tmp_path / "results")
        )

    runner.assert_not_called()
    assert response["spawn_failed"] is True
    assert response["returncode"] == SPAWN_FAILURE_RETURNCODE
    assert "values hook returned an unusable answer" in response["error"], response
    assert scanner.exit_code == SPAWN_FAILURE_RETURNCODE


def test_a_raising_hook_before_the_run_refuses_the_run(
    plugin_context, tmp_path, monkeypatch
):
    def _raises(self):
        raise RuntimeError("hook broke on ENVCANARY-9c1")

    scanner = _scanner(plugin_context)
    monkeypatch.setattr(type(scanner), "_values_to_redact", _raises)

    with patch(_RUNNER) as runner:
        response = scanner._run_subprocess(
            ["stub-tool", "scan"], results_dir=str(tmp_path / "results")
        )

    runner.assert_not_called()
    assert response["spawn_failed"] is True
    assert response["returncode"] == SPAWN_FAILURE_RETURNCODE
    assert scanner.exit_code == SPAWN_FAILURE_RETURNCODE
    assert "values hook raised RuntimeError" in response["error"], response
    assert "ENVCANARY-9c1" not in response["error"]
    assert "ENVCANARY-9c1" not in response["stderr"]


def test_a_hook_that_raises_after_the_run_started_stays_inside_the_handler(
    plugin_context, tmp_path, monkeypatch
):
    """The hook works until the runner is entered, then raises: at the base the
    handler's bare read raised RuntimeError out of _run_subprocess."""
    state = {"run": False}

    def _hook(self):
        if state["run"]:
            raise RuntimeError("hook broke on ENVCANARY-9c1")
        return ()

    def _runner(*args, **kwargs):
        state["run"] = True
        raise OSError("could not start on ENVCANARY-run-9c1")

    scanner = _scanner(plugin_context)
    monkeypatch.setattr(type(scanner), "_values_to_redact", _hook)

    with patch(_RUNNER, side_effect=_runner):
        response = scanner._run_subprocess(
            ["stub-tool", "scan"], results_dir=str(tmp_path / "results")
        )

    # The test measures the handler's guarded read only if the runner was
    # entered: a patch that stopped reaching the call would leave the hook
    # unraised and let the assertions below pass on the real runner's text.
    assert state["run"] is True
    assert response["spawn_failed"] is True
    assert "text not shown" in response["error"], response
    assert "ENVCANARY-run-9c1" not in response["error"], response
    assert "ENVCANARY-run-9c1" not in response["stderr"], response
    # The hook's own message is kept out too, not only the runner's.
    assert "ENVCANARY-9c1" not in response["error"], response
    assert "ENVCANARY-9c1" not in response["stderr"], response
    assert scanner.exit_code == SPAWN_FAILURE_RETURNCODE
