# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A direct run whose recorder raised leaves no processed mark on the plugin.

The "processed" marks are references to the response objects, so a mark that is
never retired keeps the response, with its whole stdout and stderr, for the plugin's
life, and the list that holds them is scanned on every check. ``_run_subprocess``'s
handler records a COPY of the response (``post_run``), so retiring the copy's mark left
the original's behind whenever the original had been marked, and a direct run (no uv)
marked it inside the accumulator. The accumulator sets no mark now, and the handler
retires the original's when it had one, so a run whose recording raised leaves the list
empty.
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


def test_a_direct_run_whose_first_recording_raised_leaves_no_mark(
    plugin_context, tmp_path, monkeypatch
):
    scanner = _scanner(plugin_context)
    scanner.use_uv_tool = False
    real_record = type(scanner)._record_response

    def _record(self, response, timeout, invoked, guard=False):
        # The unguarded recording raises; the handler's guarded one runs for real.
        if not guard:
            raise RuntimeError("could not record the response")
        return real_record(self, response, timeout, invoked, guard=guard)

    monkeypatch.setattr(type(scanner), "_record_response", _record)

    with patch(
        _RUNNER, return_value={"returncode": 0, "stdout": "", "stderr": "said it"}
    ):
        response = scanner._run_subprocess(
            ["stub-tool", "scan"], results_dir=str(tmp_path / "results")
        )

    assert response["post_run_error"] is True, response
    assert scanner._processed_responses == [], scanner._processed_responses
