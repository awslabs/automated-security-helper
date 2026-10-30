# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A plugin shapes its tool's text before the base records it.

``_process_command_response`` splits a run's stdout and stderr into the
recorded ``output`` and ``errors`` lines with the environment-value redaction
and nothing else. A tool that prints a finding's OWN secret in its output
(actionlint's JSON carries a credentials finding's password as its snippet)
had that text recorded, and from there written into the results file's
raw_results. ``_tool_text_for_records`` is the hook such a plugin overrides;
the base applies it to both streams before the split and keeps the text as
it is by default.
"""

from __future__ import annotations

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from tests.unit.base.test_scanner_plugin_coverage import _scanner

pytestmark = pytest.mark.unit

PLANTED = "hunter2-planted-password"


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


def test_an_override_shapes_both_recorded_streams(plugin_context, monkeypatch):
    scanner = _scanner(plugin_context)

    streams: list[str] = []

    def _without_the_planted(self, text, stream):
        streams.append(stream)
        return None if text is None else text.replace(PLANTED, "[removed]")

    monkeypatch.setattr(type(scanner), "_tool_text_for_records", _without_the_planted)

    scanner._process_command_response(
        {
            "stdout": f'{{"snippet": "{PLANTED}"}}',
            "stderr": f"saw {PLANTED} again",
            "returncode": 1,
        }
    )

    assert PLANTED not in " ".join(scanner.output), scanner.output
    assert PLANTED not in " ".join(scanner.errors), scanner.errors
    assert any("[removed]" in line for line in scanner.output), scanner.output
    # The stderr lines were shaped too, not dropped: a swapped stream label or a
    # lost stream would leave the PLANTED checks above green.
    assert any("[removed]" in line for line in scanner.errors), scanner.errors
    assert streams == ["stdout", "stderr"], streams
    assert scanner.exit_code == 1


def test_the_default_keeps_the_text(plugin_context):
    scanner = _scanner(plugin_context)

    scanner._process_command_response(
        {"stdout": "tool line one", "stderr": "tool err one", "returncode": 0}
    )

    assert "tool line one" in " ".join(scanner.output)
    assert "tool err one" in " ".join(scanner.errors)
