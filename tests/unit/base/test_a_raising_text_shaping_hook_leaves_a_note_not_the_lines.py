# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A raising ``_tool_text_for_records`` hook leaves a value-free note, not the lines.

``_process_command_response`` reads two overridable hooks before it records a
run's output: ``_values_to_redact`` (guarded: a raise loses the lines and leaves a
note) and ``_tool_text_for_records`` (the text-shaping hook, which hides the
plugin's own inputs from the lines). The second was called bare, so a shaping hook
that raised escaped the accumulator and turned the run's own outcome into an
error, and recording the unshaped text instead would have shown what the hook was
there to hide. Now a raise records a note for that stream, names no text, and the
run's exit code is still folded.
"""

from __future__ import annotations

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from tests.unit.base.test_scanner_plugin_coverage import _scanner

pytestmark = pytest.mark.unit


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


def test_a_raising_shaping_hook_records_notes_and_no_text(plugin_context, monkeypatch):
    def _raises(self, text, stream):
        raise RuntimeError("shaping broke on SHAPECANARY-4d2")

    scanner = _scanner(plugin_context)
    monkeypatch.setattr(type(scanner), "_tool_text_for_records", _raises)

    scanner._process_command_response(
        {
            "returncode": 1,
            "stdout": "said on stdout SHAPECANARY-out",
            "stderr": "said on stderr SHAPECANARY-err",
        }
    )

    recorded = "\n".join([*scanner.output, *scanner.errors])
    assert "SHAPECANARY" not in recorded, recorded
    assert "(stdout not shown: the plugin's text-shaping hook raised)" in (
        scanner.output
    ), scanner.output
    assert "(stderr not shown: the plugin's text-shaping hook raised)" in (
        scanner.errors
    ), scanner.errors
    # The run's own outcome is still folded.
    assert scanner.exit_code == 1


def test_an_empty_stream_gets_no_note(plugin_context, monkeypatch):
    def _raises(self, text, stream):
        raise RuntimeError("shaping broke")

    scanner = _scanner(plugin_context)
    monkeypatch.setattr(type(scanner), "_tool_text_for_records", _raises)

    scanner._process_command_response(
        {"returncode": 0, "stdout": "", "stderr": "said on stderr"}
    )

    assert not [line for line in scanner.output if "not shown" in line], scanner.output
    assert [line for line in scanner.errors if "stderr not shown" in line]


def test_a_working_shaping_hook_is_unchanged(plugin_context, monkeypatch):
    """The control: a hook that answers is applied and no note is written."""
    scanner = _scanner(plugin_context)
    monkeypatch.setattr(
        type(scanner),
        "_tool_text_for_records",
        lambda self, text, stream: (text or "").replace("SECRET", "***"),
    )

    scanner._process_command_response(
        {"returncode": 0, "stdout": "a SECRET line", "stderr": ""}
    )

    assert "a *** line" in scanner.output, scanner.output
    assert not [line for line in scanner.output if "not shown" in line]
