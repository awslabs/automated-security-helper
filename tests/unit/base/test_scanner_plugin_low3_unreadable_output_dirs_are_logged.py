# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scanner that cannot work out ASH's output directories says so in the log.

``ScannerPluginBase._ash_output_dirs_inside`` answers the directories a scanner
that hands a whole directory to its tool must tell the tool to skip. When the
answer cannot be worked out it returns no directories, and the scan goes on. It
used to do that without a word, so a programming error (a TypeError out of the
scan-set code) became a scan that read ASH's own output back in, with nothing in
the log to say why. It now logs a warning that names the error's type, and not
its text, which can quote a path.
"""

from __future__ import annotations

import logging

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils import scan_output_dirs

pytestmark = pytest.mark.unit

PluginContext.model_rebuild()
AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

GUARD_LINE = "ASH's output directories could not be worked out"
QUOTED_PATH = "/private/place/the-error-quoted"


class _Config(ScannerPluginConfigBase):
    name: str = "output-dirs-probe"


class _Scanner(ScannerPluginBase[_Config]):
    def validate_plugin_dependencies(self) -> bool:
        return True

    def _execute_scan(self, target, target_type, global_ignore_paths):
        raise NotImplementedError("only the output directory helper is used")


def _scanner_and_log(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    output = tmp_path / "output"
    output.mkdir()
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=tmp_path / "work",
        config=AshConfig(project_name="test"),
    )
    logged: list = []
    original = _Scanner._plugin_log

    def recording(self, message, *args, **kwargs):
        logged.append((str(message), kwargs.get("level")))
        return original(self, message, *args, **kwargs)

    monkeypatch.setattr(_Scanner, "_plugin_log", recording)
    return _Scanner(config=_Config(), context=context), source, logged


def _guard_lines(logged):
    return [entry for entry in logged if entry[0].startswith(GUARD_LINE)]


@pytest.mark.parametrize("error", [TypeError, OSError, ValueError])
def test_an_unreadable_answer_is_empty_and_logged_by_type(tmp_path, monkeypatch, error):
    scanner, source, logged = _scanner_and_log(tmp_path, monkeypatch)

    def refuses(*args, **kwargs):
        raise error(QUOTED_PATH)

    monkeypatch.setattr(scan_output_dirs, "output_dirs_to_exclude", refuses)

    assert scanner._ash_output_dirs_inside(source) == []

    lines = _guard_lines(logged)
    assert len(lines) == 1, logged
    message, level = lines[0]
    assert level == logging.WARNING, lines
    assert error.__name__ in message, message
    assert QUOTED_PATH not in message, message


def test_a_readable_answer_logs_no_guard_line(tmp_path, monkeypatch):
    scanner, source, logged = _scanner_and_log(tmp_path, monkeypatch)

    answer = scanner._ash_output_dirs_inside(source)

    assert isinstance(answer, list), answer
    assert _guard_lines(logged) == [], logged
