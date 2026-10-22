# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A raising values hook cannot abort the plugin's timeout line.

The line is a record, so it follows the guarding rule for record paths: a hook
that raised loses the values, and the line is written with a value-free note
instead of the limit, never skipped and never raising into the run.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
    CheckovScanner,
    CheckovScannerConfig,
)

PluginContext.model_rebuild()

_TIMEOUT = {"timed_out": True, "returncode": 124}


def _raising(_self):
    raise RuntimeError("the hook broke")


@pytest.fixture
def scanner(tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    context = PluginContext(source_dir=source, output_dir=output, config=AshConfig())
    built = CheckovScanner(context=context, config=CheckovScannerConfig())
    built.use_uv_tool = False
    return built


def test_a_raising_hook_still_writes_the_timeout_line(scanner):
    with (
        patch.object(CheckovScanner, "_values_to_redact", _raising),
        patch.object(CheckovScanner, "_plugin_log") as log,
    ):
        scanner._record_timeout(dict(_TIMEOUT), 5)

    assert log.call_count == 1
    line = log.call_args.args[0]
    assert "timed out" in line and "was killed" in line, line
    assert "values hook raised RuntimeError" in line, line


def test_a_working_hook_writes_the_limit(scanner):
    """The control: with a usable hook the line carries the limit as before."""
    with (
        patch.object(CheckovScanner, "_values_to_redact", lambda _self: ()),
        patch.object(CheckovScanner, "_plugin_log") as log,
    ):
        scanner._record_timeout(dict(_TIMEOUT), 5)

    line = log.call_args.args[0]
    assert "timed out after" in line and "was killed" in line, line
    assert "values hook" not in line, line
