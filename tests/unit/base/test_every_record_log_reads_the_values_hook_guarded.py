# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The plugin's record logs read the values hook through the one guarded read.

The could-not-start line, the post-run-error line and the recorder handler's
added error each read the overridable hook bare. A hook that answered something
that is no value set read as "no values" there, so the tool's text was written
in clear, and a hook that raised raised again inside the handler. Each record
now takes ``guarded_values_read``: a hook that raised or gave no usable answer
loses the text, and a value-free note takes its place.
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

pytestmark = pytest.mark.unit

PluginContext.model_rebuild()

_VALUE = "SECRET-qz4b9xyz"


def _raising(_self):
    raise RuntimeError(f"the hook broke on {_VALUE}")


def _answering(answer):
    return lambda _self: answer


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


def _logged(scanner, hook, record, response):
    with (
        patch.object(CheckovScanner, "_values_to_redact", hook),
        patch.object(CheckovScanner, "_plugin_log") as log,
    ):
        getattr(scanner, record)(response)
    assert log.call_count == 1, log.call_args_list
    return log.call_args.args[0]


_RECORDS = [
    pytest.param(
        "_record_spawn_failure",
        {"spawn_failed": True, "stderr": f"no such file: {_VALUE}"},
        id="could-not-start",
    ),
    pytest.param(
        "_record_post_run_error",
        {"post_run_error": True, "error": f"write failed: {_VALUE}"},
        id="post-run-error",
    ),
]


@pytest.mark.parametrize("record, response", _RECORDS)
def test_an_unusable_answer_hides_the_text_and_says_why(scanner, record, response):
    line = _logged(scanner, _answering(None), record, dict(response))

    assert _VALUE not in line, line
    assert "values hook returned an unusable answer" in line, line


@pytest.mark.parametrize("record, response", _RECORDS)
def test_a_raising_hook_still_writes_a_value_free_line(scanner, record, response):
    line = _logged(scanner, _raising, record, dict(response))

    assert _VALUE not in line, line
    assert "values hook raised RuntimeError" in line, line


@pytest.mark.parametrize("record, response", _RECORDS)
def test_a_working_hook_hides_only_its_values(scanner, record, response):
    """The control: with a usable hook the line is written and the value hidden."""
    line = _logged(scanner, _answering((_VALUE,)), record, dict(response))

    assert _VALUE not in line, line
    assert "values hook" not in line, line


def test_the_handlers_added_error_survives_a_raising_hook(scanner):
    def broken_recorder(*_args, **_kwargs):
        raise OSError(f"the recorder broke on {_VALUE}")

    response = {"timed_out": True, "returncode": 124}
    with (
        patch.object(CheckovScanner, "_values_to_redact", _raising),
        patch.object(CheckovScanner, "_record_timeout", broken_recorder),
        patch.object(CheckovScanner, "_plugin_log"),
    ):
        scanner._record_response(response, 5, set(), guard=True)

    assert response.get("error"), response
    assert _VALUE not in response["error"], response
    assert "values hook raised RuntimeError" in response["error"], response
