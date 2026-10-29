# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every record path reads the plugin's values hook through one guarded read.

``_values_to_redact`` is an overridable hook, and its record paths each guarded
it their own way: one normalized the answer, another split a bare string into
its characters (each below the length floor, so nothing was hidden), another
turned a raising hook into an empty value set (so the text printed in clear).
``PluginBase._guarded_values`` is the one read: ``None`` when the hook raised
or answered something that is not a value set, ``()`` when there are none, and
a bare string is ONE value.

The "not shown" note also says which of the two broke: a hook that raised, or a
hook that returned an answer no value set can be read from.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
    CheckovScanner,
    CheckovScannerConfig,
)
from tests.unit.base.test_uv_tool_mixin import FakePlugin

pytestmark = pytest.mark.unit

PluginContext.model_rebuild()

#: Long enough to clear the redaction length floor, so a split into characters
#: is the only reason it would print.
_VALUE = "tool-qz4b9secret"


def _raising(_self):
    raise RuntimeError("the hook broke")


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


def _version_probe(plugin, hook):
    """Run ``_get_uv_tool_version`` with ``hook`` as the values hook; return the
    runner stand-in and the version the plugin carried."""
    with (
        patch.object(type(plugin), "_values_to_redact", hook),
        patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner"
        ) as get_runner,
    ):
        runner = MagicMock()
        runner.is_uv_available.return_value = True
        runner.get_tool_version.return_value = "1.7.0"
        get_runner.return_value = runner
        version = plugin._get_uv_tool_version("bandit")
    return runner, version


def test_a_bare_string_answer_reaches_the_version_probe_whole():
    runner, _ = _version_probe(FakePlugin(), _answering(_VALUE))

    assert runner.get_tool_version.call_args.kwargs["values"] == (_VALUE,)


def test_a_list_answer_reaches_the_version_probe_as_a_tuple():
    """The control: an ordinary value set is passed on as it is."""
    runner, _ = _version_probe(FakePlugin(), _answering([_VALUE, "other-value"]))

    assert runner.get_tool_version.call_args.kwargs["values"] == (
        _VALUE,
        "other-value",
    )


def test_a_raising_hook_does_not_run_the_version_probe():
    """The probe's answer is memoized by the runner. With no values to redact
    with, running it would record the unredacted answer, so the probe is not
    run and the version stays unknown."""
    runner, version = _version_probe(FakePlugin(), _raising)

    runner.get_tool_version.assert_not_called()
    assert version is None


def test_a_bare_string_answer_is_hidden_from_the_install_setup_line():
    plugin = FakePlugin(command=_VALUE, use_uv_tool=True)
    with (
        patch.object(type(plugin), "_values_to_redact", _answering(_VALUE)),
        patch.object(plugin, "_is_offline_mode", return_value=False),
    ):
        plugin._setup_uv_tool_install_commands()

    logged = "\n".join(
        " ".join(str(part) for part in msg) for msg in plugin._log_messages
    )
    assert logged, "the setup logged nothing, so the cell shows nothing"
    assert _VALUE not in logged, logged


def _recorded(scanner, hook, **response):
    with patch.object(type(scanner), "_values_to_redact", hook):
        scanner._process_command_response(
            {"stdout": "out line", "stderr": "err line", "returncode": 0, **response}
        )
    return list(scanner.output), list(scanner.errors)


def test_a_raising_hook_keeps_the_raised_note(scanner):
    """The control: a hook that raised still loses the lines, and says so."""
    output, errors = _recorded(scanner, _raising)

    assert output == ["(stdout not shown: the plugin's redaction hook raised)"]
    assert errors == ["(stderr not shown: the plugin's redaction hook raised)"]


def test_a_hook_that_returned_no_value_set_is_not_said_to_have_raised(scanner):
    output, errors = _recorded(scanner, _answering(None))

    assert output == [
        "(stdout not shown: the plugin's redaction hook returned an unusable answer)"
    ]
    assert errors == [
        "(stderr not shown: the plugin's redaction hook returned an unusable answer)"
    ]


def test_a_bare_string_answer_hides_the_whole_value_in_report_lines(scanner):
    """The control: the record path already reads a bare string as one value."""
    output, errors = _recorded(
        scanner,
        _answering(_VALUE),
        stdout=f"found {_VALUE} here",
        stderr=f"saw {_VALUE} there",
    )

    assert output and errors
    assert _VALUE not in "\n".join(output + errors), (output, errors)


def test_no_values_leaves_the_lines_as_they_are(scanner):
    """The control: an empty value set is no values, not a broken hook."""
    output, errors = _recorded(scanner, _answering(()))

    assert output == ["out line"]
    assert errors == ["err line"]
