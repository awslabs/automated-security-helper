# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Regression test: `ash report` reads the results file as UTF-8, not as the locale.

Why this file exists
--------------------
Measured on ``scan (python-local, windows-latest)``, in the "Validate No Plugin Errors"
step:

    Checking for plugin execution errors...
    Error loading results file: 'charmap' codec can't decode byte 0x9d in ...

That message is ``cli/report.py``'s, from the broad ``except`` around the results load.
``open(results_file, "r")`` with no encoding uses the process's locale encoding, which is
cp1252 on Windows, and 0x9d is unmapped in cp1252. ASH writes this file as UTF-8, and
findings routinely carry bytes cp1252 cannot decode -- a snippet quoted out of a
non-ASCII source file, a tool's smart quotes. So on Windows ``ash report`` could not
render a report for any scan whose results were not pure cp1252.

Why the existing tests in test_report.py did not catch it
--------------------------------------------------------
All four of them mock ``builtins.open``, ``Path`` and ``AshAggregatedResults`` together,
so not one of them ever opens a real file. A test that never performs the read cannot
observe how the read is decoded. Hence a real file with real bytes below.

How the platform is simulated, and why not with the locale
----------------------------------------------------------
The obvious test -- patch ``locale.getpreferredencoding`` to return cp1252 and watch the
read fail -- is vacuous. Measured on CPython 3.13: ``open(encoding=None)`` resolves the
locale encoding in C and ignores the Python-level function, so patching
``locale.getpreferredencoding`` *and* ``locale.getencoding`` both leave ``open`` reading
UTF-8. That test passes whether or not the fix is present.

So ``open`` is shimmed inside the report module's namespace instead: a caller that pins
no encoding gets cp1252, which is what Windows does and this runner does not. The shim
delegates to the real ``open`` for everything else, so the read is a real read of a real
file. Injected into the module globals rather than over ``builtins.open``, which would
apply to plugin loading, rich and pydantic for the duration of the call.
"""

import json
from unittest.mock import MagicMock, patch

import pytest
import typer

from automated_security_helper.cli.report import report_command

# U+009D encodes to UTF-8 as C2 9D. 0x9D is one of cp1252's five unmapped bytes, which is
# why the CI failure named that byte specifically.
NON_CP1252_CHAR = chr(0x9D)


class _LocaleDefaultOpen:
    """An ``open`` that decodes with cp1252 when the caller pins no encoding.

    Records the encoding each text-mode call asked for, so a test can assert the call was
    explicit rather than only that it happened to succeed.
    """

    def __init__(self, real_open, locale_encoding="cp1252"):
        self._real_open = real_open
        self._locale_encoding = locale_encoding
        self.text_encodings_requested = []

    def __call__(self, file, mode="r", buffering=-1, encoding=None, *args, **kwargs):
        if "b" not in mode:
            self.text_encodings_requested.append(encoding)
            if encoding is None:
                encoding = self._locale_encoding
        return self._real_open(file, mode, buffering, encoding, *args, **kwargs)


def _write_results_file(output_dir):
    """A results file holding a character cp1252 cannot decode, written as UTF-8."""
    results_path = output_dir / "ash_aggregated_results.json"
    payload = {
        "metadata": {"summary_stats": {"actionable": 1}},
        "scanner_results": {
            "cfn-nag": {
                "status": "FAILED",
                # Shaped like what actually carries these bytes: a snippet quoted out of
                # the scanned source.
                "detail": f"unparseable template near{NON_CP1252_CHAR}line 3",
            }
        },
    }
    # ensure_ascii=False is load-bearing. json.dumps escapes non-ASCII by default, which
    # wrote the character as a six-character ASCII escape sequence instead of the two
    # UTF-8 bytes -- a pure-ASCII file, which decodes identically under cp1252 and
    # UTF-8, so the test passed with and without the fix. The guard below is what
    # caught that, and is why it is an assert rather than a comment.
    results_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    assert b"\xc2\x9d" in results_path.read_bytes(), (
        "the fixture did not put a non-cp1252 byte on disk, so this test cannot "
        "distinguish a utf-8 read from a locale read"
    )
    return results_path


@pytest.fixture
def reporter_plugin():
    """A text reporter, mocked. This test is about the read, not about rendering."""
    plugin = MagicMock()
    plugin.config.name = "text"
    plugin.report.return_value = "rendered"
    plugin_class = MagicMock()
    plugin_class.__name__ = "MockTextReporter"
    plugin_class.return_value = plugin
    return plugin_class, plugin


@patch("automated_security_helper.cli.report.load_plugins")
@patch("automated_security_helper.cli.report.resolve_config")
@patch("automated_security_helper.cli.report.ash_plugin_manager")
@patch("automated_security_helper.cli.report.PluginContext")
@patch("automated_security_helper.cli.report.AshAggregatedResults")
@patch("automated_security_helper.cli.report.print")
def test_results_file_is_read_as_utf8_under_a_cp1252_locale(
    _mock_print,
    mock_results_class,
    _mock_plugin_context,
    mock_plugin_manager,
    _mock_resolve_config,
    _mock_load_plugins,
    tmp_path,
    reporter_plugin,
):
    """The failing case, end to end through report_command.

    Before the fix this raises ``typer.Exit(1)`` from the ``except`` that printed
    "Error loading results file: 'charmap' codec can't decode byte 0x9d".
    """
    _write_results_file(tmp_path)
    plugin_class, _plugin = reporter_plugin
    mock_plugin_manager.plugin_modules.return_value = [plugin_class]

    shim = _LocaleDefaultOpen(open)
    with patch("automated_security_helper.cli.report.open", shim, create=True):
        # No pytest.raises: completing without a typer.Exit is the assertion.
        report_command(report_format="text", output_dir=str(tmp_path))

    mock_results_class.model_validate_json.assert_called_once()
    loaded_text = mock_results_class.model_validate_json.call_args[0][0]
    assert NON_CP1252_CHAR in loaded_text, (
        "the results file was read but the non-cp1252 character did not survive, so "
        "some decoding happened that this test did not intend"
    )


@patch("automated_security_helper.cli.report.load_plugins")
@patch("automated_security_helper.cli.report.resolve_config")
@patch("automated_security_helper.cli.report.ash_plugin_manager")
@patch("automated_security_helper.cli.report.PluginContext")
@patch("automated_security_helper.cli.report.AshAggregatedResults")
@patch("automated_security_helper.cli.report.print")
def test_the_read_pins_an_encoding_rather_than_inheriting_one(
    _mock_print,
    _mock_results_class,
    _mock_plugin_context,
    mock_plugin_manager,
    _mock_resolve_config,
    _mock_load_plugins,
    tmp_path,
    reporter_plugin,
):
    """The invariant, named directly: no text read here may pass encoding=None.

    The test above would also pass if someone set the locale to UTF-8 somewhere; this one
    only passes if the call site is explicit, which is the property that makes the
    behaviour platform-independent.
    """
    _write_results_file(tmp_path)
    plugin_class, _plugin = reporter_plugin
    mock_plugin_manager.plugin_modules.return_value = [plugin_class]

    shim = _LocaleDefaultOpen(open)
    with patch("automated_security_helper.cli.report.open", shim, create=True):
        report_command(report_format="text", output_dir=str(tmp_path))

    assert shim.text_encodings_requested, "no text-mode open happened at all"
    assert None not in shim.text_encodings_requested, (
        "a text read left encoding unset, so it decodes with whatever the platform "
        f"locale happens to be. Encodings requested: {shim.text_encodings_requested}"
    )
    assert set(shim.text_encodings_requested) == {"utf-8"}, (
        f"expected every text read to pin utf-8; got {shim.text_encodings_requested}"
    )


@patch("automated_security_helper.cli.report.load_plugins")
@patch("automated_security_helper.cli.report.resolve_config")
@patch("automated_security_helper.cli.report.ash_plugin_manager")
@patch("automated_security_helper.cli.report.PluginContext")
@patch("automated_security_helper.cli.report.print")
def test_an_unreadable_results_file_still_exits_non_zero(
    _mock_print,
    _mock_plugin_context,
    mock_plugin_manager,
    _mock_resolve_config,
    _mock_load_plugins,
    tmp_path,
    reporter_plugin,
):
    """Pinning utf-8 must not turn a genuinely broken file into a silent success.

    The point of the fix is that a *valid UTF-8* file stops failing, not that failures
    stop being reported. A file that is not valid UTF-8 at all must still exit 1 rather
    than being decoded with errors="replace" into something that parses.
    """
    results_path = tmp_path / "ash_aggregated_results.json"
    # 0x9d as a bare byte is not valid UTF-8 -- it is a continuation byte with no lead.
    results_path.write_bytes(b'{"metadata": {"x": "\x9d"}}')
    plugin_class, _plugin = reporter_plugin
    mock_plugin_manager.plugin_modules.return_value = [plugin_class]

    with pytest.raises(typer.Exit) as exit_info:
        report_command(report_format="text", output_dir=str(tmp_path))
    assert exit_info.value.exit_code == 1
