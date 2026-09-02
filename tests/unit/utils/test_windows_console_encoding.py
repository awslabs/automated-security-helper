# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Regression tests: Windows consoles must be able to encode what ASH prints.

ASH writes emoji from three modules outside the logging path -- cli/config.py,
cli/main.py and interactions/run_ash_scan.py -- via typer.secho, typer.echo and
print. Six of those characters have no cp1252 representation, which is the default
console encoding on Windows, so each write raises UnicodeEncodeError there.

The failure is self-compounding. cli/config.py reports validation problems with
typer.secho(f"❌ Error validating config: {e}"), so an encoding error raised
inside validation causes the handler to raise a second encoding error while
reporting the first. The scan job exits 1 with a traceback instead of a message.

_make_message_windows_safe substitutes ASCII for emoji, but it only sees log
records; direct console writes bypass it. configure_windows_safe_logging closes that
gap by reconfiguring stdout/stderr to UTF-8, and is gated to Windows plus either CI
or a console that cannot encode, so it is a no-op elsewhere.
"""

import io
import os
import platform
import sys
from unittest.mock import patch

import pytest

from automated_security_helper.utils.log import configure_windows_safe_logging

# The characters ASH actually emits from non-logging call sites.
ASH_CONSOLE_SYMBOLS = ["❌", "✅", "⚠", "️", "✓", "\U0001f527"]


def _cp1252_stream() -> io.TextIOWrapper:
    """A console that behaves like a default Windows one."""
    return io.TextIOWrapper(
        io.BytesIO(), encoding="cp1252", errors="strict", write_through=True
    )


class TestSymbolsAreGenuinelyUnencodable:
    """Guard the premise: without the fix these characters really do fail."""

    @pytest.mark.parametrize("symbol", ASH_CONSOLE_SYMBOLS)
    def test_symbol_cannot_be_encoded_as_cp1252(self, symbol):
        with pytest.raises(UnicodeEncodeError):
            symbol.encode("cp1252")

    def test_raw_cp1252_console_raises_on_the_error_handler_string(self):
        """The exact string cli/config.py's failure handler writes."""
        stream = _cp1252_stream()
        with pytest.raises(UnicodeEncodeError):
            stream.write("❌ Error validating config: boom\n")


class TestConfigureWindowsSafeLogging:
    def test_is_a_noop_off_windows(self):
        """Must not touch stdout on Linux or macOS."""
        before = sys.stdout
        before_encoding = getattr(sys.stdout, "encoding", None)
        with patch.object(platform, "system", return_value="Linux"):
            configure_windows_safe_logging()
        assert sys.stdout is before
        assert getattr(sys.stdout, "encoding", None) == before_encoding

    def test_makes_ash_symbols_writable_on_a_cp1252_console(self):
        """The regression: emoji-bearing console writes must stop raising."""
        replacement = _cp1252_stream()
        original_out, original_err = sys.stdout, sys.stderr
        try:
            sys.stdout, sys.stderr = replacement, replacement
            with (
                patch.object(platform, "system", return_value="Windows"),
                patch.dict(os.environ, {"CI": "true"}, clear=False),
            ):
                configure_windows_safe_logging()
                # Write through whatever the function left in place.
                for symbol in ASH_CONSOLE_SYMBOLS:
                    sys.stdout.write(f"{symbol} ok\n")
                sys.stdout.flush()
                encoding = getattr(sys.stdout, "encoding", "")
        finally:
            sys.stdout, sys.stderr = original_out, original_err

        assert "utf-8" in encoding.lower(), (
            f"stdout left at {encoding!r}; console writes will still raise"
        )

    def test_stderr_is_handled_too(self):
        """The compounding failure path writes to stderr as well."""
        replacement = _cp1252_stream()
        original_out, original_err = sys.stdout, sys.stderr
        try:
            sys.stdout, sys.stderr = replacement, replacement
            with (
                patch.object(platform, "system", return_value="Windows"),
                patch.dict(os.environ, {"CI": "true"}, clear=False),
            ):
                configure_windows_safe_logging()
                sys.stderr.write("❌ on stderr\n")
                sys.stderr.flush()
                encoding = getattr(sys.stderr, "encoding", "")
        finally:
            sys.stdout, sys.stderr = original_out, original_err

        assert "utf-8" in encoding.lower()

    def test_survives_a_stream_without_reconfigure(self):
        """Must degrade quietly rather than raise on an exotic stream."""

        class Bare:
            encoding = "cp1252"

            def write(self, _s):
                return 0

            def flush(self):
                return None

        original_out, original_err = sys.stdout, sys.stderr
        try:
            sys.stdout, sys.stderr = Bare(), Bare()
            with (
                patch.object(platform, "system", return_value="Windows"),
                patch.dict(os.environ, {"CI": "true"}, clear=False),
            ):
                configure_windows_safe_logging()  # must not raise
        finally:
            sys.stdout, sys.stderr = original_out, original_err


class TestGetLoggerAppliesIt:
    def test_get_logger_configures_the_console(self):
        """get_logger is the entry point every CLI path goes through."""
        with patch(
            "automated_security_helper.utils.log.configure_windows_safe_logging"
        ) as mock_cfg:
            from automated_security_helper.utils.log import get_logger

            get_logger(name="test-windows-console")
            mock_cfg.assert_called()
