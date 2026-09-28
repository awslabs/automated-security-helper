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
import subprocess
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


# The other half of the problem: configure_windows_safe_logging fixes what ASH can
# *write*, and nothing fixed what a test could *read* back out of it.
#
# A test that captures an ASH child process with subprocess.run(text=True) and no
# encoding decodes the pipe with locale.getpreferredencoding(False). On a Windows
# runner that is cp1252, while the child -- thanks to the very function this file
# tests -- is writing UTF-8. The first byte cp1252 cannot map ends the capture.
#
# What makes it a trap rather than a visible failure is where the decode happens. On
# Windows, Popen._communicate reads each pipe on a daemon thread whose body is
# `buffer.append(fh.read())`; a raising read appends nothing, and _communicate ends
# with `stdout = stdout[0] if stdout else None`. An empty buffer is falsy, so
# subprocess.run returns a CompletedProcess whose stdout is None and raises nothing.
# The returncode is still correct, so a test that checks the exit status passes and
# then dies on a TypeError one line later, pointing at the assertion rather than at
# the decode. That is exactly how it presented: all five Windows legs red, every
# Linux and macOS leg green, on a diff that had nothing to do with encodings.
#
# POSIX decodes on the calling thread, so there the same mistake raises
# UnicodeDecodeError out of subprocess.run instead of yielding None. These tests
# therefore pin the decode, which is platform-independent and is the part the fix
# controls, rather than the swallow, which is not reproducible off Windows.
#
# A rounded-corner panel would have survived: U+256D..U+2570 encode to bytes cp1252
# happens to map, so the capture comes back as mojibake and the assertions still
# pass. The failure needed a glyph whose UTF-8 form contains an unassigned byte, and
# Rich supplies one on Windows specifically -- rich.box.Box.substitute swaps
# box.ROUNDED for box.SQUARE when options.legacy_windows is set, and SQUARE's
# top-right corner is U+2510.
WINDOWS_UNASSIGNED_CP1252_BYTES = (0x81, 0x8D, 0x8F, 0x90, 0x9D)

# U+2510 '┐': box.SQUARE's top-right corner, the glyph that actually broke CI.
SQUARE_PANEL_CORNER = "┐"


class TestTheCaptureHazardIsReal:
    """Guard the premise, in the same spirit as the encode-side control above.

    Without these, the test below could pass because nothing was ever at risk.
    """

    def test_the_square_corner_is_unassigned_in_cp1252(self):
        encoded = SQUARE_PANEL_CORNER.encode("utf-8")
        assert encoded == b"\xe2\x94\x90"
        assert encoded[2] in WINDOWS_UNASSIGNED_CP1252_BYTES
        with pytest.raises(UnicodeDecodeError):
            encoded.decode("cp1252")

    def test_a_rounded_corner_would_not_have_failed(self):
        """Why this stayed hidden: the default box decodes into mojibake."""
        for rounded in "╭╮╯╰":
            rounded.encode("utf-8").decode("cp1252")  # must not raise


class TestCapturedChildOutputIsDecodedExplicitly:
    """A captured ASH stream must not be decoded with the host code page."""

    @staticmethod
    def _child(payload: str) -> list:
        """A child that writes UTF-8 to stdout, as ASH does under CI."""
        program = (
            "import sys; "
            f"sys.stdout.buffer.write({payload!r}.encode('utf-8')); "
            "sys.stdout.buffer.flush()"
        )
        return [sys.executable, "-c", program]

    # "Nothing installed" is the panel title cli/dependencies.py sets, and the phrase
    # test_unknown_tool_reaches_a_real_stdout searches for.
    PAYLOAD = f"{SQUARE_PANEL_CORNER} Nothing installed: Unknown tool(s): nonexistent"

    def test_the_host_code_page_loses_the_payload(self):
        """The bug, reproduced by naming cp1252 instead of inheriting it."""
        with pytest.raises(UnicodeDecodeError):
            subprocess.run(
                self._child(self.PAYLOAD),
                capture_output=True,
                text=True,
                encoding="cp1252",
                timeout=60,
            )

    def test_explicit_utf8_replace_keeps_the_payload(self):
        """The fix. errors="replace" is what makes this true for any byte."""
        proc = subprocess.run(
            self._child(self.PAYLOAD),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )
        assert proc.stdout is not None
        assert "Nothing installed" in proc.stdout
        assert "Unknown tool" in proc.stdout

    def test_replace_survives_bytes_that_are_not_utf8_either(self):
        """A child that is neither cp1252 nor UTF-8 must still not lose the text.

        Pinning encoding="utf-8" without errors="replace" would only move the
        failure, and a capture that raises is a capture that comes back None on
        Windows. This is the assertion that would fail if errors= were dropped.
        """
        program = (
            "import sys; "
            "sys.stdout.buffer.write(b'Nothing installed \\xff\\xfe Unknown tool'); "
            "sys.stdout.buffer.flush()"
        )
        proc = subprocess.run(
            [sys.executable, "-c", program],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )
        assert proc.stdout is not None
        assert "Nothing installed" in proc.stdout
        assert "Unknown tool" in proc.stdout
