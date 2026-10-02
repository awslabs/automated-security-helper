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

import contextlib
import io
import locale
import os
import platform
import subprocess
import sys
import threading
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
# UnicodeDecodeError out of subprocess.run instead of yielding None.
#
# An earlier revision of this file drew the wrong conclusion from that split: that
# the swallow "is not reproducible off Windows", so the control should assert the
# decode with pytest.raises(UnicodeDecodeError) around subprocess.run and let each
# platform sort itself out. On Windows that assertion cannot be satisfied at all. The
# decode does fail there -- it just fails on the reader thread, and run() returns
# normally -- so the control reported "DID NOT RAISE UnicodeDecodeError" on all five
# Windows legs while passing on every POSIX leg. Measured, not inferred: in job
# 109519096363 (windows-latest, py3.10) the same run's warnings summary carries
# `PytestUnhandledThreadExceptionWarning: Exception in thread Thread-49
# (_readerthread)` whose traceback ends `UnicodeDecodeError: 'charmap' codec can't
# decode byte 0x90 in position 2`, through encodings\cp1252.py, from
# `buffer.append(fh.read())` at subprocess.py:1515. The hazard fired exactly as
# designed; only the assertion was in the wrong place.
#
# The swallow *is* reproducible off Windows, because the one Windows-specific
# ingredient is the decision to read on a thread. That the swallow was believed
# Windows-only is also what sent the first attempt at this failure after the wrong
# mechanism entirely -- see ``_child`` for the argv-encoding theory it produced, and
# the two Windows jobs that refute it. Read on a thread and the whole
# mechanism reproduces on Linux and macOS, which is what
# test_a_reader_thread_turns_the_decode_error_into_a_silent_none does. So the shape
# that used to be visible only in CI now has a control that runs everywhere, and the
# hazard control below asserts the loss rather than one platform's way of reporting
# it.
#
# Rejected, for the record. Gating the control on the measured code page (chcp,
# locale.getpreferredencoding) -- no code page can change this outcome, because the
# decode is named in the call as encoding="cp1252" rather than inherited from the
# host, and the runner's own cp1252 codec raised precisely as the premise says it
# should. xfail -- an xfail that passes unexpectedly is its own noise, and this one
# passes on POSIX. Deleting the control -- then nothing proves the hazard is real and
# the next regression ships in silence.
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


@contextlib.contextmanager
def _exceptions_raised_on_threads():
    """Collect exceptions that killed another thread, where Windows decodes pipes.

    threading.excepthook is how CPython surfaces them: Thread._bootstrap_inner looks
    the module global up at raise time, which is why replacing it here is enough, and
    is the same mechanism test.support.catch_threading_exception uses. pytest installs
    its own hook to turn these into PytestUnhandledThreadExceptionWarning; borrowing
    it for the length of one call both makes the exception assertable and keeps that
    warning out of the run, which is correct here because the test consumes the
    exception on purpose rather than overlooking it.
    """
    raised: list = []
    previous = threading.excepthook
    threading.excepthook = lambda args: raised.append(args.exc_value)
    try:
        yield raised
    finally:
        threading.excepthook = previous


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
        """A child that writes UTF-8 to stdout, as ASH does under CI.

        The program source is ASCII-only: the payload is spelled as escaped UTF-8
        bytes rather than embedded with ``{payload!r}``, so nothing about how a
        platform encodes a command line can reach the child's output, and this child
        matches the one ``test_replace_survives_bytes_that_are_not_utf8_either``
        builds instead of differing for no reason.

        An earlier revision claimed more than that: that embedding the glyph put a
        non-ASCII character on the command line, that Windows encoded argv with the
        active ANSI code page, and that the substituted character was why
        ``test_the_host_code_page_loses_the_payload`` failed on Windows alone. The
        first half is measurable and the second is not: CPython spawns through
        CreateProcessW and a child python.exe reads GetCommandLineW, both wide, so
        U+2510 crosses argv intact. The claim came from simulating the encoding on
        Linux -- ``program.encode("cp1252")`` raises -- and calling that a
        platform-independent measurement of Windows.

        Measured on Windows instead, in the two jobs either side of that change:
        109089825008 (glyph embedded in argv) and 109519096363 (escaped literal) both
        carry the identical reader-thread traceback, ``UnicodeDecodeError: 'charmap'
        codec can't decode byte 0x90 in position 2``. Same byte, same position, so the
        child emitted the same bytes both ways and argv had altered nothing. The
        failure never moved, because its cause was the swallow described above and the
        revision did not touch it. ``test_the_child_emits_exactly_the_bytes_this_class_
        assumes`` now pins the crossing directly rather than leaving it to a comment.
        """
        literal = "".join(f"\\x{b:02x}" for b in payload.encode("utf-8"))
        program = (
            "import sys; "
            f"sys.stdout.buffer.write(b'{literal}'); "
            "sys.stdout.buffer.flush()"
        )
        return [sys.executable, "-c", program]

    # "Nothing installed" is the panel title cli/dependencies.py sets, and the phrase
    # test_unknown_tool_reaches_a_real_stdout searches for.
    PAYLOAD = f"{SQUARE_PANEL_CORNER} Nothing installed: Unknown tool(s): nonexistent"

    def test_the_child_emits_exactly_the_bytes_this_class_assumes(self):
        """The two controls below assume these exact bytes crossed the pipe.

        Both of them are about what a *decode* does with b"\\xe2\\x94\\x90", so both are
        meaningless if the child never wrote it -- and a child that writes something
        else does not announce itself: the hazard control simply stops finding a
        hazard, which reads identically to the hazard having gone away. That
        indistinguishability is the whole reason the previous revision misdiagnosed
        this failure as an argv-encoding problem. Asserting the bytes here separates
        the two, so a child that drifts fails as itself.
        """
        proc = subprocess.run(
            self._child(self.PAYLOAD), capture_output=True, timeout=60
        )
        assert proc.stdout == self.PAYLOAD.encode("utf-8")
        assert proc.stdout[:3] == b"\xe2\x94\x90"

    def test_the_host_code_page_loses_the_payload(self):
        """The hazard: a cp1252 capture never hands back the payload.

        One hazard, two shapes, and the assertion names the part they share. POSIX
        decodes on the calling thread, so subprocess.run raises UnicodeDecodeError
        here. Windows decodes on Popen._communicate's reader thread, so the error
        lands on threading.excepthook and run() returns a CompletedProcess whose
        stdout is None. Either way the text is gone, and that is what the fix --
        naming encoding="utf-8" with errors="replace" at every capture site -- exists
        to prevent.

        The code page is named in the call rather than inherited, so this control does
        not depend on the host's ACP, on PYTHONUTF8, or on whether a runner image ever
        turns the UTF-8 beta option on. That independence is the point: the control
        must keep exercising the hazard on a host that has itself moved to UTF-8.
        """
        with _exceptions_raised_on_threads() as on_threads:
            try:
                captured = subprocess.run(
                    self._child(self.PAYLOAD),
                    capture_output=True,
                    text=True,
                    encoding="cp1252",
                    timeout=60,
                ).stdout
            except UnicodeDecodeError as exc:
                captured, in_this_frame = None, exc
            else:
                in_this_frame = None

        decode_failures = [
            exc for exc in on_threads if isinstance(exc, UnicodeDecodeError)
        ]
        assert in_this_frame is not None or decode_failures, (
            "a cp1252 decode of the child's UTF-8 bytes failed nowhere, so this "
            "control no longer exercises the hazard it exists to prove. "
            f"captured={captured!r}; other thread exceptions={on_threads!r}; "
            f"locale.getpreferredencoding(False)="
            f"{locale.getpreferredencoding(False)!r}; "
            f"sys.getfilesystemencoding()={sys.getfilesystemencoding()!r}; "
            f"sys.flags.utf8_mode={sys.flags.utf8_mode}"
        )
        assert captured is None or "Nothing installed" not in captured, (
            f"the payload survived a cp1252 capture: {captured!r}"
        )

    def test_a_reader_thread_turns_the_decode_error_into_a_silent_none(self):
        """Pin the Windows shape on every platform, by doing what Windows does.

        Popen._communicate on Windows reads each pipe on a daemon thread whose body is
        ``buffer.append(fh.read())`` and ends with
        ``stdout = stdout[0] if stdout else None``. Nothing in that is
        Windows-specific except the decision to read on a thread, so reading on a
        thread reproduces it here: the read raises, the buffer stays empty, an empty
        list is falsy, and the caller is handed None having seen no exception at all.

        This is the assertion that was missing. Without it the swallow was only
        observable on a Windows runner, which is how a control that could never fire
        there survived a revision looking sound.
        """
        buffer: list = []
        with subprocess.Popen(
            self._child(self.PAYLOAD), stdout=subprocess.PIPE, encoding="cp1252"
        ) as proc:
            with _exceptions_raised_on_threads() as on_threads:

                def _readerthread(fh, buf):  # Popen._communicate's body, verbatim.
                    buf.append(fh.read())
                    fh.close()

                reader = threading.Thread(
                    target=_readerthread, args=(proc.stdout, buffer)
                )
                reader.start()
                reader.join(timeout=60)
            assert not reader.is_alive(), "the reader thread never finished"

        assert [type(exc) for exc in on_threads] == [UnicodeDecodeError], (
            f"expected one decode failure on the reader thread, got {on_threads!r}"
        )
        assert buffer == [], "a read that raises must append nothing"
        # The expression in _communicate that turns the dead read into a clean return.
        assert (buffer[0] if buffer else None) is None

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
