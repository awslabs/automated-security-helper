"""A late or partial read of a text-mode child is decoded as communicate would have.

Popen's text mode decodes with replacement and translates universal newlines
(``\\r\\n`` and a lone ``\\r`` become ``\\n``). The two late-read decoders,
_decoded (the output a failed wait carried) and _late_decoded (the partial
output of a TimeoutExpired), decoded with replacement only, so the same bytes
read with ``\\r`` kept when the wait ended early and dropped when it finished.
"""

import subprocess  # nosec B404 - the module under test wraps subprocess
from types import SimpleNamespace

import pytest

from automated_security_helper.utils import subprocess_utils

pytestmark = pytest.mark.unit

WINDOWS_LINES = b"first\r\nsecond\rthird\n"


def test_the_shared_helper_reads_as_text_mode_does():
    assert (
        subprocess_utils._as_text_mode_reads(WINDOWS_LINES, "utf-8")
        == "first\nsecond\nthird\n"
    )
    # Replacement, as text mode's errors="replace" gives it.
    assert subprocess_utils._as_text_mode_reads(b"caf\xe9\r\n", "utf-8") == "caf�\n"


def test_the_partial_output_of_a_timeout_translates_newlines():
    assert (
        subprocess_utils._late_decoded(WINDOWS_LINES, "utf-8")
        == "first\nsecond\nthird\n"
    )
    # Not bytes: handed back as it is (the text-mode case where communicate decoded).
    assert (
        subprocess_utils._late_decoded("already\r\ntext", "utf-8") == "already\r\ntext"
    )


def test_the_output_a_failed_wait_carried_translates_newlines():
    process = SimpleNamespace(
        stdout=SimpleNamespace(encoding="utf-8"), stderr=None, pid=4242
    )
    assert subprocess_utils._decoded(WINDOWS_LINES, process) == "first\nsecond\nthird\n"


def test_the_decoders_agree_with_popens_own_text_mode_translation():
    """The reference is CPython's Popen._translate_newlines, read on the class."""
    translate = getattr(subprocess.Popen, "_translate_newlines", None)
    if translate is None:
        pytest.skip("this Python has no Popen._translate_newlines to compare with")
    expected = translate(subprocess.Popen, WINDOWS_LINES, "utf-8", "replace")
    assert subprocess_utils._as_text_mode_reads(WINDOWS_LINES, "utf-8") == expected
