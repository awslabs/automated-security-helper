"""run_command's TimedOutProcess carries text when the caller asked for text.

TimeoutExpired carries what communicate had read undecoded, text mode or not,
so a tool that wrote output before its timeout handed a text-mode caller bytes
in the stdout and stderr of the TimedOutProcess run_command returned.
"""

import locale
import os
import subprocess  # nosec B404 - the module under test wraps subprocess
from unittest.mock import patch

import pytest

from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import (
    TimedOutProcess,
    run_command,
)

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _unresolved_names_reach_the_mocked_spawn(monkeypatch):
    """The program is not installed; on Windows ASH would refuse it before spawning."""
    monkeypatch.setattr(subprocess_utils, "_refuse_unresolved_on_windows", False)


def _timed_out_with_partial_output() -> subprocess.TimeoutExpired:
    # "café" in UTF-8: the last two bytes are one character.
    return subprocess.TimeoutExpired(
        cmd=["tool"], timeout=5, output=b"caf\xc3\xa9\n", stderr=b"still working\n"
    )


def _timed_out_mid_character() -> subprocess.TimeoutExpired:
    # A timeout cuts the output at an arbitrary byte: the first byte of "é"
    # was read, the second never was.
    return subprocess.TimeoutExpired(
        cmd=["tool"], timeout=5, output=b"caf\xc3", stderr=b"still working\n"
    )


@patch(
    "automated_security_helper.utils.subprocess_utils.find_executable",
    return_value=None,
)
@patch("automated_security_helper.utils.subprocess_utils._run_plain")
def test_text_mode_decodes_the_partial_output_with_the_callers_encoding(
    mock_run, _mock_find
):
    mock_run.side_effect = _timed_out_with_partial_output()

    result = run_command(["tool"], timeout=5, text=True, encoding="utf-8")

    assert isinstance(result, TimedOutProcess)
    assert result.stdout == "café\n"
    assert result.stderr == "still working\n"


@patch(
    "automated_security_helper.utils.subprocess_utils.find_executable",
    return_value=None,
)
@patch("automated_security_helper.utils.subprocess_utils._run_plain")
def test_text_mode_replaces_a_character_the_timeout_cut_in_half(mock_run, _mock_find):
    """The default handler is replace, so the half character reads as the
    replacement character; a strict decode would have raised out of the timeout
    handler instead of returning the result."""
    mock_run.side_effect = _timed_out_mid_character()

    result = run_command(["tool"], timeout=5, text=True, encoding="utf-8")

    assert isinstance(result, TimedOutProcess)
    assert result.stdout == "caf�"
    assert result.stderr == "still working\n"


@pytest.mark.skipif(os.name == "nt", reason="run_command pins utf-8 on Windows")
@patch(
    "automated_security_helper.utils.subprocess_utils.find_executable",
    return_value=None,
)
@patch("automated_security_helper.utils.subprocess_utils._run_plain")
def test_text_mode_without_an_encoding_reads_as_popens_text_mode_would(
    mock_run, _mock_find
):
    """With no encoding named, the partial output is decoded with the locale
    encoding Popen's text mode resolves to, so the two agree on a non-UTF-8
    locale too."""
    mock_run.side_effect = _timed_out_mid_character()

    result = run_command(["tool"], timeout=5, text=True)

    expected = b"caf\xc3".decode(locale.getpreferredencoding(False), errors="replace")
    assert result.stdout == expected


@patch(
    "automated_security_helper.utils.subprocess_utils.find_executable",
    return_value=None,
)
@patch("automated_security_helper.utils.subprocess_utils._run_plain")
def test_bytes_mode_keeps_the_partial_output_as_bytes(mock_run, _mock_find):
    mock_run.side_effect = _timed_out_with_partial_output()

    result = run_command(["tool"], timeout=5, text=False)

    assert isinstance(result, TimedOutProcess)
    assert result.stdout == b"caf\xc3\xa9\n"
    assert result.stderr == b"still working\n"


@patch(
    "automated_security_helper.utils.subprocess_utils.find_executable",
    return_value=None,
)
@patch("automated_security_helper.utils.subprocess_utils._run_plain")
def test_a_timeout_with_nothing_read_keeps_the_timeout_sentence(mock_run, _mock_find):
    mock_run.side_effect = subprocess.TimeoutExpired(cmd=["tool"], timeout=5)

    result = run_command(["tool"], timeout=5, text=True)

    assert result.stdout == ""
    assert result.stderr.startswith("Command timed out after")
