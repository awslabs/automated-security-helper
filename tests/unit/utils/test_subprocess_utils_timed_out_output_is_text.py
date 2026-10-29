"""run_command's TimedOutProcess carries text when the caller asked for text.

TimeoutExpired carries what communicate had read undecoded, text mode or not,
so a tool that wrote output before its timeout handed a text-mode caller bytes
in the stdout and stderr of the TimedOutProcess run_command returned.
"""

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
