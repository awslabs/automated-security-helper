"""A late or partial read is decoded with the caller's error handler.

run_command and run_command_with_output_handling take an ``errors`` handler and
hand it to Popen, whose text mode decodes a finished run with it. The late-read
decoders hard-coded replacement, so a caller that asked for another handler
(backslashreplace, say) got it on a finished run and not on a timed-out one.
"""

import subprocess  # nosec B404 - the module under test wraps subprocess
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from automated_security_helper.utils import subprocess_utils

pytestmark = pytest.mark.unit

UNDECODABLE = b"caf\xe9\r\n"


@pytest.fixture(autouse=True)
def _unresolved_names_reach_the_mocked_spawn(monkeypatch):
    monkeypatch.setattr(subprocess_utils, "_refuse_unresolved_on_windows", False)


def test_the_partial_read_uses_the_callers_handler():
    assert (
        subprocess_utils._late_decoded(UNDECODABLE, "utf-8", "backslashreplace")
        == "caf\\xe9\n"
    )
    # The default stays replacement.
    assert subprocess_utils._late_decoded(UNDECODABLE, "utf-8") == "caf�\n"


def test_a_strict_partial_read_falls_back_to_replacement_so_it_cannot_raise():
    """A strict caller whose partial output ends mid-character: the timeout result
    is reported, never a UnicodeDecodeError from inside the timeout handler."""
    assert subprocess_utils._late_decoded(UNDECODABLE, "utf-8", "strict") == "caf�\n"


ENTRY_POINTS = ["run_command", "run_command_with_output_handling"]


def _timed_out_through(entry_point: str, **kwargs):
    """The timed-out run's (stdout, stderr) through either public entry point.

    Both take ``errors`` and hand it to the late read of the partial output;
    the second appends its own timeout sentence to the stderr it returns."""
    if entry_point == "run_command":
        result = subprocess_utils.run_command(["tool"], timeout=5, text=True, **kwargs)
        assert isinstance(result, subprocess_utils.TimedOutProcess)
        return result.stdout, result.stderr
    response = subprocess_utils.run_command_with_output_handling(
        ["tool"],
        stdout_preference="return",
        stderr_preference="return",
        timeout=5,
        **kwargs,
    )
    assert response["timed_out"] is True
    return response["stdout"], response["stderr"]


@pytest.mark.parametrize("entry_point", ENTRY_POINTS)
@patch(
    "automated_security_helper.utils.subprocess_utils.find_executable",
    return_value=None,
)
@patch("automated_security_helper.utils.subprocess_utils._run_plain")
def test_a_strict_handler_still_returns_the_timeout_result(
    mock_run, _mock_find, entry_point
):
    mock_run.side_effect = subprocess.TimeoutExpired(
        cmd=["tool"], timeout=5, output=UNDECODABLE, stderr=UNDECODABLE
    )

    stdout, stderr = _timed_out_through(entry_point, encoding="utf-8", errors="strict")

    assert stdout == "caf�\n"
    assert stderr.startswith("caf�\n")


def test_the_failed_wait_read_uses_the_streams_handler():
    process = SimpleNamespace(
        stdout=SimpleNamespace(encoding="utf-8", errors="backslashreplace"),
        stderr=None,
        pid=4242,
    )
    assert subprocess_utils._decoded(UNDECODABLE, process) == "caf\\xe9\n"


def test_a_strict_stream_falls_back_to_replacement_so_the_late_read_cannot_raise():
    process = SimpleNamespace(
        stdout=SimpleNamespace(encoding="utf-8", errors="strict"),
        stderr=None,
        pid=4242,
    )
    assert subprocess_utils._decoded(UNDECODABLE, process) == "caf�\n"


@pytest.mark.parametrize("entry_point", ENTRY_POINTS)
@patch(
    "automated_security_helper.utils.subprocess_utils.find_executable",
    return_value=None,
)
@patch("automated_security_helper.utils.subprocess_utils._run_plain")
def test_the_errors_handler_reaches_the_timed_out_output(
    mock_run, _mock_find, entry_point
):
    mock_run.side_effect = subprocess.TimeoutExpired(
        cmd=["tool"], timeout=5, output=UNDECODABLE, stderr=UNDECODABLE
    )

    stdout, stderr = _timed_out_through(
        entry_point, encoding="utf-8", errors="backslashreplace"
    )

    assert stdout == "caf\\xe9\n"
    assert stderr.startswith("caf\\xe9\n")
