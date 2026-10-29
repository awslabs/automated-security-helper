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


@patch(
    "automated_security_helper.utils.subprocess_utils.find_executable",
    return_value=None,
)
@patch("automated_security_helper.utils.subprocess_utils._run_plain")
def test_run_command_passes_its_errors_handler_to_the_timed_out_output(
    mock_run, _mock_find
):
    mock_run.side_effect = subprocess.TimeoutExpired(
        cmd=["tool"], timeout=5, output=UNDECODABLE, stderr=UNDECODABLE
    )

    result = subprocess_utils.run_command(
        ["tool"], timeout=5, text=True, encoding="utf-8", errors="backslashreplace"
    )

    assert result.stdout == "caf\\xe9\n"
    assert result.stderr == "caf\\xe9\n"
