"""Tests for the with-retry.sh helper used by every network install in the Dockerfile.

The bug these pin was invisible and load-bearing. `pipefail` is a shell option,
not an environment variable, so it does not cross a `bash -c` boundary. The
script set it on itself and then ran the caller's command in a fresh `bash -c`,
which meant the option protected nothing.

That matters because essentially every caller is a piped network install:

    with-retry 'curl -sSfL https://.../install.sh | sh -s -- -b /usr/local/bin'

When curl fails it hands `sh` an empty stdin, and `sh` exits 0. Without pipefail
on the *inner* shell the pipeline reports success, the retry loop exits on the
first attempt, and the failure only surfaces at the next Dockerfile step as a
missing binary.

Observed 2026-08-20: curl hit "(35) Recv failure: Connection reset by peer"
fetching grype's installer, no retry was attempted, and the build died at
`RUN grype --version` with exit 127. CI has no job-level retry, so that single
transient reset was enough to fail the run.
"""

import os
import shutil
import subprocess
import sys

import pytest

from automated_security_helper.core.constants import ASH_ASSETS_DIR

WITH_RETRY = ASH_ASSETS_DIR.joinpath("with-retry.sh")

# with-retry.sh only ever runs inside the Linux container image, so there is
# nothing to cover on Windows -- and trying to is actively misleading. On a
# GitHub Windows runner `shutil.which("bash")` resolves to
# C:\Windows\System32\bash.exe, the WSL launcher stub, which is on PATH whether
# or not a distribution is installed. With none installed it exits 1 and prints
# "Windows Subsystem for Linux has no installed distributions" as UTF-16, so a
# which() guard alone passes and then every assertion fails on empty output.
pytestmark = [
    pytest.mark.skipif(
        os.name == "nt",
        reason="bash on Windows runners is the WSL stub; with-retry.sh runs in the Linux image",
    ),
    pytest.mark.skipif(
        shutil.which("bash") is None,
        reason="with-retry.sh is a bash script; no bash interpreter available",
    ),
]


def run_with_retry(command: str, attempts: int = 3, extra_env: dict | None = None):
    """Invoke the real script, with the backoff collapsed so tests stay fast."""
    env = {
        **os.environ,
        "WITH_RETRY_MAX_ATTEMPTS": str(attempts),
        "WITH_RETRY_DELAY": "0",
    }
    if extra_env:
        env.update(extra_env)
    return subprocess.run(  # nosec B603 B607 — fixed script path, list args, no shell
        ["bash", str(WITH_RETRY), command],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
        check=False,
    )


class TestPipedFailuresAreDetected:
    """The regression: a failing pipeline must not look like success."""

    def test_failing_pipe_head_is_not_treated_as_success(self):
        """`false | true` is the shape of `curl-that-died | sh`."""
        result = run_with_retry("false | true")
        assert result.returncode != 0, (
            "a pipeline whose first stage failed must fail; if this passes, "
            "pipefail is not reaching the inner shell and every piped install "
            "in the Dockerfile has an inert retry"
        )
        assert "All 3 attempts failed" in result.stderr

    def test_failing_pipe_is_actually_retried(self):
        """Detecting the failure is only useful if the retry then happens.

        Three messages, not two: the script logs after every failed attempt,
        including the final one, and only then prints "All N attempts failed".
        """
        result = run_with_retry("false | true")
        assert result.stderr.count("failed, retrying in") == 3

    def test_curl_style_install_failure_is_caught(self, tmp_path):
        """The real pattern: an unreachable URL piped into a shell."""
        result = run_with_retry(
            f"curl -sSfL https://ash-test.invalid/install.sh | sh -s -- -b {tmp_path}",
            attempts=2,
        )
        assert result.returncode != 0
        assert "All 2 attempts failed" in result.stderr


class TestRetrySucceeds:
    """A transient failure must be recovered from, not just reported."""

    def test_command_succeeding_on_the_second_attempt_exits_zero(self, tmp_path):
        """This is the grype case: fail once on the network, then succeed."""
        marker = tmp_path / "attempts"
        # Fails while the marker holds fewer than 2 characters, then succeeds.
        command = f"printf x >> {marker}; test $(wc -c < {marker}) -ge 2"
        result = run_with_retry(command)
        assert result.returncode == 0, result.stderr
        assert marker.read_text() == "xx"
        assert result.stderr.count("failed, retrying in") == 1

    def test_success_on_first_attempt_does_not_retry(self):
        result = run_with_retry("true")
        assert result.returncode == 0
        assert "retrying" not in result.stderr


class TestExitStatus:
    def test_total_failure_exits_one(self):
        result = run_with_retry("false", attempts=2)
        assert result.returncode == 1

    def test_defaults_are_three_attempts(self):
        """Callers in the Dockerfile pass no overrides, so the default matters."""
        env = {**os.environ}
        env.pop("WITH_RETRY_MAX_ATTEMPTS", None)
        env["WITH_RETRY_DELAY"] = "0"
        result = subprocess.run(  # nosec B603 B607 — fixed script path, list args
            ["bash", str(WITH_RETRY), "false"],
            capture_output=True,
            text=True,
            env=env,
            timeout=60,
            check=False,
        )
        assert "All 3 attempts failed" in result.stderr


def _sleep_recorder(tmp_path):
    """Put a `sleep` on PATH that records its argv and returns immediately.

    Returns ``(shim_dir, log_path)``.
    """
    shim_dir = tmp_path / "shim"
    shim_dir.mkdir()
    log = tmp_path / "sleep-argv"
    shim = shim_dir / "sleep"
    shim.write_text('#!/bin/bash\nprintf "%s\\n" "$*" >> "' + str(log) + '"\nexit 0\n')
    shim.chmod(0o755)
    return shim_dir, log


class TestTheIntervalItActuallySleeps:
    """What `sleep` is handed -- not what the log line says it was handed.

    Every test above collapses the backoff with `WITH_RETRY_DELAY=0`, which is
    what keeps them fast and also means not one of them can observe the interval.
    With the delay pinned to zero, `delay=$((delay * 2))` stays zero forever, so a
    change that destroyed the growth entirely would leave every assertion in this
    file green.

    That is the shape worth guarding against: the attempt count and the
    "retrying in Ns" line are both emitted *upstream* of the arithmetic, so they
    keep printing after the arithmetic is gone. These tests shim `sleep` onto
    PATH and assert the argv it received, which pins the arithmetic without
    measuring wall clock -- an elapsed-time bound would flake low on a fast
    machine and high on a loaded one.
    """

    def test_default_backoff_doubles_and_sleep_receives_it(self, tmp_path):
        """The Dockerfile passes no overrides, so this is the schedule in production."""
        shim_dir, log = _sleep_recorder(tmp_path)
        env = {**os.environ, "PATH": f"{shim_dir}{os.pathsep}{os.environ['PATH']}"}
        env.pop("WITH_RETRY_DELAY", None)
        env.pop("WITH_RETRY_MAX_ATTEMPTS", None)

        result = subprocess.run(  # nosec B603 B607 — fixed script path, list args
            ["bash", str(WITH_RETRY), "false"],
            capture_output=True,
            text=True,
            env=env,
            timeout=60,
            check=False,
        )

        assert result.returncode == 1, result.stderr
        assert log.is_file(), (
            "sleep was never invoked, so there is no backoff between attempts at "
            "all and every retry fires back-to-back"
        )
        assert log.read_text().split() == ["5", "10", "20"], (
            "the interval must double between attempts. ['5', '5', '5'] is a "
            "fixed delay wearing the name backoff, and an empty or partial list "
            "means the arithmetic broke part-way through the loop"
        )


class TestMalformedKnobsAreRejectedNotSilentlyHonoured:
    """A non-integer delay used to truncate the loop to a single attempt.

    `sleep $delay; delay=$((delay * 2))` is bash integer arithmetic, and bash
    cannot parse `0.1` -- the obvious way to ask for a fast-but-nonzero backoff.
    The arithmetic error aborts the enclosing `while` without aborting the script
    (there is no `set -e` here), so exactly ONE attempt ran and the script still
    printed "All 3 attempts failed" and exited 1.

    Both of those observables were therefore useless for catching it: the exit
    code was already 1 and the summary already said 3. So these assert how many
    times the command actually ran.
    """

    def test_a_fractional_delay_is_rejected_before_any_attempt(self, tmp_path):
        marker = tmp_path / "attempts"
        result = run_with_retry(
            f"printf x >> {marker}; false",
            extra_env={"WITH_RETRY_DELAY": "0.1"},
        )
        assert not marker.exists(), (
            "a rejected configuration must run the command zero times; a marker "
            "holding one 'x' is the old behaviour, where the loop ran once and "
            "then silently truncated while claiming three attempts"
        )
        assert result.returncode == 2, result.stderr

    def test_a_non_numeric_attempt_count_is_rejected(self, tmp_path):
        marker = tmp_path / "attempts"
        result = run_with_retry(
            f"printf x >> {marker}; false",
            extra_env={"WITH_RETRY_MAX_ATTEMPTS": "three"},
        )
        assert not marker.exists()
        assert result.returncode == 2, result.stderr

    def test_zero_attempts_is_rejected_rather_than_reported_as_a_failed_run(
        self, tmp_path
    ):
        """max=0 skipped the loop and then reported "All 0 attempts failed".

        Exiting 1 with the command never run is indistinguishable from exiting 1
        with the command run and failed, and the second is what a reader assumes.
        """
        marker = tmp_path / "attempts"
        result = run_with_retry(f"printf x >> {marker}; false", attempts=0)
        assert not marker.exists()
        assert result.returncode == 2, result.stderr

    def test_a_valid_integer_delay_is_still_accepted(self, tmp_path):
        """Positive control: the guard must not reject the values callers use."""
        marker = tmp_path / "attempts"
        result = run_with_retry(
            f"printf x >> {marker}; false",
            attempts=2,
            extra_env={"WITH_RETRY_DELAY": "0"},
        )
        assert marker.read_text() == "xx", "both attempts must have run"
        assert result.returncode == 1


def test_script_is_present_and_executable_source():
    """A missing script would make every test above skip-shaped rather than fail."""
    assert WITH_RETRY.is_file(), f"expected with-retry.sh at {WITH_RETRY}"
    assert WITH_RETRY.read_text().startswith("#!/bin/bash")


if __name__ == "__main__":  # pragma: no cover
    sys.exit(pytest.main([__file__, "-v"]))
