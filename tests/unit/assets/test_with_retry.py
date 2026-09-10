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

        Two messages for three attempts, because the message announces a retry
        and only two of the three attempts have one after them. A zero here is
        the original defect -- the loop exiting on its first pass -- and the
        trailing third message is the separate defect pinned in
        ``TestNothingFollowsTheFinalAttempt`` below.
        """
        result = run_with_retry("false | true")
        assert result.stderr.count("failed, retrying in") == 2

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
        assert log.read_text().split() == ["5", "10"], (
            "the interval must double between attempts. ['5', '5'] is a "
            "fixed delay wearing the name backoff, and an empty or partial list "
            "means the arithmetic broke part-way through the loop. A trailing "
            "'20' is the sleep after the final attempt -- see "
            "TestNothingFollowsTheFinalAttempt"
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


class TestTheSummaryCountMatchesWhatRan:
    """The defect was a disagreement between two observables, so compare them.

    Every other test here reads one side or the other: the attempt marker, or the
    "All N attempts failed" line. The bug lived in the gap -- one attempt ran and
    the summary said three -- so a test that reads only one side cannot see it no
    matter how precise it is. These read both in the same run and assert they
    agree.

    This is the assertion that would have caught the original defect with no
    knowledge of bash arithmetic at all.
    """

    @staticmethod
    def _summary_count(stderr: str) -> int | None:
        """The N out of "All N attempts failed", or None if no claim was made."""
        for line in stderr.splitlines():
            if line.startswith("All ") and "attempts failed" in line:
                return int(line.split()[1])
        return None

    @pytest.mark.parametrize("attempts", [1, 2, 3, 5])
    def test_the_claim_equals_the_number_of_runs(self, tmp_path, attempts):
        marker = tmp_path / "attempts"
        result = run_with_retry(f"printf x >> {marker}; false", attempts=attempts)

        actually_ran = len(marker.read_text()) if marker.exists() else 0
        claimed = self._summary_count(result.stderr)

        assert claimed == attempts, result.stderr
        assert actually_ran == claimed, (
            f"the script ran the command {actually_ran} time(s) but reported "
            f"{claimed}. That disagreement is the defect: a truncated loop still "
            f"prints the summary, so the message alone always looked right"
        )

    def test_a_rejected_config_makes_no_claim_at_all(self, tmp_path):
        """Silence beats a false count.

        The old behaviour on WITH_RETRY_DELAY=0.1 was to run once and then assert
        three attempts had failed. Exiting 2 with no summary is the honest
        alternative -- there is nothing to summarize, because nothing ran.
        """
        marker = tmp_path / "attempts"
        result = run_with_retry(
            f"printf x >> {marker}; false",
            extra_env={"WITH_RETRY_DELAY": "0.1"},
        )
        assert result.returncode == 2, result.stderr
        assert not marker.exists()
        assert self._summary_count(result.stderr) is None, (
            "a config that was never accepted must not report attempts as failed"
        )


def _run_recording_sleeps(
    command: str, tmp_path, attempts: int | None = None, delay: int | None = None
):
    """Run the script with a recording ``sleep`` on PATH.

    Returns ``(CompletedProcess, sleep_argv)`` where ``sleep_argv`` is the list of
    arguments each ``sleep`` call received, in order. Omitting ``attempts`` or
    ``delay`` unsets the corresponding override so the production default applies.
    """
    shim_dir, log = _sleep_recorder(tmp_path)
    env = {**os.environ, "PATH": f"{shim_dir}{os.pathsep}{os.environ['PATH']}"}
    env.pop("WITH_RETRY_MAX_ATTEMPTS", None)
    env.pop("WITH_RETRY_DELAY", None)
    if attempts is not None:
        env["WITH_RETRY_MAX_ATTEMPTS"] = str(attempts)
    if delay is not None:
        env["WITH_RETRY_DELAY"] = str(delay)

    result = subprocess.run(  # nosec B603 B607 — fixed script path, list args
        ["bash", str(WITH_RETRY), command],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
        check=False,
    )
    return result, (log.read_text().split() if log.is_file() else [])


class TestNothingFollowsTheFinalAttempt:
    """The last attempt has no retry after it, so the wait after it is dead time.

    The loop announced and took a backoff unconditionally, including after the
    attempt that ended it. On the production schedule that reads:

        Attempt 3/3 failed, retrying in 20s...
        <20 real seconds pass>
        All 3 attempts failed

    Two adjacent lines contradicting each other, and 20 seconds of wall clock
    burned per failing call site across every ``with-retry`` invocation in the
    Dockerfile. Measured on this branch before the fix: three sleeps of 5, 10 and
    20 for a command that fails every time; after: two, of 5 and 10.

    Both halves are asserted separately, because either can be fixed while the
    other stays broken: dropping only the message still burns the 20 seconds, and
    dropping only the sleep still promises a retry that never comes. Neither
    assertion measures wall clock -- the shim records what ``sleep`` was handed,
    which does not flake low on a fast machine or high on a loaded one.
    """

    def test_no_sleep_follows_the_last_attempt(self, tmp_path):
        """The Dockerfile passes no overrides, so this is the production schedule."""
        result, slept = _run_recording_sleeps("false", tmp_path)

        assert result.returncode == 1, result.stderr
        assert slept == ["5", "10"], (
            "three attempts have two gaps between them, so two sleeps. A "
            "trailing '20' is the defect: the loop announced a retry, slept the "
            "full 20 seconds, then left the loop and reported total failure"
        )

    def test_the_final_attempt_does_not_announce_a_retry(self, tmp_path):
        result, _ = _run_recording_sleeps("false", tmp_path)

        assert "Attempt 3/3 failed, retrying" not in result.stderr, (
            "the final attempt claimed a retry was coming and then the very next "
            "line said every attempt had failed"
        )
        assert result.stderr.count("failed, retrying in") == 2
        assert "All 3 attempts failed" in result.stderr

    def test_a_single_attempt_never_sleeps_at_all(self, tmp_path):
        """max=1 is the degenerate case: no gaps, so nothing to wait for."""
        result, slept = _run_recording_sleeps("false", tmp_path, attempts=1)

        assert slept == [], (
            "with one attempt there is no second attempt to wait for, yet the "
            "old loop still slept the full delay before giving up"
        )
        assert "retrying" not in result.stderr
        assert "All 1 attempts failed" in result.stderr

    def test_the_gap_before_a_real_retry_is_still_announced_and_slept(self, tmp_path):
        """Positive control: the guard must silence the last attempt, not the retry.

        A guard that suppressed every message and every sleep would satisfy the
        three assertions above and destroy the backoff this file exists to
        provide.
        """
        result, slept = _run_recording_sleeps("false", tmp_path, attempts=2, delay=7)

        assert slept == ["7"], "the gap between attempt 1 and attempt 2 must be slept"
        assert "Attempt 1/2 failed, retrying in 7s..." in result.stderr
        assert result.stderr.count("failed, retrying in") == 1


def _run_argv(*argv: str, attempts: int = 3, delay: int = 0):
    """Invoke the script with an exact argument vector, including an empty one."""
    env = {
        **os.environ,
        "WITH_RETRY_MAX_ATTEMPTS": str(attempts),
        "WITH_RETRY_DELAY": str(delay),
    }
    return subprocess.run(  # nosec B603 B607 — fixed script path, list args, no shell
        ["bash", str(WITH_RETRY), *argv],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
        check=False,
    )


class TestAnEmptyCommandIsRejectedRatherThanReportedAsSuccess:
    """``bash -c ""`` exits 0, so an empty invocation looked like a clean run.

    This is the mirror image of the ``max=0`` guard further up the script, and
    the guard there states the reasoning exactly: a result "indistinguishable
    from the command having been run and failed, when it was never run at all".
    Flip the sign and it is worse, because a false *success* is not investigated.
    Inside a Dockerfile

        RUN with-retry "$SOME_ARG"

    with ``SOME_ARG`` unset or renamed produces a RUN layer that does nothing and
    exits 0, and the build dies several steps later at a missing binary -- the
    exact failure mode this file's header describes for the pipefail bug.

    An argument *count* check alone is not enough. A quoted expansion of an unset
    variable still passes one argument, so ``$#`` is 1 and ``$*`` is empty; that
    is the likelier of the two shapes in practice, and the reason the guard tests
    the joined command rather than the count.
    """

    def test_no_arguments_at_all_exits_non_zero(self):
        result = _run_argv()

        assert result.returncode != 0, (
            "with-retry with no command exited 0, reporting success for work it "
            "never did and never could have done"
        )
        assert result.returncode == 2, result.stderr
        assert "no command given" in result.stderr

    def test_an_argument_that_expanded_to_nothing_is_also_rejected(self):
        """The Dockerfile shape: ``with-retry "$SOME_ARG"`` with SOME_ARG unset."""
        result = _run_argv("")

        assert result.returncode == 2, result.stderr
        assert "no command given" in result.stderr

    def test_a_whitespace_only_command_is_rejected(self):
        result = _run_argv("   ")

        assert result.returncode == 2, result.stderr
        assert "no command given" in result.stderr

    def test_nothing_is_reported_as_attempted_when_no_command_was_given(self):
        """Silence beats a count, the same way a rejected config makes no claim."""
        result = _run_argv()

        assert "attempts failed" not in result.stderr
        assert "retrying" not in result.stderr

    def test_a_real_command_is_still_run(self):
        """Positive control. A guard that rejected everything would pass the four
        assertions above and break all 13 ``with-retry`` invocations in the
        Dockerfile at once, which is far worse than the bug it closed."""
        assert _run_argv("true").returncode == 0

    def test_a_real_command_that_fails_still_retries(self, tmp_path):
        marker = tmp_path / "attempts"
        result = _run_argv(f"printf x >> {marker}; false", attempts=3)

        assert marker.read_text() == "xxx", "all three attempts must still run"
        assert result.returncode == 1

    def test_a_command_split_across_several_arguments_is_still_run(self, tmp_path):
        """Callers pass one quoted string, but ``"$*"`` joins whatever it gets."""
        marker = tmp_path / "written"
        assert _run_argv("printf", "ok", ">", str(marker)).returncode == 0
        assert marker.read_text() == "ok"


def test_script_is_present_and_executable_source():
    """A missing script would make every test above skip-shaped rather than fail."""
    assert WITH_RETRY.is_file(), f"expected with-retry.sh at {WITH_RETRY}"
    assert WITH_RETRY.read_text().startswith("#!/bin/bash")


if __name__ == "__main__":  # pragma: no cover
    sys.exit(pytest.main([__file__, "-v"]))
