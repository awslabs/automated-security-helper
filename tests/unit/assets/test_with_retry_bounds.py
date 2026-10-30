"""with-retry.sh bounds both the attempt count and every backoff interval.

Two gaps were left by the guards that already existed:

* The attempt count was checked for being all digits and nothing more. A value
  past the 64-bit range passes that check, but ``test`` answers it with "integer
  expression expected" and status 2. The ``[ "$max" -lt 1 ]`` guard sits in an
  ``if``, so it read as false and let the value through, and the ``while``
  condition then failed the same way: the command never ran, and the script still
  printed "All N attempts failed" and exited 1.
* The 86400 second ceiling applied to the first interval only. The doubling after
  each failed attempt was uncapped, so a larger attempt count asked ``sleep`` for
  days, then years, and finally wrapped to a negative number that ``sleep``
  rejects and nothing checks.

Runs the real script, with ``sleep`` shimmed onto PATH where the interval matters.
Large numbers are built at run time rather than written out.
"""

import os
import shutil
import subprocess

import pytest

from automated_security_helper.core.constants import ASH_ASSETS_DIR

WITH_RETRY = ASH_ASSETS_DIR.joinpath("with-retry.sh")

CEILING = 86400

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.name == "nt",
        reason="bash on Windows runners is the WSL stub; with-retry.sh runs in the Linux image",
    ),
    pytest.mark.skipif(
        shutil.which("bash") is None,
        reason="with-retry.sh is a bash script; no bash interpreter available",
    ),
]


def _run(command: str, tmp_path, attempts: str, delay: str = "0", record_sleep=False):
    """Run the script; return ``(CompletedProcess, sleep_argv)``.

    With ``record_sleep`` a ``sleep`` shim that logs its argv and returns at once is
    put first on PATH, so the interval the script asks for can be read directly.
    """
    env = {
        **os.environ,
        "WITH_RETRY_MAX_ATTEMPTS": attempts,
        "WITH_RETRY_DELAY": delay,
    }
    log = tmp_path / "sleep-argv"
    if record_sleep:
        shim_dir = tmp_path / "shim"
        shim_dir.mkdir(parents=True)
        shim = shim_dir / "sleep"
        shim.write_text(
            '#!/bin/bash\nprintf "%s\\n" "$*" >> "' + str(log) + '"\nexit 0\n'
        )
        shim.chmod(0o755)
        env["PATH"] = f"{shim_dir}{os.pathsep}{os.environ['PATH']}"
    result = subprocess.run(  # nosec B603 B607 - fixed script path, list args, no shell
        ["bash", str(WITH_RETRY), command],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
        check=False,
    )
    return result, (log.read_text().split() if log.is_file() else [])


class TestAnAttemptCountPastTheIntegerRangeIsRejected:
    """The command must run, or the configuration must be refused; never neither."""

    def test_twenty_digits_is_refused_before_anything_runs(self, tmp_path):
        marker = tmp_path / "ran"
        result, _ = _run(f"printf x >> {marker}; false", tmp_path, attempts="9" * 20)

        assert not marker.exists()
        assert result.returncode == 2, (
            "exit 1 with 'All N attempts failed' is the old behaviour: the loop "
            "condition errored, the command never ran, and the summary claimed it "
            f"had. stderr was: {result.stderr}"
        )
        assert "WITH_RETRY_MAX_ATTEMPTS" in result.stderr
        assert "attempts failed" not in result.stderr

    def test_nineteen_digits_past_the_signed_limit_is_refused(self, tmp_path):
        marker = tmp_path / "ran"
        result, _ = _run(f"printf x >> {marker}; false", tmp_path, attempts="9" * 19)

        assert not marker.exists()
        assert result.returncode == 2, result.stderr
        assert "attempts failed" not in result.stderr

    def test_the_largest_accepted_width_still_runs_the_command(self, tmp_path):
        """Positive control: eighteen digits is in range and must not be refused."""
        marker = tmp_path / "ran"
        result, _ = _run(f"printf x >> {marker}", tmp_path, attempts="1" + "0" * 17)

        assert result.returncode == 0, result.stderr
        assert marker.read_text() == "x"

    def test_padding_is_not_magnitude(self, tmp_path):
        """Thirty leading zeros before a 3 still mean three attempts."""
        marker = tmp_path / "ran"
        result, _ = _run(
            f"printf x >> {marker}; false", tmp_path, attempts="0" * 30 + "3"
        )

        assert marker.read_text() == "xxx", result.stderr
        assert result.returncode == 1

    def test_an_all_zero_count_is_still_the_at_least_one_refusal(self, tmp_path):
        marker = tmp_path / "ran"
        result, _ = _run(f"printf x >> {marker}", tmp_path, attempts="0" * 30)

        assert not marker.exists()
        assert result.returncode == 2
        assert "at least 1" in result.stderr


class TestEveryBackoffIntervalIsCapped:
    """The ceiling checked on the starting delay holds for every doubled one."""

    def test_doubling_stops_at_the_ceiling(self, tmp_path):
        result, slept = _run(
            "false", tmp_path, attempts="5", delay=str(CEILING), record_sleep=True
        )

        assert result.returncode == 1, result.stderr
        assert slept == [str(CEILING)] * 4, (
            "the starting delay is already at the ceiling, so no interval may be "
            "longer; 172800 as the second entry is the uncapped doubling"
        )

    def test_the_cap_applies_where_the_doubling_crosses_it(self, tmp_path):
        result, slept = _run(
            "false", tmp_path, attempts="5", delay="40000", record_sleep=True
        )

        assert slept == ["40000", "80000", str(CEILING), str(CEILING)], (
            "doubling is unchanged below the ceiling and held at it above; 160000 "
            "as the third entry is the uncapped doubling"
        )
        assert result.returncode == 1

    def test_a_large_attempt_count_never_wraps_or_leaves_the_range(self, tmp_path):
        attempts = 80
        result, slept = _run(
            "false", tmp_path, attempts=str(attempts), delay="5", record_sleep=True
        )

        assert result.returncode == 1, result.stderr
        assert len(slept) == attempts - 1
        values = [int(v) for v in slept]
        assert all(1 <= v <= CEILING for v in values), (
            "an interval outside 1..86400 is the uncapped doubling: past a day "
            "within a dozen attempts, and a negative or zero value once 64-bit "
            f"arithmetic wraps. Got min {min(values)} and max {max(values)}"
        )
        assert values == sorted(values), "the backoff must never shrink"
        assert values[-1] == CEILING

    def test_the_announced_interval_is_the_one_slept(self, tmp_path):
        result, slept = _run(
            "false", tmp_path, attempts="3", delay=str(CEILING), record_sleep=True
        )

        assert slept == [str(CEILING), str(CEILING)]
        assert result.stderr.count(f"retrying in {CEILING}s...") == 2, result.stderr
        assert "172800" not in result.stderr

    def test_the_default_schedule_is_unchanged(self, tmp_path):
        """Positive control: below the ceiling the doubling is exactly as before."""
        result, slept = _run(
            "false", tmp_path, attempts="5", delay="5", record_sleep=True
        )

        assert slept == ["5", "10", "20", "40"]
        assert result.returncode == 1
