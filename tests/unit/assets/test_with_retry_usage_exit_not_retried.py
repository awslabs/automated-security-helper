"""with-retry.sh does not retry exit status 2 by default.

install-pinned-tool exits 2 for a request that can never succeed: an unknown tool or
bundle, a platform with no asset, a non-https URL, a half-applied version bump. The
default no-retry list held only 3, so each of those was run five times with the full
backoff between runs and then reported as a generic exit 1. Another attempt repeats
the same refusal.

Runs the real script with the backoff collapsed, the same way the sibling files do,
so it is an integration test like theirs.
"""

import os
import shutil
import subprocess

import pytest

from automated_security_helper.core.constants import ASH_ASSETS_DIR

WITH_RETRY = ASH_ASSETS_DIR.joinpath("with-retry.sh")

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


def run_with_retry(command: str, attempts: int = 3, extra_env: dict | None = None):
    env = {
        **os.environ,
        "WITH_RETRY_MAX_ATTEMPTS": str(attempts),
        "WITH_RETRY_DELAY": "0",
    }
    env.pop("WITH_RETRY_NO_RETRY_EXITS", None)
    if extra_env:
        env.update(extra_env)
    return subprocess.run(  # nosec B603 B607 - fixed script path, list args, no shell
        ["bash", str(WITH_RETRY), command],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
        check=False,
    )


class TestAStatusOfTwoIsNotRetriedByDefault:
    def test_exit_2_runs_once_and_is_passed_through(self, tmp_path):
        marker = tmp_path / "attempts"
        result = run_with_retry(f"printf x >> {marker}; exit 2")

        assert result.returncode == 2, result.stderr
        assert marker.read_text() == "x", (
            "'xxx' is the old behaviour: the refusal was run once per attempt"
        )
        assert "not retried" in result.stderr
        assert "failed, retrying in" not in result.stderr
        assert "All 3 attempts failed" not in result.stderr

    def test_the_message_names_the_default_list(self, tmp_path):
        marker = tmp_path / "attempts"
        result = run_with_retry(f"printf x >> {marker}; exit 2")

        assert "WITH_RETRY_NO_RETRY_EXITS='2 3'" in result.stderr, result.stderr

    def test_exit_2_from_a_failing_pipeline_stage_is_not_retried(self, tmp_path):
        """pipefail reports the failing stage's status, so a piped install counts."""
        marker = tmp_path / "attempts"
        result = run_with_retry(f"printf x >> {marker}; (exit 2) | cat")

        assert result.returncode == 2, result.stderr
        assert marker.read_text() == "x"


class TestTheRestOfTheBehaviourIsUnchanged:
    def test_exit_1_is_still_retried(self, tmp_path):
        marker = tmp_path / "attempts"
        result = run_with_retry(f"printf x >> {marker}; exit 1")

        assert result.returncode == 1
        assert marker.read_text() == "xxx"
        assert "All 3 attempts failed" in result.stderr

    def test_exit_3_is_still_not_retried(self, tmp_path):
        marker = tmp_path / "attempts"
        result = run_with_retry(f"printf x >> {marker}; exit 3")

        assert result.returncode == 3, result.stderr
        assert marker.read_text() == "x"

    def test_an_explicit_list_of_3_alone_retries_exit_2(self, tmp_path):
        """A set list replaces the default; it does not extend it."""
        marker = tmp_path / "attempts"
        result = run_with_retry(
            f"printf x >> {marker}; exit 2",
            extra_env={"WITH_RETRY_NO_RETRY_EXITS": "3"},
        )

        assert result.returncode == 1, result.stderr
        assert marker.read_text() == "xxx"

    def test_an_explicit_list_decides_which_statuses_stop(self, tmp_path):
        marker = tmp_path / "attempts"
        result = run_with_retry(
            f"printf x >> {marker}; exit 4",
            extra_env={"WITH_RETRY_NO_RETRY_EXITS": "4"},
        )

        assert result.returncode == 4, result.stderr
        assert marker.read_text() == "x"

    def test_the_scripts_own_exit_2_for_a_bad_knob_is_unchanged(self, tmp_path):
        marker = tmp_path / "attempts"
        result = run_with_retry(
            f"printf x >> {marker}", extra_env={"WITH_RETRY_DELAY": "0.1"}
        )

        assert result.returncode == 2, result.stderr
        assert not marker.exists()
        assert "not retried" not in result.stderr
