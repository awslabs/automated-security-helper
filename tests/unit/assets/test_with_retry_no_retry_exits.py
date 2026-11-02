"""with-retry.sh does not retry an integrity failure, and passes its status through.

install-pinned-tool exits 3 on a SHA256 mismatch against a pinned digest, and its
docstring says that status is "never retried" so a caller can tell it from a
network failure. with-retry wraps every pinned install in the Dockerfile and
retried that exit like any other: five fetches of the same mismatching bytes,
then exit 1, so the caller could not tell an integrity failure from a dead
network either. The script now takes a space-separated set of exit statuses it
never retries (2 and 3 by default) and exits with the command's own status on one.

Runs the real script with the backoff collapsed, the same way the sibling file
does, so it is an integration test like that file's classes.
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


class TestIntegrityFailuresAreNotRetried:
    def test_exit_3_is_passed_through_after_one_attempt(self, tmp_path):
        marker = tmp_path / "attempts"
        result = run_with_retry(f"printf x >> {marker}; exit 3")
        assert result.returncode == 3, result.stderr
        assert marker.read_text() == "x", "the integrity failure was retried"
        assert "not retried" in result.stderr
        assert "failed, retrying in" not in result.stderr
        assert "All 3 attempts failed" not in result.stderr

    def test_other_failures_are_still_retried(self, tmp_path):
        """The control: an ordinary failure keeps the old shape."""
        marker = tmp_path / "attempts"
        result = run_with_retry(f"printf x >> {marker}; exit 1")
        assert result.returncode == 1
        assert marker.read_text() == "xxx"
        assert "All 3 attempts failed" in result.stderr

    def test_the_set_is_configurable(self, tmp_path):
        marker = tmp_path / "attempts"
        result = run_with_retry(
            f"printf x >> {marker}; exit 4",
            extra_env={"WITH_RETRY_NO_RETRY_EXITS": "3 4"},
        )
        assert result.returncode == 4, result.stderr
        assert marker.read_text() == "x"

    def test_a_non_numeric_set_is_refused_before_anything_runs(self, tmp_path):
        marker = tmp_path / "attempts"
        result = run_with_retry(
            f"printf x >> {marker}", extra_env={"WITH_RETRY_NO_RETRY_EXITS": "three"}
        )
        assert result.returncode == 2
        assert "WITH_RETRY_NO_RETRY_EXITS" in result.stderr
        assert not marker.exists()
