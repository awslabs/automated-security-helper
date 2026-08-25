# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scanner subprocess must be bounded, not left to run forever.

Why this file exists
--------------------
Bandit ran for over 50 minutes under the MCP server and never finished. The same
project scanned in about 20 seconds from the CLI, so the report reads like an MCP
bug, but the cause is simpler: nothing bounded the scanner subprocess at all.

`run_command_with_output_handling` called `subprocess.run` with no `timeout`, and
that is the single call every template-based scanner goes through
(`ScannerPluginBase.scan` -> `_run_subprocess` -> here). So bandit, checkov,
semgrep, grype, syft, opengrep, cfn_nag and npm-audit were all equally unbounded.

detect-secrets was the exception, and it is the reason the report contrasts the
two: it grew its own `scan_timeout` option (default 300s) and enforces it with
`future.result(timeout=...)` in its own overridden scan. That was a per-scanner
workaround for a gap in the shared path, which is why only that one scanner
timed out cleanly in the reporter's log.

What "bounded" has to mean
--------------------------
`subprocess.run(timeout=...)` raises TimeoutExpired *and kills the child*. That
matters more than the exception: without the kill, the scanner process would keep
holding CPU after ASH stopped waiting for it. The tests below assert on elapsed
time to prove the call actually returns early, rather than only that some error
was reported.

Exit code 124 is used for a timeout, matching coreutils `timeout(1)`, so a
timed-out scanner is distinguishable from the generic returncode 1 the previous
error path returned for everything.
"""

import sys
import time

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.utils.subprocess_utils import (
    run_command_with_output_handling,
)

# Long enough that a passing test cannot have waited for it.
_SLEEP_SECONDS = 60
_TIMEOUT_SECONDS = 2


def _sleep_command(seconds: int = _SLEEP_SECONDS):
    return [sys.executable, "-c", f"import time; time.sleep({seconds})"]


class TestTimeoutIsEnforced:
    def test_a_hanging_command_returns_instead_of_blocking(self, tmp_path):
        """The reported failure mode, reduced to its smallest form."""
        started = time.monotonic()

        response = run_command_with_output_handling(
            command=_sleep_command(),
            results_dir=tmp_path,
            timeout=_TIMEOUT_SECONDS,
        )

        elapsed = time.monotonic() - started

        # Generous headroom over the timeout for interpreter startup on a loaded
        # runner, while still far below the 60s the command wanted.
        assert elapsed < 30, (
            f"Call took {elapsed:.1f}s for a {_TIMEOUT_SECONDS}s timeout, so the "
            "timeout is not being applied to the subprocess."
        )
        assert response["returncode"] == 124
        assert response.get("timed_out") is True

    def test_timeout_message_names_the_limit(self, tmp_path):
        """A hang is hard to diagnose, so the message has to say what happened."""
        response = run_command_with_output_handling(
            command=_sleep_command(),
            results_dir=tmp_path,
            timeout=_TIMEOUT_SECONDS,
        )

        combined = f"{response.get('error', '')} {response.get('stderr', '')}"
        assert "timed out" in combined.lower()
        assert str(_TIMEOUT_SECONDS) in combined

    def test_timeout_is_distinguishable_from_a_generic_failure(self, tmp_path):
        """124 vs 1.

        The previous error path returned returncode 1 for every exception, so a
        caller could not tell a timeout from a missing binary. Anything that keys
        off the exit code needs those to differ.
        """
        timed_out = run_command_with_output_handling(
            command=_sleep_command(), results_dir=tmp_path, timeout=_TIMEOUT_SECONDS
        )
        failed = run_command_with_output_handling(
            command=[sys.executable, "-c", "raise SystemExit(3)"],
            results_dir=tmp_path,
            timeout=_TIMEOUT_SECONDS,
        )

        assert timed_out["returncode"] == 124
        assert failed["returncode"] == 3
        assert failed.get("timed_out") is not True


class TestNormalExecutionIsUnaffected:
    def test_fast_command_succeeds_within_a_timeout(self, tmp_path):
        response = run_command_with_output_handling(
            command=[sys.executable, "-c", "print('done')"],
            results_dir=tmp_path,
            stdout_preference="return",
            timeout=_TIMEOUT_SECONDS,
        )

        assert response["returncode"] == 0
        assert "done" in response.get("stdout", "")
        assert response.get("timed_out") is not True

    def test_no_timeout_argument_keeps_previous_behaviour(self, tmp_path):
        """Omitting timeout must not start bounding callers that never asked.

        The parameter defaults to None so existing callers behave exactly as
        before; only the scanner template opts in.
        """
        response = run_command_with_output_handling(
            command=[sys.executable, "-c", "print('unbounded')"],
            results_dir=tmp_path,
            stdout_preference="return",
        )

        assert response["returncode"] == 0
        assert "unbounded" in response.get("stdout", "")


def test_scanner_options_expose_a_scan_timeout_default():
    """Every scanner gets the knob, not just the one that grew its own.

    300s matches the default detect-secrets already chose for the same problem,
    and what the issue asks for.
    """
    options = ScannerOptionsBase()

    assert options.scan_timeout == 300
